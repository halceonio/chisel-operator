use super::{cloud_init::generate_cloud_init_config, Provisioner};
use crate::ops::{
    parse_provisioner_label_value, ExitNode, ExitNodeStatus, EXIT_NODE_PROVISIONER_LABEL,
};
use async_trait::async_trait;
use color_eyre::eyre::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt;
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
use tokio::time::sleep;
use tracing::{debug, info, warn};

const DEFAULT_MACHINE_TYPE: &str = "e2-micro";
const DEFAULT_IMAGE: &str = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts";
const DEFAULT_DISK_TYPE: &str = "pd-balanced";
const COMPUTE_SCOPE: &str = "https://www.googleapis.com/auth/compute";

fn default_machine_type() -> String {
    DEFAULT_MACHINE_TYPE.to_string()
}

fn default_scopes() -> Vec<String> {
    vec![COMPUTE_SCOPE.to_string()]
}

fn default_tags() -> Vec<String> {
    Vec::new()
}

fn default_labels() -> BTreeMap<String, String> {
    BTreeMap::new()
}

fn default_image() -> String {
    DEFAULT_IMAGE.to_string()
}

fn sanitize_label_component(
    raw: &str,
    require_letter_start: bool,
    allow_empty: bool,
) -> (String, bool) {
    if raw.is_empty() {
        return if allow_empty {
            (String::new(), false)
        } else {
            (
                String::from(if require_letter_start { "k" } else { "v" }),
                true,
            )
        };
    }

    let mut changed = false;
    let mut bytes: Vec<u8> = raw
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => b,
            b'A'..=b'Z' => {
                changed = true;
                b + 32
            }
            _ => {
                changed = true;
                b'-'
            }
        })
        .collect();

    let valid_start = |b: &u8| {
        if require_letter_start {
            b.is_ascii_lowercase()
        } else {
            b.is_ascii_lowercase() || b.is_ascii_digit()
        }
    };

    if let Some(idx) = bytes.iter().position(valid_start) {
        if idx > 0 {
            bytes.drain(0..idx);
            changed = true;
        }
    } else {
        bytes.clear();
    }

    let mut end = bytes.len();
    while end > 0 {
        let b = bytes[end - 1];
        if b.is_ascii_lowercase() || b.is_ascii_digit() {
            break;
        }
        end -= 1;
    }
    if end < bytes.len() {
        bytes.truncate(end);
        changed = true;
    }

    if bytes.is_empty() {
        if allow_empty {
            return (String::new(), true);
        }
        let fallback = if require_letter_start { b'k' } else { b'v' };
        bytes.push(fallback);
        changed = true;
    }

    if require_letter_start && !bytes[0].is_ascii_lowercase() {
        bytes.insert(0, b'k');
        changed = true;
    } else if !require_letter_start && !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
    {
        bytes.insert(0, b'v');
        changed = true;
    }

    if bytes.len() > 63 {
        bytes.truncate(63);
        changed = true;
    }

    (String::from_utf8(bytes).unwrap_or_default(), changed)
}

fn sanitize_label_key(raw: &str) -> (String, bool) {
    sanitize_label_component(raw, true, false)
}

fn sanitize_label_value(raw: &str, allow_empty: bool) -> (String, bool) {
    sanitize_label_component(raw, false, allow_empty)
}

fn sanitize_gcp_labels(
    labels: &BTreeMap<String, String>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut sanitized = BTreeMap::new();
    let mut warnings = Vec::new();

    for (key, value) in labels {
        let (clean_key, key_changed) = sanitize_label_key(key);
        let (clean_value, value_changed) = sanitize_label_value(value, true);

        if key_changed || value_changed {
            warnings.push(format!("{}={}", key, value));
        }

        if sanitized.insert(clean_key.clone(), clean_value).is_some() {
            warnings.push(format!(
                "Label key `{}` collided after sanitization; overwriting previous value",
                clean_key
            ));
        }
    }

    (sanitized, warnings)
}

fn sanitize_network_tag(raw: &str) -> (String, bool) {
    let mut changed = false;
    let mut bytes: Vec<u8> = raw
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' => b,
            b'A'..=b'Z' => {
                changed = true;
                b + 32
            }
            _ => {
                changed = true;
                b'-'
            }
        })
        .collect();

    if let Some(idx) = bytes.iter().position(|b| b.is_ascii_lowercase()) {
        if idx > 0 {
            bytes.drain(0..idx);
            changed = true;
        }
    } else {
        bytes.clear();
    }

    let mut end = bytes.len();
    while end > 0 {
        let b = bytes[end - 1];
        if b.is_ascii_lowercase() || b.is_ascii_digit() {
            break;
        }
        end -= 1;
    }
    if end < bytes.len() {
        bytes.truncate(end);
        changed = true;
    }

    if bytes.is_empty() {
        bytes.push(b't');
        changed = true;
    }

    if bytes.len() > 63 {
        bytes.truncate(63);
        changed = true;
    }

    (
        String::from_utf8(bytes).unwrap_or_else(|_| "t".into()),
        changed,
    )
}

fn push_unique_tag(tags: &mut Vec<String>, tag: String) {
    if !tags.iter().any(|existing| existing == &tag) {
        tags.push(tag);
    }
}

fn normalize_network_reference(network: &str) -> String {
    network
        .trim_start_matches("https://www.googleapis.com/compute/v1/")
        .trim_start_matches('/')
        .to_string()
}

fn firewall_url(project: &str, rule: &str) -> String {
    if rule.starts_with("https://") {
        rule.to_string()
    } else if rule.starts_with("projects/") {
        format!(
            "https://compute.googleapis.com/compute/v1/{}",
            rule.trim_start_matches('/')
        )
    } else {
        format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls/{}",
            project, rule
        )
    }
}

#[derive(Debug, Deserialize)]
struct FirewallRuleResponse {
    #[serde(rename = "targetTags", default)]
    target_tags: Vec<String>,
    network: Option<String>,
    name: Option<String>,
}

async fn resolve_firewall_rule_tags(
    client: &reqwest::Client,
    token: &str,
    project: &str,
    firewall_rule: &str,
    network: &str,
) -> Result<Vec<String>> {
    let url = firewall_url(project, firewall_rule);
    let response = client.get(&url).bearer_auth(token).send().await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Err(anyhow!(
            "Firewall rule `{}` was not found in project `{}`",
            firewall_rule,
            project
        ));
    }

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to fetch firewall rule `{}`: {}",
            firewall_rule,
            body
        ));
    }

    let rule: FirewallRuleResponse = response.json().await?;
    if let Some(rule_network) = rule.network.as_deref() {
        let normalized_rule = normalize_network_reference(rule_network);
        let normalized_request = normalize_network_reference(network);
        if normalized_rule != normalized_request {
            return Err(anyhow!(
                "Firewall rule `{}` targets network `{}`, but the provisioner is configured for `{}`",
                firewall_rule,
                rule_network,
                network
            ));
        }
    }

    if rule.target_tags.is_empty() {
        return Err(anyhow!(
            "Firewall rule `{}` does not define any targetTags. \
             Please add targetTags to the firewall rule or configure `spec.GCP.tags` on the provisioner.",
            firewall_rule
        ));
    }

    Ok(rule.target_tags)
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct GCPProvisioner {
    /// Reference to the secret containing a Google Cloud service account JSON key under `GCP_SERVICE_ACCOUNT_KEY`.
    pub auth: String,
    /// Google Cloud project ID
    pub project: String,
    /// Compute Engine zone (e.g. `us-central1-a`).
    pub zone: String,
    /// Machine type to provision.
    #[serde(default = "default_machine_type")]
    pub machine_type: String,
    /// Optional fully-qualified network resource (defaults to the project's `default` network).
    #[serde(default)]
    pub network: Option<String>,
    /// Optional fully-qualified subnetwork resource.
    #[serde(default)]
    pub subnetwork: Option<String>,
    /// Disk image to use.
    #[serde(default = "default_image")]
    pub image: String,
    /// Optional service account email override. Defaults to the service account from the secret.
    #[serde(default)]
    pub service_account_email: Option<String>,
    /// OAuth scopes to grant to the VM's service account.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Network tags to apply.
    #[serde(default = "default_tags")]
    pub tags: Vec<String>,
    /// Labels to apply to the instance.
    #[serde(default = "default_labels")]
    pub labels: BTreeMap<String, String>,
    /// Optional firewall rule name or selfLink whose target tags should be applied to the instance.
    #[serde(default)]
    pub firewall_rule: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

#[derive(Debug)]
struct GcpCredentials {
    client_email: String,
    private_key: String,
    token_uri: String,
}

impl GcpCredentials {
    fn from_secret(secret: &Secret) -> Result<Self> {
        let json = secret
            .data
            .as_ref()
            .and_then(|map| map.get("GCP_SERVICE_ACCOUNT_KEY"))
            .ok_or_else(|| anyhow!("GCP_SERVICE_ACCOUNT_KEY not found in secret"))?;

        let json_str = String::from_utf8(json.0.clone())?;
        let key: ServiceAccountKey = serde_json::from_str(&json_str)?;

        Ok(Self {
            client_email: key.client_email,
            private_key: key.private_key,
            token_uri: key.token_uri,
        })
    }

    async fn access_token(&self, client: &reqwest::Client, scopes: &[String]) -> Result<String> {
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            scope: String,
            aud: &'a str,
            exp: usize,
            iat: usize,
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as usize;

        let claims = Claims {
            iss: &self.client_email,
            scope: scopes.join(" "),
            aud: &self.token_uri,
            iat: now,
            exp: now + 3600,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_string());

        let encoding_key = EncodingKey::from_rsa_pem(self.private_key.as_bytes())?;
        let jwt = encode(&header, &claims, &encoding_key)?;

        let resp = client
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?;

        let token: TokenResponse = resp.json().await?;
        Ok(token.access_token)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GcpTrackedInstance {
    name: String,
    self_link: String,
}

impl GcpTrackedInstance {
    fn new(name: String, self_link: String) -> Self {
        Self { name, self_link }
    }

    fn encode(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn decode(raw: &str) -> Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }
}

fn zone_instances_url(project: &str, zone: &str) -> String {
    format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances",
        project, zone
    )
}

fn zone_instance_url(project: &str, zone: &str, instance: &str) -> String {
    format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}",
        project, zone, instance
    )
}

fn zone_operation_url(project: &str, zone: &str, operation: &str) -> String {
    format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/operations/{}",
        project, zone, operation
    )
}

fn project_network_default(project: &str) -> String {
    format!("projects/{}/global/networks/default", project)
}

fn sanitize_instance_name(name: &str) -> String {
    let mut normalized: String = name
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '-' => c,
            _ => '-',
        })
        .collect();

    if normalized.is_empty() {
        normalized.push('n');
    }

    if !matches!(normalized.chars().next(), Some('a'..='z')) {
        normalized.insert(0, 'n');
    }

    while normalized.ends_with('-') {
        normalized.pop();
    }

    if normalized.is_empty() {
        normalized.push('n');
    }

    if normalized.len() > 63 {
        normalized.truncate(63);
    }

    normalized
}

async fn wait_for_zone_operation(
    client: &reqwest::Client,
    token: &str,
    project: &str,
    zone: &str,
    operation: &str,
    action: &str,
) -> Result<()> {
    let url = zone_operation_url(project, zone, operation);

    for attempt in 0..60 {
        let response = client.get(&url).bearer_auth(token).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            warn!(status = ?status, "Failed to poll GCP operation: {}", text);
        } else {
            let body: serde_json::Value = response.json().await?;
            let status = body
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("DONE");

            if status == "DONE" {
                if let Some(error) = body.get("error") {
                    return Err(anyhow!("GCP operation {} failed: {}", action, error));
                }
                return Ok(());
            }
        }

        sleep(Duration::from_secs(5)).await;
        debug!(attempt, operation, action, "Waiting for GCP operation");
    }

    Err(anyhow!("Timed out waiting for GCP operation: {}", action))
}

async fn fetch_instance_ip(
    client: &reqwest::Client,
    token: &str,
    project: &str,
    zone: &str,
    instance: &str,
) -> Result<(String, String)> {
    let url = zone_instance_url(project, zone, instance);

    for attempt in 0..60 {
        let response = client.get(&url).bearer_auth(token).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("GCP instance {} not found", instance));
        }

        if response.status().is_success() {
            let body: serde_json::Value = response.json().await?;
            if let Some(ip) = body
                .pointer("/networkInterfaces/0/accessConfigs/0/natIP")
                .and_then(|v| v.as_str())
            {
                let self_link = body
                    .get("selfLink")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                return Ok((ip.to_string(), self_link));
            }
        } else {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            warn!(status = ?status, "Failed to fetch GCP instance: {}", text);
        }

        sleep(Duration::from_secs(5)).await;
        debug!(attempt, instance, "Waiting for GCP instance NAT IP");
    }

    Err(anyhow!(
        "Timed out waiting for GCP instance {} to obtain a public IP",
        instance
    ))
}

#[async_trait]
impl Provisioner for GCPProvisioner {
    async fn create_exit_node(
        &self,
        auth: Secret,
        exit_node: ExitNode,
        node_password: String,
    ) -> Result<ExitNodeStatus> {
        let provisioner_label = exit_node
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(EXIT_NODE_PROVISIONER_LABEL))
            .ok_or_else(|| {
                anyhow!(
                    "No provisioner found in annotations for exit node {}",
                    exit_node.metadata.name.as_deref().unwrap_or("<unknown>")
                )
            })?;

        let current_namespace = exit_node.namespace().unwrap_or_default();
        let (_, provisioner_name) =
            parse_provisioner_label_value(&current_namespace, provisioner_label);

        let instance_name = sanitize_instance_name(&format!(
            "{}-{}",
            provisioner_name,
            exit_node.metadata.name.as_deref().unwrap_or("exit-node")
        ));
        let body_instance_name = instance_name.clone();

        let client = reqwest::Client::builder().build()?;
        let credentials = GcpCredentials::from_secret(&auth)?;
        let email = self
            .service_account_email
            .clone()
            .unwrap_or_else(|| credentials.client_email.clone());
        let token = credentials.access_token(&client, &self.scopes).await?;

        let machine_type = format!(
            "projects/{}/zones/{}/machineTypes/{}",
            self.project, self.zone, self.machine_type
        );
        let disk_type = format!(
            "projects/{}/zones/{}/diskTypes/{}",
            self.project, self.zone, DEFAULT_DISK_TYPE
        );
        let network = self
            .network
            .clone()
            .unwrap_or_else(|| project_network_default(&self.project));

        let (mut labels, label_warnings) = sanitize_gcp_labels(&self.labels);
        for warning in label_warnings {
            warn!(
                label = %warning,
                "Sanitized invalid GCP label to satisfy API requirements"
            );
        }

        let (sanitized_provisioner_label, provisioner_label_changed) =
            sanitize_label_value(provisioner_label, false);
        if provisioner_label_changed {
            warn!(
                original = provisioner_label,
                sanitized = sanitized_provisioner_label,
                "Sanitized provisioner label value for GCP labels"
            );
        }
        labels.insert(
            "chisel-operator-provisioner".to_string(),
            sanitized_provisioner_label,
        );

        let mut network_tags: Vec<String> = self
            .tags
            .iter()
            .map(|tag| {
                let (sanitized, changed) = sanitize_network_tag(tag);
                if changed {
                    warn!(
                        original = tag,
                        sanitized = sanitized,
                        "Sanitized invalid GCP tag"
                    );
                }
                sanitized
            })
            .collect();

        if let Some(rule_name) = &self.firewall_rule {
            let firewall_tags =
                resolve_firewall_rule_tags(&client, &token, &self.project, rule_name, &network)
                    .await?;

            for tag in firewall_tags {
                let (sanitized, changed) = sanitize_network_tag(&tag);
                if changed {
                    warn!(
                        rule = rule_name,
                        original = tag,
                        sanitized = sanitized,
                        "Sanitized firewall target tag returned by GCP"
                    );
                }
                push_unique_tag(&mut network_tags, sanitized);
            }
        }

        let cloud_init = generate_cloud_init_config(&node_password, exit_node.spec.port);

        let metadata_items = vec![
            json!({
                "key": "user-data",
                "value": cloud_init.clone(),
            }),
            json!({
                "key": "startup-script",
                "value": cloud_init,
            }),
        ];

        let mut network_interface = json!({
            "network": network,
            "accessConfigs": [
                {
                    "name": "External NAT",
                    "type": "ONE_TO_ONE_NAT",
                    "networkTier": "STANDARD"
                }
            ]
        });

        if let Some(subnetwork) = &self.subnetwork {
            network_interface
                .as_object_mut()
                .unwrap()
                .insert("subnetwork".to_string(), json!(subnetwork));
        }

        let mut body = json!({
            "name": body_instance_name,
            "machineType": machine_type,
            "disks": [
                {
                    "boot": true,
                    "autoDelete": true,
                    "initializeParams": {
                        "sourceImage": self.image.clone(),
                        "diskType": disk_type,
                    }
                }
            ],
            "networkInterfaces": [network_interface],
            "metadata": {
                "items": metadata_items,
            },
            "labels": labels,
            "serviceAccounts": [
                {
                    "email": email,
                    "scopes": self.scopes.clone(),
                }
            ]
        });

        if !network_tags.is_empty() {
            body.as_object_mut().unwrap().insert(
                "tags".to_string(),
                json!({
                    "items": network_tags,
                }),
            );
        }

        let instances_url = zone_instances_url(&self.project, &self.zone);
        let response = client
            .post(&instances_url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(anyhow!("Failed to create GCP instance: {}", body_text));
        }

        let operation: serde_json::Value = serde_json::from_str(&body_text)?;
        let operation_name = operation
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing operation name in GCP response"))?;

        wait_for_zone_operation(
            &client,
            &token,
            &self.project,
            &self.zone,
            operation_name,
            "create instance",
        )
        .await?;

        let (public_ip, self_link) =
            fetch_instance_ip(&client, &token, &self.project, &self.zone, &instance_name).await?;

        let tracked = GcpTrackedInstance::new(instance_name.clone(), self_link);

        let status = ExitNodeStatus::new(
            provisioner_label.clone(),
            instance_name,
            public_ip,
            Some(tracked.encode()?),
        );

        Ok(status)
    }

    async fn update_exit_node(
        &self,
        auth: Secret,
        exit_node: ExitNode,
        _node_password: String,
    ) -> Result<ExitNodeStatus> {
        let status = exit_node
            .status
            .as_ref()
            .ok_or_else(|| anyhow!("Exit node status missing for update"))?;

        let id_raw = status
            .id
            .as_ref()
            .ok_or_else(|| anyhow!("GCP instance identifier missing"))?;

        let tracked = GcpTrackedInstance::decode(id_raw)?;

        let client = reqwest::Client::builder().build()?;
        let credentials = GcpCredentials::from_secret(&auth)?;
        let token = credentials.access_token(&client, &self.scopes).await?;

        let (public_ip, _) =
            fetch_instance_ip(&client, &token, &self.project, &self.zone, &tracked.name).await?;

        let mut new_status = status.clone();
        new_status.ip = public_ip;

        Ok(new_status)
    }

    async fn delete_exit_node(&self, auth: Secret, exit_node: ExitNode) -> Result<()> {
        let Some(status) = exit_node.status else {
            return Ok(());
        };

        let Some(id_raw) = status.id else {
            return Ok(());
        };

        let tracked = GcpTrackedInstance::decode(&id_raw)?;

        let client = reqwest::Client::builder().build()?;
        let credentials = GcpCredentials::from_secret(&auth)?;
        let token = credentials.access_token(&client, &self.scopes).await?;

        let instance_url = zone_instance_url(&self.project, &self.zone, &tracked.name);
        let response = client
            .delete(&instance_url)
            .bearer_auth(&token)
            .send()
            .await?;

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();

        if status == reqwest::StatusCode::NOT_FOUND {
            info!(instance = %tracked.name, "GCP instance already deleted");
            return Ok(());
        }

        if !status.is_success() {
            return Err(anyhow!("Failed to delete GCP instance: {}", body_text));
        }

        let operation: serde_json::Value = serde_json::from_str(&body_text)?;
        let operation_name = operation
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing operation name in delete response"))?;

        wait_for_zone_operation(
            &client,
            &token,
            &self.project,
            &self.zone,
            operation_name,
            "delete instance",
        )
        .await?;

        Ok(())
    }
}
