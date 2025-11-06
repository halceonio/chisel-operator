use super::{cloud_init::generate_cloud_init_config, Provisioner};
use crate::ops::{
    parse_provisioner_label_value, ExitNode, ExitNodeStatus, EXIT_NODE_PROVISIONER_LABEL,
};
use async_trait::async_trait;
use color_eyre::eyre::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt;
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
    format!(
        "projects/{}/global/networks/default",
        project
    )
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
        let response = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await?;

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
                    return Err(anyhow!(
                        "GCP operation {} failed: {}",
                        action, error
                    ));
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
        let response = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await?;

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
        let token = credentials
            .access_token(&client, &self.scopes)
            .await?;

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

        let mut labels = self.labels.clone();
        labels.insert(
            "chisel-operator-provisioner".to_string(),
            provisioner_label.to_string(),
        );

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

        if !self.tags.is_empty() {
            body.as_object_mut().unwrap().insert(
                "tags".to_string(),
                json!({
                    "items": self.tags.clone(),
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

        let (public_ip, self_link) = fetch_instance_ip(
            &client,
            &token,
            &self.project,
            &self.zone,
            &instance_name,
        )
        .await?;

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
        let token = credentials
            .access_token(&client, &self.scopes)
            .await?;

        let (public_ip, _) = fetch_instance_ip(
            &client,
            &token,
            &self.project,
            &self.zone,
            &tracked.name,
        )
        .await?;

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
        let token = credentials
            .access_token(&client, &self.scopes)
            .await?;

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
