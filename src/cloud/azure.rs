use super::{cloud_init::generate_cloud_init_config, pwgen::generate_password, Provisioner};
use crate::ops::{
    parse_provisioner_label_value, ExitNode, ExitNodeStatus, EXIT_NODE_PROVISIONER_LABEL,
};
use async_trait::async_trait;
use base64::Engine as _;
use color_eyre::eyre::{anyhow, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
use tokio::time::sleep;
use tracing::{debug, info, warn};

const DEFAULT_VM_SIZE: &str = "Standard_B1s";
const DEFAULT_IMAGE_PUBLISHER: &str = "Canonical";
const DEFAULT_IMAGE_OFFER: &str = "0001-com-ubuntu-server-jammy";
const DEFAULT_IMAGE_SKU: &str = "24_04-lts";
const DEFAULT_IMAGE_VERSION: &str = "latest";

const NETWORK_API_VERSION: &str = "2023-04-01";
const COMPUTE_API_VERSION: &str = "2023-09-01";

fn default_vm_size() -> String {
    DEFAULT_VM_SIZE.to_string()
}

fn default_image_reference() -> AzureImageReference {
    AzureImageReference {
        publisher: DEFAULT_IMAGE_PUBLISHER.to_string(),
        offer: DEFAULT_IMAGE_OFFER.to_string(),
        sku: DEFAULT_IMAGE_SKU.to_string(),
        version: DEFAULT_IMAGE_VERSION.to_string(),
    }
}

fn default_admin_username() -> String {
    "azureuser".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct AzureImageReference {
    #[serde(default = "default_image_reference_publisher")]
    pub publisher: String,
    #[serde(default = "default_image_reference_offer")]
    pub offer: String,
    #[serde(default = "default_image_reference_sku")]
    pub sku: String,
    #[serde(default = "default_image_reference_version")]
    pub version: String,
}

fn default_image_reference_publisher() -> String {
    DEFAULT_IMAGE_PUBLISHER.to_string()
}

fn default_image_reference_offer() -> String {
    DEFAULT_IMAGE_OFFER.to_string()
}

fn default_image_reference_sku() -> String {
    DEFAULT_IMAGE_SKU.to_string()
}

fn default_image_reference_version() -> String {
    DEFAULT_IMAGE_VERSION.to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct AzureProvisioner {
    /// Reference to a secret containing Azure credentials.
    /// The secret must contain the `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID` keys.
    pub auth: String,
    /// Azure subscription ID where resources should be created.
    pub subscription_id: String,
    /// Azure resource group that will contain the provisioned resources.
    pub resource_group: String,
    /// Azure location/region (e.g. `eastus`).
    pub location: String,
    /// Subnet resource ID used for the network interface (e.g. `/subscriptions/.../virtualNetworks/.../subnets/default`).
    pub subnet_id: String,
    /// Optional Network Security Group to attach to the network interface.
    #[serde(default)]
    pub network_security_group_id: Option<String>,
    /// VM size to launch — defaults to `Standard_B1s`.
    #[serde(default = "default_vm_size")]
    pub vm_size: String,
    /// Admin username for the VM. If omitted, defaults to `azureuser`.
    #[serde(default = "default_admin_username")]
    pub admin_username: String,
    /// Optional SSH public key to add to the VM.
    #[serde(default)]
    pub ssh_public_key: Option<String>,
    /// Image reference to use for the VM. Defaults to Ubuntu 24.04 LTS.
    #[serde(default = "default_image_reference")]
    pub image: AzureImageReference,
    /// Additional tags to attach to all provisioned resources.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AzureCredentials {
    client_id: String,
    client_secret: String,
    tenant_id: String,
}

impl AzureCredentials {
    fn from_secret(secret: &Secret) -> Result<Self> {
        Ok(Self {
            client_id: read_secret_field(secret, "AZURE_CLIENT_ID")?,
            client_secret: read_secret_field(secret, "AZURE_CLIENT_SECRET")?,
            tenant_id: read_secret_field(secret, "AZURE_TENANT_ID")?,
        })
    }

    async fn access_token(&self, client: &reqwest::Client) -> Result<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: Option<String>,
        }

        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope", "https://management.azure.com/.default"),
        ];

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let resp = client
            .post(token_url)
            .form(&form)
            .send()
            .await?
            .error_for_status()?;

        let token: TokenResponse = resp.json().await?;
        Ok(token.access_token)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AzureTrackedResources {
    vm_id: String,
    nic_id: String,
    public_ip_id: String,
}

impl AzureTrackedResources {
    fn new(subscription: &str, resource_group: &str, name: &str) -> Self {
        let vm_id = format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}",
            subscription, resource_group, name
        );
        let nic_id = format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkInterfaces/{}",
            subscription,
            resource_group,
            format!("{}-nic", name)
        );
        let public_ip_id = format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPAddresses/{}",
            subscription,
            resource_group,
            format!("{}-ip", name)
        );

        Self {
            vm_id,
            nic_id,
            public_ip_id,
        }
    }

    fn encoded(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn decode(raw: &str) -> Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }
}

fn read_secret_field(secret: &Secret, key: &str) -> Result<String> {
    secret
        .data
        .as_ref()
        .and_then(|map| map.get(key))
        .ok_or_else(|| anyhow!("{} not found in secret", key))
        .and_then(|value| {
            String::from_utf8(value.0.clone()).map_err(|_| anyhow!("Invalid UTF-8 in {}", key))
        })
}

fn management_url(resource_id: &str, api_version: &str) -> String {
    format!(
        "https://management.azure.com{}?api-version={}",
        resource_id, api_version
    )
}

async fn wait_for_provisioning(
    client: &reqwest::Client,
    token: &str,
    resource_id: &str,
    api_version: &str,
    resource_kind: &str,
) -> Result<()> {
    let url = management_url(resource_id, api_version);

    for attempt in 0..60 {
        let response = client.get(&url).bearer_auth(token).send().await?;

        if response.status().is_success() {
            let body: serde_json::Value = response.json().await?;
            let state = body
                .pointer("/properties/provisioningState")
                .and_then(|value| value.as_str())
                .unwrap_or("Succeeded");

            debug!(resource_id, state, attempt, "Azure provisioning state");

            match state {
                "Succeeded" => return Ok(()),
                "Failed" => {
                    return Err(anyhow!(
                        "Azure {} provisioning failed for {}",
                        resource_kind,
                        resource_id
                    ))
                }
                _ => {}
            }
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            debug!(resource_id, "Azure resource not found while polling");
        } else {
            warn!(
                resource_id,
                status = ?response.status(),
                "Unexpected Azure response while polling"
            );
        }

        sleep(Duration::from_secs(5)).await;
    }

    Err(anyhow!(
        "Timed out waiting for Azure {} provisioning for {}",
        resource_kind,
        resource_id
    ))
}

async fn delete_resource(
    client: &reqwest::Client,
    token: &str,
    resource_id: &str,
    api_version: &str,
    resource_kind: &str,
) -> Result<()> {
    let url = management_url(resource_id, api_version);

    let response = client.delete(&url).bearer_auth(token).send().await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        debug!(
            resource_id,
            "Azure resource not found during delete, ignoring"
        );
        return Ok(());
    }

    if !response.status().is_success() && response.status() != reqwest::StatusCode::ACCEPTED {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to delete Azure {} {}: {}",
            resource_kind,
            resource_id,
            text
        ));
    }

    // Follow-up polling until the resource disappears
    for attempt in 0..60 {
        let verify = client.get(&url).bearer_auth(token).send().await?;

        if verify.status() == reqwest::StatusCode::NOT_FOUND {
            debug!(resource_id, attempt, "Azure resource deleted");
            return Ok(());
        }

        sleep(Duration::from_secs(5)).await;
    }

    Err(anyhow!(
        "Timed out waiting for Azure {} deletion for {}",
        resource_kind,
        resource_id
    ))
}

fn build_tags(
    base: &BTreeMap<String, String>,
    provisioner_label: &str,
) -> BTreeMap<String, String> {
    let mut tags = base.clone();
    tags.insert(
        "chisel-operator-provisioner".to_string(),
        provisioner_label.to_string(),
    );
    tags
}

async fn ensure_public_ip(
    client: &reqwest::Client,
    token: &str,
    provisioner: &AzureProvisioner,
    ids: &AzureTrackedResources,
    tags: &BTreeMap<String, String>,
) -> Result<()> {
    let body = json!({
        "location": provisioner.location.clone(),
        "tags": tags,
        "properties": {
            "publicIPAllocationMethod": "Static",
            "idleTimeoutInMinutes": 4,
            "sku": {
                "name": "Standard"
            }
        }
    });

    let url = management_url(&ids.public_ip_id, NETWORK_API_VERSION);

    let response = client
        .put(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!("Azure public IP creation failed: {}", text));
    }

    wait_for_provisioning(
        client,
        token,
        &ids.public_ip_id,
        NETWORK_API_VERSION,
        "public IP",
    )
    .await
}

async fn ensure_network_interface(
    client: &reqwest::Client,
    token: &str,
    provisioner: &AzureProvisioner,
    ids: &AzureTrackedResources,
    tags: &BTreeMap<String, String>,
) -> Result<()> {
    let mut properties = json!({
        "ipConfigurations": [
            {
                "name": "primary",
                "properties": {
                    "subnet": { "id": provisioner.subnet_id.clone() },
                    "publicIPAddress": { "id": ids.public_ip_id },
                    "primary": true,
                    "privateIPAllocationMethod": "Dynamic"
                }
            }
        ]
    });

    if let Some(nsg_id) = &provisioner.network_security_group_id {
        properties
            .as_object_mut()
            .unwrap()
            .insert("networkSecurityGroup".to_string(), json!({ "id": nsg_id }));
    }

    let body = json!({
        "location": provisioner.location.clone(),
        "tags": tags,
        "properties": properties,
    });

    let url = management_url(&ids.nic_id, NETWORK_API_VERSION);

    let response = client
        .put(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!("Azure NIC creation failed: {}", text));
    }

    wait_for_provisioning(
        client,
        token,
        &ids.nic_id,
        NETWORK_API_VERSION,
        "network interface",
    )
    .await
}

async fn ensure_virtual_machine(
    client: &reqwest::Client,
    token: &str,
    provisioner: &AzureProvisioner,
    ids: &AzureTrackedResources,
    vm_name: &str,
    custom_data: &str,
    tags: &BTreeMap<String, String>,
) -> Result<()> {
    let admin_password = generate_password(24);

    let mut linux_configuration = json!({
        "disablePasswordAuthentication": false,
    });

    if let Some(ssh_key) = &provisioner.ssh_public_key {
        linux_configuration
            .as_object_mut()
            .unwrap()
            .insert(
                "ssh".to_string(),
                json!({
                    "publicKeys": [
                        {
                            "path": format!("/home/{}/.ssh/authorized_keys", provisioner.admin_username),
                            "keyData": ssh_key,
                        }
                    ]
                }),
            );
    }

    let body = json!({
        "location": provisioner.location.clone(),
        "tags": tags,
        "properties": {
            "hardwareProfile": {
                "vmSize": provisioner.vm_size.clone(),
            },
            "storageProfile": {
                "imageReference": {
                    "publisher": provisioner.image.publisher.clone(),
                    "offer": provisioner.image.offer.clone(),
                    "sku": provisioner.image.sku.clone(),
                    "version": provisioner.image.version.clone(),
                },
                "osDisk": {
                    "createOption": "FromImage",
                    "managedDisk": {
                        "storageAccountType": "Standard_LRS"
                    }
                }
            },
            "osProfile": {
                "computerName": vm_name,
                "adminUsername": provisioner.admin_username.clone(),
                "adminPassword": admin_password,
                "linuxConfiguration": linux_configuration,
                "customData": custom_data,
            },
            "networkProfile": {
                "networkInterfaces": [
                    {
                        "id": ids.nic_id,
                        "properties": {
                            "primary": true
                        }
                    }
                ]
            }
        }
    });

    let url = management_url(&ids.vm_id, COMPUTE_API_VERSION);

    let response = client
        .put(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!("Azure VM creation failed: {}", text));
    }

    wait_for_provisioning(
        client,
        token,
        &ids.vm_id,
        COMPUTE_API_VERSION,
        "virtual machine",
    )
    .await
}

async fn fetch_public_ip(
    client: &reqwest::Client,
    token: &str,
    ids: &AzureTrackedResources,
) -> Result<String> {
    let url = management_url(&ids.public_ip_id, NETWORK_API_VERSION);

    for attempt in 0..60 {
        let response = client.get(&url).bearer_auth(token).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            warn!(status = ?status, "Failed to fetch Azure public IP: {}", text);
        } else {
            let body: serde_json::Value = response.json().await?;
            if let Some(ip) = body
                .pointer("/properties/ipAddress")
                .and_then(|v| v.as_str())
            {
                debug!(ip, attempt, "Obtained Azure public IP");
                return Ok(ip.to_string());
            }
        }

        sleep(Duration::from_secs(5)).await;
    }

    Err(anyhow!("Timed out fetching Azure public IP address"))
}

#[async_trait]
impl Provisioner for AzureProvisioner {
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

        let vm_name = format!(
            "{}-{}",
            provisioner_name,
            exit_node.metadata.name.as_deref().unwrap_or("exit-node")
        );

        let client = reqwest::Client::builder().build()?;
        let credentials = AzureCredentials::from_secret(&auth)?;
        let token = credentials.access_token(&client).await?;

        let tracked =
            AzureTrackedResources::new(&self.subscription_id, &self.resource_group, &vm_name);
        let tags = build_tags(&self.tags, provisioner_label);

        ensure_public_ip(&client, &token, self, &tracked, &tags).await?;
        ensure_network_interface(&client, &token, self, &tracked, &tags).await?;

        let cloud_init = generate_cloud_init_config(&node_password, exit_node.spec.port);
        let custom_data = base64::engine::general_purpose::STANDARD.encode(cloud_init);

        ensure_virtual_machine(
            &client,
            &token,
            self,
            &tracked,
            &vm_name,
            &custom_data,
            &tags,
        )
        .await?;

        let public_ip = fetch_public_ip(&client, &token, &tracked).await?;

        let status = ExitNodeStatus::new(
            provisioner_label.clone(),
            vm_name,
            public_ip,
            Some(tracked.encoded()?),
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
            .ok_or_else(|| anyhow!("Azure resource identifiers missing in status"))?;

        let tracked = AzureTrackedResources::decode(id_raw)?;

        let client = reqwest::Client::builder().build()?;
        let credentials = AzureCredentials::from_secret(&auth)?;
        let token = credentials.access_token(&client).await?;

        let public_ip = fetch_public_ip(&client, &token, &tracked).await?;

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

        let tracked = AzureTrackedResources::decode(&id_raw)?;

        let client = reqwest::Client::builder().build()?;
        let credentials = AzureCredentials::from_secret(&auth)?;
        let token = credentials.access_token(&client).await?;

        info!(vm_id = %tracked.vm_id, "Deleting Azure virtual machine");
        delete_resource(
            &client,
            &token,
            &tracked.vm_id,
            COMPUTE_API_VERSION,
            "virtual machine",
        )
        .await?;
        delete_resource(
            &client,
            &token,
            &tracked.nic_id,
            NETWORK_API_VERSION,
            "network interface",
        )
        .await?;
        delete_resource(
            &client,
            &token,
            &tracked.public_ip_id,
            NETWORK_API_VERSION,
            "public IP",
        )
        .await?;

        Ok(())
    }
}
