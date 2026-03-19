//! Azure VM self-management — deallocate this VM after idle timeout.
//!
//! Uses the Azure REST API to deallocate the VM when the worker has been
//! idle (no jobs) for a configurable number of minutes, stopping compute billing.
//! The VM's OS disk is preserved so it can be started again later.

use serde::Deserialize;

/// Azure VM configuration from environment variables.
#[derive(Clone)]
pub struct AzureVmConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub subscription_id: String,
    pub resource_group: String,
    pub vm_name: String,
}

impl AzureVmConfig {
    /// Load Azure VM config from environment variables. Returns None if not configured.
    pub fn from_env() -> Option<Self> {
        Some(Self {
            tenant_id: std::env::var("AZURE_TENANT_ID").ok()?,
            client_id: std::env::var("AZURE_CLIENT_ID").ok()?,
            client_secret: std::env::var("AZURE_CLIENT_SECRET").ok()?,
            subscription_id: std::env::var("AZURE_SUBSCRIPTION_ID").ok()?,
            resource_group: std::env::var("AZURE_VM_RESOURCE_GROUP").ok()?,
            vm_name: std::env::var("AZURE_VM_NAME").ok()?,
        })
    }

    /// Get the idle timeout in minutes from env, defaulting to 5.
    pub fn idle_timeout_mins() -> u64 {
        std::env::var("AZURE_IDLE_TIMEOUT_MINS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Get an OAuth2 access token from Azure AD using client credentials.
async fn get_access_token(config: &AzureVmConfig) -> Result<String, String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        config.tenant_id
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("scope", "https://management.azure.com/.default"),
        ])
        .send()
        .await
        .map_err(|e| format!("Failed to request Azure token: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Azure token request failed: {body}"));
    }

    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Azure token response: {e}"))?;

    Ok(token.access_token)
}

/// Deallocate this VM. This stops the VM and releases compute billing.
/// The VM's OS disk is preserved so it can be started again later.
pub async fn deallocate_self(config: &AzureVmConfig) -> Result<(), String> {
    let token = get_access_token(config).await?;

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}/deallocate?api-version=2024-07-01",
        config.subscription_id, config.resource_group, config.vm_name
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .header("Content-Length", "0")
        .send()
        .await
        .map_err(|e| format!("Failed to call Azure deallocate API: {e}"))?;

    let status = resp.status();
    if status.is_success() || status.as_u16() == 202 {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Azure deallocate failed ({status}): {body}"))
    }
}
