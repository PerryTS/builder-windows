//! Build job types — manifest, credentials, and status.
//! These types are shared between the hub (which creates them) and the worker (which uses them).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    pub app_name: String,
    pub bundle_id: String,
    pub version: String,
    pub short_version: Option<String>,
    pub entry: String,
    pub icon: Option<String>,
    pub targets: Vec<String>,
    pub category: Option<String>,
    pub minimum_os_version: Option<String>,
    pub entitlements: Option<Vec<String>>,
    // Windows-specific fields
    #[serde(default)]
    pub windows_distribute: Option<String>,
    #[serde(default)]
    pub windows_uac_level: Option<String>,
    #[serde(default)]
    pub windows_dpi_aware: Option<String>,
    #[serde(default)]
    pub windows_file_description: Option<String>,
    #[serde(default)]
    pub windows_company_name: Option<String>,
    #[serde(default)]
    pub windows_copyright: Option<String>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop, serde::Deserialize)]
pub struct BuildCredentials {
    // Windows signing credentials
    #[serde(default)]
    pub windows_pfx_base64: Option<String>,
    #[serde(default)]
    pub windows_pfx_password: Option<String>,
    #[serde(default)]
    pub windows_timestamp_url: Option<String>,
    // Azure Trusted Signing fields
    #[serde(default)]
    pub azure_tenant_id: Option<String>,
    #[serde(default)]
    pub azure_client_id: Option<String>,
    #[serde(default)]
    pub azure_client_secret: Option<String>,
    #[serde(default)]
    pub azure_signing_endpoint: Option<String>,
    #[serde(default)]
    pub azure_signing_account: Option<String>,
    #[serde(default)]
    pub azure_signing_profile: Option<String>,
}

impl BuildCredentials {
    pub fn timestamp_url(&self) -> &str {
        self.windows_timestamp_url
            .as_deref()
            .unwrap_or("http://timestamp.digicert.com")
    }

    pub fn has_pfx(&self) -> bool {
        self.windows_pfx_base64.is_some()
    }

    pub fn has_azure(&self) -> bool {
        self.azure_tenant_id.is_some()
            && self.azure_client_id.is_some()
            && self.azure_client_secret.is_some()
            && self.azure_signing_endpoint.is_some()
            && self.azure_signing_account.is_some()
            && self.azure_signing_profile.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_minimal() {
        let json = r#"{}"#;
        let creds: BuildCredentials = serde_json::from_str(json).unwrap();
        assert!(creds.windows_pfx_base64.is_none());
        assert!(!creds.has_pfx());
        assert!(!creds.has_azure());
        assert_eq!(creds.timestamp_url(), "http://timestamp.digicert.com");
    }

    #[test]
    fn test_credentials_with_pfx() {
        let json = r#"{
            "windows_pfx_base64": "dGVzdA==",
            "windows_pfx_password": "pass123",
            "windows_timestamp_url": "http://timestamp.comodoca.com"
        }"#;
        let creds: BuildCredentials = serde_json::from_str(json).unwrap();
        assert!(creds.has_pfx());
        assert!(!creds.has_azure());
        assert_eq!(creds.timestamp_url(), "http://timestamp.comodoca.com");
    }

    #[test]
    fn test_credentials_with_azure() {
        let json = r#"{
            "azure_tenant_id": "tenant",
            "azure_client_id": "client",
            "azure_client_secret": "secret",
            "azure_signing_endpoint": "https://eus.codesigning.azure.net",
            "azure_signing_account": "account",
            "azure_signing_profile": "profile"
        }"#;
        let creds: BuildCredentials = serde_json::from_str(json).unwrap();
        assert!(creds.has_azure());
        assert!(!creds.has_pfx());
    }

    #[test]
    fn test_manifest_windows_fields() {
        let json = r#"{
            "app_name": "TestApp",
            "bundle_id": "com.test.app",
            "version": "1.0.0",
            "entry": "src/main.ts",
            "targets": ["windows"],
            "windows_distribute": "installer",
            "windows_uac_level": "asInvoker",
            "windows_company_name": "Test Inc."
        }"#;
        let manifest: BuildManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.windows_distribute.as_deref(), Some("installer"));
        assert_eq!(manifest.windows_uac_level.as_deref(), Some("asInvoker"));
        assert_eq!(manifest.windows_company_name.as_deref(), Some("Test Inc."));
    }

    #[test]
    fn test_manifest_defaults() {
        let json = r#"{
            "app_name": "TestApp",
            "bundle_id": "com.test.app",
            "version": "1.0.0",
            "entry": "src/main.ts",
            "targets": ["windows"]
        }"#;
        let manifest: BuildManifest = serde_json::from_str(json).unwrap();
        assert!(manifest.windows_distribute.is_none());
        assert!(manifest.windows_uac_level.is_none());
        assert!(manifest.windows_copyright.is_none());
    }
}
