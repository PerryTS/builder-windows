use crate::config;
use crate::queue::job::BuildCredentials;
use std::path::Path;
use zeroize::Zeroize;

/// Determine the signing method and sign the file.
pub async fn sign_executable(
    file_path: &Path,
    credentials: &BuildCredentials,
    tmpdir: &Path,
) -> Result<(), String> {
    if credentials.has_pfx() {
        sign_with_signtool(
            file_path,
            credentials.windows_pfx_base64.as_deref().unwrap(),
            credentials.windows_pfx_password.as_deref().unwrap_or(""),
            credentials.timestamp_url(),
            tmpdir,
        )
        .await
    } else if credentials.has_azure() {
        sign_with_azure(file_path, credentials).await
    } else if credentials.has_gcloud_kms() {
        sign_with_gcloud_kms(file_path, credentials, tmpdir).await
    } else {
        Err("No signing credentials provided (need PFX, Azure Trusted Signing, or Google Cloud KMS)".into())
    }
}

/// Sign a file using signtool.exe with a PFX certificate.
async fn sign_with_signtool(
    file_path: &Path,
    pfx_base64: &str,
    pfx_password: &str,
    timestamp_url: &str,
    tmpdir: &Path,
) -> Result<(), String> {
    let signtool = config::find_signtool()
        .ok_or("signtool.exe not found. Install Windows SDK.")?;

    // Decode PFX and write to temp file
    use base64::Engine;
    let pfx_bytes = base64::engine::general_purpose::STANDARD
        .decode(pfx_base64.trim())
        .map_err(|e| format!("Invalid PFX base64: {e}"))?;

    let pfx_path = tmpdir.join("signing.pfx");
    std::fs::write(&pfx_path, &pfx_bytes)
        .map_err(|e| format!("Failed to write temp PFX: {e}"))?;

    // Sign
    let output = tokio::process::Command::new(&signtool)
        .arg("sign")
        .arg("/f")
        .arg(&pfx_path)
        .arg("/p")
        .arg(pfx_password)
        .arg("/fd")
        .arg("sha256")
        .arg("/tr")
        .arg(timestamp_url)
        .arg("/td")
        .arg("sha256")
        .arg(file_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run signtool sign: {e}"))?;

    // Securely delete the temp PFX immediately
    let mut pfx_data = std::fs::read(&pfx_path).unwrap_or_default();
    pfx_data.zeroize();
    std::fs::remove_file(&pfx_path).ok();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "signtool sign failed (exit {}):\n{stdout}\n{stderr}",
            output.status.code().unwrap_or(-1)
        ));
    }

    // Verify
    let verify_output = tokio::process::Command::new(&signtool)
        .arg("verify")
        .arg("/pa")
        .arg(file_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run signtool verify: {e}"))?;

    if !verify_output.status.success() {
        let stderr = String::from_utf8_lossy(&verify_output.stderr);
        tracing::warn!("signtool verify failed (non-fatal): {stderr}");
    }

    Ok(())
}

/// Sign a file using Google Cloud KMS via the CNG provider.
///
/// Self-bootstrapping: installs the CNG provider if missing, writes the cert and
/// service account key to temp files, activates the service account, signs, then
/// cleans up. Safe for ephemeral / multi-tenant workers.
async fn sign_with_gcloud_kms(
    file_path: &Path,
    credentials: &BuildCredentials,
    tmpdir: &Path,
) -> Result<(), String> {
    let signtool = config::find_signtool()
        .ok_or("signtool.exe not found. Install Windows SDK.")?;

    let kms_key = credentials.gcloud_kms_key.as_deref().unwrap();
    let cert_b64 = credentials.gcloud_kms_cert_base64.as_deref().unwrap();
    let sa_b64 = credentials.gcloud_service_account_base64.as_deref().unwrap();

    // Ensure CNG provider is installed
    ensure_cng_provider_installed().await?;

    // Decode and write cert to temp file
    use base64::Engine;
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(cert_b64.trim())
        .map_err(|e| format!("Invalid cert base64: {e}"))?;
    let cert_path = tmpdir.join("kms_signing.crt");
    std::fs::write(&cert_path, &cert_bytes)
        .map_err(|e| format!("Failed to write temp cert: {e}"))?;

    // Decode and write service account key to temp file
    let sa_bytes = base64::engine::general_purpose::STANDARD
        .decode(sa_b64.trim())
        .map_err(|e| format!("Invalid service account base64: {e}"))?;
    let sa_path = tmpdir.join("gcp_sa_key.json");
    std::fs::write(&sa_path, &sa_bytes)
        .map_err(|e| format!("Failed to write temp service account key: {e}"))?;

    // Set GOOGLE_APPLICATION_CREDENTIALS so the CNG provider can auth
    std::env::set_var("GOOGLE_APPLICATION_CREDENTIALS", &sa_path);

    // Sign
    let output = tokio::process::Command::new(&signtool)
        .env("GOOGLE_APPLICATION_CREDENTIALS", &sa_path)
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/tr")
        .arg(credentials.timestamp_url())
        .arg("/td")
        .arg("SHA256")
        .arg("/f")
        .arg(&cert_path)
        .arg("/csp")
        .arg("Google Cloud KMS Provider")
        .arg("/kc")
        .arg(kms_key)
        .arg(file_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run signtool with KMS: {e}"))?;

    // Clean up temp files immediately
    let mut sa_data = std::fs::read(&sa_path).unwrap_or_default();
    sa_data.zeroize();
    std::fs::remove_file(&sa_path).ok();
    std::fs::remove_file(&cert_path).ok();
    std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "signtool KMS sign failed (exit {}):\n{stdout}\n{stderr}",
            output.status.code().unwrap_or(-1)
        ));
    }

    tracing::info!(file = %file_path.display(), "Signed with Google Cloud KMS");

    // Verify
    let verify_output = tokio::process::Command::new(&signtool)
        .arg("verify")
        .arg("/pa")
        .arg(file_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run signtool verify: {e}"))?;

    if !verify_output.status.success() {
        let stderr = String::from_utf8_lossy(&verify_output.stderr);
        tracing::warn!("signtool verify failed (non-fatal): {stderr}");
    }

    Ok(())
}

/// Install the Google Cloud KMS CNG provider if not already present.
async fn ensure_cng_provider_installed() -> Result<(), String> {
    // Check if already registered
    let check = tokio::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Google Cloud KMS Provider",
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to check CNG provider registry: {e}"))?;

    if check.status.success() {
        return Ok(());
    }

    tracing::info!("Google Cloud KMS CNG provider not found, installing...");

    // Download the CNG provider
    let tmp = std::env::temp_dir();
    let zip_path = tmp.join("kmscng.zip");
    let extract_dir = tmp.join("kmscng");

    let resp = reqwest::get(
        "https://github.com/GoogleCloudPlatform/kms-integrations/releases/download/cng-v1.3/kmscng-1.3-windows-amd64.zip",
    )
    .await
    .map_err(|e| format!("Failed to download CNG provider: {e}"))?;

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read CNG provider download: {e}"))?;

    std::fs::write(&zip_path, &bytes)
        .map_err(|e| format!("Failed to write CNG provider zip: {e}"))?;

    // Extract
    let zip_path_clone = zip_path.clone();
    let extract_dir_clone = extract_dir.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let file =
            std::fs::File::open(&zip_path_clone).map_err(|e| format!("Failed to open zip: {e}"))?;
        let mut archive =
            zip::ZipArchive::new(file).map_err(|e| format!("Failed to read zip: {e}"))?;
        archive
            .extract(&extract_dir_clone)
            .map_err(|e| format!("Failed to extract zip: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Extract task failed: {e}"))??;

    // Find and run the MSI
    let msi_path = extract_dir.join("kmscng-1.3-windows-amd64").join("kmscng.msi");
    if !msi_path.exists() {
        return Err(format!("MSI not found at: {}", msi_path.display()));
    }

    let install = tokio::process::Command::new("msiexec")
        .arg("/i")
        .arg(&msi_path)
        .arg("/qn")
        .output()
        .await
        .map_err(|e| format!("Failed to run msiexec: {e}"))?;

    // Clean up downloads
    std::fs::remove_file(&zip_path).ok();
    std::fs::remove_dir_all(&extract_dir).ok();

    if !install.status.success() {
        let stderr = String::from_utf8_lossy(&install.stderr);
        return Err(format!("CNG provider install failed: {stderr}"));
    }

    tracing::info!("Google Cloud KMS CNG provider installed successfully");
    Ok(())
}

/// Sign a file using Azure Trusted Signing (AzureSignTool).
async fn sign_with_azure(
    file_path: &Path,
    credentials: &BuildCredentials,
) -> Result<(), String> {
    let azure_sign_tool = which_azure_sign_tool()
        .ok_or("AzureSignTool.exe not found. Install via: dotnet tool install -g AzureSignTool")?;

    let output = tokio::process::Command::new(azure_sign_tool)
        .arg("sign")
        .arg("-kvu")
        .arg(credentials.azure_signing_endpoint.as_deref().unwrap())
        .arg("-kvi")
        .arg(credentials.azure_client_id.as_deref().unwrap())
        .arg("-kvt")
        .arg(credentials.azure_tenant_id.as_deref().unwrap())
        .arg("-kvs")
        .arg(credentials.azure_client_secret.as_deref().unwrap())
        .arg("-kvc")
        .arg(credentials.azure_signing_account.as_deref().unwrap())
        .arg("-kvcn")
        .arg(credentials.azure_signing_profile.as_deref().unwrap())
        .arg("-tr")
        .arg(credentials.timestamp_url())
        .arg("-td")
        .arg("sha256")
        .arg(file_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run AzureSignTool: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "AzureSignTool failed (exit {}):\n{stdout}\n{stderr}",
            output.status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

/// Try to find AzureSignTool on PATH.
fn which_azure_sign_tool() -> Option<std::path::PathBuf> {
    which("AzureSignTool.exe")
        .or_else(|| which("azuresigntool.exe"))
        .or_else(|| which("AzureSignTool"))
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(name);
            if full.exists() {
                Some(full)
            } else {
                None
            }
        })
    })
}
