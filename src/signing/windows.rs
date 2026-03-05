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
    } else {
        Err("No signing credentials provided (need PFX or Azure Trusted Signing)".into())
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
