use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub hub_ws_url: String,
    pub perry_binary: String,
    pub worker_name: Option<String>,
    pub windows_sdk_path: Option<String>,
    pub nsis_path: Option<String>,
}

impl WorkerConfig {
    pub fn from_env() -> Self {
        let config = Self {
            hub_ws_url: env::var("PERRY_HUB_URL")
                .unwrap_or_else(|_| "wss://hub.perryts.com/ws".into()),
            perry_binary: env::var("PERRY_BUILD_PERRY_BINARY")
                .unwrap_or_else(|_| "perry".into()),
            worker_name: env::var("PERRY_WORKER_NAME").ok(),
            windows_sdk_path: env::var("PERRY_BUILD_WINDOWS_SDK_PATH").ok(),
            nsis_path: env::var("PERRY_BUILD_NSIS_PATH").ok(),
        };

        // Log auto-detection results at startup
        if let Some(signtool) = find_signtool() {
            tracing::info!(path = %signtool.display(), "Found signtool.exe");
        } else {
            tracing::warn!("signtool.exe not found — code signing will be unavailable");
        }

        if let Some(makensis) = find_makensis_with_override(config.nsis_path.as_deref()) {
            tracing::info!(path = %makensis.display(), "Found makensis.exe");
        } else {
            tracing::warn!("makensis.exe not found — NSIS installer creation will be unavailable");
        }

        config
    }
}

/// Walk `C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe` to find the latest version.
pub fn find_signtool() -> Option<PathBuf> {
    find_sdk_tool("signtool.exe")
}

/// Walk Windows SDK for `MakeAppx.exe`.
pub fn find_makeappx() -> Option<PathBuf> {
    find_sdk_tool("makeappx.exe")
}

/// Find a tool inside the Windows SDK bin directories, returning the latest version found.
fn find_sdk_tool(tool_name: &str) -> Option<PathBuf> {
    let sdk_base = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    if !sdk_base.exists() {
        return None;
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(sdk_base) {
        for entry in entries.flatten() {
            let tool_path = entry.path().join("x64").join(tool_name);
            if tool_path.exists() {
                candidates.push(tool_path);
            }
        }
    }

    // Sort by version directory name descending to get the latest
    candidates.sort();
    candidates.pop()
}

/// Check for `makensis.exe`, either at the override path or the default NSIS install location.
pub fn find_makensis_with_override(nsis_path_override: Option<&str>) -> Option<PathBuf> {
    if let Some(override_path) = nsis_path_override {
        let p = PathBuf::from(override_path);
        if p.exists() {
            return Some(p);
        }
        // Try as directory containing makensis.exe
        let p2 = p.join("makensis.exe");
        if p2.exists() {
            return Some(p2);
        }
    }
    find_makensis()
}

/// Check the default NSIS installation path.
pub fn find_makensis() -> Option<PathBuf> {
    let default = PathBuf::from(r"C:\Program Files (x86)\NSIS\makensis.exe");
    if default.exists() {
        return Some(default);
    }
    let default64 = PathBuf::from(r"C:\Program Files\NSIS\makensis.exe");
    if default64.exists() {
        return Some(default64);
    }
    None
}
