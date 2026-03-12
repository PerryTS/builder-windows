use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub hub_ws_url: String,
    pub perry_binary: String,
    pub worker_name: Option<String>,
    pub windows_sdk_path: Option<String>,
    pub nsis_path: Option<String>,
    pub docker: DockerConfig,
}

#[derive(Debug, Clone)]
pub struct DockerConfig {
    pub enabled: bool,
    pub image: String,
    pub isolation: String,
    pub perry_tools_path: String,
    pub msvc_path: String,
    pub winkits_path: String,
    pub nsis_path: String,
    pub timeout_secs: u64,
    /// Resolved MSVC version subdir (e.g. "14.44.35207"), detected at startup
    pub msvc_version: Option<String>,
    /// Resolved Windows SDK version (e.g. "10.0.26100.0"), detected at startup
    pub sdk_version: Option<String>,
}

impl WorkerConfig {
    pub fn from_env() -> Self {
        let docker_enabled = env::var("PERRY_DOCKER_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let msvc_path = env::var("PERRY_DOCKER_MSVC_PATH")
            .unwrap_or_else(|_| r"C:\Program Files (x86)\Microsoft Visual Studio".into());
        let winkits_path = env::var("PERRY_DOCKER_WINKITS_PATH")
            .unwrap_or_else(|_| r"C:\Program Files (x86)\Windows Kits".into());

        let msvc_version = if docker_enabled {
            detect_msvc_version(&msvc_path)
        } else {
            None
        };
        let sdk_version = if docker_enabled {
            detect_sdk_version(&winkits_path)
        } else {
            None
        };

        let config = Self {
            hub_ws_url: env::var("PERRY_HUB_URL")
                .unwrap_or_else(|_| "wss://hub.perryts.com/ws".into()),
            perry_binary: env::var("PERRY_BUILD_PERRY_BINARY")
                .unwrap_or_else(|_| "perry".into()),
            worker_name: env::var("PERRY_WORKER_NAME").ok(),
            windows_sdk_path: env::var("PERRY_BUILD_WINDOWS_SDK_PATH").ok(),
            nsis_path: env::var("PERRY_BUILD_NSIS_PATH").ok(),
            docker: DockerConfig {
                enabled: docker_enabled,
                image: env::var("PERRY_DOCKER_IMAGE")
                    .unwrap_or_else(|_| "mcr.microsoft.com/windows/servercore:ltsc2025".into()),
                isolation: env::var("PERRY_DOCKER_ISOLATION")
                    .unwrap_or_else(|_| "process".into()),
                perry_tools_path: env::var("PERRY_DOCKER_PERRY_TOOLS")
                    .unwrap_or_else(|_| r"C:\perry-tools".into()),
                msvc_path,
                winkits_path,
                nsis_path: env::var("PERRY_DOCKER_NSIS_PATH")
                    .unwrap_or_else(|_| r"C:\Program Files (x86)\NSIS".into()),
                timeout_secs: env::var("PERRY_DOCKER_TIMEOUT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(600),
                msvc_version,
                sdk_version,
            },
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

        if config.docker.enabled {
            tracing::info!(
                image = %config.docker.image,
                isolation = %config.docker.isolation,
                msvc_version = ?config.docker.msvc_version,
                sdk_version = ?config.docker.sdk_version,
                "Docker container isolation enabled"
            );
        }

        config
    }
}

/// Detect the latest MSVC toolchain version directory.
/// Scans `{msvc_path}\2022\BuildTools\VC\Tools\MSVC\` for version subdirectories.
fn detect_msvc_version(msvc_path: &str) -> Option<String> {
    let base = Path::new(msvc_path)
        .join("2022")
        .join("BuildTools")
        .join("VC")
        .join("Tools")
        .join("MSVC");
    let mut versions: Vec<String> = std::fs::read_dir(&base)
        .ok()?
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    versions.sort();
    versions.pop()
}

/// Detect the latest Windows SDK version.
/// Scans `{winkits_path}\10\Lib\` for version subdirectories.
fn detect_sdk_version(winkits_path: &str) -> Option<String> {
    let base = Path::new(winkits_path).join("10").join("Lib");
    let mut versions: Vec<String> = std::fs::read_dir(&base)
        .ok()?
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("10."))
        .collect();
    versions.sort();
    versions.pop()
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
