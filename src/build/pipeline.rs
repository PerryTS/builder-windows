use crate::build::assets::generate_ico;
use crate::build::cleanup::{cleanup_tmpdir, create_build_tmpdir};
use crate::build::compiler;
use crate::build::validate;
use crate::config::WorkerConfig;
use crate::package::windows as win_package;
use crate::queue::job::{BuildCredentials, BuildManifest};
use crate::signing::windows as win_signing;
use crate::ws::messages::{ServerMessage, StageName};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
    for entry in std::fs::read_dir(src).map_err(|e| format!("readdir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("entry: {e}"))?;
        let dest_path = dst.join(entry.file_name());
        if entry.file_type().map_or(false, |t| t.is_dir()) {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)
                .map_err(|e| format!("copy {}: {e}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Simplified build request for the worker (no queue/broadcast internals)
pub struct BuildRequest {
    pub manifest: BuildManifest,
    pub credentials: BuildCredentials,
    pub tarball_path: PathBuf,
    pub job_id: String,
}

/// Progress sender type alias
type ProgressSender = UnboundedSender<ServerMessage>;

/// Metadata from a precompiled bundle created by the Linux cross-compilation worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecompiledMetadata {
    pub perry_version: String,
    pub compiled_by: String,
    pub compile_timestamp: String,
}

/// Paths to files extracted from a precompiled bundle.
struct PrecompiledBundle {
    exe_path: PathBuf,
    ico_path: Option<PathBuf>,
    dll_dir: Option<PathBuf>,
}

/// Check if an extracted tarball contains a precompiled bundle (from Linux cross-compilation).
/// The sentinel is `perry-precompiled/metadata.json` which never exists in normal source tarballs.
fn detect_precompiled_bundle(project_dir: &std::path::Path) -> Option<PrecompiledMetadata> {
    let metadata_path = project_dir.join("perry-precompiled").join("metadata.json");
    if !metadata_path.exists() {
        return None;
    }
    let data = std::fs::read_to_string(&metadata_path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Extract paths from a precompiled bundle directory.
fn unpack_precompiled_bundle(
    project_dir: &std::path::Path,
    app_name: &str,
) -> Result<PrecompiledBundle, String> {
    let bundle_dir = project_dir.join("perry-precompiled");

    let exe_name = format!("{}.exe", app_name);
    let exe_path = bundle_dir.join(&exe_name);
    if !exe_path.exists() {
        return Err(format!("Precompiled bundle missing {exe_name}"));
    }

    let ico_path = bundle_dir.join("app.ico");
    let ico_opt = if ico_path.exists() { Some(ico_path) } else { None };

    let dll_dir = bundle_dir.join("dlls");
    let dll_opt = if dll_dir.exists() && dll_dir.is_dir() { Some(dll_dir) } else { None };

    Ok(PrecompiledBundle {
        exe_path,
        ico_path: ico_opt,
        dll_dir: dll_opt,
    })
}

pub async fn execute_build(
    request: &BuildRequest,
    config: &WorkerConfig,
    cancelled: Arc<AtomicBool>,
    progress: ProgressSender,
) -> Result<PathBuf, String> {
    validate::validate_manifest(&request.manifest)?;

    let tmpdir = create_build_tmpdir().map_err(|e| format!("Failed to create tmpdir: {e}"))?;

    // Extract tarball first to detect build mode
    let project_dir = tmpdir.join("project");
    std::fs::create_dir_all(&project_dir)
        .map_err(|e| format!("Failed to create project dir: {e}"))?;
    extract_tarball(&request.tarball_path, &project_dir)?;

    let result = if let Some(metadata) = detect_precompiled_bundle(&project_dir) {
        tracing::info!(
            "Detected precompiled bundle (compiled by {}, perry {})",
            metadata.compiled_by,
            metadata.perry_version
        );
        run_sign_only_pipeline(request, config, &cancelled, &progress, &tmpdir, &project_dir)
            .await
    } else {
        run_windows_pipeline(request, config, &cancelled, &progress, &tmpdir, Some(&project_dir))
            .await
    };

    // Always clean up build tmpdir
    cleanup_tmpdir(&tmpdir);

    result
}

async fn run_windows_pipeline(
    request: &BuildRequest,
    config: &WorkerConfig,
    cancelled: &Arc<AtomicBool>,
    progress: &ProgressSender,
    tmpdir: &std::path::Path,
    pre_extracted: Option<&std::path::Path>,
) -> Result<PathBuf, String> {
    let distribute = request
        .manifest
        .windows_distribute
        .as_deref()
        .unwrap_or("installer");

    let project_dir = if let Some(dir) = pre_extracted {
        // Already extracted by execute_build
        send_stage(progress, StageName::Extracting, "Project already extracted");
        send_progress(progress, StageName::Extracting, 100, None);
        dir.to_path_buf()
    } else {
        // Stage 1: Extract tarball
        send_stage(progress, StageName::Extracting, "Extracting project archive");
        check_cancelled(cancelled)?;
        let dir = tmpdir.join("project");
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create project dir: {e}"))?;
        extract_tarball(&request.tarball_path, &dir)?;
        send_progress(progress, StageName::Extracting, 100, None);
        dir
    };

    // Stage 2: Compile
    send_stage(progress, StageName::Compiling, "Compiling TypeScript to native");
    check_cancelled(cancelled)?;
    let binary_name = format!("{}.exe", request.manifest.app_name);
    let binary_path = tmpdir.join("output").join(&binary_name);
    std::fs::create_dir_all(binary_path.parent().unwrap())
        .map_err(|e| format!("Failed to create output dir: {e}"))?;

    compiler::compile(
        &request.manifest,
        progress,
        cancelled,
        config,
        &project_dir,
        &binary_path,
        Some("windows"),
    )
    .await?;

    if !binary_path.exists() {
        return Err("Compiler produced no output .exe binary".into());
    }
    send_progress(progress, StageName::Compiling, 100, None);

    // Stage 3: Generate assets (ICO)
    send_stage(
        progress,
        StageName::GeneratingAssets,
        "Generating Windows icon",
    );
    check_cancelled(cancelled)?;
    let ico_path = tmpdir.join("app.ico");
    if let Some(ref icon_name) = request.manifest.icon {
        let icon_src = project_dir.join(icon_name);
        if icon_src.exists() {
            generate_ico(&icon_src, &ico_path)?;
        }
    }
    send_progress(progress, StageName::GeneratingAssets, 100, None);

    // Stage 4: Bundle — embed resources into the .exe
    send_stage(
        progress,
        StageName::Bundling,
        "Embedding resources into executable",
    );
    check_cancelled(cancelled)?;
    let bundle_dir = tmpdir.join("bundle");
    let ico_opt = if ico_path.exists() {
        Some(ico_path.as_path())
    } else {
        None
    };
    win_package::create_windows_bundle(&request.manifest, &binary_path, ico_opt, &bundle_dir)?;
    send_progress(progress, StageName::Bundling, 100, None);

    // Stage 5: Sign the .exe
    send_stage(progress, StageName::Signing, "Signing executable");
    check_cancelled(cancelled)?;
    let bundled_exe = bundle_dir.join(&binary_name);
    let signed = win_signing::sign_executable(&bundled_exe, &request.credentials, tmpdir).await;
    if let Err(ref e) = signed {
        tracing::warn!("Signing skipped or failed: {e}");
    }
    send_progress(progress, StageName::Signing, 100, None);

    // Stage 6: Package based on distribution mode
    send_stage(
        progress,
        StageName::Packaging,
        &format!("Creating {distribute} package"),
    );
    check_cancelled(cancelled)?;

    let artifact_path = match distribute {
        "msix" => {
            let msix_path = tmpdir.join(format!("{}.msix", request.manifest.app_name));
            win_package::create_msix_package(&request.manifest, &bundle_dir, &msix_path, config).await?;
            // Sign the MSIX too
            let _ =
                win_signing::sign_executable(&msix_path, &request.credentials, tmpdir).await;
            msix_path
        }
        "portable" => {
            let zip_path = tmpdir.join(format!("{}.zip", request.manifest.app_name));
            win_package::create_portable_zip(&bundle_dir, &zip_path)?;
            zip_path
        }
        _ => {
            // Default: NSIS installer
            let installer_path =
                tmpdir.join(format!("{}-Setup.exe", request.manifest.app_name));
            win_package::create_nsis_installer(
                &request.manifest,
                &bundle_dir,
                &installer_path,
                config,
            )
            .await?;
            // Sign the installer too
            let _ = win_signing::sign_executable(
                &installer_path,
                &request.credentials,
                tmpdir,
            )
            .await;
            installer_path
        }
    };
    send_progress(progress, StageName::Packaging, 100, None);

    // Stage 7: Publishing (Microsoft Store — deferred)
    send_stage(
        progress,
        StageName::Publishing,
        "Skipping store upload (not configured)",
    );
    send_progress(progress, StageName::Publishing, 100, None);

    let final_path = copy_artifact(
        &artifact_path,
        &request.manifest.app_name,
        &request.job_id,
        artifact_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("exe"),
    )?;
    Ok(final_path)
}

/// Sign-only pipeline for precompiled bundles from the Linux cross-compilation worker.
/// Skips compilation and asset generation; only does resource embedding, signing, and packaging.
async fn run_sign_only_pipeline(
    request: &BuildRequest,
    config: &WorkerConfig,
    cancelled: &Arc<AtomicBool>,
    progress: &ProgressSender,
    tmpdir: &std::path::Path,
    project_dir: &std::path::Path,
) -> Result<PathBuf, String> {
    let distribute = request
        .manifest
        .windows_distribute
        .as_deref()
        .unwrap_or("installer");

    // Stage 1: Already extracted
    send_stage(progress, StageName::Extracting, "Precompiled bundle extracted");
    send_progress(progress, StageName::Extracting, 100, None);

    // Stage 2: Skip compilation (already done by Linux worker)
    send_stage(progress, StageName::Compiling, "Skipping compilation (precompiled by Linux worker)");
    send_progress(progress, StageName::Compiling, 100, None);

    // Stage 3: Skip asset generation (ICO already in bundle)
    send_stage(progress, StageName::GeneratingAssets, "Using precompiled assets");
    send_progress(progress, StageName::GeneratingAssets, 100, None);

    // Unpack the precompiled bundle
    let bundle = unpack_precompiled_bundle(project_dir, &request.manifest.app_name)?;

    // Stage 4: Bundle — copy exe + DLLs and embed PE resources
    send_stage(progress, StageName::Bundling, "Embedding resources into executable");
    check_cancelled(cancelled)?;
    let bundle_dir = tmpdir.join("bundle");
    std::fs::create_dir_all(&bundle_dir)
        .map_err(|e| format!("Failed to create bundle dir: {e}"))?;

    // Copy exe to bundle dir
    let binary_name = format!("{}.exe", request.manifest.app_name);
    let dest_exe = bundle_dir.join(&binary_name);
    std::fs::copy(&bundle.exe_path, &dest_exe)
        .map_err(|e| format!("Failed to copy exe to bundle: {e}"))?;

    // Copy DLLs from precompiled bundle
    if let Some(ref dll_dir) = bundle.dll_dir {
        if let Ok(entries) = std::fs::read_dir(dll_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let dest = bundle_dir.join(entry.file_name());
                    std::fs::copy(&path, &dest)
                        .map_err(|e| format!("Failed to copy DLL: {e}"))?;
                }
            }
        }
    }

    // Copy asset directories from precompiled bundle (assets/, logo/, etc.)
    let precompiled_dir = project_dir.join("perry-precompiled");
    for dir_name in &["assets", "logo", "resources", "images"] {
        let src = precompiled_dir.join(dir_name);
        if src.is_dir() {
            let dest = bundle_dir.join(dir_name);
            if let Err(e) = copy_dir_recursive(&src, &dest) {
                tracing::warn!("Failed to copy {dir_name}: {e}");
            }
        }
    }

    // Embed PE resources (icon, version info, manifest XML)
    let ico_ref = bundle.ico_path.as_deref();
    win_package::finalize_windows_bundle(&request.manifest, &bundle_dir, ico_ref)?;
    send_progress(progress, StageName::Bundling, 100, None);

    // Stage 5: Sign the .exe
    send_stage(progress, StageName::Signing, "Signing executable");
    check_cancelled(cancelled)?;
    let bundled_exe = bundle_dir.join(&binary_name);
    let signed = win_signing::sign_executable(&bundled_exe, &request.credentials, tmpdir).await;
    if let Err(ref e) = signed {
        tracing::warn!("Signing skipped or failed: {e}");
    }
    send_progress(progress, StageName::Signing, 100, None);

    // Stage 6: Package based on distribution mode
    send_stage(
        progress,
        StageName::Packaging,
        &format!("Creating {distribute} package"),
    );
    check_cancelled(cancelled)?;

    let artifact_path = match distribute {
        "msix" => {
            let msix_path = tmpdir.join(format!("{}.msix", request.manifest.app_name));
            win_package::create_msix_package(&request.manifest, &bundle_dir, &msix_path, config).await?;
            let _ = win_signing::sign_executable(&msix_path, &request.credentials, tmpdir).await;
            msix_path
        }
        "portable" => {
            let zip_path = tmpdir.join(format!("{}.zip", request.manifest.app_name));
            win_package::create_portable_zip(&bundle_dir, &zip_path)?;
            zip_path
        }
        _ => {
            let installer_path = tmpdir.join(format!("{}-Setup.exe", request.manifest.app_name));
            win_package::create_nsis_installer(
                &request.manifest,
                &bundle_dir,
                &installer_path,
                config,
            )
            .await?;
            let _ = win_signing::sign_executable(&installer_path, &request.credentials, tmpdir).await;
            installer_path
        }
    };
    send_progress(progress, StageName::Packaging, 100, None);

    // Stage 7: Publishing (deferred)
    send_stage(progress, StageName::Publishing, "Skipping store upload (not configured)");
    send_progress(progress, StageName::Publishing, 100, None);

    let final_path = copy_artifact(
        &artifact_path,
        &request.manifest.app_name,
        &request.job_id,
        artifact_path.extension().and_then(|e| e.to_str()).unwrap_or("exe"),
    )?;
    Ok(final_path)
}

/// Copy artifact to a stable location (outside the build tmpdir that gets cleaned up)
fn copy_artifact(
    source: &std::path::Path,
    app_name: &str,
    job_id: &str,
    ext: &str,
) -> Result<PathBuf, String> {
    let artifact_dir = std::env::temp_dir().join("perry-artifacts");
    std::fs::create_dir_all(&artifact_dir)
        .map_err(|e| format!("Failed to create artifact dir: {e}"))?;

    let dest = artifact_dir.join(format!("{app_name}-{job_id}.{ext}"));
    std::fs::copy(source, &dest).map_err(|e| format!("Failed to copy artifact: {e}"))?;
    Ok(dest)
}

fn check_cancelled(cancelled: &Arc<AtomicBool>) -> Result<(), String> {
    if cancelled.load(Ordering::Relaxed) {
        Err("Build cancelled".into())
    } else {
        Ok(())
    }
}

fn send_stage(progress: &ProgressSender, stage: StageName, message: &str) {
    let _ = progress.send(ServerMessage::Stage {
        stage,
        message: message.to_string(),
    });
}

fn send_progress(progress: &ProgressSender, stage: StageName, percent: u8, message: Option<&str>) {
    let _ = progress.send(ServerMessage::Progress {
        stage,
        percent,
        message: message.map(String::from),
    });
}

fn extract_tarball(tarball_path: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    let file =
        std::fs::File::open(tarball_path).map_err(|e| format!("Failed to open tarball: {e}"))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    archive.set_unpack_xattrs(false);

    // Manually iterate entries to prevent path traversal attacks.
    // archive.unpack() does NOT validate paths — a malicious tarball could
    // write files outside the destination via ".." components or absolute paths.
    for entry in archive
        .entries()
        .map_err(|e| format!("Failed to read tarball entries: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("Failed to read tarball entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read entry path: {e}"))?
            .into_owned();

        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(format!(
                "Tarball contains unsafe path (path traversal rejected): {}",
                path.display()
            ));
        }

        entry
            .unpack_in(dest)
            .map_err(|e| format!("Failed to extract {}: {e}", path.display()))?;
    }

    Ok(())
}
