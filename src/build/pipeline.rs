use crate::build::assets::generate_ico;
use crate::build::cleanup::{cleanup_tmpdir, create_build_tmpdir};
use crate::build::compiler;
use crate::config::WorkerConfig;
use crate::package::windows as win_package;
use crate::queue::job::{BuildCredentials, BuildManifest};
use crate::signing::windows as win_signing;
use crate::ws::messages::{ServerMessage, StageName};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

/// Simplified build request for the worker (no queue/broadcast internals)
pub struct BuildRequest {
    pub manifest: BuildManifest,
    pub credentials: BuildCredentials,
    pub tarball_path: PathBuf,
    pub job_id: String,
}

/// Progress sender type alias
type ProgressSender = UnboundedSender<ServerMessage>;

pub async fn execute_build(
    request: &BuildRequest,
    config: &WorkerConfig,
    cancelled: Arc<AtomicBool>,
    progress: ProgressSender,
) -> Result<PathBuf, String> {
    let tmpdir = create_build_tmpdir().map_err(|e| format!("Failed to create tmpdir: {e}"))?;

    let result = run_windows_pipeline(request, config, &cancelled, &progress, &tmpdir).await;

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
) -> Result<PathBuf, String> {
    let distribute = request
        .manifest
        .windows_distribute
        .as_deref()
        .unwrap_or("installer");

    // Stage 1: Extract tarball
    send_stage(progress, StageName::Extracting, "Extracting project archive");
    check_cancelled(cancelled)?;
    let project_dir = tmpdir.join("project");
    std::fs::create_dir_all(&project_dir)
        .map_err(|e| format!("Failed to create project dir: {e}"))?;
    extract_tarball(&request.tarball_path, &project_dir)?;
    send_progress(progress, StageName::Extracting, 100, None);

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
        &config.perry_binary,
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
            win_package::create_msix_package(&request.manifest, &bundle_dir, &msix_path).await?;
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
                config.nsis_path.as_deref(),
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
    // Set options to handle symlinks gracefully on Windows
    archive.set_unpack_xattrs(false);
    archive
        .unpack(dest)
        .map_err(|e| format!("Failed to extract tarball: {e}"))?;
    Ok(())
}
