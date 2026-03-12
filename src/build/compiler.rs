use crate::build::docker::{ContainerMount, ContainerRun, run_in_container};
use crate::config::WorkerConfig;
use crate::queue::job::BuildManifest;
use crate::ws::messages::{LogStream, ServerMessage, StageName};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;

pub async fn compile(
    manifest: &BuildManifest,
    progress: &UnboundedSender<ServerMessage>,
    cancelled: &Arc<AtomicBool>,
    config: &WorkerConfig,
    project_dir: &Path,
    output_path: &Path,
    target: Option<&str>,
) -> Result<(), String> {
    let entry = project_dir.join(&manifest.entry);

    let canonical_project = project_dir
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize project dir: {e}"))?;
    let canonical_entry = entry
        .canonicalize()
        .map_err(|e| format!("Entry file not found or inaccessible: {e}"))?;
    if !canonical_entry.starts_with(&canonical_project) {
        return Err(format!(
            "Entry path escapes project directory: {}",
            manifest.entry
        ));
    }

    if config.docker.enabled {
        compile_in_container(manifest, progress, cancelled, config, project_dir, output_path, target).await
    } else {
        compile_direct(manifest, progress, cancelled, &config.perry_binary, project_dir, output_path, target).await
    }
}

async fn compile_in_container(
    manifest: &BuildManifest,
    progress: &UnboundedSender<ServerMessage>,
    cancelled: &Arc<AtomicBool>,
    config: &WorkerConfig,
    project_dir: &Path,
    output_path: &Path,
    target: Option<&str>,
) -> Result<(), String> {
    let dc = &config.docker;
    let msvc_ver = dc.msvc_version.as_deref()
        .ok_or("MSVC version not detected — cannot compile in container")?;
    let sdk_ver = dc.sdk_version.as_deref()
        .ok_or("Windows SDK version not detected — cannot compile in container")?;

    let output_dir = output_path.parent()
        .ok_or("Invalid output path")?;
    let output_name = output_path.file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid output filename")?;

    let project_dir_str = project_dir.to_string_lossy().to_string();
    let output_dir_str = output_dir.to_string_lossy().to_string();

    let mounts = vec![
        ContainerMount {
            host_path: dc.perry_tools_path.clone(),
            container_path: r"C:\tools".into(),
            read_only: true,
        },
        ContainerMount {
            host_path: dc.msvc_path.clone(),
            container_path: r"C:\VS".into(),
            read_only: true,
        },
        ContainerMount {
            host_path: dc.winkits_path.clone(),
            container_path: r"C:\WinKits".into(),
            read_only: true,
        },
        ContainerMount {
            host_path: project_dir_str,
            container_path: r"C:\project".into(),
            read_only: true,
        },
        ContainerMount {
            host_path: output_dir_str,
            container_path: r"C:\output".into(),
            read_only: false,
        },
    ];

    let msvc_bin = format!(r"C:\VS\2022\BuildTools\VC\Tools\MSVC\{msvc_ver}\bin\Hostx64\x64");
    let msvc_lib = format!(r"C:\VS\2022\BuildTools\VC\Tools\MSVC\{msvc_ver}\lib\x64");
    let msvc_inc = format!(r"C:\VS\2022\BuildTools\VC\Tools\MSVC\{msvc_ver}\include");
    let ucrt_lib = format!(r"C:\WinKits\10\Lib\{sdk_ver}\ucrt\x64");
    let um_lib = format!(r"C:\WinKits\10\Lib\{sdk_ver}\um\x64");
    let ucrt_inc = format!(r"C:\WinKits\10\Include\{sdk_ver}\ucrt");

    let path_val = format!(r"C:\tools;{msvc_bin};C:\WINDOWS\system32");
    let lib_val = format!(r"{msvc_lib};{ucrt_lib};{um_lib};C:\tools");
    let include_val = format!(r"{msvc_inc};{ucrt_inc}");

    let mut compile_cmd = format!(
        r"C:\tools\perry.exe compile C:\project\{entry} -o C:\output\{output_name}",
        entry = manifest.entry.replace('/', "\\"),
    );
    if let Some(t) = target {
        compile_cmd.push_str(&format!(" --target {t}"));
    }

    let job_id_short = &manifest.app_name;
    let container_name = format!("perry-compile-{}", sanitize_container_name(job_id_short));

    let run = ContainerRun {
        name: container_name,
        image: dc.image.clone(),
        isolation: dc.isolation.clone(),
        mounts,
        working_dir: Some(r"C:\project".into()),
        env_vars: vec![
            ("PATH".into(), path_val),
            ("LIB".into(), lib_val),
            ("INCLUDE".into(), include_val),
        ],
        command: compile_cmd,
        timeout: Duration::from_secs(dc.timeout_secs),
        network: false,
    };

    run_in_container(&run, progress, StageName::Compiling, cancelled).await?;

    if !output_path.exists() {
        return Err("Compiler produced no output binary".into());
    }

    Ok(())
}

async fn compile_direct(
    manifest: &BuildManifest,
    progress: &UnboundedSender<ServerMessage>,
    cancelled: &Arc<AtomicBool>,
    perry_binary: &str,
    project_dir: &Path,
    output_path: &Path,
    target: Option<&str>,
) -> Result<(), String> {
    let entry = project_dir.join(&manifest.entry);

    let mut cmd = Command::new(perry_binary);
    cmd.arg("compile")
        .arg(&entry)
        .arg("-o")
        .arg(output_path);

    if let Some(t) = target {
        cmd.arg("--target").arg(t);
    }

    cmd.current_dir(project_dir)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn perry: {e}"))?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let tx_stdout = progress.clone();
    let stdout_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        let mut lines = Vec::new();
        while let Ok(Some(line)) = reader.next_line().await {
            let _ = tx_stdout.send(ServerMessage::Log {
                stage: StageName::Compiling,
                line: line.clone(),
                stream: LogStream::Stdout,
            });
            lines.push(line);
        }
        lines
    });

    let tx_stderr = progress.clone();
    let cancelled_clone = cancelled.clone();
    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        let mut lines = Vec::new();
        while let Ok(Some(line)) = reader.next_line().await {
            if cancelled_clone.load(Ordering::Relaxed) {
                break;
            }
            let _ = tx_stderr.send(ServerMessage::Log {
                stage: StageName::Compiling,
                line: line.clone(),
                stream: LogStream::Stderr,
            });
            lines.push(line);
        }
        lines
    });

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Failed to wait for perry: {e}"))?;

    let stdout_lines = stdout_task.await.unwrap_or_default();
    let stderr_lines = stderr_task.await.unwrap_or_default();

    if cancelled.load(Ordering::Relaxed) {
        return Err("Build cancelled".into());
    }

    if !status.success() {
        let mut err_detail = format!(
            "perry compile exited with code {}",
            status.code().unwrap_or(-1)
        );
        if !stderr_lines.is_empty() {
            err_detail.push_str(&format!("\n{}", stderr_lines.join("\n")));
        }
        if !stdout_lines.is_empty() {
            err_detail.push_str(&format!("\n{}", stdout_lines.join("\n")));
        }
        return Err(err_detail);
    }

    if !output_path.exists() {
        return Err("Compiler produced no output binary".into());
    }

    Ok(())
}

/// Sanitize a string for use as a Docker container name (lowercase alphanumeric + hyphens).
fn sanitize_container_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}
