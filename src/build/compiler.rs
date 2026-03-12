use crate::queue::job::BuildManifest;
use crate::ws::messages::{LogStream, ServerMessage, StageName};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;

pub async fn compile(
    manifest: &BuildManifest,
    progress: &UnboundedSender<ServerMessage>,
    cancelled: &Arc<AtomicBool>,
    perry_binary: &str,
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
