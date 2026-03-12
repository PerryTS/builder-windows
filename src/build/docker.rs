use crate::ws::messages::{LogStream, ServerMessage, StageName};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;

pub struct ContainerMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

pub struct ContainerRun {
    pub name: String,
    pub image: String,
    pub isolation: String,
    pub mounts: Vec<ContainerMount>,
    pub working_dir: Option<String>,
    pub env_vars: Vec<(String, String)>,
    pub command: String,
    pub timeout: Duration,
    pub network: bool,
}

/// Run a command inside a Docker container with streaming output.
pub async fn run_in_container(
    run: &ContainerRun,
    progress: &UnboundedSender<ServerMessage>,
    stage: StageName,
    cancelled: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut args = vec![
        "run".to_string(),
        format!("--isolation={}", run.isolation),
        "--rm".to_string(),
        format!("--name={}", run.name),
    ];

    if !run.network {
        args.push("--network=none".to_string());
    }

    for mount in &run.mounts {
        let ro = if mount.read_only { ":ro" } else { "" };
        args.push("-v".to_string());
        args.push(format!("{}:{}{}", mount.host_path, mount.container_path, ro));
    }

    if let Some(ref wd) = run.working_dir {
        args.push("-w".to_string());
        args.push(wd.clone());
    }

    for (key, val) in &run.env_vars {
        args.push("-e".to_string());
        args.push(format!("{key}={val}"));
    }

    args.push(run.image.clone());
    args.push("cmd".to_string());
    args.push("/c".to_string());
    args.push(run.command.clone());

    tracing::info!(container = %run.name, "Starting Docker container");

    let mut child = Command::new("docker")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn docker: {e}"))?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let tx_stdout = progress.clone();
    let stage_out = stage.clone();
    let stdout_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        let mut lines = Vec::new();
        while let Ok(Some(line)) = reader.next_line().await {
            let _ = tx_stdout.send(ServerMessage::Log {
                stage: stage_out.clone(),
                line: line.clone(),
                stream: LogStream::Stdout,
            });
            lines.push(line);
        }
        lines
    });

    let tx_stderr = progress.clone();
    let stage_err = stage.clone();
    let cancelled_stream = cancelled.clone();
    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        let mut lines = Vec::new();
        while let Ok(Some(line)) = reader.next_line().await {
            if cancelled_stream.load(Ordering::Relaxed) {
                break;
            }
            let _ = tx_stderr.send(ServerMessage::Log {
                stage: stage_err.clone(),
                line: line.clone(),
                stream: LogStream::Stderr,
            });
            lines.push(line);
        }
        lines
    });

    // Cancellation monitor
    let container_name = run.name.clone();
    let cancelled_kill = cancelled.clone();
    let kill_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if cancelled_kill.load(Ordering::Relaxed) {
                let _ = Command::new("docker")
                    .args(["kill", &container_name])
                    .output()
                    .await;
                return true;
            }
        }
    });

    // Wait with timeout
    let result = tokio::time::timeout(run.timeout, child.wait()).await;
    kill_task.abort();

    let stdout_lines = stdout_task.await.unwrap_or_default();
    let stderr_lines = stderr_task.await.unwrap_or_default();

    match result {
        Ok(Ok(status)) => {
            if cancelled.load(Ordering::Relaxed) {
                return Err("Build cancelled".into());
            }
            if !status.success() {
                let mut err = format!(
                    "Container exited with code {}",
                    status.code().unwrap_or(-1)
                );
                if !stderr_lines.is_empty() {
                    err.push_str(&format!("\n{}", stderr_lines.join("\n")));
                }
                if !stdout_lines.is_empty() {
                    err.push_str(&format!("\n{}", stdout_lines.join("\n")));
                }
                return Err(err);
            }
            Ok(())
        }
        Ok(Err(e)) => Err(format!("Failed to wait for container: {e}")),
        Err(_) => {
            // Timeout — kill the container
            let _ = Command::new("docker")
                .args(["kill", &run.name])
                .output()
                .await;
            Err(format!(
                "Container timed out after {}s",
                run.timeout.as_secs()
            ))
        }
    }
}
