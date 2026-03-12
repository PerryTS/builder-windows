# Perry Ship Windows - Build Worker

Windows build worker for the Perry ecosystem. Connects to a Perry hub via WebSocket, receives build jobs, and produces signed Windows executables and installers.

## Build & Test

```bash
cargo build          # Build the project
cargo test           # Run unit tests
cargo run            # Run the worker (needs PERRY_HUB_URL)
```

## Architecture

- **WebSocket worker** (`worker.rs`): Connects to hub, receives job assignments, reports progress
- **Build pipeline** (`build/pipeline.rs`): Orchestrates extract → compile → assets → bundle → sign → package
- **Assets** (`build/assets.rs`): Generates Windows .ico files from source PNGs
- **Compiler** (`build/compiler.rs`): Invokes `perry compile --target windows` to produce .exe (direct or inside Docker container)
- **Docker** (`build/docker.rs`): Container execution engine — spawns `docker run`, streams output, handles cancellation/timeout
- **Packaging** (`package/windows.rs`): NSIS installer, MSIX, portable ZIP; embeds PE resources (icon, version info, manifest)
- **Signing** (`signing/windows.rs`): signtool.exe (PFX), AzureSignTool (Azure Trusted Signing), or Google Cloud KMS CNG provider

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PERRY_HUB_URL` | `wss://hub.perryts.com/ws` | Hub WebSocket URL |
| `PERRY_BUILD_PERRY_BINARY` | `perry` | Path to perry compiler |
| `PERRY_WORKER_NAME` | hostname | Worker display name |
| `PERRY_BUILD_WINDOWS_SDK_PATH` | auto-detect | Windows SDK path override |
| `PERRY_BUILD_NSIS_PATH` | auto-detect | NSIS installation path override |
| `PERRY_DOCKER_ENABLED` | `false` | Enable Docker container isolation for builds |
| `PERRY_DOCKER_IMAGE` | `mcr.microsoft.com/windows/servercore:ltsc2025` | Container base image |
| `PERRY_DOCKER_ISOLATION` | `process` | Docker isolation mode (`process` or `hyperv`) |
| `PERRY_DOCKER_PERRY_TOOLS` | `C:\perry-tools` | Host path to perry compiler + runtime libs + nm.exe |
| `PERRY_DOCKER_MSVC_PATH` | `C:\Program Files (x86)\Microsoft Visual Studio` | Host MSVC path (bind-mounted read-only) |
| `PERRY_DOCKER_WINKITS_PATH` | `C:\Program Files (x86)\Windows Kits` | Host Windows Kits path (bind-mounted read-only) |
| `PERRY_DOCKER_NSIS_PATH` | `C:\Program Files (x86)\NSIS` | Host NSIS path (bind-mounted read-only) |
| `PERRY_DOCKER_TIMEOUT` | `600` | Container timeout in seconds |

## Prerequisites

- **Windows SDK** (for signtool.exe, MakeAppx.exe) — auto-detected under `C:\Program Files (x86)\Windows Kits\10\`
- **NSIS** (for installer creation) — auto-detected at `C:\Program Files (x86)\NSIS\`
- **AzureSignTool** (optional, for Azure Trusted Signing) — install via `dotnet tool install -g AzureSignTool`
- **Google Cloud KMS CNG Provider** (optional, for KMS signing) — auto-installed on first use if missing
- **Docker** (optional, for build isolation) — Windows Containers feature + Docker CE engine

## Docker Container Isolation

When `PERRY_DOCKER_ENABLED=true`, the compile and packaging steps run inside disposable Windows containers:

- **Compile** and **NSIS/MSIX packaging** run inside containers
- **Signing** stays on the host (credentials never enter containers)
- **Asset generation** and **PE resource embedding** stay on the host (in-process, no external tools)

Each container runs with:
- `--isolation=process` — filesystem and process namespace isolation (shared kernel)
- `--network=none` — no network access during build
- `--rm` — container destroyed after each step
- Read-only bind-mounts for tools (perry, MSVC, Windows SDK, NSIS)
- Read-only bind-mount for project source
- Writable bind-mount only for the output directory

### Perry Tools Directory

The `PERRY_DOCKER_PERRY_TOOLS` directory must contain:
- `perry.exe` — the perry compiler
- `perry_runtime.lib` — perry runtime library
- `perry_stdlib.lib` — perry standard library
- `perry_ui_windows.lib` — perry UI library (for stub generation)
- `nm.exe` — copy of `llvm-nm.exe` from rustup's `llvm-tools` component (needed for symbol scanning inside containers where rustc is not available)

### Setup

```
# Install Windows Containers feature (requires reboot)
Install-WindowsFeature -Name Containers -Restart

# Install Docker CE
Invoke-WebRequest -Uri 'https://download.docker.com/win/static/stable/x86_64/docker-28.1.1.zip' -OutFile docker.zip
Expand-Archive docker.zip -DestinationPath $env:ProgramFiles
dockerd --register-service
net start docker

# Pull the base image
docker pull mcr.microsoft.com/windows/servercore:ltsc2025

# Create the tools directory
mkdir C:\perry-tools
copy perry.exe C:\perry-tools\
copy perry_runtime.lib C:\perry-tools\
copy perry_stdlib.lib C:\perry-tools\
copy perry_ui_windows.lib C:\perry-tools\
# Copy llvm-nm.exe as nm.exe (install llvm-tools first: rustup component add llvm-tools)
copy $env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\bin\llvm-nm.exe C:\perry-tools\nm.exe
```

At startup, the worker auto-detects the MSVC toolchain version and Windows SDK version from the configured paths. If either is missing, containerized builds will fail with a clear error.

## Distribution Modes

Set `windows_distribute` in the build manifest:
- `"installer"` (default): NSIS-based Setup.exe with Start Menu/Desktop shortcuts and uninstaller
- `"msix"`: Modern Windows package via MakeAppx.exe
- `"portable"`: ZIP containing the .exe and DLLs

## Code Style

- Use `tracing` for logging (not println)
- Errors are `Result<T, String>` (matching macOS worker pattern)
- Credentials are zeroized on drop via the `zeroize` crate
- All external tool invocations use `tokio::process::Command`
