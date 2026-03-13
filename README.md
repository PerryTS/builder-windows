# Perry Builder (Windows)

Build worker for the [Perry](https://github.com/PerryTS/perry) ecosystem, targeting **Windows**. Connects to [Perry Hub](https://github.com/PerryTS/hub) via WebSocket, receives build jobs, and returns signed executables and installers.

## How It Works

```
Perry Hub ──WebSocket──► This Worker
   │                        │
   │  job_assign            ├─ compile (perry compiler)
   │  (manifest + tarball)  ├─ package (NSIS / MSIX / ZIP)
   │                        ├─ sign (signtool / Azure / KMS)
   │  ◄── progress/logs ────┘
   │  ◄── artifacts
```

1. Worker connects to hub, sends `worker_hello` with platform capabilities
2. Hub assigns a job with manifest, credentials, and tarball
3. Worker runs: **compile** → **assets** → **bundle** → **sign** → **package**
4. Progress and logs stream back to hub in real-time
5. Built artifacts are uploaded for CLI download

## Building

```sh
cargo build --release
```

## Running

```sh
set PERRY_BUILD_PERRY_BINARY=C:\path\to\perry.exe
set PERRY_HUB_URL=wss://hub.perryts.com/ws
.\target\release\perry-ship-windows.exe
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PERRY_HUB_URL` | `wss://hub.perryts.com/ws` | Hub WebSocket URL |
| `PERRY_HUB_WORKER_SECRET` | *(empty)* | Shared secret for hub authentication |
| `PERRY_BUILD_PERRY_BINARY` | `perry` | Path to the Perry compiler binary |
| `PERRY_WORKER_NAME` | hostname | Worker display name |
| `PERRY_BUILD_WINDOWS_SDK_PATH` | auto-detect | Windows SDK path override |
| `PERRY_BUILD_NSIS_PATH` | auto-detect | NSIS installation path override |

## Distribution Modes

Set `windows_distribute` in the build manifest:

| Mode | Output | Description |
|---|---|---|
| `installer` (default) | Setup.exe | NSIS installer with Start Menu/Desktop shortcuts and uninstaller |
| `msix` | .msix | Modern Windows package via MakeAppx.exe |
| `portable` | .zip | ZIP containing the .exe and DLLs |

## Code Signing

Three signing methods are supported, configured via build credentials:

- **PFX** — Local `.pfx` certificate with `signtool.exe`
- **Azure Trusted Signing** — Cloud-based signing via `AzureSignTool`
- **Google Cloud KMS** — Hardware-backed keys via KMS CNG provider

## Docker Container Isolation

Optional build isolation via Windows Containers (`PERRY_DOCKER_ENABLED=true`):

- Compile and packaging steps run inside disposable containers
- Signing stays on the host (credentials never enter containers)
- Containers run with `--network=none` and are destroyed after each step

## Prerequisites

- [Perry compiler](https://github.com/PerryTS/perry)
- Windows SDK (for signtool.exe, MakeAppx.exe)
- NSIS (for installer creation)
- Optional: AzureSignTool, Docker (Windows Containers)

## Related Repos

- [perry](https://github.com/PerryTS/perry) — The Perry compiler and CLI
- [hub](https://github.com/PerryTS/hub) — Central build server
- [builder-macos](https://github.com/PerryTS/builder-macos) — macOS/iOS build worker
- [builder-linux](https://github.com/PerryTS/builder-linux) — Linux build worker

## License

MIT
