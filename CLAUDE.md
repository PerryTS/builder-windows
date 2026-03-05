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
- **Compiler** (`build/compiler.rs`): Invokes `perry compile --target windows` to produce .exe
- **Packaging** (`package/windows.rs`): NSIS installer, MSIX, portable ZIP; embeds PE resources (icon, version info, manifest)
- **Signing** (`signing/windows.rs`): signtool.exe (PFX) or AzureSignTool (Azure Trusted Signing)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PERRY_HUB_URL` | `wss://hub.perryts.com/ws` | Hub WebSocket URL |
| `PERRY_BUILD_PERRY_BINARY` | `perry` | Path to perry compiler |
| `PERRY_WORKER_NAME` | hostname | Worker display name |
| `PERRY_BUILD_WINDOWS_SDK_PATH` | auto-detect | Windows SDK path override |
| `PERRY_BUILD_NSIS_PATH` | auto-detect | NSIS installation path override |

## Prerequisites

- **Windows SDK** (for signtool.exe, MakeAppx.exe) — auto-detected under `C:\Program Files (x86)\Windows Kits\10\`
- **NSIS** (for installer creation) — auto-detected at `C:\Program Files (x86)\NSIS\`
- **AzureSignTool** (optional, for Azure Trusted Signing) — install via `dotnet tool install -g AzureSignTool`

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
