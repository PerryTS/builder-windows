use crate::build::validate::{escape_nsis, escape_xml};
use crate::config;
use crate::queue::job::BuildManifest;
use std::io::Write;
use std::path::Path;

/// System DLLs that should NOT be bundled (lowercase for comparison)
const SYSTEM_DLLS: &[&str] = &[
    "kernel32.dll",
    "user32.dll",
    "gdi32.dll",
    "ntdll.dll",
    "advapi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "ws2_32.dll",
    "wsock32.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
    "msvcp140.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
    "api-ms-win-crt-heap-l1-1-0.dll",
    "api-ms-win-crt-math-l1-1-0.dll",
    "api-ms-win-crt-stdio-l1-1-0.dll",
    "api-ms-win-crt-string-l1-1-0.dll",
    "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-time-l1-1-0.dll",
    "api-ms-win-crt-convert-l1-1-0.dll",
    "api-ms-win-crt-environment-l1-1-0.dll",
    "api-ms-win-crt-filesystem-l1-1-0.dll",
    "api-ms-win-crt-process-l1-1-0.dll",
    "api-ms-win-crt-utility-l1-1-0.dll",
    "bcrypt.dll",
    "crypt32.dll",
    "secur32.dll",
    "shlwapi.dll",
    "imm32.dll",
    "winmm.dll",
    "setupapi.dll",
    "cfgmgr32.dll",
    "wintrust.dll",
    "version.dll",
    "d3d11.dll",
    "dxgi.dll",
    "opengl32.dll",
    "dbghelp.dll",
    "psapi.dll",
    "iphlpapi.dll",
    "userenv.dll",
    "powrprof.dll",
    "rpcrt4.dll",
    "sspicli.dll",
    "nsi.dll",
    "normaliz.dll",
];

/// Create a Windows application bundle directory containing the .exe and any non-system DLL
/// dependencies. Also embeds a Windows application manifest XML into the .exe via resource APIs.
pub fn create_windows_bundle(
    manifest: &BuildManifest,
    binary_path: &Path,
    ico_path: Option<&Path>,
    bundle_dir: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(bundle_dir)
        .map_err(|e| format!("Failed to create bundle dir: {e}"))?;

    let exe_name = binary_path
        .file_name()
        .ok_or("Invalid binary path")?;
    let dest_exe = bundle_dir.join(exe_name);
    std::fs::copy(binary_path, &dest_exe)
        .map_err(|e| format!("Failed to copy exe to bundle: {e}"))?;

    // Scan for non-system DLL dependencies and copy them alongside the exe
    scan_and_copy_dlls(binary_path, bundle_dir)?;

    // Write an application manifest XML alongside (will be embedded by resource update)
    let manifest_xml = generate_app_manifest(manifest);
    let manifest_path = bundle_dir.join(format!("{}.exe.manifest", manifest.app_name));
    std::fs::write(&manifest_path, &manifest_xml)
        .map_err(|e| format!("Failed to write manifest: {e}"))?;

    // Embed resources into the exe (icon, version info, manifest)
    embed_resources(&dest_exe, manifest, ico_path, &manifest_xml)?;

    Ok(())
}

/// Scan PE imports using pelite and copy non-system DLLs from the same directory as the binary.
fn scan_and_copy_dlls(binary_path: &Path, bundle_dir: &Path) -> Result<(), String> {
    let data = std::fs::read(binary_path)
        .map_err(|e| format!("Failed to read binary for DLL scanning: {e}"))?;

    let imports: Vec<String> = match pelite::PeFile::from_bytes(&data) {
        Ok(pelite::Wrap::T64(pe)) => {
            use pelite::pe64::Pe;
            match pe.imports() {
                Ok(imp) => imp
                    .iter()
                    .filter_map(|desc| {
                        desc.dll_name().ok().map(|s| s.to_str().unwrap_or("").to_string())
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
        Ok(pelite::Wrap::T32(pe)) => {
            use pelite::pe32::Pe;
            match pe.imports() {
                Ok(imp) => imp
                    .iter()
                    .filter_map(|desc| {
                        desc.dll_name().ok().map(|s| s.to_str().unwrap_or("").to_string())
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
        Err(e) => {
            tracing::warn!("Failed to parse PE for DLL scanning: {e}");
            return Ok(());
        }
    };

    let binary_dir = binary_path.parent().unwrap_or(Path::new("."));
    for dll_name in imports {
        let dll_lower = dll_name.to_lowercase();
        if SYSTEM_DLLS.contains(&dll_lower.as_str()) || dll_lower.starts_with("api-ms-win-") {
            continue;
        }
        // Try to find the DLL next to the binary
        let dll_src = binary_dir.join(&dll_name);
        if dll_src.exists() {
            let dll_dest = bundle_dir.join(&dll_name);
            if !dll_dest.exists() {
                std::fs::copy(&dll_src, &dll_dest)
                    .map_err(|e| format!("Failed to copy DLL {dll_name}: {e}"))?;
            }
        }
    }

    Ok(())
}

/// Generate a Windows application manifest XML with UAC level, DPI awareness, and OS compatibility.
fn generate_app_manifest(manifest: &BuildManifest) -> String {
    let uac_level = manifest
        .windows_uac_level
        .as_deref()
        .unwrap_or("asInvoker");

    let dpi_aware = manifest
        .windows_dpi_aware
        .as_deref()
        .unwrap_or("true/pm");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="{bundle_id}" version="{version}.0" />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="{uac_level}" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 / 11 -->
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}" />
      <!-- Windows 8.1 -->
      <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}" />
      <!-- Windows 8 -->
      <supportedOS Id="{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}" />
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">{dpi_aware}</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>"#,
        bundle_id = escape_xml(&manifest.bundle_id),
        version = escape_xml(&manifest.version),
        uac_level = escape_xml(uac_level),
        dpi_aware = escape_xml(dpi_aware),
    )
}

/// Embed icon, version info, and manifest resources into a PE executable using Win32 APIs.
fn embed_resources(
    exe_path: &Path,
    manifest: &BuildManifest,
    ico_path: Option<&Path>,
    manifest_xml: &str,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::{
            BeginUpdateResourceA, EndUpdateResourceA, UpdateResourceA,
        };

        let exe_str = exe_path.to_string_lossy();
        let exe_cstr = std::ffi::CString::new(exe_str.as_ref())
            .map_err(|e| format!("Invalid exe path: {e}"))?;

        unsafe {
            let handle = BeginUpdateResourceA(PCSTR(exe_cstr.as_ptr() as *const u8), false)
                .map_err(|e| format!("BeginUpdateResource failed: {e}"))?;

            // Embed application manifest (RT_MANIFEST = 24, resource ID = 1)
            let manifest_bytes = manifest_xml.as_bytes();
            UpdateResourceA(
                handle,
                PCSTR(24u16 as *const u8), // RT_MANIFEST
                PCSTR(1u16 as *const u8),  // resource ID 1
                0x0409,                     // LANG_ENGLISH
                Some(manifest_bytes.as_ptr() as *const std::ffi::c_void),
                manifest_bytes.len() as u32,
            )
            .map_err(|e| format!("UpdateResource (manifest) failed: {e}"))?;

            // Embed version info (RT_VERSION = 16, resource ID = 1)
            let version_data = build_vs_version_info(manifest);
            UpdateResourceA(
                handle,
                PCSTR(16u16 as *const u8), // RT_VERSION
                PCSTR(1u16 as *const u8),  // resource ID 1
                0x0409,
                Some(version_data.as_ptr() as *const std::ffi::c_void),
                version_data.len() as u32,
            )
            .map_err(|e| format!("UpdateResource (version) failed: {e}"))?;

            // Embed icon if provided
            if let Some(ico) = ico_path {
                let ico_data = std::fs::read(ico)
                    .map_err(|e| format!("Failed to read ico for embedding: {e}"))?;
                embed_ico_resources(handle, &ico_data)?;
            }

            EndUpdateResourceA(handle, false)
                .map_err(|e| format!("EndUpdateResource failed: {e}"))?;
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (exe_path, manifest, ico_path, manifest_xml);
        tracing::warn!("Resource embedding is only supported on Windows");
    }

    Ok(())
}

/// Embed ICO data as RT_GROUP_ICON + individual RT_ICON resources.
#[cfg(target_os = "windows")]
unsafe fn embed_ico_resources(
    handle: windows::Win32::Foundation::HANDLE,
    ico_data: &[u8],
) -> Result<(), String> {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::UpdateResourceA;

    if ico_data.len() < 6 {
        return Err("ICO data too small".into());
    }

    let count = u16::from_le_bytes([ico_data[4], ico_data[5]]) as usize;
    if ico_data.len() < 6 + count * 16 {
        return Err("ICO data truncated".into());
    }

    // Build GRPICONDIR: same header as ICO but entries use nID instead of dwImageOffset
    let mut grp_data: Vec<u8> = Vec::new();
    grp_data.extend_from_slice(&ico_data[0..6]); // ICONDIR header (reserved, type, count)

    for i in 0..count {
        let entry_offset = 6 + i * 16;
        // Copy first 12 bytes of ICONDIRENTRY (width, height, colors, reserved, planes, bpp, size)
        grp_data.extend_from_slice(&ico_data[entry_offset..entry_offset + 12]);
        // Replace dwImageOffset (4 bytes) with nID (2 bytes) — resource ID for this icon
        let id = (i + 1) as u16;
        grp_data.extend_from_slice(&id.to_le_bytes());
    }

    // Write RT_GROUP_ICON (type 14), resource ID 1
    UpdateResourceA(
        handle,
        PCSTR(14u16 as *const u8), // RT_GROUP_ICON
        PCSTR(1u16 as *const u8),
        0x0409,
        Some(grp_data.as_ptr() as *const std::ffi::c_void),
        grp_data.len() as u32,
    )
    .map_err(|e| format!("UpdateResource (group icon) failed: {e}"))?;

    // Write each individual icon as RT_ICON (type 3)
    for i in 0..count {
        let entry_offset = 6 + i * 16;
        let img_size = u32::from_le_bytes([
            ico_data[entry_offset + 8],
            ico_data[entry_offset + 9],
            ico_data[entry_offset + 10],
            ico_data[entry_offset + 11],
        ]) as usize;
        let img_offset = u32::from_le_bytes([
            ico_data[entry_offset + 12],
            ico_data[entry_offset + 13],
            ico_data[entry_offset + 14],
            ico_data[entry_offset + 15],
        ]) as usize;

        if img_offset + img_size > ico_data.len() {
            return Err(format!("ICO image {i} extends beyond file"));
        }

        let id = (i + 1) as u16;
        UpdateResourceA(
            handle,
            PCSTR(3u16 as *const u8), // RT_ICON
            PCSTR(id as *const u8),
            0x0409,
            Some(ico_data[img_offset..].as_ptr() as *const std::ffi::c_void),
            img_size as u32,
        )
        .map_err(|e| format!("UpdateResource (icon {i}) failed: {e}"))?;
    }

    Ok(())
}

/// Build a VS_VERSIONINFO binary structure for embedding as RT_VERSION.
/// This is a complex nested structure with UTF-16 strings and alignment padding.
fn build_vs_version_info(manifest: &BuildManifest) -> Vec<u8> {
    let parts: Vec<&str> = manifest.version.split('.').collect();
    let major: u16 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(1);
    let minor: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u16 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let file_description = manifest
        .windows_file_description
        .as_deref()
        .unwrap_or(&manifest.app_name);
    let company_name = manifest.windows_company_name.as_deref().unwrap_or("");
    let copyright = manifest.windows_copyright.as_deref().unwrap_or("");
    let product_name = &manifest.app_name;
    let product_version = &manifest.version;

    let string_pairs = [
        ("CompanyName", company_name),
        ("FileDescription", file_description),
        ("FileVersion", product_version),
        ("InternalName", &manifest.app_name),
        ("LegalCopyright", copyright),
        ("OriginalFilename", &format!("{}.exe", manifest.app_name)),
        ("ProductName", product_name),
        ("ProductVersion", product_version),
    ];

    // Build StringTable
    let mut string_table_children = Vec::new();
    for (key, value) in &string_pairs {
        let entry = build_version_string(key, value);
        string_table_children.extend_from_slice(&entry);
    }

    // StringTable header: key = "040904B0" (US English, Unicode)
    let string_table = build_version_node(
        "040904B0",
        &[],
        &string_table_children,
        true, // text node type
    );

    // StringFileInfo header
    let string_file_info = build_version_node("StringFileInfo", &[], &string_table, true);

    // VarFileInfo with Translation value
    let translation: [u8; 4] = [0x09, 0x04, 0xB0, 0x04]; // 0x0409, 0x04B0
    let var = build_version_node("Translation", &translation, &[], false);
    let var_file_info = build_version_node("VarFileInfo", &[], &var, true);

    // VS_FIXEDFILEINFO (52 bytes)
    let mut ffi = Vec::with_capacity(52);
    ffi.extend_from_slice(&0xFEEF04BDu32.to_le_bytes()); // dwSignature
    ffi.extend_from_slice(&0x00010000u32.to_le_bytes()); // dwStrucVersion
    ffi.extend_from_slice(&((major as u32) << 16 | minor as u32).to_le_bytes()); // dwFileVersionMS
    ffi.extend_from_slice(&((patch as u32) << 16).to_le_bytes()); // dwFileVersionLS
    ffi.extend_from_slice(&((major as u32) << 16 | minor as u32).to_le_bytes()); // dwProductVersionMS
    ffi.extend_from_slice(&((patch as u32) << 16).to_le_bytes()); // dwProductVersionLS
    ffi.extend_from_slice(&0u32.to_le_bytes()); // dwFileFlagsMask
    ffi.extend_from_slice(&0u32.to_le_bytes()); // dwFileFlags
    ffi.extend_from_slice(&0x00040004u32.to_le_bytes()); // dwFileOS = VOS_NT_WINDOWS32
    ffi.extend_from_slice(&0x00000001u32.to_le_bytes()); // dwFileType = VFT_APP
    ffi.extend_from_slice(&0u32.to_le_bytes()); // dwFileSubtype
    ffi.extend_from_slice(&0u32.to_le_bytes()); // dwFileDateMS
    ffi.extend_from_slice(&0u32.to_le_bytes()); // dwFileDateLS

    let mut children = Vec::new();
    children.extend_from_slice(&string_file_info);
    children.extend_from_slice(&var_file_info);

    build_version_node("VS_VERSION_INFO", &ffi, &children, false)
}

/// Build a single String entry within a StringTable.
fn build_version_string(key: &str, value: &str) -> Vec<u8> {
    let key_utf16: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
    let value_utf16: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();

    let key_bytes: Vec<u8> = key_utf16.iter().flat_map(|w| w.to_le_bytes()).collect();
    let value_bytes: Vec<u8> = value_utf16.iter().flat_map(|w| w.to_le_bytes()).collect();

    let header_size = 6; // wLength(2) + wValueLength(2) + wType(2)
    let key_padded_size = align4(header_size + key_bytes.len());
    let total_size = align4(key_padded_size + value_bytes.len());

    let mut buf = Vec::with_capacity(total_size);
    buf.extend_from_slice(&(total_size as u16).to_le_bytes()); // wLength
    buf.extend_from_slice(&(value_utf16.len() as u16).to_le_bytes()); // wValueLength (in WCHARs)
    buf.extend_from_slice(&1u16.to_le_bytes()); // wType = 1 (text)
    buf.extend_from_slice(&key_bytes);

    // Pad to DWORD boundary
    while buf.len() < key_padded_size {
        buf.push(0);
    }

    buf.extend_from_slice(&value_bytes);

    // Pad to DWORD boundary
    while buf.len() < total_size {
        buf.push(0);
    }

    buf
}

/// Build a version info node (used for VS_VERSION_INFO, StringFileInfo, StringTable, etc.)
fn build_version_node(
    key: &str,
    value: &[u8],
    children: &[u8],
    is_text: bool,
) -> Vec<u8> {
    let key_utf16: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
    let key_bytes: Vec<u8> = key_utf16.iter().flat_map(|w| w.to_le_bytes()).collect();

    let header_size = 6; // wLength(2) + wValueLength(2) + wType(2)
    let after_key = header_size + key_bytes.len();
    let after_key_padded = align4(after_key);
    let after_value = after_key_padded + value.len();
    let after_value_padded = align4(after_value);
    let total = after_value_padded + children.len();
    let total_padded = align4(total);

    let value_len = if is_text {
        // For text nodes, wValueLength is in WCHARs
        value.len() / 2
    } else {
        value.len()
    };

    let mut buf = Vec::with_capacity(total_padded);
    buf.extend_from_slice(&(total as u16).to_le_bytes()); // wLength
    buf.extend_from_slice(&(value_len as u16).to_le_bytes()); // wValueLength
    buf.extend_from_slice(&(if is_text { 1u16 } else { 0u16 }).to_le_bytes()); // wType
    buf.extend_from_slice(&key_bytes);

    while buf.len() < after_key_padded {
        buf.push(0);
    }

    buf.extend_from_slice(value);

    while buf.len() < after_value_padded {
        buf.push(0);
    }

    buf.extend_from_slice(children);

    while buf.len() % 4 != 0 {
        buf.push(0);
    }

    // Fix up wLength now that we know the final size
    let final_len = buf.len() as u16;
    buf[0] = (final_len & 0xFF) as u8;
    buf[1] = (final_len >> 8) as u8;

    buf
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Create an NSIS installer script and invoke makensis.exe.
pub async fn create_nsis_installer(
    manifest: &BuildManifest,
    bundle_dir: &Path,
    output_path: &Path,
    nsis_path_override: Option<&str>,
) -> Result<(), String> {
    let makensis = config::find_makensis_with_override(nsis_path_override)
        .ok_or("makensis.exe not found. Install NSIS or set PERRY_BUILD_NSIS_PATH.")?;

    let app_name = escape_nsis(&manifest.app_name);
    let version = escape_nsis(&manifest.version);
    let bundle_dir_str = bundle_dir.to_string_lossy().replace('/', "\\");
    let output_str = output_path.to_string_lossy().replace('/', "\\");

    // Collect files to install
    let mut install_files = String::new();
    let mut uninstall_files = String::new();
    if let Ok(entries) = std::fs::read_dir(bundle_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".exe.manifest") {
                continue; // Manifest is embedded, skip standalone copy
            }
            install_files.push_str(&format!(
                "  File \"{bundle_dir_str}\\{name}\"\n"
            ));
            uninstall_files.push_str(&format!("  Delete \"$INSTDIR\\{name}\"\n"));
        }
    }

    let nsi_script = format!(
        r#"!include "MUI2.nsh"

Name "{app_name}"
OutFile "{output_str}"
InstallDir "$PROGRAMFILES64\{app_name}"
InstallDirRegKey HKLM "Software\{app_name}" "InstallDir"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
{install_files}
  ; Create Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\{app_name}"
  CreateShortcut "$SMPROGRAMS\{app_name}\{app_name}.lnk" "$INSTDIR\{app_name}.exe"
  CreateShortcut "$DESKTOP\{app_name}.lnk" "$INSTDIR\{app_name}.exe"

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Add/Remove Programs registry entries
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "DisplayName" "{app_name}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "DisplayVersion" "{version}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "Publisher" "{company}"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "NoRepair" 1
SectionEnd

Section "Uninstall"
{uninstall_files}
  Delete "$INSTDIR\Uninstall.exe"

  ; Remove shortcuts
  Delete "$SMPROGRAMS\{app_name}\{app_name}.lnk"
  RMDir "$SMPROGRAMS\{app_name}"
  Delete "$DESKTOP\{app_name}.lnk"

  ; Remove install directory
  RMDir "$INSTDIR"

  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}"
  DeleteRegKey HKLM "Software\{app_name}"
SectionEnd
"#,
        company = escape_nsis(manifest.windows_company_name.as_deref().unwrap_or("")),
    );

    let nsi_path = bundle_dir.join("installer.nsi");
    std::fs::write(&nsi_path, &nsi_script)
        .map_err(|e| format!("Failed to write NSI script: {e}"))?;

    let output = tokio::process::Command::new(makensis)
        .arg(&nsi_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run makensis: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "makensis failed (exit {}):\nstdout: {stdout}\nstderr: {stderr}",
            output.status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

/// Create an MSIX package using MakeAppx.exe.
pub async fn create_msix_package(
    manifest: &BuildManifest,
    bundle_dir: &Path,
    output_path: &Path,
) -> Result<(), String> {
    let makeappx = config::find_makeappx()
        .ok_or("MakeAppx.exe not found. Install Windows SDK.")?;

    // Generate AppxManifest.xml
    let appx_manifest = generate_appx_manifest(manifest);
    let manifest_path = bundle_dir.join("AppxManifest.xml");
    std::fs::write(&manifest_path, &appx_manifest)
        .map_err(|e| format!("Failed to write AppxManifest.xml: {e}"))?;

    let output = tokio::process::Command::new(makeappx)
        .arg("pack")
        .arg("/d")
        .arg(bundle_dir)
        .arg("/p")
        .arg(output_path)
        .arg("/o") // overwrite
        .output()
        .await
        .map_err(|e| format!("Failed to run MakeAppx: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "MakeAppx failed (exit {}): {stderr}",
            output.status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

fn generate_appx_manifest(manifest: &BuildManifest) -> String {
    let publisher = manifest
        .windows_company_name
        .as_deref()
        .unwrap_or("CN=Unknown");
    let description = manifest
        .windows_file_description
        .as_deref()
        .unwrap_or(&manifest.app_name);

    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="{bundle_id}" Version="{version}.0" Publisher="{publisher}" />
  <Properties>
    <DisplayName>{app_name}</DisplayName>
    <PublisherDisplayName>{publisher}</PublisherDisplayName>
    <Description>{description}</Description>
    <Logo>app.ico</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Applications>
    <Application Id="App" Executable="{app_name}.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="{app_name}" Description="{description}"
                          BackgroundColor="transparent" Square150x150Logo="app.ico" Square44x44Logo="app.ico" />
    </Application>
  </Applications>
</Package>"#,
        bundle_id = escape_xml(&manifest.bundle_id),
        app_name = escape_xml(&manifest.app_name),
        version = escape_xml(&manifest.version),
        publisher = escape_xml(publisher),
        description = escape_xml(description),
    )
}

/// Create a portable ZIP containing the bundle directory contents.
pub fn create_portable_zip(bundle_dir: &Path, output_path: &Path) -> Result<(), String> {
    let file = std::fs::File::create(output_path)
        .map_err(|e| format!("Failed to create zip: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);

    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    if let Ok(entries) = std::fs::read_dir(bundle_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".nsi") || name.ends_with(".exe.manifest") {
                    continue; // Skip build artifacts
                }
                zip.start_file(&name, options)
                    .map_err(|e| format!("Failed to start zip entry {name}: {e}"))?;
                let data = std::fs::read(&path)
                    .map_err(|e| format!("Failed to read {name}: {e}"))?;
                zip.write_all(&data)
                    .map_err(|e| format!("Failed to write {name} to zip: {e}"))?;
            }
        }
    }

    zip.finish()
        .map_err(|e| format!("Failed to finalize zip: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_app_manifest() {
        let manifest = BuildManifest {
            app_name: "TestApp".into(),
            bundle_id: "com.test.app".into(),
            version: "1.2.3".into(),
            short_version: None,
            entry: "src/main.ts".into(),
            icon: None,
            targets: vec!["windows".into()],
            category: None,
            minimum_os_version: None,
            entitlements: None,
            windows_distribute: None,
            windows_uac_level: Some("requireAdministrator".into()),
            windows_dpi_aware: None,
            windows_file_description: None,
            windows_company_name: None,
            windows_copyright: None,
        };

        let xml = generate_app_manifest(&manifest);
        assert!(xml.contains("requireAdministrator"));
        assert!(xml.contains("com.test.app"));
        assert!(xml.contains("1.2.3.0"));
        assert!(xml.contains("PerMonitorV2"));
    }

    #[test]
    fn test_nsis_script_generation() {
        let manifest = BuildManifest {
            app_name: "MyApp".into(),
            bundle_id: "com.my.app".into(),
            version: "2.0.0".into(),
            short_version: None,
            entry: "src/main.ts".into(),
            icon: None,
            targets: vec!["windows".into()],
            category: None,
            minimum_os_version: None,
            entitlements: None,
            windows_distribute: Some("installer".into()),
            windows_uac_level: None,
            windows_dpi_aware: None,
            windows_file_description: None,
            windows_company_name: Some("My Company".into()),
            windows_copyright: None,
        };

        let appx = generate_appx_manifest(&manifest);
        assert!(appx.contains("com.my.app"));
        assert!(appx.contains("My Company"));
        assert!(appx.contains("MyApp.exe"));
    }

    #[test]
    fn test_vs_version_info_structure() {
        let manifest = BuildManifest {
            app_name: "TestApp".into(),
            bundle_id: "com.test.app".into(),
            version: "1.2.3".into(),
            short_version: None,
            entry: "src/main.ts".into(),
            icon: None,
            targets: vec!["windows".into()],
            category: None,
            minimum_os_version: None,
            entitlements: None,
            windows_distribute: None,
            windows_uac_level: None,
            windows_dpi_aware: None,
            windows_file_description: Some("Test Application".into()),
            windows_company_name: Some("Test Inc.".into()),
            windows_copyright: Some("Copyright 2025".into()),
        };

        let data = build_vs_version_info(&manifest);

        // Should start with the length field
        assert!(data.len() >= 6);
        let total_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        assert_eq!(total_len, data.len());

        // The VS_FIXEDFILEINFO signature should appear after the key "VS_VERSION_INFO"
        // Find 0xFEEF04BD in the data
        let sig_bytes = 0xFEEF04BDu32.to_le_bytes();
        let sig_pos = data
            .windows(4)
            .position(|w| w == sig_bytes);
        assert!(sig_pos.is_some(), "VS_FIXEDFILEINFO signature not found");
    }
}
