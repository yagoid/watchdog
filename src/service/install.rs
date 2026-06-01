//! `install-service` / `uninstall-service`: register Watchdog with the SCM as
//! an auto-start LocalSystem service and harden its on-disk footprint.
//!
//! Hardening (v1): the service binary is copied into `Program Files` (admin-
//! write-only by default) and `%ProgramData%\Watchdog\` gets an explicit,
//! inheritance-protected DACL granting full access only to SYSTEM and the
//! local Administrators group. Crash recovery is left to the SCM via failure
//! actions (restart after 1s / 5s / 30s).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE,
};

use super::{data_dir, SERVICE_DISPLAY_NAME, SERVICE_NAME};

/// `EventLog\Application\Watchdog` source key.
const EVENT_SOURCE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Watchdog";

/// Where the hardened copy of the binary lives once installed.
fn install_exe_path() -> PathBuf {
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    PathBuf::from(pf).join("Watchdog").join("watchdog.exe")
}

pub fn install() -> Result<()> {
    // 1. Data dir with a locked-down DACL (baseline + incident logs live here).
    let dir = data_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    harden_dacl(&dir).context("hardening data dir DACL")?;

    // 2. Copy the binary into Program Files and register that path, so the
    //    service can't be swapped out from a user-writable location.
    let dst = install_exe_path();
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let src = std::env::current_exe().context("locating current exe")?;
    if src != dst {
        std::fs::copy(&src, &dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    }

    // 3. Event Log source registration.
    register_event_source().context("registering Event Log source")?;

    // 4. Create the service (LocalSystem, auto-start).
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening SCM")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: dst,
        launch_arguments: vec![OsString::from("run-service")],
        dependencies: vec![],
        account_name: None, // None == LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating service")?;

    // 5. Failure actions via sc.exe (restart 1s/5s/30s, reset counter daily).
    set_failure_actions()?;

    // 6. Start it now.
    let no_args: Vec<OsString> = Vec::new();
    service.start(&no_args).context("starting service")?;

    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening SCM")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .context("opening service (is it installed?)")?;

    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
        }
    }
    service.delete().context("deleting service")?;
    deregister_event_source();
    Ok(())
}

fn set_failure_actions() -> Result<()> {
    // sc.exe is invoked directly (no shell), so PowerShell's stderr wrapping
    // doesn't apply; we trust the exit status.
    let ok = Command::new("sc.exe")
        .args([
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/1000/restart/5000/restart/30000",
        ])
        .status()
        .context("invoking sc.exe failure")?
        .success();
    if !ok {
        bail!("sc.exe failure returned non-zero");
    }
    Ok(())
}

/// Apply an inheritance-protected DACL: full control for SYSTEM (SY) and the
/// local Administrators group (BA), no one else.
fn harden_dacl(path: &Path) -> Result<()> {
    let sddl = to_wide("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let mut psd = PSECURITY_DESCRIPTOR::default();

    // SAFETY: sddl is a valid NUL-terminated wide string; psd receives a
    // LocalAlloc'd descriptor we free below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .context("parsing SDDL")?;
    }

    let mut present = false.into();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = false.into();
    let wpath = to_wide(&path.to_string_lossy());

    // SAFETY: psd is a valid descriptor; dacl points into it and outlives the
    // SetNamedSecurityInfoW call. PROTECTED blocks inherited ACEs.
    let result = unsafe {
        GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted)
            .context("reading DACL from descriptor")?;
        SetNamedSecurityInfoW(
            PCWSTR(wpath.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl as *const ACL),
            None,
        )
    };

    // SAFETY: psd came from ConvertStringSecurityDescriptor... (LocalAlloc).
    unsafe {
        let _ = LocalFree(HLOCAL(psd.0));
    }

    if result != ERROR_SUCCESS {
        bail!("SetNamedSecurityInfoW failed: {:?}", result);
    }
    Ok(())
}

fn register_event_source() -> Result<()> {
    let subkey = to_wide(EVENT_SOURCE_KEY);
    let mut hkey = HKEY::default();
    // SAFETY: subkey is NUL-terminated; hkey receives the opened handle.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        bail!("RegCreateKeyExW failed: {:?}", rc);
    }
    // TypesSupported = Error | Warning | Information.
    let types_supported: u32 = 7;
    // SAFETY: hkey is open; we pass a 4-byte little-endian DWORD.
    unsafe {
        let _ = RegSetValueExW(
            hkey,
            w!("TypesSupported"),
            0,
            REG_DWORD,
            Some(&types_supported.to_le_bytes()),
        );
        let _ = RegCloseKey(hkey);
    }
    Ok(())
}

fn deregister_event_source() {
    let subkey = to_wide(EVENT_SOURCE_KEY);
    // SAFETY: subkey is NUL-terminated. Best-effort cleanup; errors ignored.
    unsafe {
        let _ = RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(subkey.as_ptr()));
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
