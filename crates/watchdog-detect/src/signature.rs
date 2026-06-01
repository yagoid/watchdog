//! Authenticode signature verification via `WinVerifyTrust`.
//!
//! Calling `WinVerifyTrust` is the same path Microsoft's own
//! SigCheck/Defender use: it walks the embedded PKCS#7 signature, all
//! relevant catalog files in the system catalog store, and (depending
//! on flags) does revocation checks. We turn revocation off for now —
//! it can hit the network with an OCSP/CRL request which would block
//! the scorer thread for seconds at a time. We can revisit when there's
//! a worker pool.
//!
//! Each path is verified at most once per run; the cache lives in
//! memory only. Hash-based invalidation would be the right TOCTOU
//! defence but it costs an extra read+SHA-256 per process start; for
//! step 4c we accept the cheaper cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureStatus {
    Signed,
    Unsigned,
    /// Has a signature, but it didn't verify (revoked, expired, root not
    /// trusted, bad digest, etc.). Worth alerting on — installers don't
    /// usually ship with broken signatures.
    Failed,
    /// Could not verify (file gone, IO error). We surface this so the
    /// detector can choose how strict to be; today we treat it as
    /// inconclusive and emit nothing.
    Unknown,
}

pub struct SignatureCache {
    cache: Mutex<HashMap<PathBuf, SignatureStatus>>,
}

impl SignatureCache {
    pub fn new() -> Self {
        Self { cache: Mutex::new(HashMap::new()) }
    }

    pub fn check(&self, path: &Path) -> SignatureStatus {
        if let Some(s) = self.cache.lock().unwrap().get(path).copied() {
            return s;
        }
        let status = verify(path);
        self.cache.lock().unwrap().insert(path.to_path_buf(), status);
        status
    }
}

impl Default for SignatureCache {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn verify(path: &Path) -> SignatureStatus {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    if !path.exists() {
        return SignatureStatus::Unknown;
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    // WINTRUST_DATA is large and full of pointers; zero-init and patch
    // only what we care about.
    let mut data = WINTRUST_DATA::default();
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file_info as *mut _ };

    // Caller takes *mut GUID, but the constant is `const`, so copy.
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let result = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };

    // CLOSE pass — required to release the trust provider's state buffer.
    // Ignoring its result is intentional; the meaningful answer is `result`.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    classify_hresult(result)
}

#[cfg(windows)]
fn classify_hresult(hr: i32) -> SignatureStatus {
    // WinVerifyTrust returns 0 on full success and a (usually) HRESULT
    // for everything else. We surface a small handful explicitly; the
    // rest collapse into `Failed`.
    const TRUST_E_NOSIGNATURE: i32       = 0x800B_0100u32 as i32;
    const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003u32 as i32;
    const TRUST_E_PROVIDER_UNKNOWN: i32  = 0x800B_0001u32 as i32;
    const CRYPT_E_FILE_ERROR: i32        = 0x8009_2003u32 as i32;

    match hr {
        0 => SignatureStatus::Signed,
        TRUST_E_NOSIGNATURE
        | TRUST_E_SUBJECT_FORM_UNKNOWN
        | TRUST_E_PROVIDER_UNKNOWN => SignatureStatus::Unsigned,
        CRYPT_E_FILE_ERROR => SignatureStatus::Unknown,
        _ => SignatureStatus::Failed,
    }
}

#[cfg(not(windows))]
fn verify(_path: &Path) -> SignatureStatus {
    SignatureStatus::Unknown
}
