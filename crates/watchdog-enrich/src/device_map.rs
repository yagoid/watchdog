//! Maps NT device paths (`\Device\HarddiskVolume3\Windows\…`) back to
//! DOS paths (`C:\Windows\…`).
//!
//! The mapping is built once at startup but can be refreshed at runtime
//! (e.g. when the `DriveWatcher` notices a new drive letter has
//! appeared). Lookups go through an `RwLock` so most callers can read
//! concurrently while refresh holds the write briefly.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};

use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

struct DeviceMap {
    /// Pairs of (NT device path lower-cased, drive letter). Longest
    /// first so prefix matching is unambiguous when one device
    /// contains another.
    entries: Vec<(String, char)>,
}

static MAP: LazyLock<RwLock<DeviceMap>> = LazyLock::new(|| RwLock::new(DeviceMap::build()));

impl DeviceMap {
    fn build() -> Self {
        let mut entries: Vec<(String, char)> = Vec::new();
        let mut buf = vec![0u16; 1024];

        for letter in b'A'..=b'Z' {
            let drive = [letter as u16, b':' as u16, 0u16];
            let len = unsafe {
                QueryDosDeviceW(
                    windows::core::PCWSTR(drive.as_ptr()),
                    Some(buf.as_mut_slice()),
                )
            };
            if len == 0 {
                continue;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let device = String::from_utf16_lossy(&buf[..end]);
            entries.push((device.to_ascii_lowercase(), letter as char));
        }

        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self { entries }
    }
}

/// Rewrite an NT path into DOS form. If no mapping is found the input
/// is returned unchanged so the caller still gets something useful.
pub fn canonicalize(nt_path: &str) -> PathBuf {
    if nt_path.is_empty() {
        return PathBuf::new();
    }
    let lower = nt_path.to_ascii_lowercase();
    let map = MAP.read().unwrap();
    for (device, letter) in &map.entries {
        if let Some(rest) = lower.strip_prefix(device.as_str()) {
            let preserved = &nt_path[nt_path.len() - rest.len()..];
            let mut out = String::with_capacity(2 + preserved.len());
            out.push(*letter);
            out.push(':');
            out.push_str(preserved);
            return PathBuf::from(out);
        }
    }
    PathBuf::from(nt_path)
}

/// Last path component, lower-cased.
pub fn basename_lower(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Rebuild the device→letter cache from scratch. The `DriveWatcher`
/// calls this when its poll discovers a new drive letter so that
/// subsequent `FileCreate` events on the new volume get canonicalized
/// to `X:\…` instead of staying in `\Device\HarddiskVolumeN\…` form.
pub fn refresh() {
    let fresh = DeviceMap::build();
    *MAP.write().unwrap() = fresh;
}

/// Set of drive letters currently assigned. Cheap: just walks the
/// already-cached map. Call `refresh()` first if you need a current
/// snapshot.
pub fn cached_drive_letters() -> HashSet<char> {
    MAP.read().unwrap().entries.iter().map(|(_, c)| *c).collect()
}
