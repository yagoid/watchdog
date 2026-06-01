//! Classification of "user-writable / unusual" filesystem locations.
//!
//! Shared by `UnsignedFromUserPath` (process images) and
//! `ImageLoadFromUnusualPath` (loaded modules). The marker list is
//! security-relevant — malware lands in exactly these directories — so it
//! lives in one place rather than being duplicated and drifting between
//! the two detectors.

/// Lowercase substrings that mark a "user-writable" path. We deliberately
/// treat a colon past the drive letter as an alternate-data-stream marker
/// (see [`has_alternate_data_stream`]).
const USER_PATH_MARKERS: &[&str] = &[
    r"\appdata\local\temp\",
    r"\appdata\roaming\",
    r"\downloads\",
    r"\desktop\",
    r"\users\public\downloads\",
    r"\users\public\desktop\",
    r"\$recycle.bin\",
    r"\temp\",
    r"\users\public\documents\",
];

/// True if `path` (any case) sits in a user-writable / unusual location,
/// including an alternate data stream.
pub(crate) fn is_user_writable(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    USER_PATH_MARKERS.iter().any(|m| lower.contains(m)) || has_alternate_data_stream(&lower)
}

/// `C:\path\file.dll:Zone.Identifier` is the Win32 syntax for an alternate
/// data stream. Anything after a colon following a path-like substring
/// counts as ADS. We do the cheap check: a colon at position > 2 (past the
/// `C:\` drive-letter colon at index 1).
fn has_alternate_data_stream(path_lower: &str) -> bool {
    path_lower.match_indices(':').any(|(i, _)| i > 2)
}

#[cfg(test)]
mod tests {
    use super::is_user_writable;

    #[test]
    fn flags_user_writable_locations() {
        assert!(is_user_writable(r"C:\Users\yago\AppData\Local\Temp\x.dll"));
        assert!(is_user_writable(r"C:\Users\yago\Downloads\setup.exe"));
        assert!(is_user_writable(r"C:\Users\yago\AppData\Roaming\app\mod.dll"));
        assert!(is_user_writable(r"C:\Users\yago\Desktop\tool.exe"));
        assert!(is_user_writable(r"C:\$Recycle.Bin\S-1-5-21\a.exe"));
    }

    #[test]
    fn is_case_insensitive() {
        assert!(is_user_writable(r"C:\USERS\YAGO\DOWNLOADS\X.DLL"));
    }

    #[test]
    fn ignores_system_locations() {
        assert!(!is_user_writable(r"C:\Windows\System32\kernel32.dll"));
        assert!(!is_user_writable(r"C:\Program Files\App\app.dll"));
    }

    #[test]
    fn detects_alternate_data_stream_but_not_drive_colon() {
        assert!(is_user_writable(r"C:\some\file.exe:Zone.Identifier"));
        // A plain drive-letter path has only the colon at index 1.
        assert!(!is_user_writable(r"C:\some\ordinary\file.exe"));
    }
}
