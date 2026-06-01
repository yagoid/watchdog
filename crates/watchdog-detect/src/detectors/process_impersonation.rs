//! Critical Windows system processes running from the wrong location, or
//! launched by the wrong parent. MITRE T1036.005 (masquerading) and the
//! classic "drop malware named svchost.exe somewhere writable" trick.
//!
//! `svchost.exe`, `lsass.exe`, `services.exe`, … only ever live in
//! `System32` (explorer.exe in the Windows root). They are never WOW64,
//! never relocated. So a process *named* like one of them but executing
//! from `%TEMP%`, a user profile, or any other directory is impersonation
//! — there is no benign reason for it. That makes the path check a
//! near-zero-false-positive, high-signal heuristic with no new plumbing:
//! it rides on `ProcessStart`, whose image path the enricher already
//! canonicalizes to `C:\…`.
//!
//! Secondary signal: a correctly-located `svchost.exe` whose parent is
//! something other than `services.exe`. On a healthy system the Service
//! Control Manager is the only launcher of svchost; a different parent
//! suggests hollowing / a masqueraded host. We only raise this when the
//! parent is actually known, so a missing parent record never fires it.

use std::path::Path;
use std::sync::OnceLock;

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;

/// Where a protected image is expected to live, relative to the Windows
/// root. The vast majority sit in `System32`; a few (explorer) sit in the
/// Windows directory itself.
enum ExpectedDir {
    System32,
    WindowsRoot,
}

/// Returns the expected location for a protected system image, or `None`
/// if the image isn't one we guard. `image` is the lowercase basename.
fn expected_dir(image: &str) -> Option<ExpectedDir> {
    use ExpectedDir::*;
    let dir = match image {
        // Session-critical native processes — always System32, never WOW64.
        "smss.exe" | "csrss.exe" | "wininit.exe" | "winlogon.exe"
        | "services.exe" | "lsass.exe" | "lsaiso.exe" | "svchost.exe"
        // Frequently-impersonated user-session hosts, also always System32.
        | "spoolsv.exe" | "taskhostw.exe" | "dwm.exe" | "fontdrvhost.exe" => System32,
        // explorer.exe lives in the Windows root, not System32.
        "explorer.exe" => WindowsRoot,
        _ => return None,
    };
    Some(dir)
}

/// `%SystemRoot%` lowercased with no trailing separator, resolved once.
/// Falls back to the overwhelmingly common default if the env var is
/// missing (it never is on a real Windows host).
fn windows_root() -> &'static str {
    static ROOT: OnceLock<String> = OnceLock::new();
    ROOT.get_or_init(|| {
        std::env::var("SystemRoot")
            .unwrap_or_else(|_| "C:\\Windows".to_string())
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    })
}

/// True if `dir` is the directory `expected` expects, compared
/// case-insensitively (Windows paths are case-insensitive).
fn dir_matches(dir: &Path, expected: &ExpectedDir) -> bool {
    let dir = dir.to_string_lossy().to_ascii_lowercase();
    let dir = dir.trim_end_matches('\\');
    let root = windows_root();
    match expected {
        ExpectedDir::System32 => dir == format!("{root}\\system32"),
        ExpectedDir::WindowsRoot => dir == root,
    }
}

/// True if `s` looks like a fully-qualified drive path (`C:\…`). The
/// enricher canonicalizes real system images to this form; if it couldn't
/// resolve a DOS path (left a `\Device\Harddisk…` form or an empty string)
/// we can't judge the location, so we decline rather than risk a false
/// positive. A genuinely-impersonated binary in a user directory still has
/// a drive-letter path, so this guard costs no real detection.
fn is_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

pub struct ProcessImpersonation;

impl Detector for ProcessImpersonation {
    fn name(&self) -> &'static str { "ProcessImpersonation" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        if !matches!(ev.raw.payload, EventPayload::ProcessStart { .. }) {
            return None;
        }
        let proc = ev.process.as_ref()?;
        let expected = expected_dir(&proc.image_name)?;

        let path = proc.image_path.as_path();
        let dir = path.parent()?;
        if !is_drive_path(&dir.to_string_lossy()) {
            return None;
        }

        if !dir_matches(dir, &expected) {
            // Strong, near-zero-FP: a protected system image executing from
            // a directory it never legitimately runs from. CRIT on its own.
            return Some(ScoreReason {
                detector: "ProcessImpersonation",
                sub_score: 0.85,
                explanation: format!(
                    "{} running from {} — system image expected in {}",
                    proc.image_name,
                    path.display(),
                    match expected {
                        ExpectedDir::System32 => format!("{}\\System32", windows_root()),
                        ExpectedDir::WindowsRoot => windows_root().to_string(),
                    },
                ),
            });
        }

        // Located correctly. Secondary check: svchost must descend from
        // services.exe. Only fires when the parent is actually known.
        if proc.image_name == "svchost.exe" {
            if let Some(parent) = ev.parent.as_ref() {
                if parent.image_name != "services.exe" {
                    return Some(ScoreReason {
                        detector: "ProcessImpersonation",
                        // WARN: legitimate path but anomalous launcher. Climbs
                        // toward CRIT if another detector also fires on it.
                        sub_score: 0.55,
                        explanation: format!(
                            "svchost.exe launched by {} (expected services.exe)",
                            parent.image_name
                        ),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::SystemTime;
    use watchdog_core::{EventSource, ProcessInfo, RawEvent};

    fn proc(name: &str, path: &str, ppid: u32) -> Arc<ProcessInfo> {
        Arc::new(ProcessInfo {
            pid: 1234,
            ppid,
            session_id: 1,
            image_path: PathBuf::from(path),
            image_name: name.to_string(),
            cmdline: String::new(),
            started_at: SystemTime::now(),
        })
    }

    fn event(child: Arc<ProcessInfo>, parent: Option<Arc<ProcessInfo>>) -> EnrichedEvent {
        EnrichedEvent {
            raw: RawEvent {
                ts: SystemTime::now(),
                src: EventSource::Process,
                pid: child.pid,
                tid: 0,
                payload: EventPayload::ProcessStart {
                    ppid: child.ppid,
                    image: child.image_path.to_string_lossy().into_owned(),
                    cmdline: String::new(),
                    session_id: child.session_id,
                },
            },
            process: Some(child),
            parent,
        }
    }

    // The tests assume the conventional C:\Windows root. windows_root() reads
    // %SystemRoot% once; on any normal host (and CI) that's C:\Windows.
    fn sys32(file: &str) -> String {
        format!("{}\\System32\\{file}", windows_root())
    }

    #[test]
    fn legit_lsass_in_system32_is_silent() {
        let table = ProcessTable::new();
        let ev = event(proc("lsass.exe", &sys32("lsass.exe"), 600), None);
        assert!(ProcessImpersonation.evaluate(&ev, &table).is_none());
    }

    #[test]
    fn lsass_from_user_path_fires_crit() {
        let table = ProcessTable::new();
        let ev = event(
            proc("lsass.exe", "C:\\Users\\yago\\AppData\\Local\\Temp\\lsass.exe", 4000),
            None,
        );
        let r = ProcessImpersonation.evaluate(&ev, &table).expect("should fire");
        assert!(r.sub_score >= 0.7, "wrong-location impersonation must be CRIT-class");
    }

    #[test]
    fn explorer_in_windows_root_is_silent() {
        let table = ProcessTable::new();
        let ev = event(proc("explorer.exe", &format!("{}\\explorer.exe", windows_root()), 4000), None);
        assert!(ProcessImpersonation.evaluate(&ev, &table).is_none());
    }

    #[test]
    fn explorer_in_system32_fires() {
        // explorer.exe belongs in the Windows root, NOT System32.
        let table = ProcessTable::new();
        let ev = event(proc("explorer.exe", &sys32("explorer.exe"), 4000), None);
        assert!(ProcessImpersonation.evaluate(&ev, &table).is_some());
    }

    #[test]
    fn svchost_from_services_is_silent() {
        let table = ProcessTable::new();
        let parent = proc("services.exe", &sys32("services.exe"), 600);
        let ev = event(proc("svchost.exe", &sys32("svchost.exe"), parent.pid), Some(parent));
        assert!(ProcessImpersonation.evaluate(&ev, &table).is_none());
    }

    #[test]
    fn svchost_wrong_parent_fires_warn() {
        let table = ProcessTable::new();
        let parent = proc("explorer.exe", &format!("{}\\explorer.exe", windows_root()), 4000);
        let ev = event(proc("svchost.exe", &sys32("svchost.exe"), parent.pid), Some(parent));
        let r = ProcessImpersonation.evaluate(&ev, &table).expect("should fire");
        assert!(r.sub_score >= 0.4 && r.sub_score < 0.7, "wrong-parent svchost is WARN-class");
    }

    #[test]
    fn svchost_unknown_parent_is_silent() {
        // No parent record -> we must not guess.
        let table = ProcessTable::new();
        let ev = event(proc("svchost.exe", &sys32("svchost.exe"), 600), None);
        assert!(ProcessImpersonation.evaluate(&ev, &table).is_none());
    }

    #[test]
    fn unresolved_device_path_is_silent() {
        // Enricher couldn't canonicalize: don't risk a false positive.
        let table = ProcessTable::new();
        let ev = event(
            proc("svchost.exe", "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe", 600),
            None,
        );
        assert!(ProcessImpersonation.evaluate(&ev, &table).is_none());
    }

    #[test]
    fn non_protected_image_is_silent() {
        let table = ProcessTable::new();
        let ev = event(proc("notepad.exe", "C:\\Users\\yago\\Desktop\\notepad.exe", 4000), None);
        assert!(ProcessImpersonation.evaluate(&ev, &table).is_none());
    }
}
