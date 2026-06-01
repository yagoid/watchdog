//! A module (DLL/OCX) loaded from a user-writable location — the
//! fingerprint of DLL sideloading and search-order hijacking.
//!
//! Classic sideloading: a trusted, signed executable is made to load an
//! attacker-supplied DLL placed next to it or somewhere on its search
//! path that the attacker can write to (`%TEMP%`, `%APPDATA%`, Downloads,
//! …). The loader looks innocent; the malice is in the module. Catching
//! the load of an *unsigned* module from a user-writable path is the
//! cheap, plumbing-free version of that signal — it mirrors
//! `UnsignedFromUserPath` but for `ImageLoad` instead of `ProcessStart`,
//! and shares the same user-path classifier and signature cache.
//!
//! We gate on signature for the same reason `UnsignedFromUserPath` does:
//! legitimate apps that load modules from user space (Electron, Spotify,
//! Discord, dev toolchains) ship signed binaries, so requiring
//! unsigned/untrusted kills most of the noise. The residual false
//! positives are unsigned-but-benign native modules (some Node/Python
//! extensions, .NET temp assemblies from `Add-Type`); those keep this at
//! WARN, climbing to CRIT only when another detector fires on the same
//! loader.
//!
//! Volume note: the provider drops loads from `\Windows\` and
//! `\Program Files\` at the ETW callback, so by the time an `ImageLoad`
//! reaches here it is already an out-of-the-ordinary location and the
//! signature check runs rarely.

use std::path::Path;
use std::sync::Arc;

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;
use crate::paths::is_user_writable;
use crate::signature::{SignatureCache, SignatureStatus};

pub struct ImageLoadFromUnusualPath {
    cache: Arc<SignatureCache>,
}

impl ImageLoadFromUnusualPath {
    pub fn with_cache(cache: Arc<SignatureCache>) -> Self {
        Self { cache }
    }
}

impl Detector for ImageLoadFromUnusualPath {
    fn name(&self) -> &'static str { "ImageLoadFromUnusualPath" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let module = match &ev.raw.payload {
            EventPayload::ImageLoad { image, .. } => image,
            _ => return None,
        };

        if !is_user_writable(module) {
            return None;
        }

        // Skip the process's own primary image: a process always maps its
        // own executable, and an executable from a user-writable path is
        // already covered by UnsignedFromUserPath/ProcessImpersonation on
        // ProcessStart. Sideloading is about a *different* module loaded
        // into the process, so double-counting the EXE here is just noise.
        let loader = if let Some(p) = ev.process.as_ref() {
            if p.image_path.to_string_lossy().eq_ignore_ascii_case(module) {
                return None;
            }
            p.image_name.as_str()
        } else {
            // PID not in the table yet; can't dedupe, but the load is still
            // worth reporting.
            "unknown process"
        };

        match self.cache.check(Path::new(module)) {
            SignatureStatus::Unsigned => Some(ScoreReason {
                detector: "ImageLoadFromUnusualPath",
                // WARN alone; combines toward CRIT with LolbinSpawn,
                // UnusualParentChild, or a wrong-location loader.
                sub_score: 0.60,
                explanation: format!(
                    "{loader} loaded unsigned module from user-writable path: {module}"
                ),
            }),
            SignatureStatus::Failed => Some(ScoreReason {
                detector: "ImageLoadFromUnusualPath",
                sub_score: 0.55,
                explanation: format!(
                    "{loader} loaded module with invalid/distrusted signature from user-writable path: {module}"
                ),
            }),
            SignatureStatus::Signed | SignatureStatus::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::SystemTime;
    use watchdog_core::{EventSource, ProcessInfo, RawEvent};

    fn detector() -> ImageLoadFromUnusualPath {
        ImageLoadFromUnusualPath::with_cache(Arc::new(SignatureCache::new()))
    }

    fn image_load_event(image: &str) -> EnrichedEvent {
        EnrichedEvent {
            raw: RawEvent {
                ts: SystemTime::now(),
                src: EventSource::Process,
                pid: 1000,
                tid: 0,
                payload: EventPayload::ImageLoad {
                    image: image.to_string(),
                    base: 0,
                    size: 0,
                },
            },
            process: None,
            parent: None,
        }
    }

    fn proc(image_path: &str) -> Arc<ProcessInfo> {
        Arc::new(ProcessInfo {
            pid: 1000,
            ppid: 4,
            session_id: 1,
            image_path: PathBuf::from(image_path),
            image_name: "x".into(),
            cmdline: String::new(),
            started_at: SystemTime::now(),
        })
    }

    #[test]
    fn ignores_non_image_load_events() {
        let table = ProcessTable::new();
        let ev = EnrichedEvent {
            raw: RawEvent {
                ts: SystemTime::now(),
                src: EventSource::File,
                pid: 1000,
                tid: 0,
                payload: EventPayload::FileCreate { path: r"C:\Users\yago\Downloads\x.dll".into() },
            },
            process: None,
            parent: None,
        };
        assert!(detector().evaluate(&ev, &table).is_none());
    }

    #[test]
    fn ignores_system_path_before_signature_check() {
        // A System32 load never reaches the (filesystem-touching) signature
        // check: the user-writable gate rejects it first.
        let table = ProcessTable::new();
        let ev = image_load_event(r"C:\Windows\System32\kernel32.dll");
        assert!(detector().evaluate(&ev, &table).is_none());
    }

    #[test]
    fn skips_process_own_primary_image() {
        // The EXE mapping its own image is covered by ProcessStart-stage
        // detectors; we must not double-count it (and must not even reach
        // the signature check). Path match is case-insensitive.
        let table = ProcessTable::new();
        let path = r"C:\Users\yago\Downloads\tool.exe";
        let mut ev = image_load_event(path);
        ev.process = Some(proc(&path.to_uppercase()));
        assert!(detector().evaluate(&ev, &table).is_none());
    }

    #[test]
    fn user_path_to_missing_file_is_inconclusive() {
        // User-writable path but the file doesn't exist -> WinVerifyTrust
        // returns Unknown -> we emit nothing rather than guess.
        let table = ProcessTable::new();
        let ev = image_load_event(r"C:\Users\yago\Downloads\does-not-exist-7f3a.dll");
        assert!(detector().evaluate(&ev, &table).is_none());
    }
}
