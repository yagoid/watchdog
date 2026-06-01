//! Fires when an unsigned (or untrusted) binary is launched from a
//! location any non-admin user can write to.
//!
//! This is the single highest-yield detector in the plan: real malware
//! almost always lands in `%TEMP%`, `%APPDATA%`, `Downloads`, the
//! Desktop, or an `:Zone.Identifier`-tagged Alternate Data Stream, and
//! almost never carries a valid Authenticode signature. Conversely,
//! legitimate user-launched tools from those paths are almost always
//! signed (Chrome installer, Slack, dev tools, …). The signal/noise
//! ratio is excellent.
//!
//! We only signature-check when the path matches a user-writable
//! pattern, so the (potentially slow) `WinVerifyTrust` call doesn't run
//! for every process start — only the suspicious-shaped ones.

use std::sync::Arc;

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;
use crate::signature::{SignatureCache, SignatureStatus};

/// Lowercase substrings that mark a "user-writable" path. The matcher
/// lowercases its input. We deliberately include `:` (alternate data
/// stream marker) so any ADS-loaded binary is flagged.
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

pub struct UnsignedFromUserPath {
    cache: Arc<SignatureCache>,
}

impl UnsignedFromUserPath {
    pub fn with_cache(cache: Arc<SignatureCache>) -> Self {
        Self { cache }
    }
}

impl Detector for UnsignedFromUserPath {
    fn name(&self) -> &'static str { "UnsignedFromUserPath" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        if !matches!(ev.raw.payload, EventPayload::ProcessStart { .. }) {
            return None;
        }
        let proc = ev.process.as_ref()?;

        let path_str = proc.image_path.to_string_lossy();
        let path_lower = path_str.to_ascii_lowercase();

        let matches_user_path = USER_PATH_MARKERS.iter().any(|m| path_lower.contains(m))
            || has_alternate_data_stream(&path_lower);
        if !matches_user_path {
            return None;
        }

        // Now the (potentially expensive) signature check, only on
        // paths already shaped like user-writable locations.
        match self.cache.check(&proc.image_path) {
            SignatureStatus::Unsigned => Some(ScoreReason {
                detector: "UnsignedFromUserPath",
                // WARN on its own; combined with LolbinSpawn or
                // UnusualParentChild it climbs into CRIT.
                sub_score: 0.65,
                explanation: format!(
                    "unsigned binary from user-writable path: {}",
                    proc.image_path.display()
                ),
            }),
            SignatureStatus::Failed => Some(ScoreReason {
                detector: "UnsignedFromUserPath",
                sub_score: 0.55,
                explanation: format!(
                    "binary with invalid/distrusted signature from user-writable path: {}",
                    proc.image_path.display()
                ),
            }),
            SignatureStatus::Signed | SignatureStatus::Unknown => None,
        }
    }
}

/// `C:\path\file.exe:Zone.Identifier` is the Win32 syntax for an
/// alternate data stream. Anything after a colon following a path-like
/// substring counts as ADS. We do the cheap check: look for a colon at
/// position > 2 (past `C:\`).
fn has_alternate_data_stream(path_lower: &str) -> bool {
    // Skip drive-letter colon (always at index 1, e.g. "c:")
    path_lower.match_indices(':').any(|(i, _)| i > 2)
}
