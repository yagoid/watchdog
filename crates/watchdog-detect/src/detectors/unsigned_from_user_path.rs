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
use crate::paths::is_user_writable;
use crate::signature::{SignatureCache, SignatureStatus};

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

        if !is_user_writable(&proc.image_path.to_string_lossy()) {
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
