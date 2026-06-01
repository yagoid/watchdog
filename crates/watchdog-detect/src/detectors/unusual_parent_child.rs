//! Parent → child pairs that almost never have a legitimate reason to
//! occur on a typical workstation.
//!
//! This is not yet a learned baseline (step 5 of the plan). It's a
//! hand-curated set of pairs known from incident-response experience —
//! Office macros launching shells, browsers spawning scripting hosts,
//! LSASS spawning anything at all. When the runtime baseline lands,
//! these built-ins become "always-suspicious" overrides on top of it.

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;

/// `(parent_basename_lowercase, &[child_basename_lowercase, ...])`
const SUSPICIOUS_CHAINS: &[(&str, &[&str])] = &[
    // Office macros pivoting into shells / scripting hosts
    ("winword.exe",   &["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]),
    ("excel.exe",     &["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]),
    ("powerpnt.exe",  &["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]),
    ("outlook.exe",   &["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),
    ("onenote.exe",   &["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),
    ("acrord32.exe",  &["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]),

    // Browsers spawning shells (a Chrome bug or a malicious extension)
    ("chrome.exe",    &["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),
    ("msedge.exe",    &["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),
    ("firefox.exe",   &["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),
    ("brave.exe",     &["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),

    // LSASS spawning anything is highly anomalous — typically credential dumping or weird AV behavior
    ("lsass.exe",     &["cmd.exe", "powershell.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "net.exe", "whoami.exe"]),
];

pub struct UnusualParentChild;

impl Detector for UnusualParentChild {
    fn name(&self) -> &'static str { "UnusualParentChild" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        if !matches!(ev.raw.payload, EventPayload::ProcessStart { .. }) {
            return None;
        }
        let child = ev.process.as_ref()?;
        let parent = ev.parent.as_ref()?;

        for (parent_name, suspicious_children) in SUSPICIOUS_CHAINS {
            if parent.image_name == *parent_name
                && suspicious_children.contains(&child.image_name.as_str())
            {
                // 0.65: alone is WARN. Combined with `LolbinSpawn` (e.g.
                // winword → powershell -EncodedCommand) it climbs into CRIT.
                return Some(ScoreReason {
                    detector: "UnusualParentChild",
                    sub_score: 0.65,
                    explanation: format!(
                        "{} → {} (rarely benign chain)",
                        parent.image_name, child.image_name
                    ),
                });
            }
        }
        None
    }
}
