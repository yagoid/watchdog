//! Detect writes to well-known Windows persistence locations.
//!
//! These keys survive reboot and load the configured program at user
//! login, system boot, or process start (depending on which one). They
//! are the canonical foothold for malware that wants to come back
//! after the user closes their session — and also a fingerprint of a
//! handful of legitimate installers. We score moderately so a single
//! write is `WARN`, not `CRIT`; combined with other signals it can
//! escalate.
//!
//! ETW delivers registry paths in NT form
//! (`\REGISTRY\MACHINE\SOFTWARE\…` or `\REGISTRY\USER\<sid>\…`) so we
//! lowercase-match against the substrings characteristic of each
//! persistence mechanism, agnostic of the user SID.

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;

/// `(substring, human-readable mechanism name)`. Substrings already in
/// lowercase; the matcher lowercases its input before comparing.
const PERSISTENCE_KEYS: &[(&str, &str)] = &[
    (r"\software\microsoft\windows\currentversion\run",               "Run autostart"),
    (r"\software\microsoft\windows\currentversion\runonce",           "RunOnce autostart"),
    (r"\software\microsoft\windows\currentversion\runservices",       "RunServices autostart"),
    (r"\software\microsoft\windows\currentversion\runservicesonce",   "RunServicesOnce autostart"),
    (r"\software\microsoft\windows nt\currentversion\winlogon\shell",   "Winlogon Shell hijack"),
    (r"\software\microsoft\windows nt\currentversion\winlogon\userinit","Winlogon Userinit hijack"),
    (r"\software\microsoft\windows nt\currentversion\image file execution options", "Image File Execution Options (debugger redirect)"),
    (r"\software\microsoft\windows nt\currentversion\appinit_dlls",     "AppInit_DLLs"),
    (r"\software\microsoft\windows\currentversion\policies\explorer\run","Policies\\Explorer\\Run"),
    (r"\system\currentcontrolset\services\",                            "Service ImagePath / parameters"),
    (r"\software\classes\exefile\shell\open\command",                   "Exefile shell command hijack"),
    (r"\software\microsoft\active setup\installed components",          "Active Setup"),
    (r"\environment",                                                   "User environment (UserInitMprLogonScript)"),
    (r"\software\microsoft\command processor\autorun",                  "cmd.exe Autorun"),
];

pub struct RegistryPersistence;

impl Detector for RegistryPersistence {
    fn name(&self) -> &'static str { "RegistryPersistence" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let (key_name, value_name) = match &ev.raw.payload {
            EventPayload::RegistrySetValue { key_name, value_name } => (key_name, value_name),
            _ => return None,
        };

        let key_lower = key_name.to_ascii_lowercase();
        for (needle, mechanism) in PERSISTENCE_KEYS {
            if key_lower.contains(needle) {
                let writer = ev
                    .process
                    .as_ref()
                    .map(|p| p.image_name.as_str())
                    .unwrap_or("?");
                let value = if value_name.is_empty() {
                    "<default>".to_string()
                } else {
                    value_name.clone()
                };
                return Some(ScoreReason {
                    detector: "RegistryPersistence",
                    // 0.55: WARN by itself; combined with LolbinSpawn or
                    // UnusualParentChild it climbs into CRIT.
                    sub_score: 0.55,
                    explanation: format!("{writer} wrote {mechanism}: {value}"),
                });
            }
        }
        None
    }
}
