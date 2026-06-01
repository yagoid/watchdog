//! Living-Off-The-Land binary detector.
//!
//! These are signed Microsoft binaries that ship with Windows and are
//! often abused by attackers because (a) their presence on disk is
//! unremarkable and (b) they can fetch/execute remote content. The list
//! is not a "signature" — it's the names of the binaries themselves,
//! which is information about Windows, not about any specific threat.
//!
//! A bare LOLBin invocation alone is a faint signal (lots of legitimate
//! uses); we boost it materially when the cmdline contains tokens
//! commonly associated with abuse (encoded payloads, remote download
//! patterns, execution-policy bypass).

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;

const LOLBINS: &[&str] = &[
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "installutil.exe",
    "msbuild.exe",
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "forfiles.exe",
    "hh.exe",
    "msdt.exe",
    "regedit.exe",
    "regini.exe",
    "ftp.exe",
];

/// Lower-case substrings we look for inside `cmdline`. Each hit adds a
/// fixed amount to the sub-score.
const SUSPICIOUS_TOKENS: &[&str] = &[
    "-encodedcommand",
    "-enc ",
    "iex(",
    "iex (",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "frombase64string",
    "-executionpolicy bypass",
    "-ep bypass",
    "-nop",
    "-noprofile",
    "-windowstyle hidden",
    "-w hidden",
    "/c start http",
    "javascript:",
    "vbscript:",
];

pub struct LolbinSpawn;

impl Detector for LolbinSpawn {
    fn name(&self) -> &'static str { "LolbinSpawn" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        if !matches!(ev.raw.payload, EventPayload::ProcessStart { .. }) {
            return None;
        }
        let proc = ev.process.as_ref()?;
        if !LOLBINS.contains(&proc.image_name.as_str()) {
            return None;
        }

        let cmdline_lc = proc.cmdline.to_ascii_lowercase();
        let mut hits: Vec<&'static str> = Vec::new();
        for token in SUSPICIOUS_TOKENS {
            if cmdline_lc.contains(token) {
                hits.push(*token);
            }
        }

        // Base 0.20 for any LOLBin: enough to surface in a `>=0.0` view
        // without spamming default `>=0.30` view unless cmdline boosts it.
        // Each suspicious token adds 0.15, capped at 0.85 total.
        let sub_score = (0.20 + 0.15 * hits.len() as f32).min(0.85);

        let explanation = if hits.is_empty() {
            format!("{} executed (known LOLBin)", proc.image_name)
        } else {
            format!("{} with abuse markers: {}", proc.image_name, hits.join(", "))
        };

        Some(ScoreReason {
            detector: "LolbinSpawn",
            sub_score,
            explanation,
        })
    }
}
