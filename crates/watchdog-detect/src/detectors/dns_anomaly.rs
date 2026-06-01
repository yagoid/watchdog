//! Flag DNS queries whose name has the shape commonly produced by
//! malware (DGA-style random subdomains under abused TLDs).
//!
//! This is a *multi-evidence* detector: any single heuristic alone is
//! too noisy (CDN subdomains often look random; harmless sites use
//! free TLDs). We require two of three signals before emitting
//! anything. The signals are:
//!
//!   1. Shannon entropy of the leftmost label > `ENTROPY_THRESHOLD`.
//!      Real words score 2.0–3.0 bits/char; uniform random strings
//!      approach `log2(36) ≈ 5.17`.
//!   2. The effective TLD is on a small list known to be heavily
//!      abused by cheap-or-free registrars.
//!   3. The leftmost label is very long (`LONG_LABEL`+ chars).
//!
//! The list of TLDs is *behavioural* — these TLDs are abused because
//! they're free or one-click-buy, not because of any country or
//! political consideration. It can be tuned without affecting the
//! detector's architecture.

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;

const ENTROPY_THRESHOLD: f32 = 3.5;
const LONG_LABEL: usize = 40;

/// Lower-case TLDs (without leading dot) known to be heavily abused by
/// malware distribution. Keep the list small — false positives here
/// translate directly into noise.
const SUSPICIOUS_TLDS: &[&str] = &[
    "tk", "ml", "ga", "cf", "gq", // Freenom — historically free, now mostly retired but legacy
    "top", "xyz", "icu", "click",
    "pw", "kim", "work",
];

pub struct DnsAnomaly;

impl Detector for DnsAnomaly {
    fn name(&self) -> &'static str { "DnsAnomaly" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let name = match &ev.raw.payload {
            EventPayload::DnsQuery { name, .. } => name,
            _ => return None,
        };
        let lower = name.to_ascii_lowercase();
        let labels: Vec<&str> = lower.split('.').filter(|s| !s.is_empty()).collect();
        if labels.len() < 2 {
            return None; // bare hostnames or empty queries
        }
        let leftmost = labels[0];
        let tld = labels[labels.len() - 1];

        let entropy = shannon_entropy(leftmost);
        let entropy_hit = entropy > ENTROPY_THRESHOLD;
        let tld_hit = SUSPICIOUS_TLDS.contains(&tld);
        let length_hit = leftmost.len() >= LONG_LABEL;

        let hits = [entropy_hit, tld_hit, length_hit]
            .iter()
            .filter(|b| **b)
            .count();
        if hits < 2 {
            return None;
        }

        // 2 hits → 0.50 WARN, 3 hits → 0.75 CRIT
        let sub_score = match hits {
            2 => 0.50,
            _ => 0.75,
        };

        let mut why_parts = Vec::with_capacity(3);
        if entropy_hit { why_parts.push(format!("high-entropy label ({entropy:.2} bits)")); }
        if tld_hit     { why_parts.push(format!("abused TLD .{tld}")); }
        if length_hit  { why_parts.push(format!("long label ({} chars)", leftmost.len())); }

        Some(ScoreReason {
            detector: "DnsAnomaly",
            sub_score,
            explanation: format!("{name}: {}", why_parts.join(", ")),
        })
    }
}

/// Shannon entropy in bits per character. Works on bytes — fine for
/// ASCII/host-safe labels; for IDN punycode it's already ASCII.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}
