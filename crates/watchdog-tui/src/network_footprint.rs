//! Rolling counters on top of the event stream — what this machine's
//! network looks like since the watchdog started running.
//!
//! Everything here is computed incrementally in `observe()` (called
//! from `App::ingest`) so there's no extra cost in the render path.
//! Cardinality of the unique-IP / unique-domain sets is capped to keep
//! memory bounded on long-running sessions; counts keep growing but
//! the set just stops admitting new members past the cap.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use watchdog_core::{EventPayload, ScoredEvent};

/// Hard cap on the cardinality sets. Past this they freeze instead of
/// growing — the counters keep counting but new IPs/domains aren't
/// remembered individually. 10 000 of each is more than any home
/// machine produces in a week.
const MAX_SET_SIZE: usize = 10_000;

#[derive(Debug, Default)]
pub struct NetworkFootprint {
    pub outbound_connects: u64,
    pub dns_queries: u64,

    /// Distinct remote IPs we've talked to (TCP).
    pub unique_remote_ips: HashSet<IpAddr>,
    /// Distinct domains queried.
    pub unique_domains: HashSet<String>,

    /// Hit counts for the "top destination" / "top domain" leaderboards.
    pub dest_counts: HashMap<IpAddr, u32>,
    pub domain_counts: HashMap<String, u32>,

    /// Public vs RFC1918/loopback/link-local split. Mostly interesting
    /// as a sanity check ("am I phoning home a lot?").
    pub public_count: u64,
    pub private_count: u64,

    /// Distinct executables that made any outbound connection.
    pub processes_with_egress: HashSet<String>,
}

impl NetworkFootprint {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, ev: &ScoredEvent) {
        match &ev.enriched.raw.payload {
            EventPayload::NetworkConnect { remote_ip, .. } => {
                self.outbound_connects += 1;
                if is_public_ip(remote_ip) {
                    self.public_count += 1;
                } else {
                    self.private_count += 1;
                }
                if self.unique_remote_ips.len() < MAX_SET_SIZE {
                    self.unique_remote_ips.insert(*remote_ip);
                }
                *self.dest_counts.entry(*remote_ip).or_insert(0) += 1;
                if let Some(p) = &ev.enriched.process {
                    if self.processes_with_egress.len() < MAX_SET_SIZE {
                        self.processes_with_egress.insert(p.image_name.clone());
                    }
                }
            }
            EventPayload::DnsQuery { name, .. } => {
                self.dns_queries += 1;
                let normalized = name.trim_end_matches('.').to_ascii_lowercase();
                if normalized.is_empty() {
                    return;
                }
                if self.unique_domains.len() < MAX_SET_SIZE {
                    self.unique_domains.insert(normalized.clone());
                }
                *self.domain_counts.entry(normalized).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    /// IP that received the most connects, with its hit count.
    pub fn top_destination(&self) -> Option<(IpAddr, u32)> {
        self.dest_counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(ip, c)| (*ip, *c))
    }

    /// Domain queried most often (canonicalised lowercase).
    pub fn top_domain(&self) -> Option<(String, u32)> {
        self.domain_counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(d, c)| (d.clone(), *c))
    }

    pub fn public_ratio_pct(&self) -> u32 {
        let total = self.public_count + self.private_count;
        if total == 0 {
            return 0;
        }
        ((self.public_count * 100) / total) as u32
    }
}

/// Classifier for "is this destination on the open internet". Treats
/// RFC1918 / loopback / link-local / multicast / broadcast as private.
fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let s = v6.segments();
            // fe80::/10 link-local OR fc00::/7 unique-local
            if (s[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            if (s[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            true
        }
    }
}
