//! A mature, focused program suddenly contacting a network destination
//! it has never reached before — a C2-callback / data-staging signal that
//! complements `NewNetworkEgress` (which only fires on the *first* egress
//! of an otherwise-silent image).
//!
//! Destinations are bucketed by /24 (IPv4) or /48 (IPv6) prefix rather
//! than exact IP: legitimate services rotate addresses within a network,
//! and we don't want to alert on every DNS round-robin. We have no
//! external ASN/GeoIP feed (a deliberate project constraint), so the
//! prefix is the coarsest "same operator" proxy available without one.
//!
//! Noise control lives in the baseline: an image whose distinct-prefix
//! set overflows `DEST_PREFIX_CAP` is marked *chatty* (browsers, updaters,
//! CDN consumers) and never alerts. So this only fires for programs that
//! normally talk to a small, stable set of endpoints — exactly the ones
//! where a brand-new destination is meaningful. LOLBins are excluded
//! (they belong to `LolbinSpawn`).

use std::net::IpAddr;
use std::sync::Arc;

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::baseline::Baseline;
use crate::detector::Detector;

pub struct RareDestination {
    baseline: Arc<Baseline>,
}

impl RareDestination {
    pub fn with_baseline(baseline: Arc<Baseline>) -> Self {
        Self { baseline }
    }
}

impl Detector for RareDestination {
    fn name(&self) -> &'static str { "RareDestination" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let remote = match &ev.raw.payload {
            EventPayload::NetworkConnect { remote_ip, .. } => *remote_ip,
            _ => return None,
        };
        // Only routable, external destinations. LAN/infra churn (gateway,
        // DNS, mDNS, DHCP, NAS, link-local) is constant noise and not what
        // a C2-callback signal is about; lateral movement to internal hosts
        // is a different problem for a future detector.
        if !is_external_destination(remote) {
            return None;
        }
        let image = ev.process.as_ref()?.image_name.clone();
        let prefix = dest_prefix(remote);

        // Records the prefix and tells us whether it's rare enough to act
        // on (mature + non-chatty + had history + new). Recording here
        // mirrors NewNetworkEgress: learning happens as we observe.
        if !self.baseline.observe_destination(&image, &prefix) {
            return None;
        }

        Some(ScoreReason {
            detector: "RareDestination",
            // WARN alone; combines toward CRIT with DnsAnomaly, LolbinSpawn,
            // or an off-hours connection.
            sub_score: 0.50,
            explanation: format!(
                "{image} connected to {remote} ({prefix}) — a destination it has never used before"
            ),
        })
    }
}

/// True only for globally-routable destinations. We can't use the
/// nightly-only `IpAddr::is_global`, so we exclude the non-routable /
/// infrastructure ranges by hand with stable methods.
fn is_external_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
                || a.is_documentation())
        }
        IpAddr::V6(a) => {
            if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
                return false;
            }
            let seg0 = a.segments()[0];
            // fe80::/10 link-local, fc00::/7 unique-local.
            !((seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xfe00) == 0xfc00)
        }
    }
}

/// Coarse "same network/operator" bucket: /24 for IPv4, /48 for IPv6.
fn dest_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;
    use watchdog_core::{EventSource, ProcessInfo, RawEvent};

    fn connect_event(image: &str, remote: IpAddr) -> EnrichedEvent {
        let proc = Arc::new(ProcessInfo {
            pid: 1000,
            ppid: 4,
            session_id: 1,
            image_path: format!(r"C:\Program Files\{image}").into(),
            image_name: image.to_string(),
            cmdline: String::new(),
            started_at: SystemTime::now(),
        });
        EnrichedEvent {
            raw: RawEvent {
                ts: SystemTime::now(),
                src: EventSource::Network,
                pid: 1000,
                tid: 0,
                payload: EventPayload::NetworkConnect {
                    local_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                    local_port: 50000,
                    remote_ip: remote,
                    remote_port: 443,
                },
            },
            process: Some(proc),
            parent: None,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn prefix_buckets_by_24_and_48() {
        assert_eq!(dest_prefix(v4(203, 0, 113, 7)), "203.0.113.0/24");
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 1, 2, 3, 4, 5));
        assert_eq!(dest_prefix(v6), "2001:db8:abcd::/48");
    }

    #[test]
    fn first_destination_does_not_fire() {
        // No prior history -> NewNetworkEgress' job, not ours.
        let baseline = Arc::new(Baseline::new());
        // Make the image mature so only the "had history" condition gates it.
        for _ in 0..5 {
            baseline.observe_process_start("app.exe", Some("explorer.exe"));
        }
        let det = RareDestination::with_baseline(baseline);
        let table = ProcessTable::new();
        assert!(det.evaluate(&connect_event("app.exe", v4(8, 8, 8, 8)), &table).is_none());
    }

    #[test]
    fn new_prefix_after_history_fires_for_mature_image() {
        let baseline = Arc::new(Baseline::new());
        for _ in 0..5 {
            baseline.observe_process_start("app.exe", Some("explorer.exe"));
        }
        let det = RareDestination::with_baseline(baseline);
        let table = ProcessTable::new();
        // First destination establishes history (no fire).
        assert!(det.evaluate(&connect_event("app.exe", v4(8, 8, 8, 8)), &table).is_none());
        // Same /24 again: known, no fire.
        assert!(det.evaluate(&connect_event("app.exe", v4(8, 8, 8, 200)), &table).is_none());
        // A different /24: rare, fires.
        let r = det.evaluate(&connect_event("app.exe", v4(1, 1, 1, 1)), &table).expect("should fire");
        assert!(r.sub_score >= 0.4 && r.sub_score < 0.7);
    }

    #[test]
    fn immature_image_never_fires() {
        // Fewer than LEARN_SAMPLES spawns -> not mature.
        let baseline = Arc::new(Baseline::new());
        baseline.observe_process_start("app.exe", Some("explorer.exe"));
        let det = RareDestination::with_baseline(baseline);
        let table = ProcessTable::new();
        det.evaluate(&connect_event("app.exe", v4(8, 8, 8, 8)), &table);
        assert!(det.evaluate(&connect_event("app.exe", v4(1, 1, 1, 1)), &table).is_none());
    }

    #[test]
    fn loopback_and_lan_are_ignored() {
        let baseline = Arc::new(Baseline::new());
        for _ in 0..5 {
            baseline.observe_process_start("app.exe", Some("explorer.exe"));
        }
        let det = RareDestination::with_baseline(baseline);
        let table = ProcessTable::new();
        // Loopback, private LAN, and the gateway DNS are all infra noise.
        assert!(det.evaluate(&connect_event("app.exe", v4(127, 0, 0, 1)), &table).is_none());
        assert!(det.evaluate(&connect_event("app.exe", v4(192, 168, 1, 1)), &table).is_none());
        assert!(det.evaluate(&connect_event("app.exe", v4(10, 0, 0, 5)), &table).is_none());
    }
}
