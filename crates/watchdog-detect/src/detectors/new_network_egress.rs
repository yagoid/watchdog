//! Fires the first time we observe a *mature* image make an outbound
//! TCP connection. Once recorded in the baseline as having gone out,
//! the image is silent for all future connections.
//!
//! "Mature" matters because brand-new images (first run on this
//! machine) will trivially hit the network on startup (update check,
//! telemetry) — flagging those would be pure noise. We wait until the
//! image has been observed a handful of times in *other* contexts
//! (process spawn, file activity) before treating "no network history"
//! as meaningful. After that, a previously-quiet image suddenly
//! reaching the internet is exactly the C2-callback signal we want.
//!
//! LOLBins (powershell, certutil, etc.) are excluded because they
//! routinely make legitimate network calls — singling them out here
//! would compete with `LolbinSpawn`, which is the better detector for
//! their misuse.

use std::sync::Arc;

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::baseline::Baseline;
use crate::detector::Detector;

pub struct NewNetworkEgress {
    baseline: Arc<Baseline>,
}

impl NewNetworkEgress {
    pub fn with_baseline(baseline: Arc<Baseline>) -> Self {
        Self { baseline }
    }
}

impl Detector for NewNetworkEgress {
    fn name(&self) -> &'static str { "NewNetworkEgress" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let (ip, port) = match &ev.raw.payload {
            EventPayload::NetworkConnect { remote_ip, remote_port, .. } => (*remote_ip, *remote_port),
            _ => return None,
        };
        let image = ev.process.as_ref()?.image_name.clone();

        if self.baseline.is_excluded(&image) {
            // Still record in case any other code wants to know.
            let _ = self.baseline.observe_network_egress(&image);
            return None;
        }

        let was_observed = self.baseline.observe_network_egress(&image);
        if was_observed {
            return None;
        }
        if !self.baseline.is_mature_for(&image) {
            // First connection from a not-yet-mature image: don't alert,
            // we'd have nothing to compare it against. The
            // `observe_network_egress` call above already set the flag
            // so we won't fire on subsequent connections either.
            return None;
        }

        Some(ScoreReason {
            detector: "NewNetworkEgress",
            // WARN alone; if combined with LolbinSpawn or UnusualParentChild
            // (e.g. winword.exe → powershell → first-ever outbound) it
            // climbs into CRIT.
            sub_score: 0.55,
            explanation: format!(
                "{image} made its first observed outbound connection (to {ip}:{port})"
            ),
        })
    }
}
