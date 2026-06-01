//! Interactive process activity during an hour this host is normally
//! idle. On a workstation the human's presence has a shape: a band of
//! active hours and a long quiet stretch overnight. A program launching
//! in an interactive session at 03:00 on a machine that's reliably asleep
//! then is weak-but-real evidence — of a scheduled implant, a remote
//! operator, or lateral movement while nobody's watching.
//!
//! Alone this is only a nudge (INFO): plenty of benign things start
//! off-hours (updaters spawning UI helpers, a late night at the desk).
//! Its value is *amplification* — combined probabilistically with a
//! LOLBin spawn, a rare destination, or an unsigned binary, an off-hours
//! coincidence pushes a borderline event over the line.
//!
//! The "usual hours" come from `HostProfile`, a decayed hour-of-day
//! histogram fed by the scorer. We gate on session != 0 (interactive)
//! both when learning and when judging, so 24/7 background services don't
//! define — or trip — the profile. We only judge once the profile is
//! mature (`is_off_hour` returns `None` until then); recording is done by
//! the scorer *after* scoring, so the current event never biases the
//! verdict on its own hour.

use std::sync::Arc;

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::baseline::{hour_and_day, Baseline};
use crate::detector::Detector;

pub struct OffHoursActivity {
    baseline: Arc<Baseline>,
}

impl OffHoursActivity {
    pub fn with_baseline(baseline: Arc<Baseline>) -> Self {
        Self { baseline }
    }
}

impl Detector for OffHoursActivity {
    fn name(&self) -> &'static str { "OffHoursActivity" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let session_id = match &ev.raw.payload {
            EventPayload::ProcessStart { session_id, .. } => *session_id,
            _ => return None,
        };
        if session_id == 0 {
            return None;
        }

        let (hour, _day) = hour_and_day(ev.raw.ts);
        // `?` short-circuits when the profile is too young to judge.
        if !self.baseline.is_off_hour(hour)? {
            return None;
        }

        let image = ev.process.as_ref()?.image_name.clone();
        Some(ScoreReason {
            detector: "OffHoursActivity",
            // INFO on its own; amplifies other detectors into WARN/CRIT.
            sub_score: 0.35,
            explanation: format!(
                "{image} started at ~{hour:02}:00, outside this host's usual active hours"
            ),
        })
    }
}
