use watchdog_core::{EnrichedEvent, ScoreReason};
use watchdog_enrich::ProcessTable;

/// One heuristic. Receives an enriched event and the live process
/// table; returns `Some(reason)` if it has anything to say.
///
/// Detectors must be cheap (run on the hot path, once per event) and
/// stateless across calls, or hold their own internal `Mutex`.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, event: &EnrichedEvent, table: &ProcessTable) -> Option<ScoreReason>;
}
