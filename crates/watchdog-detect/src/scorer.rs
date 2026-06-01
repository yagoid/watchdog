use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};
use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason, ScoredEvent, Severity};
use watchdog_enrich::ProcessTable;

use crate::baseline::Baseline;
use crate::detector::Detector;
use crate::detectors::{
    DnsAnomaly, LolbinSpawn, NewNetworkEgress, RapidFileTraversal, RegistryPersistence,
    UnsignedFromUserPath, UnusualParentChild, UsbExfilHint,
};
use crate::signature::SignatureCache;

const BASELINE_SAVE_INTERVAL: Duration = Duration::from_secs(300);

pub struct Scorer {
    detectors: Vec<Box<dyn Detector>>,
    table: Arc<ProcessTable>,
    baseline: Arc<Baseline>,
    /// When true, every event is observed (baseline updates) but no
    /// detector runs and no alert is emitted. Useful for the first 30
    /// minutes after install on a new machine.
    learn_only: bool,
}

impl Scorer {
    pub fn with_defaults(table: Arc<ProcessTable>, learn_only: bool) -> Self {
        let baseline = Arc::new(Baseline::load_or_new());
        let sig_cache = Arc::new(SignatureCache::new());
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(LolbinSpawn),
            Box::new(UnusualParentChild),
            Box::new(RegistryPersistence),
            Box::new(RapidFileTraversal::with_baseline(Arc::clone(&baseline))),
            Box::new(UnsignedFromUserPath::with_cache(sig_cache)),
            Box::new(NewNetworkEgress::with_baseline(Arc::clone(&baseline))),
            Box::new(DnsAnomaly),
            Box::new(UsbExfilHint::new()),
        ];
        Self {
            detectors,
            table,
            baseline,
            learn_only,
        }
    }

    pub fn baseline(&self) -> Arc<Baseline> {
        Arc::clone(&self.baseline)
    }

    pub fn run(self, rx: Receiver<EnrichedEvent>, tx: Sender<ScoredEvent>) {
        // Background save thread. We don't care if it gets killed at
        // process exit — the foreground save below covers graceful
        // shutdown, and an ungraceful one would have lost the partial
        // updates anyway.
        let baseline_save = Arc::clone(&self.baseline);
        std::thread::Builder::new()
            .name("watchdog-baseline-save".into())
            .spawn(move || loop {
                std::thread::sleep(BASELINE_SAVE_INTERVAL);
                if let Err(e) = baseline_save.save_to_disk() {
                    eprintln!("watchdog-detect: baseline save failed: {e}");
                }
            })
            .ok(); // spawn failure is non-fatal

        while let Ok(enriched) = rx.recv() {
            self.observe(&enriched);
            let scored = self.score(enriched);
            if tx.send(scored).is_err() {
                break;
            }
        }

        // Final save on graceful shutdown.
        let _ = self.baseline.save_to_disk();
    }

    fn observe(&self, ev: &EnrichedEvent) {
        if let EventPayload::ProcessStart { .. } = &ev.raw.payload {
            if let Some(p) = &ev.process {
                let parent = ev.parent.as_ref().map(|x| x.image_name.as_str());
                self.baseline.observe_process_start(&p.image_name, parent);
            }
        }
        // FileCreate observations are folded into RapidFileTraversal's
        // window-completion path so the baseline sees window totals,
        // not individual file events.
    }

    fn score(&self, enriched: EnrichedEvent) -> ScoredEvent {
        let mut reasons: Vec<ScoreReason> = Vec::new();
        if !self.learn_only {
            for d in &self.detectors {
                if let Some(r) = d.evaluate(&enriched, &self.table) {
                    reasons.push(r);
                }
            }
        }
        let score = combine_scores(&reasons);
        let severity = Severity::from_score(score);
        reasons.sort_by(|a, b| b.sub_score.partial_cmp(&a.sub_score).unwrap_or(std::cmp::Ordering::Equal));
        ScoredEvent {
            enriched,
            score,
            severity,
            reasons,
        }
    }
}

fn combine_scores(reasons: &[ScoreReason]) -> f32 {
    if reasons.is_empty() {
        return 0.0;
    }
    let mut not_p: f32 = 1.0;
    for r in reasons {
        not_p *= 1.0 - r.sub_score.clamp(0.0, 1.0);
    }
    (1.0 - not_p).clamp(0.0, 1.0)
}
