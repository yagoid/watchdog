//! Builds the watchdog processing pipeline shared by both front-ends: the
//! interactive TUI and the headless service. Wires the bounded channels,
//! spawns the enrich/detect/drive-watcher threads and starts the ETW
//! session, then hands back the scored-event consumer end for the caller to
//! drive however it likes (render it, or sink it to disk).
//!
//! Teardown note: the drive-watcher thread loops forever holding a clone of
//! the raw-event sender, so dropping the pipeline does NOT cascade a clean
//! channel close. Consumers that need the baseline persisted on shutdown must
//! call `baseline.save_to_disk()` explicitly (see the service runner).

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Result;
use crossbeam_channel::{bounded, Receiver};

use watchdog_core::{EnrichedEvent, RawEvent, ScoredEvent};
use watchdog_detect::{Baseline, Scorer};
use watchdog_enrich::{DriveWatcher, Enricher, ProcessTable};
use watchdog_etw::Session;

const CHANNEL_CAPACITY: usize = 8192;

/// A running pipeline. Holding it keeps the ETW session and worker threads
/// alive; dropping it stops ETW ingestion (the worker threads are detached
/// and torn down on process exit). The shared state is exposed so a
/// front-end can read the live process table / baseline.
pub struct Pipeline {
    pub table: Arc<ProcessTable>,
    pub baseline: Arc<Baseline>,
    pub dropped: Arc<AtomicU64>,
    /// Dropping this stops the real-time ETW session.
    _session: Session,
    _drive_watcher: JoinHandle<()>,
    _enrich: JoinHandle<()>,
    _detect: JoinHandle<()>,
}

/// Construct and start the pipeline on the ETW session named `session_name`.
/// Returns the pipeline handle plus the scored-event consumer end.
///
/// `session_name` differs per front-end (`Watchdog-RT` interactive,
/// `Watchdog-SVC` service) so the two don't fight over the same real-time
/// session — the session auto-recovery in `Session::start` stops any session
/// with a matching name, which would otherwise let one steal the other's.
pub fn start(session_name: &str, learn_only: bool) -> Result<(Pipeline, Receiver<ScoredEvent>)> {
    let (tx_raw, rx_raw) = bounded::<RawEvent>(CHANNEL_CAPACITY);
    let (tx_enriched, rx_enriched) = bounded::<EnrichedEvent>(CHANNEL_CAPACITY);
    let (tx_scored, rx_scored) = bounded::<ScoredEvent>(CHANNEL_CAPACITY);

    let dropped = Arc::new(AtomicU64::new(0));

    let (enricher, _snapshot_count) = Enricher::bootstrap();
    let table = enricher.table();

    let enrich = std::thread::Builder::new()
        .name("watchdog-enrich".into())
        .spawn(move || enricher.run(rx_raw, tx_enriched))?;

    let scorer = Scorer::with_defaults(Arc::clone(&table), learn_only);
    let baseline = scorer.baseline();
    let detect = std::thread::Builder::new()
        .name("watchdog-detect".into())
        .spawn(move || scorer.run(rx_enriched, tx_scored))?;

    // The drive watcher emits synthetic RemovableDriveMounted events into the
    // same raw channel the ETW callbacks feed.
    let drive_watcher = DriveWatcher::start(tx_raw.clone(), Arc::clone(&dropped))?;

    let session = Session::start(session_name, tx_raw, Arc::clone(&dropped))?;

    let pipeline = Pipeline {
        table,
        baseline,
        dropped,
        _session: session,
        _drive_watcher: drive_watcher,
        _enrich: enrich,
        _detect: detect,
    };
    Ok((pipeline, rx_scored))
}
