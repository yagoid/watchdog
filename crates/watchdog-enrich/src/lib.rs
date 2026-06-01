//! Enrichment stage of the watchdog pipeline.
//!
//! Consumes `RawEvent`s from the ETW thread, maintains a live process
//! table, resolves NT device paths into DOS paths, queries the kernel for
//! command lines, and emits `EnrichedEvent`s downstream.
//!
//! Windows-only.

#[cfg(windows)]
mod cmdline;
#[cfg(windows)]
mod device_map;
#[cfg(windows)]
mod drive_watcher;
#[cfg(windows)]
mod enricher;
#[cfg(windows)]
pub mod network_inspect;
#[cfg(windows)]
mod process_table;
#[cfg(windows)]
mod socket_table;
#[cfg(windows)]
pub mod wifi_scan;

#[cfg(windows)]
pub use drive_watcher::DriveWatcher;
#[cfg(windows)]
pub use enricher::Enricher;
#[cfg(windows)]
pub use process_table::ProcessTable;

#[cfg(not(windows))]
pub struct Enricher;

#[cfg(not(windows))]
impl Enricher {
    pub fn start(
        _rx_raw: crossbeam_channel::Receiver<watchdog_core::RawEvent>,
        _tx_enriched: crossbeam_channel::Sender<watchdog_core::EnrichedEvent>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("watchdog-enrich is Windows-only")
    }
}
