//! ETW ingestion: opens a real-time user-mode session and dispatches
//! events from each enabled provider into the shared `RawEvent` channel.
//!
//! Windows-only. On non-Windows targets the crate exposes the same
//! `Session` type but `start` returns an error.

#[cfg(windows)]
mod session;
#[cfg(windows)]
pub mod providers;

#[cfg(windows)]
pub use session::Session;

#[cfg(not(windows))]
pub struct Session;

#[cfg(not(windows))]
impl Session {
    pub fn start(
        _name: &str,
        _tx: crossbeam_channel::Sender<watchdog_core::RawEvent>,
    ) -> anyhow::Result<Self> {
        anyhow::bail!("watchdog-etw is Windows-only")
    }
}
