//! Background poller that detects drive letters appearing at runtime
//! and emits a synthetic `RemovableDriveMounted` event into the same
//! pipeline channel ETW callbacks feed.
//!
//! Polling instead of subscribing to a USB ETW provider is intentional:
//! `Microsoft-Windows-USB-USBHUB` and friends fire on every URB and
//! enumeration step, dwarfing real activity. We only care about the
//! observable consequence — a new drive letter exists. That single
//! signal covers USB sticks, SD cards, mounted VHDs/ISOs, and runtime
//! network drive mappings, all the same way.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crossbeam_channel::Sender;
use watchdog_core::{EventPayload, EventSource, RawEvent};

use crate::device_map;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub struct DriveWatcher;

impl DriveWatcher {
    /// Spawn the watcher thread. The returned `JoinHandle` is yours to
    /// drop or join. The thread runs forever; the watchdog process
    /// exits via the main thread so leaving it detached is fine.
    pub fn start(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> std::io::Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name("watchdog-drives".into())
            .spawn(move || run(tx, dropped))
    }
}

fn run(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) {
    // Initial snapshot: anything present right now is "always-there"
    // from our perspective and should not trigger an alert.
    let mut known = device_map::cached_drive_letters();

    loop {
        std::thread::sleep(POLL_INTERVAL);

        // Refresh the device map so subsequent FileCreate events on the
        // new volume get canonicalized to a real drive-letter path.
        device_map::refresh();
        let now = device_map::cached_drive_letters();

        for letter in now.difference(&known) {
            let ev = RawEvent {
                ts: SystemTime::now(),
                src: EventSource::Usb,
                pid: 0,
                tid: 0,
                payload: EventPayload::RemovableDriveMounted { drive_letter: *letter },
            };
            if tx.try_send(ev).is_err() {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
        }

        known = now;
    }
}
