//! Correlates a fresh removable-drive mount with a burst of file
//! writes onto that drive. This is the canonical exfiltration
//! fingerprint: someone (a human or a piece of malware acting on their
//! behalf) plugs in a USB, then a process copies a meaningful chunk of
//! data onto it.
//!
//! Two domains feed the detector:
//!   1. `RemovableDriveMounted` from the `DriveWatcher` background
//!      poller — gives us the letter and the mount timestamp.
//!   2. `FileCreate` events on paths whose drive letter matches.
//!
//! Per (drive_letter, process) we count *distinct* file paths created
//! inside `WATCH_WINDOW` from mount. Anti-spam: alerts only re-fire
//! when the count grows by at least `REFIRE_DELTA`, so a sustained
//! transfer doesn't generate one alert per file.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;

const WATCH_WINDOW: Duration = Duration::from_secs(300); // 5 min after mount
const TRIGGER_FILES: usize = 10;
const SATURATION_FILES: usize = 60;
const REFIRE_DELTA: usize = 10;

#[derive(Default)]
struct FileBurst {
    distinct_paths: HashSet<String>,
    last_alert_count: usize,
}

struct DriveActivity {
    mounted_at: Instant,
    by_pid: HashMap<u32, FileBurst>,
}

pub struct UsbExfilHint {
    state: Mutex<HashMap<char, DriveActivity>>,
}

impl UsbExfilHint {
    pub fn new() -> Self {
        Self { state: Mutex::new(HashMap::new()) }
    }
}

impl Default for UsbExfilHint {
    fn default() -> Self { Self::new() }
}

impl Detector for UsbExfilHint {
    fn name(&self) -> &'static str { "UsbExfilHint" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        match &ev.raw.payload {
            EventPayload::RemovableDriveMounted { drive_letter } => {
                // Just remember the mount; don't alert by itself.
                let mut state = self.state.lock().unwrap();
                state.insert(
                    drive_letter.to_ascii_uppercase(),
                    DriveActivity {
                        mounted_at: Instant::now(),
                        by_pid: HashMap::new(),
                    },
                );
                None
            }
            EventPayload::FileCreate { path } => {
                let letter = drive_letter_of(path)?;
                let pid = ev.raw.pid;
                let image = ev.process.as_ref()?.image_name.clone();

                let mut state = self.state.lock().unwrap();
                let activity = state.get_mut(&letter)?;
                if activity.mounted_at.elapsed() > WATCH_WINDOW {
                    return None;
                }

                let burst = activity.by_pid.entry(pid).or_default();
                burst.distinct_paths.insert(path.clone());
                let count = burst.distinct_paths.len();

                if count < TRIGGER_FILES {
                    return None;
                }
                if burst.last_alert_count > 0 && count < burst.last_alert_count + REFIRE_DELTA {
                    return None;
                }
                burst.last_alert_count = count;

                let span = (SATURATION_FILES - TRIGGER_FILES) as f32;
                let progress = ((count - TRIGGER_FILES) as f32 / span).clamp(0.0, 1.0);
                let sub_score = 0.45 + 0.40 * progress;
                let elapsed = activity.mounted_at.elapsed().as_secs();

                Some(ScoreReason {
                    detector: "UsbExfilHint",
                    sub_score,
                    explanation: format!(
                        "{image} wrote {count} files to {letter}:\\ within {elapsed}s of mount"
                    ),
                })
            }
            _ => None,
        }
    }
}

/// Extract the drive letter from a DOS-style path (`E:\foo\bar.txt`).
/// Returns `None` for NT paths (`\Device\HarddiskVolumeN\…`) or
/// anything else without a leading drive-letter prefix.
fn drive_letter_of(path: &str) -> Option<char> {
    let mut chars = path.chars();
    let c = chars.next()?;
    if !c.is_ascii_alphabetic() {
        return None;
    }
    if chars.next()? != ':' {
        return None;
    }
    Some(c.to_ascii_uppercase())
}
