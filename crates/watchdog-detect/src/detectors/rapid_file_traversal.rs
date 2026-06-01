//! Detect a process touching many distinct directories in a short
//! window — the canonical fingerprint of ransomware enumerating user
//! files (or bulk exfiltration).
//!
//! When the window rolls over, we feed the previous count to the
//! baseline. If the image is "mature" in the baseline (>= LEARN_SAMPLES
//! observations) we trust the learned ceiling and only alert when the
//! current count is materially above what we've seen before. This is
//! how `msmpeng.exe`, `searchindexer.exe`, OneDrive and similar
//! legitimately I/O-heavy processes stop tripping the alarm after a
//! short familiarisation period.
//!
//! Excluded LOLBins (`powershell.exe` etc.) never become "mature" in
//! the baseline by design, so they remain fully suspicious no matter
//! how often they do it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::baseline::Baseline;
use crate::detector::Detector;

const WINDOW: Duration = Duration::from_secs(10);
const TRIGGER_DIRS: usize = 25;
const SATURATION_DIRS: usize = 80;
/// We treat the count as "still normal for this image" if it doesn't
/// exceed the learned peak by this factor.
const BASELINE_TOLERANCE: f32 = 1.5;

struct WindowState {
    distinct_parents: HashSet<String>,
    window_start: Instant,
    last_alert_count: usize,
}

impl WindowState {
    fn new(now: Instant) -> Self {
        Self {
            distinct_parents: HashSet::new(),
            window_start: now,
            last_alert_count: 0,
        }
    }
}

pub struct RapidFileTraversal {
    state: Mutex<HashMap<u32, WindowState>>,
    baseline: Arc<Baseline>,
}

impl RapidFileTraversal {
    pub fn with_baseline(baseline: Arc<Baseline>) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            baseline,
        }
    }
}

impl Detector for RapidFileTraversal {
    fn name(&self) -> &'static str { "RapidFileTraversal" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let path = match &ev.raw.payload {
            EventPayload::FileCreate { path } => path,
            _ => return None,
        };
        let parent = parent_dir(path)?;
        let image = ev.process.as_ref()?.image_name.clone();
        let pid = ev.raw.pid;
        let now = Instant::now();

        // Phase 1: mutate window state under the lock; capture what we
        // need to act on afterwards.
        let (count, rolled_over_prev_count, should_emit) = {
            let mut map = self.state.lock().unwrap();
            let entry = map.entry(pid).or_insert_with(|| WindowState::new(now));

            let rolled = if now.duration_since(entry.window_start) > WINDOW {
                let prev = entry.distinct_parents.len();
                entry.distinct_parents.clear();
                entry.window_start = now;
                entry.last_alert_count = 0;
                Some(prev)
            } else {
                None
            };

            entry.distinct_parents.insert(parent);
            let count = entry.distinct_parents.len();

            let should_emit = count >= TRIGGER_DIRS
                && count != entry.last_alert_count
                && (entry.last_alert_count == 0 || count >= entry.last_alert_count + 10);

            if should_emit {
                entry.last_alert_count = count;
            }

            (count, rolled, should_emit)
        };

        // Phase 2: feed the baseline outside the lock.
        if let Some(prev) = rolled_over_prev_count {
            self.baseline.observe_file_traversal_window(&image, prev);
        }

        if !should_emit {
            return None;
        }

        // Phase 3: ask the baseline whether this count is unremarkable
        // for this image. Mature → trust the learned ceiling.
        if self.baseline.is_mature_for(&image) {
            let typical = self.baseline.typical_traversal_max(&image).unwrap_or(0);
            let allowed = ((typical as f32) * BASELINE_TOLERANCE).max(TRIGGER_DIRS as f32) as usize;
            if count <= allowed {
                return None;
            }
        }

        // Phase 4: score on absolute count.
        let span = (SATURATION_DIRS - TRIGGER_DIRS) as f32;
        let progress = ((count - TRIGGER_DIRS) as f32 / span).clamp(0.0, 1.0);
        let sub_score = 0.35 + 0.50 * progress;

        Some(ScoreReason {
            detector: "RapidFileTraversal",
            sub_score,
            explanation: format!(
                "{image} touched {count} distinct directories in <{}s",
                WINDOW.as_secs()
            ),
        })
    }
}

fn parent_dir(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(|c| c == '\\' || c == '/');
    let idx = trimmed.rfind(|c| c == '\\' || c == '/')?;
    Some(trimmed[..idx].to_ascii_lowercase())
}
