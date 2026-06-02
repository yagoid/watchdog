//! Detect a process touching many distinct directories in a short
//! window — the canonical fingerprint of ransomware enumerating user
//! files (or bulk exfiltration).
//!
//! Only *high-signal* directories count toward the window. Ransomware
//! goes after user data; an IDE indexer, package manager or language
//! server walks its own install tree and read-only library caches
//! (`typeshed`, `node_modules`, `site-packages`, `.vscode\extensions`,
//! …). Those are filtered out here so Pylance reindexing a venv doesn't
//! look like a cryptolocker. See [`is_low_signal_dir`].
//!
//! When the window rolls over, we feed the previous (high-signal) count
//! to the baseline. We only trust the learned ceiling once we've seen
//! enough traversal *windows* for the image (`Baseline::traversal_ceiling`)
//! — process spawns alone don't grant traversal trust. This is how
//! `msmpeng.exe`, `searchindexer.exe`, OneDrive and similar legitimately
//! I/O-heavy processes stop tripping the alarm after a short
//! familiarisation period.
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
        let proc = ev.process.as_ref()?;
        let image = proc.image_name.clone();

        // Path-quality gate: bulk reads of a tool's own install tree or of
        // read-only library/cache trees are not what ransomware does, so
        // they never enter the window. Drop before locking — a process that
        // only ever touches low-signal dirs never gets window state at all.
        let own_install = install_dir_prefix(&proc.image_path);
        if is_low_signal_dir(&parent, own_install.as_deref()) {
            return None;
        }

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

        // Phase 3: suppress if the count is within the learned ceiling for
        // this image. `traversal_ceiling` returns `Some` only once we've
        // observed enough traversal windows to trust it — spawn-only
        // maturity says nothing about how a process walks the filesystem.
        if let Some(typical) = self.baseline.traversal_ceiling(&image) {
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

/// Lowercased install directory of a process image, used as a prefix to
/// recognise "the program reading its own tree". `None` if the image path
/// has no parent (shouldn't happen for a real `C:\…\foo.exe`).
fn install_dir_prefix(image_path: &std::path::Path) -> Option<String> {
    let parent = image_path.parent()?;
    let s = parent.to_string_lossy().to_ascii_lowercase();
    (!s.is_empty()).then_some(s)
}

/// Read-only library / tooling / cache trees whose bulk traversal is
/// routine for dev tools and never resembles ransomware hitting user
/// data. Substrings, matched against an already-lowercased parent dir.
const LOW_SIGNAL_MARKERS: &[&str] = &[
    r"\node_modules\",
    r"\site-packages\",
    r"\typeshed",            // typeshed-fallback, typeshed/stdlib, …
    r"\.vscode\extensions\",
    r"\.vscode-insiders\extensions\",
    r"\.vscode-server\",
    r"\.cargo\registry\",
    r"\.rustup\toolchains\",
    r"\.nuget\packages\",
    r"\.gradle\caches\",
    r"\.m2\repository\",
    r"\__pycache__\",
    r"\appdata\local\programs\", // per-user app installs (VS Code, etc.)
];

/// A directory is low-signal if it lives inside the process's own install
/// tree or inside any known read-only library/cache tree. `parent_lower`
/// is expected already lowercased (as `parent_dir` returns).
fn is_low_signal_dir(parent_lower: &str, own_install: Option<&str>) -> bool {
    if let Some(prefix) = own_install {
        if parent_lower.starts_with(prefix) {
            return true;
        }
    }
    LOW_SIGNAL_MARKERS.iter().any(|m| parent_lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_trees_are_low_signal() {
        // The Pylance reindex from the false-positive report.
        assert!(is_low_signal_dir(
            r"c:\users\yago\.vscode\extensions\ms-python.vscode-pylance-2026.2.1\dist\typeshed-fallback\stubs\sympy",
            None,
        ));
        assert!(is_low_signal_dir(r"c:\proj\node_modules\react\lib", None));
        assert!(is_low_signal_dir(r"c:\proj\.venv\lib\site-packages\numpy", None));
    }

    #[test]
    fn own_install_tree_is_low_signal() {
        let install = Some(r"c:\users\yago\appdata\local\programs\microsoft vs code");
        assert!(is_low_signal_dir(
            r"c:\users\yago\appdata\local\programs\microsoft vs code\resources\app\out",
            install,
        ));
    }

    #[test]
    fn user_data_dirs_are_high_signal() {
        assert!(!is_low_signal_dir(r"c:\users\yago\documents\taxes", None));
        assert!(!is_low_signal_dir(r"c:\users\yago\pictures\2026", None));
        assert!(!is_low_signal_dir(r"d:\work\contracts", None));
    }
}
