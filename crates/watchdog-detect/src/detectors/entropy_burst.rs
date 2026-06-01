//! A process writing many *high-entropy* files in a short window — the
//! in-the-act fingerprint of ransomware encrypting user data.
//!
//! `RapidFileTraversal` already catches "one process touches many
//! directories fast". This is its content-aware complement: it asks
//! whether the files being written look *encrypted*. Encrypted (or
//! compressed) data is statistically near-random — Shannon entropy close
//! to the 8.0 bits/byte ceiling — whereas documents, code, and config
//! sit well below. A burst of near-random writes from one process is a
//! strong "encryption underway" signal.
//!
//! Cost control, because ETW `FileCreate` carries no content and we must
//! read the file ourselves:
//!   * A **velocity gate** — we only start sampling once a PID has created
//!     several files in the window. Normal single-file saves never read.
//!   * An **extension denylist** — formats that are *inherently* high
//!     entropy (archives, media, Office/PDF which are zip containers) are
//!     skipped, so saving a JPEG or a .docx doesn't look like encryption.
//!   * We read only the first 4 KiB, outside the state lock.
//! (Synchronous file I/O on the scorer thread is already precedent here —
//! `UnsignedFromUserPath` calls `WinVerifyTrust`, which reads the file.)
//!
//! Limitations worth knowing: we read at the file-*create* event, so a
//! brand-new file not yet written reads as empty and is skipped; a file
//! held with an exclusive write lock can't be opened. Neither is fatal —
//! ransomware churns through enough files that the count still ramps, and
//! `RapidFileTraversal` covers the traversal shape regardless. In-place
//! encryption that keeps an inherently-high-entropy extension (e.g. a
//! `.docx` rewritten in place) is intentionally not counted, trading that
//! miss for far fewer false positives on normal media/Office activity.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use watchdog_core::{EnrichedEvent, EventPayload, ScoreReason};
use watchdog_enrich::ProcessTable;

use crate::detector::Detector;

const WINDOW: Duration = Duration::from_secs(10);
/// Files a PID must create in the window before we begin paying the read
/// cost — a single save is never enough to look like mass encryption.
const READ_PRECONDITION: usize = 5;
/// Distinct high-entropy files in the window before we alert.
const HIGH_ENTROPY_TRIGGER: usize = 6;
/// Count at which the score saturates.
const SATURATION: usize = 30;
/// Shannon entropy (bits/byte, max 8.0) at or above which a sample looks
/// encrypted/compressed rather than structured.
const ENTROPY_THRESHOLD: f64 = 7.8;
const SAMPLE_BYTES: usize = 4096;
/// Below this many bytes the entropy estimate is too noisy to trust.
const MIN_BYTES: usize = 512;

struct WindowState {
    window_start: Instant,
    total_creates: usize,
    high_entropy_paths: HashSet<String>,
    last_alert_count: usize,
}

impl WindowState {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            total_creates: 0,
            high_entropy_paths: HashSet::new(),
            last_alert_count: 0,
        }
    }
}

pub struct EntropyBurst {
    state: Mutex<HashMap<u32, WindowState>>,
}

impl EntropyBurst {
    pub fn new() -> Self {
        Self { state: Mutex::new(HashMap::new()) }
    }
}

impl Default for EntropyBurst {
    fn default() -> Self { Self::new() }
}

impl Detector for EntropyBurst {
    fn name(&self) -> &'static str { "EntropyBurst" }

    fn evaluate(&self, ev: &EnrichedEvent, _table: &ProcessTable) -> Option<ScoreReason> {
        let path = match &ev.raw.payload {
            // FileWrite (not FileCreate): we want write intent. A bulk
            // *reader* — search indexer, AV, backup — opens (Creates) many
            // high-entropy files but doesn't write them, and must not look
            // like encryption. Write events fire only for actual writers.
            EventPayload::FileWrite { path } => path,
            _ => return None,
        };
        // Cheapest rejections first, before any lock or I/O.
        if path.ends_with('\\') || path.ends_with('/') || is_compressed_ext(path) {
            return None;
        }
        let pid = ev.raw.pid;
        let now = Instant::now();

        // Phase 1: window bookkeeping under the lock; decide whether this
        // event is worth the read.
        let should_sample = {
            let mut map = self.state.lock().unwrap();
            let st = map.entry(pid).or_insert_with(|| WindowState::new(now));
            if now.duration_since(st.window_start) > WINDOW {
                *st = WindowState::new(now);
            }
            st.total_creates += 1;
            st.total_creates >= READ_PRECONDITION && !st.high_entropy_paths.contains(path)
        };
        if !should_sample {
            return None;
        }

        // Phase 2: read + entropy, outside the lock.
        let entropy = sample_entropy(path)?;
        if entropy < ENTROPY_THRESHOLD {
            return None;
        }

        // Phase 3: record the high-entropy file and decide whether to emit.
        let (count, emit) = {
            let mut map = self.state.lock().unwrap();
            let st = map.entry(pid).or_insert_with(|| WindowState::new(now));
            st.high_entropy_paths.insert(path.clone());
            let count = st.high_entropy_paths.len();
            // Emit on first crossing, then only every +3 to avoid a row per file.
            let emit = count >= HIGH_ENTROPY_TRIGGER
                && count != st.last_alert_count
                && (st.last_alert_count == 0 || count >= st.last_alert_count + 3);
            if emit {
                st.last_alert_count = count;
            }
            (count, emit)
        };
        if !emit {
            return None;
        }

        let image = ev
            .process
            .as_ref()
            .map(|p| p.image_name.clone())
            .unwrap_or_else(|| "unknown process".into());
        let span = (SATURATION - HIGH_ENTROPY_TRIGGER) as f32;
        let progress = ((count - HIGH_ENTROPY_TRIGGER) as f32 / span).clamp(0.0, 1.0);
        let sub_score = 0.40 + 0.45 * progress;

        Some(ScoreReason {
            detector: "EntropyBurst",
            sub_score,
            explanation: format!(
                "{image} wrote {count} high-entropy files in <{}s (possible mass encryption)",
                WINDOW.as_secs()
            ),
        })
    }
}

/// Shannon entropy of `data` in bits per byte (0.0–8.0).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Read the head of `path` and return its entropy, or `None` if the file
/// can't be opened (locked, gone) or is too small to judge.
fn sample_entropy(path: &str) -> Option<f64> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; SAMPLE_BYTES];
    let n = f.read(&mut buf).ok()?;
    if n < MIN_BYTES {
        return None;
    }
    Some(shannon_entropy(&buf[..n]))
}

/// True for extensions whose contents are *inherently* high entropy, so a
/// near-random sample is expected and not a sign of encryption.
fn is_compressed_ext(path: &str) -> bool {
    let name = path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(path);
    let ext = match name.rsplit_once('.') {
        Some((_, e)) => e.to_ascii_lowercase(),
        None => return false,
    };
    matches!(
        ext.as_str(),
        "zip" | "7z" | "rar" | "gz" | "bz2" | "xz" | "tar" | "tgz" | "cab" | "zst"
            | "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "heic"
            | "mp3" | "aac" | "flac" | "ogg" | "opus" | "wma"
            | "mp4" | "mkv" | "avi" | "mov" | "wmv" | "webm" | "m4v" | "flv"
            | "pdf" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub"
            | "apk" | "jar" | "iso" | "vhd" | "vhdx" | "dmg" | "msi"
            | "woff" | "woff2" | "crx" | "nupkg" | "whl"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::SystemTime;
    use watchdog_core::{EventSource, ProcessInfo, RawEvent};

    #[test]
    fn entropy_extremes() {
        assert!(shannon_entropy(&[0u8; 4096]) < 0.01, "all-same byte -> ~0");
        let uniform: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!(shannon_entropy(&uniform) > 7.99, "uniform bytes -> ~8.0");
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(50);
        assert!(shannon_entropy(&text) < 5.0, "english text -> low");
    }

    #[test]
    fn denylist_skips_inherently_random_formats() {
        assert!(is_compressed_ext(r"C:\Users\y\Pictures\photo.JPG"));
        assert!(is_compressed_ext(r"C:\Users\y\Documents\report.docx"));
        assert!(is_compressed_ext(r"C:\x\a.zip"));
        assert!(!is_compressed_ext(r"C:\Users\y\Documents\notes.txt"));
        assert!(!is_compressed_ext(r"C:\Users\y\Documents\data.locked"));
        assert!(!is_compressed_ext(r"C:\Users\y\Documents\noext"));
    }

    // Deterministic pseudo-random bytes (xorshift64) — high entropy.
    fn random_bytes(n: usize, mut x: u64) -> Vec<u8> {
        x |= 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x & 0xff) as u8
            })
            .collect()
    }

    fn file_write_event(pid: u32, path: &str) -> EnrichedEvent {
        let proc = Arc::new(ProcessInfo {
            pid,
            ppid: 4,
            session_id: 1,
            image_path: r"C:\Users\y\evil.exe".into(),
            image_name: "evil.exe".into(),
            cmdline: String::new(),
            started_at: SystemTime::now(),
        });
        EnrichedEvent {
            raw: RawEvent {
                ts: SystemTime::now(),
                src: EventSource::File,
                pid,
                tid: 0,
                payload: EventPayload::FileWrite { path: path.to_string() },
            },
            process: Some(proc),
            parent: None,
        }
    }

    #[test]
    fn fires_on_a_burst_of_high_entropy_files() {
        let dir = std::env::temp_dir().join(format!("wd-entropy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let det = EntropyBurst::new();
        let table = ProcessTable::new();
        let pid = 4242;

        // Warm the velocity gate with creates the detector won't read
        // (total < READ_PRECONDITION on the first few).
        for i in 0..READ_PRECONDITION {
            let p = dir.join(format!("warm{i}.dat"));
            std::fs::write(&p, b"plain warmup text that is short").unwrap();
            assert!(det.evaluate(&file_write_event(pid, p.to_str().unwrap()), &table).is_none());
        }

        // Now feed high-entropy files; one of these crossings must fire.
        let mut fired = false;
        for i in 0..HIGH_ENTROPY_TRIGGER + 2 {
            let p = dir.join(format!("enc{i}.bin"));
            std::fs::write(&p, random_bytes(SAMPLE_BYTES, 0x9e3779b97f4a7c15 ^ i as u64)).unwrap();
            if det.evaluate(&file_write_event(pid, p.to_str().unwrap()), &table).is_some() {
                fired = true;
            }
        }
        assert!(fired, "a burst of high-entropy files should raise EntropyBurst");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn low_entropy_burst_is_silent() {
        let dir = std::env::temp_dir().join(format!("wd-entropy-low-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let det = EntropyBurst::new();
        let table = ProcessTable::new();
        let pid = 5252;
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(200);

        let mut any = false;
        for i in 0..READ_PRECONDITION + HIGH_ENTROPY_TRIGGER + 5 {
            let p = dir.join(format!("doc{i}.txt"));
            std::fs::write(&p, &text).unwrap();
            if det.evaluate(&file_write_event(pid, p.to_str().unwrap()), &table).is_some() {
                any = true;
            }
        }
        assert!(!any, "structured text, however many files, must not trip EntropyBurst");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
