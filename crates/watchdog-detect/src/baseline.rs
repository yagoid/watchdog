//! Per-image behavioural baseline, learned at runtime, persisted to disk.
//!
//! The baseline lives in memory as a `HashMap<image_name, ImageProfile>`,
//! protected by one `Mutex`. Two stages talk to it: the `Scorer`'s
//! observe pass feeds it process-spawn pairs, and `RapidFileTraversal`
//! both reports its window samples and queries the learned ceiling.
//!
//! LOLBins are excluded from learning by design — an attacker should not
//! be able to "train" the system to ignore them by doing the same
//! malicious thing many times in a row. Their suspiciousness is
//! structural, not behavioural.
//!
//! Persistence: serialized with bincode 1.x (serde-compatible) into
//! `%ProgramData%\Watchdog\baseline.bin`. The save thread runs every
//! five minutes; the final save happens on graceful shutdown. ACLs are
//! inherited from `%ProgramData%`, so only Administrators / SYSTEM can
//! tamper with the file by default.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use chrono::{DateTime, Datelike, Local, Timelike};
use serde::{Deserialize, Serialize};

/// Minimum samples before a profile is trusted enough to suppress its
/// detector alerts.
pub const LEARN_SAMPLES: u64 = 5;

/// Once an image's distinct-destination set passes this size we treat it
/// as a chatty client (browser, updater, CDN consumer) we can't usefully
/// baseline, stop tracking, and never raise `RareDestination` for it.
pub const DEST_PREFIX_CAP: usize = 32;

/// Per-day multiplicative decay applied to the host activity histogram so
/// it tracks a moving notion of "usual hours" (~23-day half-life).
const HOST_DECAY_PER_DAY: f64 = 0.97;
/// Distinct days of observation before the host profile will judge an
/// hour as off-hours.
const HOST_MIN_DAYS: u64 = 5;
/// Minimum total (decayed) activity before judging — guards against a
/// histogram with too few samples to be meaningful.
const HOST_MIN_TOTAL: f64 = 100.0;
/// An hour is "off-hours" when its share of activity is below this
/// fraction of a flat-average hour (total / 24).
const OFF_HOUR_FRACTION: f64 = 0.20;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ImageProfile {
    pub samples: u64,
    pub parents_seen: HashSet<String>,
    pub children_seen: HashSet<String>,
    /// Peak distinct-directories-in-window count we've ever observed
    /// for this image (`RapidFileTraversal` window).
    pub max_file_traversal_in_window: usize,
    /// `true` once we've ever seen this image make an outbound TCP
    /// connection. `NewNetworkEgress` uses it to fire on the *first*
    /// observed connection of an otherwise-mature image.
    #[serde(default)]
    pub network_egress_observed: bool,
    /// Distinct remote destination prefixes (/24 v4, /48 v6) this image
    /// has been seen contacting. Used by `RareDestination`. Capped at
    /// `DEST_PREFIX_CAP`; see `dest_chatty`.
    #[serde(default)]
    pub dest_prefixes: HashSet<String>,
    /// Set once the destination set overflowed the cap: the image talks
    /// to too many endpoints to baseline, so we stop tracking it.
    #[serde(default)]
    pub dest_chatty: bool,
}

/// Machine-wide activity profile: a decayed histogram of process-start
/// activity by hour-of-day (local time), feeding `OffHoursActivity`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct HostProfile {
    hourly: [f64; 24],
    total: f64,
    days_observed: u64,
    /// Proleptic-Gregorian day number of the last observation, for
    /// applying per-day decay. Zero means "never observed" (the real day
    /// number for the current era is ~738000, so zero is a safe sentinel).
    last_day: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BaselineData {
    profiles: HashMap<String, ImageProfile>,
    #[serde(default)]
    host: HostProfile,
}

/// Local hour-of-day `[0,24)` and proleptic-Gregorian day number for an
/// event timestamp. Shared by the scorer (recording) and the
/// `OffHoursActivity` detector (judging).
pub(crate) fn hour_and_day(ts: SystemTime) -> (usize, i64) {
    let dt: DateTime<Local> = ts.into();
    (dt.hour() as usize, dt.num_days_from_ce() as i64)
}

pub struct Baseline {
    data: Mutex<BaselineData>,
    excluded: HashSet<String>,
    /// Timestamp of the last successful `save_to_disk`. Exposed for
    /// the UI's "watchdog health" panel.
    last_saved: Mutex<Option<Instant>>,
}

impl Baseline {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(BaselineData::default()),
            excluded: lolbin_set(),
            last_saved: Mutex::new(None),
        }
    }

    /// Try to load a previously-saved baseline; if anything goes wrong
    /// (file missing, corrupt, schema change) return an empty one.
    pub fn load_or_new() -> Self {
        let base = Self::new();
        if let Some(path) = baseline_path() {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(data) = bincode::deserialize::<BaselineData>(&bytes) {
                    *base.data.lock().unwrap() = data;
                }
            }
        }
        base
    }

    /// Note a parent → child spawn relationship.
    pub fn observe_process_start(&self, image: &str, parent: Option<&str>) {
        if self.excluded.contains(image) {
            return;
        }
        let mut data = self.data.lock().unwrap();
        let profile = data.profiles.entry(image.to_string()).or_default();
        profile.samples += 1;
        if let Some(p) = parent {
            profile.parents_seen.insert(p.to_string());
        }
        if let Some(p) = parent {
            // Also tag the parent's children_seen, but only if the parent
            // itself isn't an excluded LOLBin (we don't want to learn
            // what powershell "normally" spawns).
            if !self.excluded.contains(p) {
                let parent_profile = data.profiles.entry(p.to_string()).or_default();
                parent_profile.children_seen.insert(image.to_string());
            }
        }
    }

    /// Note the final count of a `RapidFileTraversal` window for an image.
    pub fn observe_file_traversal_window(&self, image: &str, count: usize) {
        if self.excluded.contains(image) || count == 0 {
            return;
        }
        let mut data = self.data.lock().unwrap();
        let profile = data.profiles.entry(image.to_string()).or_default();
        profile.samples += 1;
        if count > profile.max_file_traversal_in_window {
            profile.max_file_traversal_in_window = count;
        }
    }

    pub fn is_excluded(&self, image: &str) -> bool {
        self.excluded.contains(image)
    }

    pub fn is_mature_for(&self, image: &str) -> bool {
        if self.excluded.contains(image) {
            return false;
        }
        let data = self.data.lock().unwrap();
        data.profiles
            .get(image)
            .map_or(false, |p| p.samples >= LEARN_SAMPLES)
    }

    pub fn typical_traversal_max(&self, image: &str) -> Option<usize> {
        let data = self.data.lock().unwrap();
        data.profiles
            .get(image)
            .map(|p| p.max_file_traversal_in_window)
    }

    /// `true` if we've ever observed this image make an outbound TCP
    /// connection.
    pub fn has_network_egress(&self, image: &str) -> bool {
        let data = self.data.lock().unwrap();
        data.profiles
            .get(image)
            .map_or(false, |p| p.network_egress_observed)
    }

    /// Record that this image just made an outbound connection. Returns
    /// the previous state so the caller can decide whether to alert.
    pub fn observe_network_egress(&self, image: &str) -> bool {
        if self.excluded.contains(image) {
            return true; // pretend it's known; we never alert on LOLBins anyway
        }
        let mut data = self.data.lock().unwrap();
        let profile = data.profiles.entry(image.to_string()).or_default();
        let was = profile.network_egress_observed;
        profile.network_egress_observed = true;
        was
    }

    /// Record a destination prefix for an image and report whether it is
    /// a genuinely *rare* one worth alerting on. "Rare" means: the image
    /// is mature, not chatty, already has an established destination
    /// history, and this prefix is new to it. The image's very first
    /// destination is `NewNetworkEgress`'s job, not ours, so a first-ever
    /// prefix returns `false`.
    pub fn observe_destination(&self, image: &str, prefix: &str) -> bool {
        if self.excluded.contains(image) {
            return false;
        }
        let mut data = self.data.lock().unwrap();
        let profile = data.profiles.entry(image.to_string()).or_default();
        if profile.dest_chatty {
            return false;
        }
        let mature = profile.samples >= LEARN_SAMPLES;
        let had_history = !profile.dest_prefixes.is_empty();
        let is_new = profile.dest_prefixes.insert(prefix.to_string());
        if profile.dest_prefixes.len() > DEST_PREFIX_CAP {
            // Too many endpoints to baseline: stop tracking and free the set.
            profile.dest_chatty = true;
            profile.dest_prefixes.clear();
            return false;
        }
        is_new && had_history && mature
    }

    /// Fold one unit of interactive activity into the host's hour-of-day
    /// histogram, applying per-day decay when the calendar day advances.
    pub fn observe_host_activity(&self, hour: usize, day: i64) {
        if hour >= 24 {
            return;
        }
        let mut data = self.data.lock().unwrap();
        let h = &mut data.host;
        if h.last_day == 0 {
            h.last_day = day;
            h.days_observed = 1;
        } else if day > h.last_day {
            // Decay every bucket once per elapsed day. Cap the exponent so
            // a long idle gap can't spin (and can't underflow to nonsense).
            let elapsed = (day - h.last_day).clamp(1, 365) as i32;
            let factor = HOST_DECAY_PER_DAY.powi(elapsed);
            for b in h.hourly.iter_mut() {
                *b *= factor;
            }
            h.total *= factor;
            h.last_day = day;
            h.days_observed += 1;
        }
        h.hourly[hour] += 1.0;
        h.total += 1.0;
    }

    /// Whether `hour` is a historically-quiet hour for this host. `None`
    /// while the profile is too young to judge — callers must treat that
    /// as "no opinion", never as "off-hours".
    pub fn is_off_hour(&self, hour: usize) -> Option<bool> {
        if hour >= 24 {
            return None;
        }
        let data = self.data.lock().unwrap();
        let h = &data.host;
        if h.days_observed < HOST_MIN_DAYS || h.total < HOST_MIN_TOTAL {
            return None;
        }
        let avg = h.total / 24.0;
        Some(h.hourly[hour] < avg * OFF_HOUR_FRACTION)
    }

    /// Number of distinct images seen and number of them mature, for
    /// the UI's learning-progress indicator.
    pub fn stats(&self) -> (usize, usize) {
        let data = self.data.lock().unwrap();
        let total = data.profiles.len();
        let mature = data
            .profiles
            .values()
            .filter(|p| p.samples >= LEARN_SAMPLES)
            .count();
        (mature, total)
    }

    /// Atomically write the baseline to disk.
    pub fn save_to_disk(&self) -> std::io::Result<()> {
        let Some(path) = baseline_path() else { return Ok(()) };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = {
            let data = self.data.lock().unwrap();
            bincode::serialize(&*data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        };
        // Write to a temp file then rename so a crash mid-write can't
        // leave the baseline corrupted.
        let tmp = path.with_extension("bin.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)?;
        // Record successful save so the UI can show "saved Xs ago".
        *self.last_saved.lock().unwrap() = Some(Instant::now());
        Ok(())
    }

    /// Most recent successful `save_to_disk`, or `None` if we haven't
    /// saved this session yet (typical right after process start).
    pub fn last_saved(&self) -> Option<Instant> {
        *self.last_saved.lock().unwrap()
    }
}

impl Default for Baseline {
    fn default() -> Self { Self::new() }
}

/// Same LOLBin list as `LolbinSpawn`; ideally we'd share it but the
/// crates are wired so that pulling it from the detector module is
/// awkward. The cost of one duplicated constant is acceptable for now.
fn lolbin_set() -> HashSet<String> {
    [
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "wmic.exe", "installutil.exe", "msbuild.exe",
        "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe",
        "forfiles.exe", "hh.exe", "msdt.exe", "regedit.exe", "regini.exe",
        "ftp.exe",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn baseline_path() -> Option<PathBuf> {
    let pd = std::env::var("ProgramData").ok()?;
    Some(PathBuf::from(pd).join("Watchdog").join("baseline.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_hour_undecided_until_mature() {
        let b = Baseline::new();
        // A single busy day: not enough distinct days to judge.
        for hour in 9..18 {
            for _ in 0..20 {
                b.observe_host_activity(hour, 738000);
            }
        }
        assert_eq!(b.is_off_hour(3), None);
        assert_eq!(b.is_off_hour(13), None);
    }

    #[test]
    fn learns_daytime_shape_and_flags_night() {
        let b = Baseline::new();
        // Six distinct days of activity concentrated in 09:00–17:59.
        for day in 0..6 {
            for hour in 9..18 {
                for _ in 0..3 {
                    b.observe_host_activity(hour, 738000 + day);
                }
            }
        }
        // Mature now (>=5 days, >=100 total).
        assert_eq!(b.is_off_hour(3), Some(true), "03:00 is never active -> off-hours");
        assert_eq!(b.is_off_hour(13), Some(false), "13:00 is a usual active hour");
    }

    #[test]
    fn chatty_image_stops_tracking_destinations() {
        let b = Baseline::new();
        for _ in 0..LEARN_SAMPLES {
            b.observe_process_start("svc.exe", Some("services.exe"));
        }
        // First destination establishes history (no alert).
        assert!(!b.observe_destination("svc.exe", "10.0.0.0/24"));
        // Push past the cap with distinct prefixes.
        for i in 0..=DEST_PREFIX_CAP as u32 {
            b.observe_destination("svc.exe", &format!("203.0.{i}.0/24"));
        }
        // Now marked chatty: even a brand-new prefix no longer fires.
        assert!(!b.observe_destination("svc.exe", "198.51.100.0/24"));
    }

    #[test]
    fn lolbin_destinations_never_alert() {
        let b = Baseline::new();
        // powershell is excluded; even with history + a new prefix, silent.
        assert!(!b.observe_destination("powershell.exe", "10.0.0.0/24"));
        assert!(!b.observe_destination("powershell.exe", "203.0.113.0/24"));
    }
}
