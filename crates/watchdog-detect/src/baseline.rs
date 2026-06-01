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
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Minimum samples before a profile is trusted enough to suppress its
/// detector alerts.
pub const LEARN_SAMPLES: u64 = 5;

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
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BaselineData {
    profiles: HashMap<String, ImageProfile>,
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
