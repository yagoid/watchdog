//! Higher-level grouping of `ScoredEvent`s into "incidents" — the unit
//! a non-analyst user actually reads.
//!
//! An incident is "one process did this concerning thing, possibly
//! repeatedly, in a coherent stretch of time". 47 file events caught
//! by `RapidFileTraversal` become *one* incident, not 47 alerts. A
//! brand-new connection from `brave.exe` and an unsigned `.exe` from
//! `%TEMP%` stay as separate incidents because they're independent
//! concerns.
//!
//! Aggregation key: `(process image name, primary detector)` within
//! `MERGE_WINDOW`. The "primary" detector is the highest-scoring
//! reason on the event — usually only one fires, but combos do happen.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use watchdog_core::{ScoredEvent, Severity};

/// Coalesce events into the same incident if they share image+detector
/// and the last event is less than this old.
const MERGE_WINDOW: Duration = Duration::from_secs(180);

/// We don't need infinite history; older incidents drop off the back.
const MAX_INCIDENTS: usize = 200;

/// What we treat as "active threat happened recently enough to alarm
/// the user". Used by the verdict.
const RECENT_THREAT_WINDOW: Duration = Duration::from_secs(300);

/// Minimum score to even *create* an incident. Anything below this is
/// just routine noise and stays in the raw feed.
const INCIDENT_THRESHOLD: f32 = 0.30;

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: u64,
    pub process_image: String,
    pub detector: &'static str,
    pub max_severity: Severity,
    pub max_score: f32,
    pub event_count: u32,
    pub first_seen_wall: SystemTime,
    pub last_seen_wall: SystemTime,
    pub last_seen: Instant,
    pub headline: String,
    pub body: String,
    /// Last `ScoredEvent` sequence number this incident absorbed, for
    /// the "jump to raw events" cross-link later.
    pub last_event_seq: u64,
}

/// Current overall state — drives the colour bar at the top of the
/// Summary view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing scored above noise floor recently.
    Calm,
    /// At least one open incident, but none critical-recent.
    Review,
    /// CRIT-severity incident within `RECENT_THREAT_WINDOW`.
    Threat,
}

#[derive(Debug, Default)]
pub struct Incidents {
    list: VecDeque<Incident>,
    next_id: u64,
}

impl Incidents {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a scored event in; returns `true` if it created or extended
    /// an incident, `false` if it was below the threshold.
    pub fn ingest(&mut self, ev: &ScoredEvent, seq: u64) -> bool {
        if ev.score < INCIDENT_THRESHOLD {
            return false;
        }
        let image = match ev.enriched.process.as_ref() {
            Some(p) => p.image_name.clone(),
            None => return false, // can't anchor an incident on an unknown process
        };
        let primary_detector: &'static str = ev
            .reasons
            .first()
            .map(|r| r.detector)
            .unwrap_or("Unknown");

        let now = Instant::now();
        // Newest first; walk backwards. We only merge into the most
        // recent matching one.
        for inc in self.list.iter_mut().rev() {
            if inc.process_image == image
                && inc.detector == primary_detector
                && now.duration_since(inc.last_seen) < MERGE_WINDOW
            {
                inc.event_count += 1;
                inc.last_seen_wall = ev.enriched.raw.ts;
                inc.last_seen = now;
                inc.last_event_seq = seq;
                if ev.severity > inc.max_severity {
                    inc.max_severity = ev.severity;
                    inc.max_score = ev.score;
                    let (headline, body) = humanize(primary_detector, ev);
                    inc.headline = headline;
                    inc.body = body;
                }
                return true;
            }
        }

        // Brand-new incident.
        let (headline, body) = humanize(primary_detector, ev);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.list.push_back(Incident {
            id,
            process_image: image,
            detector: primary_detector,
            max_severity: ev.severity,
            max_score: ev.score,
            event_count: 1,
            first_seen_wall: ev.enriched.raw.ts,
            last_seen_wall: ev.enriched.raw.ts,
            last_seen: now,
            headline,
            body,
            last_event_seq: seq,
        });
        while self.list.len() > MAX_INCIDENTS {
            self.list.pop_front();
        }
        true
    }

    /// Newest-first iterator for the UI.
    pub fn iter_newest(&self) -> impl Iterator<Item = &Incident> {
        self.list.iter().rev()
    }

    /// `(open_count, last_alert_instant)`. "Open" today means
    /// everything in the list — we haven't implemented dismiss yet.
    pub fn summary(&self) -> (usize, Option<Instant>) {
        let last = self.list.back().map(|i| i.last_seen);
        (self.list.len(), last)
    }

    /// Decide the headline verdict for the summary bar.
    pub fn verdict(&self) -> Verdict {
        let now = Instant::now();
        let recent_crit = self
            .list
            .iter()
            .rev()
            .any(|i| i.max_severity == Severity::Crit && now.duration_since(i.last_seen) < RECENT_THREAT_WINDOW);
        if recent_crit {
            return Verdict::Threat;
        }
        if self.list.is_empty() {
            Verdict::Calm
        } else {
            Verdict::Review
        }
    }
}

// ---------------------------------------------------------------------------
// Plain-language translation per detector.
// ---------------------------------------------------------------------------

fn humanize(detector: &str, ev: &ScoredEvent) -> (String, String) {
    let image = ev
        .enriched
        .process
        .as_ref()
        .map(|p| p.image_name.as_str())
        .unwrap_or("<unknown>");
    let parent = ev
        .enriched
        .parent
        .as_ref()
        .map(|p| p.image_name.as_str())
        .unwrap_or("?");

    match detector {
        "LolbinSpawn" => (
            format!("{image} ran with abuse-pattern arguments"),
            "A built-in Windows program was used in a way that's more common in malware than in normal use \
             (encoded PowerShell, downloading via certutil, scripted MSHTA, etc.). If you didn't start it \
             yourself, this is worth investigating.".into(),
        ),
        "UnusualParentChild" => (
            format!("{parent} launched {image}"),
            "This parent → child chain is rarely benign on a normal machine. It commonly appears when a \
             malicious document, email attachment or browser exploit takes over a regular application and \
             pivots into a shell or scripting host.".into(),
        ),
        "RegistryPersistence" => (
            format!("{image} wrote an autostart registry key"),
            "Wrote to a registry location that makes a program run on every boot or login. Legitimate \
             installers do this; so does malware that wants to survive reboot. Check whether you just \
             installed something that explains it.".into(),
        ),
        "RapidFileTraversal" => (
            format!("{image} touched many folders very quickly"),
            "Accessed dozens of distinct directories in seconds. This pattern matches ransomware enumerating \
             your files and bulk exfiltration. Backup tools, search indexers and antivirus also do this, but \
             we suppress those that match your baseline.".into(),
        ),
        "UnsignedFromUserPath" => (
            format!("{image} ran without a valid signature from a user folder"),
            "Started from a place any user can write (Temp / Downloads / Desktop / Recycle Bin) without a \
             valid Authenticode signature. This is the classic shape of downloaded malware.".into(),
        ),
        "NewNetworkEgress" => (
            format!("{image} reached the internet for the first time"),
            "This program had never made an outbound connection before, and it just did. Could be a \
             legitimate update check the first time you ran it — or a previously-silent program now \
             phoning home.".into(),
        ),
        "DnsAnomaly" => (
            format!("{image} queried a suspicious-looking domain"),
            "The hostname matched two or more patterns associated with malware (random-looking subdomain, \
             abused TLD, very long label). Common shape for domain-generation-algorithm-based malware.".into(),
        ),
        "UsbExfilHint" => (
            format!("{image} wrote files to a just-mounted drive"),
            "A removable drive (USB / SD / mounted ISO) was plugged in, and shortly after this program \
             wrote many files to it. Matches data exfiltration to portable media.".into(),
        ),
        other => (
            format!("{image} triggered {other}"),
            "Detector fired with no plain-language description registered yet.".into(),
        ),
    }
}

/// Render a `Duration` as "hace 3 min", "hace 45 s", "hace 2 h".
pub fn pretty_ago(elapsed: Duration) -> String {
    let s = elapsed.as_secs();
    if s < 60 {
        format!("hace {s} s")
    } else if s < 3600 {
        format!("hace {} min", s / 60)
    } else {
        format!("hace {} h", s / 3600)
    }
}
