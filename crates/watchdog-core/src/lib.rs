//! Shared types that travel along the watchdog pipeline.
//!
//! Stages depend on this crate. Its only deps are `serde_json` + `chrono`
//! (both cross-platform), so it still builds on any platform — useful for
//! tests. The JSONL serialization lives here, not in a front-end, because
//! two consumers now need it: the TUI's export and the service's incident
//! sink.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource {
    Process,
    File,
    Network,
    Registry,
    Dns,
    Usb,
    Wmi,
}

#[derive(Debug, Clone)]
pub enum EventPayload {
    ProcessStart {
        ppid: u32,
        image: String,   // native form as delivered by ETW (\Device\HarddiskVolumeN\…)
        cmdline: String, // may be empty — Kernel-Process event 1 doesn't carry it
        session_id: u32,
    },
    ProcessStop {
        exit_code: u32,
        image: String,
    },
    ImageLoad {
        image: String,
        base: u64,
        size: u64,
    },
    /// `CreateFile` from Microsoft-Windows-Kernel-File. `path` is rewritten
    /// to DOS form (`C:\…`) by the enrichment stage when possible.
    FileCreate {
        path: String,
    },
    /// First write to an open file handle, from Microsoft-Windows-Kernel-File
    /// `Write` (event 16). The Write event carries only a `FileObject`
    /// handle, not a name, so the path is resolved by the provider against
    /// the `FileObject`→name map it builds from `Create` events, then
    /// canonicalized to DOS form by the enrichment stage. Emitted once per
    /// handle (first write) so a chunked write doesn't flood the pipeline.
    /// This is the *write*-intent signal `EntropyBurst` needs — `Create`
    /// alone can't tell a reader (indexer, AV) from a writer.
    FileWrite {
        path: String,
    },
    /// `SetValueKey` from Microsoft-Windows-Kernel-Registry. NT form
    /// (`\REGISTRY\MACHINE\…` or `\REGISTRY\USER\<sid>\…`).
    RegistrySetValue {
        key_name: String,
        value_name: String,
    },
    /// Outbound TCP connect from `Microsoft-Windows-Kernel-Network`
    /// (opcode 12, covering both IPv4 event 12 and IPv6 event 28). We
    /// carry both endpoints because the local side is the key that
    /// resolves PID 4 (System) attributions to the real owning process
    /// via `GetExtendedTcpTable` in the enrichment stage.
    NetworkConnect {
        local_ip: std::net::IpAddr,
        local_port: u16,
        remote_ip: std::net::IpAddr,
        remote_port: u16,
    },
    /// `DnsQueryStop` from `Microsoft-Windows-DNS-Client` (event 3008).
    /// `query_type` is the DNS RR type code (1 = A, 28 = AAAA, …).
    /// `results` is the kernel's textual rendering of the answer; we
    /// leave it unparsed because it's only ever shown to a human.
    DnsQuery {
        name: String,
        query_type: u32,
        status: u32,
        results: String,
    },
    /// Synthetic event: a drive letter that wasn't present at watchdog
    /// start has just appeared. Emitted by the enrichment crate's
    /// `DriveWatcher` background thread when its periodic poll of
    /// `QueryDosDevice` finds a new mount. Captures USB sticks, SD
    /// cards, mounted VHDs, fresh network drives — anything that gets
    /// a drive letter at runtime.
    RemovableDriveMounted {
        drive_letter: char,
    },
    /// Placeholder for events we ingest but haven't structured yet.
    Other {
        event_id: u16,
    },
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub ts: SystemTime,
    pub src: EventSource,
    pub pid: u32,
    pub tid: u32,
    pub payload: EventPayload,
}

/// Everything we know about a process while it is alive (or recently dead).
/// Shared via `Arc` so multiple events can refer to the same record cheaply.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub session_id: u32,
    pub image_path: PathBuf, // canonicalized to C:\… when possible
    pub image_name: String,  // basename, lowercase
    pub cmdline: String,     // best-effort, may be empty
    pub started_at: SystemTime,
}

/// A raw event annotated with everything the enrichment stage could resolve.
#[derive(Debug, Clone)]
pub struct EnrichedEvent {
    pub raw: RawEvent,
    pub process: Option<Arc<ProcessInfo>>,
    pub parent: Option<Arc<ProcessInfo>>,
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Severity buckets derived from a combined score. Boundaries match the
/// plan: `INFO` 0.30–0.40, `WARN` 0.40–0.70, `CRIT` ≥0.70. Anything below
/// 0.30 is considered noise and labelled `Quiet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Quiet,
    Info,
    Warn,
    Crit,
}

impl Severity {
    pub fn from_score(score: f32) -> Self {
        if score >= 0.70 {
            Severity::Crit
        } else if score >= 0.40 {
            Severity::Warn
        } else if score >= 0.30 {
            Severity::Info
        } else {
            Severity::Quiet
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Crit  => "CRIT",
            Severity::Warn  => "WARN",
            Severity::Info  => "INFO",
            Severity::Quiet => "----",
        }
    }
}

/// One detector's verdict on one event. `sub_score` is in [0.0, 1.0] and
/// is independent of other detectors' verdicts; the `Scorer` combines
/// them probabilistically.
#[derive(Debug, Clone)]
pub struct ScoreReason {
    pub detector: &'static str,
    pub sub_score: f32,
    pub explanation: String,
}

/// An enriched event after the detection stage. `score = 0.0` and
/// `reasons.is_empty()` means no detector fired.
#[derive(Debug, Clone)]
pub struct ScoredEvent {
    pub enriched: EnrichedEvent,
    pub score: f32,
    pub severity: Severity,
    pub reasons: Vec<ScoreReason>,
}

// ---------------------------------------------------------------------------
// JSONL serialization
// ---------------------------------------------------------------------------
//
// One event per line, each line a self-contained JSON object — the format
// `jq` and friends expect. We don't `#[derive(Serialize)]` on these types:
// the on-disk schema is deliberately decoupled from the in-memory layout, so
// this mapping is hand-written and owns the schema for every consumer.

use chrono::{DateTime, Local};
use serde_json::{json, Map, Value};

/// Map one scored event to its JSONL object. Used by the TUI feed export and
/// the service's incident sink alike.
pub fn scored_event_to_json(ev: &ScoredEvent) -> Value {
    let raw = &ev.enriched.raw;
    json!({
        "ts":       format_ts(raw.ts),
        "pid":      raw.pid,
        "severity": ev.severity.label(),
        "score":    ev.score,
        "source":   source_label(raw.src),
        "process":  ev.enriched.process.as_ref().map(|p| json!({
            "image_path": p.image_path.display().to_string(),
            "image_name": p.image_name,
            "cmdline":    p.cmdline,
            "ppid":       p.ppid,
            "session_id": p.session_id,
        })),
        "parent":   ev.enriched.parent.as_ref().map(|p| json!({
            "image_path": p.image_path.display().to_string(),
            "image_name": p.image_name,
        })),
        "payload":  payload_json(&raw.payload),
        "reasons":  ev.reasons.iter().map(|r| json!({
            "detector":    r.detector,
            "sub_score":   r.sub_score,
            "explanation": r.explanation,
        })).collect::<Vec<_>>(),
    })
}

fn payload_json(p: &EventPayload) -> Value {
    let mut m = Map::new();
    match p {
        EventPayload::ProcessStart { ppid, image, cmdline, session_id } => {
            m.insert("kind".into(),       "ProcessStart".into());
            m.insert("ppid".into(),       (*ppid).into());
            m.insert("image".into(),      image.clone().into());
            m.insert("cmdline".into(),    cmdline.clone().into());
            m.insert("session_id".into(), (*session_id).into());
        }
        EventPayload::ProcessStop { exit_code, image } => {
            m.insert("kind".into(),      "ProcessStop".into());
            m.insert("exit_code".into(), (*exit_code).into());
            m.insert("image".into(),     image.clone().into());
        }
        EventPayload::ImageLoad { image, base, size } => {
            m.insert("kind".into(),  "ImageLoad".into());
            m.insert("image".into(), image.clone().into());
            m.insert("base".into(),  (*base).into());
            m.insert("size".into(),  (*size).into());
        }
        EventPayload::FileCreate { path } => {
            m.insert("kind".into(), "FileCreate".into());
            m.insert("path".into(), path.clone().into());
        }
        EventPayload::FileWrite { path } => {
            m.insert("kind".into(), "FileWrite".into());
            m.insert("path".into(), path.clone().into());
        }
        EventPayload::RegistrySetValue { key_name, value_name } => {
            m.insert("kind".into(),       "RegistrySetValue".into());
            m.insert("key_name".into(),   key_name.clone().into());
            m.insert("value_name".into(), value_name.clone().into());
        }
        EventPayload::NetworkConnect { local_ip, local_port, remote_ip, remote_port } => {
            m.insert("kind".into(),        "NetworkConnect".into());
            m.insert("local_ip".into(),    local_ip.to_string().into());
            m.insert("local_port".into(),  (*local_port).into());
            m.insert("remote_ip".into(),   remote_ip.to_string().into());
            m.insert("remote_port".into(), (*remote_port).into());
        }
        EventPayload::DnsQuery { name, query_type, status, results } => {
            m.insert("kind".into(),       "DnsQuery".into());
            m.insert("name".into(),       name.clone().into());
            m.insert("query_type".into(), (*query_type).into());
            m.insert("status".into(),     (*status).into());
            m.insert("results".into(),    results.clone().into());
        }
        EventPayload::RemovableDriveMounted { drive_letter } => {
            m.insert("kind".into(),         "RemovableDriveMounted".into());
            m.insert("drive_letter".into(), drive_letter.to_string().into());
        }
        EventPayload::Other { event_id } => {
            m.insert("kind".into(),     "Other".into());
            m.insert("event_id".into(), (*event_id).into());
        }
    }
    Value::Object(m)
}

fn source_label(s: EventSource) -> &'static str {
    match s {
        EventSource::Process  => "Process",
        EventSource::File     => "File",
        EventSource::Network  => "Network",
        EventSource::Registry => "Registry",
        EventSource::Dns      => "Dns",
        EventSource::Usb      => "Usb",
        EventSource::Wmi      => "Wmi",
    }
}

fn format_ts(ts: SystemTime) -> String {
    let dt: DateTime<Local> = ts.into();
    dt.format("%Y-%m-%dT%H:%M:%S%.3f%z").to_string()
}
