//! Durable incident sinks for the headless service: a size-rotated JSONL
//! file and the Windows Event Log. Where the TUI has a live screen, the
//! service has these.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use watchdog_core::{scored_event_to_json, ScoredEvent, Severity};

use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    REPORT_EVENT_TYPE,
};

use super::{data_dir, EVENT_SOURCE};

/// Roll the JSONL over once it passes this size, keeping a few generations.
const MAX_JSONL_BYTES: u64 = 10 * 1024 * 1024;
const JSONL_GENERATIONS: u32 = 3;

/// Arbitrary event ID. Without a message file the Event Viewer wraps this in
/// a "description not found" notice, but our inserted string still shows.
const EVENT_ID_CRIT: u32 = 1001;

pub struct IncidentSink {
    jsonl_path: PathBuf,
    writer: BufWriter<File>,
    bytes: u64,
    event_log: Option<EventLog>,
}

impl IncidentSink {
    pub fn open() -> Result<Self> {
        let dir = data_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating data dir {}", dir.display()))?;
        let jsonl_path = dir.join("incidents.jsonl");
        let (writer, bytes) = open_appending(&jsonl_path)?;
        Ok(Self {
            jsonl_path,
            writer,
            bytes,
            event_log: EventLog::open(),
        })
    }

    /// Record an above-threshold scored event. Warn+ goes to JSONL; Crit also
    /// raises a Windows Event Log entry. Below Warn is ignored (the caller
    /// already filters, this is a guard).
    pub fn record(&mut self, ev: &ScoredEvent) {
        if ev.severity < Severity::Warn {
            return;
        }
        self.write_jsonl(ev);
        // Only Crit reaches the Event Log; Warn lives in JSONL alone to keep
        // the Application log readable.
        if ev.severity == Severity::Crit {
            if let Some(log) = &self.event_log {
                log.report(EVENTLOG_ERROR_TYPE, EVENT_ID_CRIT, &summary(ev));
            }
        }
    }

    fn write_jsonl(&mut self, ev: &ScoredEvent) {
        let v = scored_event_to_json(ev);
        // Serialize to a String first so a single failed write can't leave a
        // half-line in the file.
        if let Ok(mut line) = serde_json::to_string(&v) {
            line.push('\n');
            if self.writer.write_all(line.as_bytes()).is_ok() {
                self.bytes += line.len() as u64;
            }
            if self.bytes >= MAX_JSONL_BYTES {
                self.rotate();
            }
        }
    }

    fn rotate(&mut self) {
        let _ = self.writer.flush();
        // incidents.jsonl.(N-1) -> .N, ..., incidents.jsonl -> .1
        for gen in (1..JSONL_GENERATIONS).rev() {
            let from = self.gen_path(gen);
            let to = self.gen_path(gen + 1);
            let _ = std::fs::rename(&from, &to);
        }
        let _ = std::fs::rename(&self.jsonl_path, self.gen_path(1));
        if let Ok((w, n)) = open_appending(&self.jsonl_path) {
            self.writer = w;
            self.bytes = n;
        }
    }

    fn gen_path(&self, gen: u32) -> PathBuf {
        let mut s = self.jsonl_path.clone().into_os_string();
        s.push(format!(".{gen}"));
        PathBuf::from(s)
    }

    pub fn flush(&mut self) {
        let _ = self.writer.flush();
    }
}

fn open_appending(path: &PathBuf) -> Result<(BufWriter<File>, u64)> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok((BufWriter::new(file), len))
}

/// One-line human summary for the Event Log entry.
fn summary(ev: &ScoredEvent) -> String {
    let proc = ev
        .enriched
        .process
        .as_ref()
        .map(|p| format!("{} (pid {})", p.image_name, p.pid))
        .unwrap_or_else(|| format!("pid {}", ev.enriched.raw.pid));
    let detectors: Vec<&str> = ev.reasons.iter().map(|r| r.detector).collect();
    format!(
        "[{} score={:.2}] {}: {}",
        ev.severity.label(),
        ev.score,
        proc,
        detectors.join(", ")
    )
}

/// Thin RAII wrapper over a registered Event Log source handle.
struct EventLog {
    handle: HANDLE,
}

impl EventLog {
    fn open() -> Option<Self> {
        let src = to_wide(EVENT_SOURCE);
        // SAFETY: null server = local machine; src is a valid NUL-terminated
        // wide string living for the duration of the call.
        let handle = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(src.as_ptr())) };
        match handle {
            Ok(h) if !h.is_invalid() => Some(Self { handle: h }),
            _ => None,
        }
    }

    fn report(&self, kind: REPORT_EVENT_TYPE, event_id: u32, message: &str) {
        let msg = to_wide(message);
        let strings = [PCWSTR(msg.as_ptr())];
        // SAFETY: handle is a valid registered source; we pass exactly one
        // insert string and no binary data. Errors are ignored — failing to
        // write a log entry must never disturb the pipeline.
        unsafe {
            let _ = ReportEventW(
                self.handle,
                kind,
                0,
                event_id,
                None,
                0,
                Some(&strings),
                None,
            );
        }
    }
}

impl Drop for EventLog {
    fn drop(&mut self) {
        // SAFETY: handle came from RegisterEventSourceW and is dropped once.
        unsafe {
            let _ = DeregisterEventSource(self.handle);
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
