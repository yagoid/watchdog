//! Microsoft-Windows-Kernel-File
//! GUID: {EDD08927-9CC4-4E65-B970-C2560FB5C289}
//!
//! Event IDs of interest:
//!   12 = Create  (NtCreateFile / CreateFileW)
//!
//! Volume-control: file-create is one of the loudest providers on Windows
//! (every DLL load, every config-file read, every antivirus scan). We
//! filter out paths that live under well-known system directories before
//! they enter the pipeline — those events are noise for our detectors
//! (which target user-data traversal and ransomware-style patterns) and
//! they'd otherwise dwarf everything else.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use crossbeam_channel::Sender;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use watchdog_core::{EventPayload, EventSource, RawEvent};

const KERNEL_FILE_GUID: u128 = 0xedd08927_9cc4_4e65_b970_c2560fb5c289;
const EVENT_CREATE: u16 = 12;

pub fn build(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> Provider {
    Provider::by_guid(KERNEL_FILE_GUID)
        .add_callback(move |record: &EventRecord, sl: &SchemaLocator| {
            handle(record, sl, &tx, &dropped);
        })
        .build()
}

fn handle(
    record: &EventRecord,
    sl: &SchemaLocator,
    tx: &Sender<RawEvent>,
    dropped: &AtomicU64,
) {
    if record.event_id() != EVENT_CREATE {
        return;
    }

    let Ok(schema) = sl.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);
    let path: String = parser.try_parse("FileName").unwrap_or_default();

    if path.is_empty() || is_noisy_system_path(&path) {
        return;
    }

    // Microsoft-Windows-Kernel-File event 12 does not carry a ProcessID
    // field — the originating PID lives in the EVENT_HEADER metadata.
    let pid = record.process_id();

    let ev = RawEvent {
        ts: SystemTime::now(),
        src: EventSource::File,
        pid,
        tid: 0,
        payload: EventPayload::FileCreate { path },
    };

    if tx.try_send(ev).is_err() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// Drop paths that virtually every running process touches. These are
/// not security-relevant for traversal detection, and they swamp every
/// other event by 100×.
fn is_noisy_system_path(nt_path: &str) -> bool {
    let lower = nt_path.to_ascii_lowercase();
    // Match common Windows volume prefixes followed by system dirs.
    // We don't bother resolving the device prefix here — the substring
    // is unambiguous enough.
    lower.contains(r"\windows\")
        || lower.contains(r"\program files\")
        || lower.contains(r"\program files (x86)\")
        || lower.contains(r"\programdata\microsoft\")
        || lower.contains(r"\appdata\local\packages\")
        || lower.contains(r"\appdata\local\microsoft\")
        || lower.contains(r"\$extend\")
        || lower.ends_with(".pf")    // prefetch
}
