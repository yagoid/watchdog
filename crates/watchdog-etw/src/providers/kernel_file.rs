//! Microsoft-Windows-Kernel-File
//! GUID: {EDD08927-9CC4-4E65-B970-C2560FB5C289}
//!
//! Event IDs of interest:
//!   12 = Create  (NtCreateFile / CreateFileW) — carries FileObject + FileName
//!   16 = Write   (NtWriteFile)                — carries FileObject, no name
//!   14 = Close                                — carries FileObject
//!
//! Volume-control: file events are the loudest providers on Windows (every
//! DLL load, every config read, every AV scan). We filter out paths under
//! well-known system directories before they enter the pipeline.
//!
//! Write resolution: the `Write` event identifies the file only by its
//! `FileObject` handle, not by name. We keep a `FileObject`→name map built
//! from `Create` events (user paths only, so it stays small) and resolve
//! writes against it. `Close` removes the entry, both to bound memory and
//! to avoid stale mappings when the kernel reuses a `FileObject` address.
//! We emit `FileWrite` only on the *first* write to a handle, so a chunked
//! write doesn't flood downstream — one signal per file written.
//!
//! Why both Create and Write: `Create` (open) can't distinguish a reader
//! (search indexer, AV, backup) from a writer. `EntropyBurst` needs the
//! write-intent signal to avoid flagging anything that merely *reads* many
//! high-entropy files. Other detectors (RapidFileTraversal) still use the
//! broader `Create` (open/enumeration) signal.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crossbeam_channel::Sender;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use watchdog_core::{EventPayload, EventSource, RawEvent};

const KERNEL_FILE_GUID: u128 = 0xedd08927_9cc4_4e65_b970_c2560fb5c289;
const EVENT_CREATE: u16 = 12;
const EVENT_WRITE: u16 = 16;
const EVENT_CLOSE: u16 = 14;

/// Safety valve: if `Close` events are somehow missed and the map grows
/// without bound, clear it. Resolution misses until it repopulates are
/// preferable to unbounded memory.
const FILEOBJECT_MAP_CAP: usize = 32_768;

struct OpenFile {
    path: String,
    /// Set once we've emitted a `FileWrite` for this handle, so repeated
    /// writes to the same open file don't each produce an event.
    write_emitted: bool,
}

/// `FileObject` (kernel pointer) → the open user-path file it refers to.
type FileObjectMap = Arc<Mutex<HashMap<u64, OpenFile>>>;

/// Our own PID, cached. `GetCurrentProcessId` is cheap, but this runs on
/// the hottest callback in the system, so we resolve it exactly once.
fn own_pid() -> u32 {
    use std::sync::OnceLock;
    static PID: OnceLock<u32> = OnceLock::new();
    *PID.get_or_init(std::process::id)
}

pub fn build(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> Provider {
    let names: FileObjectMap = Arc::new(Mutex::new(HashMap::new()));
    Provider::by_guid(KERNEL_FILE_GUID)
        .add_callback(move |record: &EventRecord, sl: &SchemaLocator| {
            handle(record, sl, &tx, &dropped, &names);
        })
        .build()
}

fn handle(
    record: &EventRecord,
    sl: &SchemaLocator,
    tx: &Sender<RawEvent>,
    dropped: &AtomicU64,
    names: &FileObjectMap,
) {
    let event_id = record.event_id();
    if event_id != EVENT_CREATE && event_id != EVENT_WRITE && event_id != EVENT_CLOSE {
        return;
    }

    // Never observe our own file I/O. Watchdog opens files to inspect them
    // (entropy sampling, signature checks); each open emits an event for our
    // own PID, which would feed straight back into the detectors that opened
    // it — an infinite amplification loop. Drop at the source.
    if record.process_id() == own_pid() {
        return;
    }

    let Ok(schema) = sl.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);

    match event_id {
        EVENT_CREATE => {
            let path: String = parser.try_parse("FileName").unwrap_or_default();
            if path.is_empty() || is_noisy_system_path(&path) {
                return;
            }
            // Remember the handle→name mapping so a later Write can resolve
            // its path. Only user-path creates land here, keeping it small.
            let file_object: u64 = parser.try_parse("FileObject").unwrap_or(0);
            if file_object != 0 {
                let mut map = names.lock().unwrap();
                if map.len() >= FILEOBJECT_MAP_CAP {
                    map.clear();
                }
                map.insert(file_object, OpenFile { path: path.clone(), write_emitted: false });
            }
            // Microsoft-Windows-Kernel-File events don't carry a ProcessID
            // field — the originating PID lives in the EVENT_HEADER metadata.
            emit(tx, dropped, record.process_id(), EventPayload::FileCreate { path });
        }
        EVENT_WRITE => {
            let file_object: u64 = parser.try_parse("FileObject").unwrap_or(0);
            if file_object == 0 {
                return;
            }
            // Resolve against the map and emit at most once per handle.
            let path = {
                let mut map = names.lock().unwrap();
                match map.get_mut(&file_object) {
                    Some(f) if !f.write_emitted => {
                        f.write_emitted = true;
                        Some(f.path.clone())
                    }
                    // Unknown handle (system file, or its Create was filtered)
                    // or already reported — nothing to emit.
                    _ => None,
                }
            };
            if let Some(path) = path {
                emit(tx, dropped, record.process_id(), EventPayload::FileWrite { path });
            }
        }
        EVENT_CLOSE => {
            let file_object: u64 = parser.try_parse("FileObject").unwrap_or(0);
            if file_object != 0 {
                names.lock().unwrap().remove(&file_object);
            }
        }
        _ => {}
    }
}

fn emit(tx: &Sender<RawEvent>, dropped: &AtomicU64, pid: u32, payload: EventPayload) {
    let ev = RawEvent {
        ts: SystemTime::now(),
        src: EventSource::File,
        pid,
        tid: 0,
        payload,
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
