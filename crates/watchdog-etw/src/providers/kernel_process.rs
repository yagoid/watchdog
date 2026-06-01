//! Microsoft-Windows-Kernel-Process
//! GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
//!
//! Event IDs of interest:
//!   1 = ProcessStart    (ProcessID, ParentProcessID, SessionID, ImageName, CommandLine)
//!   2 = ProcessStop     (ProcessID, ExitCode, ImageName)
//!   5 = ImageLoad       (ImageBase, ImageSize, ProcessID, ImageName)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use crossbeam_channel::Sender;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use watchdog_core::{EventPayload, EventSource, RawEvent};

const KERNEL_PROCESS_GUID: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;

pub fn build(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> Provider {
    Provider::by_guid(KERNEL_PROCESS_GUID)
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
    let Ok(schema) = sl.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);
    let event_id = record.event_id();

    let (pid, payload) = match event_id {
        1 => {
            let pid: u32         = parser.try_parse("ProcessID").unwrap_or(0);
            let ppid: u32        = parser.try_parse("ParentProcessID").unwrap_or(0);
            let session_id: u32  = parser.try_parse("SessionID").unwrap_or(0);
            let image: String    = parser.try_parse("ImageName").unwrap_or_default();
            let cmdline: String  = parser.try_parse("CommandLine").unwrap_or_default();
            (pid, EventPayload::ProcessStart { ppid, image, cmdline, session_id })
        }
        2 => {
            let pid: u32         = parser.try_parse("ProcessID").unwrap_or(0);
            let exit_code: u32   = parser.try_parse("ExitCode").unwrap_or(0);
            let image: String    = parser.try_parse("ImageName").unwrap_or_default();
            (pid, EventPayload::ProcessStop { exit_code, image })
        }
        5 => {
            let pid: u32         = parser.try_parse("ProcessID").unwrap_or(0);
            let image: String    = parser.try_parse("ImageName").unwrap_or_default();
            let base: u64        = parser.try_parse("ImageBase").unwrap_or(0);
            let size: u64        = parser.try_parse("ImageSize").unwrap_or(0);
            (pid, EventPayload::ImageLoad { image, base, size })
        }
        _ => return,
    };

    let ev = RawEvent {
        ts: SystemTime::now(),
        src: EventSource::Process,
        pid,
        tid: 0,
        payload,
    };

    // try_send: never block the ETW callback thread. A full channel means
    // downstream is overloaded; bump the dropped counter so the UI can
    // surface backpressure to the user.
    if tx.try_send(ev).is_err() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}
