//! Microsoft-Windows-Kernel-Registry
//! GUID: {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
//!
//! We only listen to SetValueKey — the persistence-detector cares about
//! a value being written, not about reads or queries. Volume is modest
//! (low hundreds/sec at most), so no path filtering needed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use crossbeam_channel::Sender;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use watchdog_core::{EventPayload, EventSource, RawEvent};

const KERNEL_REGISTRY_GUID: u128 = 0x70eb4f03_c1de_4f73_a051_33d13d5413bd;

/// Event ID for SetValueKey in this provider. There are several
/// SetValueKey variants in the manifest (notably 5 and 14) so we accept
/// either: 5 is the common one, 14 is the post-Windows-10 v2.
const EVENT_SET_VALUE_PRIMARY: u16 = 5;
const EVENT_SET_VALUE_V2: u16 = 14;

pub fn build(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> Provider {
    Provider::by_guid(KERNEL_REGISTRY_GUID)
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
    let event_id = record.event_id();
    if event_id != EVENT_SET_VALUE_PRIMARY && event_id != EVENT_SET_VALUE_V2 {
        return;
    }

    let Ok(schema) = sl.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);

    // Both event versions name the field `KeyName` for the full NT path
    // and `ValueName` for the value being set.
    let key_name: String = parser.try_parse("KeyName").unwrap_or_default();
    let value_name: String = parser.try_parse("ValueName").unwrap_or_default();

    if key_name.is_empty() {
        return;
    }

    let pid = record.process_id();

    let ev = RawEvent {
        ts: SystemTime::now(),
        src: EventSource::Registry,
        pid,
        tid: 0,
        payload: EventPayload::RegistrySetValue { key_name, value_name },
    };

    if tx.try_send(ev).is_err() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}
