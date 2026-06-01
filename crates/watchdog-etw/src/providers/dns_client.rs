//! Microsoft-Windows-DNS-Client
//! GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
//!
//! Event 3008 = DNSQueryStop (query completed). Chrome/Edge/Brave do
//! DNS-over-HTTPS by default these days, bypassing the Windows DNS
//! client, so this provider doesn't see browser-initiated lookups. It
//! still captures the system resolver path used by most other apps
//! (services, native installers, .NET clients, PowerShell `Resolve-DnsName`,
//! `nslookup`, malware that uses `getaddrinfo`), which is plenty for our
//! detectors.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use crossbeam_channel::Sender;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use watchdog_core::{EventPayload, EventSource, RawEvent};

const DNS_CLIENT_GUID: u128 = 0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d;
const EVENT_DNS_QUERY_STOP: u16 = 3008;

pub fn build(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> Provider {
    Provider::by_guid(DNS_CLIENT_GUID)
        .level(5)
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
    if record.event_id() != EVENT_DNS_QUERY_STOP {
        return;
    }

    let Ok(schema) = sl.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);

    let name: String = parser.try_parse("QueryName").unwrap_or_default();
    if name.is_empty() {
        return;
    }
    let query_type: u32 = parser.try_parse("QueryType").unwrap_or(0);
    let status: u32 = parser
        .try_parse("QueryStatus")
        .or_else(|_| parser.try_parse("Status"))
        .unwrap_or(0);
    let results: String = parser.try_parse("QueryResults").unwrap_or_default();

    let pid = record.process_id();

    let ev = RawEvent {
        ts: SystemTime::now(),
        src: EventSource::Dns,
        pid,
        tid: 0,
        payload: EventPayload::DnsQuery { name, query_type, status, results },
    };

    if tx.try_send(ev).is_err() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}
