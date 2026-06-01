//! Microsoft-Windows-Kernel-Network
//! GUID: {7DD42A49-5329-4832-8DFD-43D979153A88}
//!
//! Outbound TCP connect events. We filter by **opcode** (12 = Connect),
//! not event_id, because that covers both IPv4 (event 12) and IPv6
//! (event 28) without us having to know either number — `opcode` is
//! the stable taxonomic key Microsoft uses.
//!
//! Port fields in this provider arrive in **network byte order** even
//! though they're declared `uint16`. ferrisetw reads primitives as
//! host-order little-endian, which gives us swapped bytes (e.g. port
//! 443 reads as 47873). We swap them back here so downstream code can
//! treat them as ordinary integers.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use crossbeam_channel::Sender;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use watchdog_core::{EventPayload, EventSource, RawEvent};

const KERNEL_NETWORK_GUID: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
const OPCODE_TCP_CONNECT: u8 = 12;

pub fn build(tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> Provider {
    Provider::by_guid(KERNEL_NETWORK_GUID)
        .any(0xffff_ffff_ffff_ffff)
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
    if record.opcode() != OPCODE_TCP_CONNECT {
        return;
    }

    let Ok(schema) = sl.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);

    let Ok(remote_ip) = parser.try_parse::<IpAddr>("daddr") else { return };
    if is_uninteresting_ip(&remote_ip) {
        return;
    }
    let Ok(local_ip) = parser.try_parse::<IpAddr>("saddr") else { return };

    // Ports come in network byte order; ferrisetw reads them as host LE.
    let remote_port: u16 = parser.try_parse::<u16>("dport").unwrap_or(0).swap_bytes();
    let local_port: u16  = parser.try_parse::<u16>("sport").unwrap_or(0).swap_bytes();

    // Header PID is typically 4 (System) because the connect runs in
    // kernel context; the enrichment stage will resolve to the real
    // owning process via `GetExtendedTcpTable` using (local_ip, local_port).
    let pid = match record.process_id() {
        u32::MAX => parser.try_parse::<u32>("PID").unwrap_or(4),
        p => p,
    };

    let ev = RawEvent {
        ts: SystemTime::now(),
        src: EventSource::Network,
        pid,
        tid: 0,
        payload: EventPayload::NetworkConnect {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        },
    };

    if tx.try_send(ev).is_err() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn is_uninteresting_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
