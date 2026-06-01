//! The enrichment thread.
//!
//! Reads `RawEvent`s, mutates the process table on lifecycle events,
//! canonicalizes NT paths into DOS paths inside file-event payloads,
//! resolves kernel-attributed network events to the real owning PID,
//! and emits `EnrichedEvent`s with `process` / `parent` filled in.

use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender};
use watchdog_core::{EnrichedEvent, EventPayload, ProcessInfo, RawEvent};

use crate::device_map;
use crate::process_table::ProcessTable;
use crate::socket_table::SocketTable;

/// PID 4 = the System process — what Microsoft-Windows-Kernel-Network
/// reports when the connect runs in kernel context (which is most of
/// them). Treat it as a sentinel "needs socket→PID resolution".
const SYSTEM_PID: u32 = 4;

pub struct Enricher {
    table: Arc<ProcessTable>,
    sockets: SocketTable,
    own_pid: u32,
}

impl Enricher {
    pub fn bootstrap() -> (Self, usize) {
        let table = Arc::new(ProcessTable::new());
        let snapshot_count = table.populate_from_snapshot();
        (
            Self {
                table,
                sockets: SocketTable::new(),
                own_pid: std::process::id(),
            },
            snapshot_count,
        )
    }

    pub fn table(&self) -> Arc<ProcessTable> {
        Arc::clone(&self.table)
    }

    pub fn run(self, rx_raw: Receiver<RawEvent>, tx_enriched: Sender<EnrichedEvent>) {
        while let Ok(raw) = rx_raw.recv() {
            let enriched = self.enrich(raw);
            // Don't forward our own events. File I/O is dropped earlier at
            // the provider callback; this also catches network connections,
            // which arrive as PID 4 and only resolve to our real PID here,
            // after the socket-table lookup in `enrich`. The process table
            // was still updated inside `enrich`, so dropping is safe.
            if enriched.raw.pid == self.own_pid {
                continue;
            }
            if tx_enriched.send(enriched).is_err() {
                break;
            }
        }
    }

    fn enrich(&self, mut raw: RawEvent) -> EnrichedEvent {
        // Path canonicalization on payloads that carry NT paths.
        match &mut raw.payload {
            EventPayload::FileCreate { path } | EventPayload::FileWrite { path } => {
                *path = device_map::canonicalize(path).to_string_lossy().into_owned();
            }
            EventPayload::ImageLoad { image, .. } => {
                *image = device_map::canonicalize(image).to_string_lossy().into_owned();
            }
            _ => {}
        }

        // Socket→PID resolution: most network connects are attributed
        // to the System process (4) because the syscall runs in kernel
        // context. Look the connection up by its local endpoint in the
        // kernel's TCP table to find the real owner.
        if raw.pid == SYSTEM_PID {
            if let EventPayload::NetworkConnect { local_ip, local_port, .. } = &raw.payload {
                if let Some(real_pid) = self.sockets.lookup(*local_ip, *local_port) {
                    if real_pid != 0 && real_pid != SYSTEM_PID {
                        raw.pid = real_pid;
                    }
                }
            }
        }

        let process: Option<Arc<ProcessInfo>> = match &raw.payload {
            EventPayload::ProcessStart {
                ppid,
                image,
                cmdline,
                session_id,
            } => Some(self.table.on_process_start(
                raw.pid,
                *ppid,
                *session_id,
                image,
                cmdline,
                raw.ts,
            )),
            EventPayload::ProcessStop { .. } => {
                let info = self.table.lookup(raw.pid);
                let _ = self.table.on_process_stop(raw.pid);
                info
            }
            _ => self.table.lookup(raw.pid),
        };

        let parent = process.as_ref().and_then(|p| self.table.lookup(p.ppid));

        EnrichedEvent { raw, process, parent }
    }
}
