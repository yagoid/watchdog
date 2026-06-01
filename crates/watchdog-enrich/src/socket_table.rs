//! Resolves `(local_ip, local_port) → owning PID` by walking the
//! kernel's TCP table via `GetExtendedTcpTable`.
//!
//! Microsoft-Windows-Kernel-Network attributes most TCP connect events
//! to PID 4 (System) because the connect itself runs in kernel context.
//! Without this lookup, all our network events would map to "System"
//! and no per-process detector could do anything useful with them.
//!
//! Refreshing the table on every event would be wasteful; we cache it
//! for half a second, which is short enough that the new connection's
//! row is essentially always present by the time we look (TCP socket
//! lifecycle is at least milliseconds long for any non-failed connect)
//! and long enough that bursts share one fetch.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};

const REFRESH_INTERVAL: Duration = Duration::from_millis(500);
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

#[derive(Clone, Copy)]
struct Row {
    local_ip: IpAddr,
    local_port: u16,
    pid: u32,
}

struct CachedTable {
    rows: Vec<Row>,
    fetched_at: Instant,
}

pub struct SocketTable {
    cache: Mutex<Option<CachedTable>>,
}

impl SocketTable {
    pub fn new() -> Self {
        Self { cache: Mutex::new(None) }
    }

    /// Look up which process owns the socket with this local endpoint.
    /// Returns the PID, or `None` if the socket isn't (or isn't yet)
    /// in the table.
    pub fn lookup(&self, local_ip: IpAddr, local_port: u16) -> Option<u32> {
        let mut cache = self.cache.lock().unwrap();
        let stale = cache
            .as_ref()
            .map_or(true, |c| c.fetched_at.elapsed() >= REFRESH_INTERVAL);
        if stale {
            *cache = Some(CachedTable {
                rows: refresh_all(),
                fetched_at: Instant::now(),
            });
        }
        cache
            .as_ref()?
            .rows
            .iter()
            .find(|r| r.local_ip == local_ip && r.local_port == local_port)
            .map(|r| r.pid)
    }
}

impl Default for SocketTable {
    fn default() -> Self { Self::new() }
}

fn refresh_all() -> Vec<Row> {
    let mut rows = refresh_v4();
    rows.extend(refresh_v6());
    rows
}

fn refresh_v4() -> Vec<Row> {
    unsafe {
        let mut size = 0u32;
        // Probe call: passes a null buffer to learn the required size.
        // Ignores the return code on this call — it always errors with
        // ERROR_INSUFFICIENT_BUFFER, which is exactly what we want.
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr().cast::<core::ffi::c_void>()),
            &mut size,
            false,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return Vec::new();
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        if count == 0 {
            return Vec::new();
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);
        rows.iter()
            .map(|r| Row {
                // dwLocalAddr is a u32 whose memory layout is the four
                // address octets in network byte order. `to_le_bytes`
                // gives them back in that same order.
                local_ip: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_le_bytes())),
                // Low 16 bits in network byte order; high 16 are zero.
                local_port: (r.dwLocalPort as u16).swap_bytes(),
                pid: r.dwOwningPid,
            })
            .collect()
    }
}

fn refresh_v6() -> Vec<Row> {
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr().cast::<core::ffi::c_void>()),
            &mut size,
            false,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return Vec::new();
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        if count == 0 {
            return Vec::new();
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);
        rows.iter()
            .map(|r| Row {
                // ucLocalAddr is already 16 bytes in network order — the
                // canonical IPv6 representation.
                local_ip: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                local_port: (r.dwLocalPort as u16).swap_bytes(),
                pid: r.dwOwningPid,
            })
            .collect()
    }
}
