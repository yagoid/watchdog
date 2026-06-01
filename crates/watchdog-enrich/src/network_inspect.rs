//! Read-only snapshots of the local network state — adapters, their
//! addresses/gateways/DNS, and the full TCP connection table with
//! state. Used by the TUI's Network view.
//!
//! Nothing here streams or scans. It's purely pull-on-demand against
//! the iphlpapi.dll APIs that any tool like `ipconfig`, `netstat` or
//! `Get-NetTCPConnection` uses underneath.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetExtendedTcpTable, GetIpNetTable2, IcmpCloseHandle,
    IcmpCreateFile, IcmpSendEcho, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, ICMP_ECHO_REPLY, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_DNS_SERVER_ADDRESS_XP, IP_ADAPTER_GATEWAY_ADDRESS_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IPNET_TABLE2, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    getnameinfo, socklen_t, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, NlnsDelay,
    NlnsIncomplete, NlnsPermanent, NlnsProbe, NlnsReachable, NlnsStale, NlnsUnreachable,
    NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, WSAStartup, WSADATA,
};

#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    pub adapters: Vec<Adapter>,
    pub tcp: Vec<TcpConnection>,
    pub neighbors: Vec<Neighbor>,
    pub captured_at: Instant,
}

/// A device discovered on the local network via the kernel's neighbor
/// (ARP / NDP) cache. Read-only — we don't probe anything; an entry
/// only exists if our machine has talked to that device (or vice versa).
#[derive(Debug, Clone)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub mac: [u8; 6],
    pub mac_len: u8,
    pub state: NeighborState,
    /// Interface index. Pair with `Adapter.friendly_name` (we don't
    /// expose adapter indices yet so this is an opaque number for now).
    pub interface_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Unreachable,
    Incomplete,
    Probe,
    Delay,
    Stale,
    Reachable,
    Permanent,
    Other(i32),
}

impl NeighborState {
    pub fn label(self) -> &'static str {
        match self {
            NeighborState::Unreachable => "unreach",
            NeighborState::Incomplete  => "incompl",
            NeighborState::Probe       => "probe",
            NeighborState::Delay       => "delay",
            NeighborState::Stale       => "stale",
            NeighborState::Reachable   => "reach",
            NeighborState::Permanent   => "perm",
            NeighborState::Other(_)    => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Adapter {
    /// e.g. "Wi-Fi", "Ethernet 2"
    pub friendly_name: String,
    /// e.g. "Intel(R) Wireless-AC 9560 160MHz"
    pub description: String,
    /// MAC. Always 6 bytes for ethernet/wifi; some adapters use shorter
    /// addresses, in which case `mac` is truncated to `mac_len`.
    pub mac: [u8; 6],
    pub mac_len: u8,
    /// All assigned addresses on this adapter, IPv4 and IPv6.
    pub addresses: Vec<(IpAddr, u8)>, // (ip, prefix_len)
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub is_up: bool,
    /// Negotiated speed in Mbps, if reported.
    pub link_speed_mbps: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Other(u32),
}

impl TcpState {
    pub fn from_raw(v: u32) -> Self {
        match v {
            1  => TcpState::Closed,
            2  => TcpState::Listen,
            3  => TcpState::SynSent,
            4  => TcpState::SynRcvd,
            5  => TcpState::Established,
            6  => TcpState::FinWait1,
            7  => TcpState::FinWait2,
            8  => TcpState::CloseWait,
            9  => TcpState::Closing,
            10 => TcpState::LastAck,
            11 => TcpState::TimeWait,
            12 => TcpState::DeleteTcb,
            n  => TcpState::Other(n),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TcpState::Closed      => "CLOSED",
            TcpState::Listen      => "LISTEN",
            TcpState::SynSent     => "SYN_SENT",
            TcpState::SynRcvd     => "SYN_RCVD",
            TcpState::Established => "ESTAB",
            TcpState::FinWait1    => "FIN_W1",
            TcpState::FinWait2    => "FIN_W2",
            TcpState::CloseWait   => "CLOSE_W",
            TcpState::Closing     => "CLOSING",
            TcpState::LastAck     => "LAST_ACK",
            TcpState::TimeWait    => "TIME_W",
            TcpState::DeleteTcb   => "DEL_TCB",
            TcpState::Other(_)    => "OTHER",
        }
    }
}

/// One call. Pulls adapters + IPv4/IPv6 TCP tables + ARP/NDP neighbor
/// cache. Cheap (single-digit milliseconds typically); fine to call
/// every few seconds on demand.
pub fn snapshot() -> NetworkSnapshot {
    NetworkSnapshot {
        adapters: adapters(),
        tcp: tcp_connections(),
        neighbors: neighbors(),
        captured_at: Instant::now(),
    }
}

// ---------------------------------------------------------------------------
// Neighbors (ARP / NDP cache) via GetIpNetTable2
// ---------------------------------------------------------------------------

fn neighbors() -> Vec<Neighbor> {
    unsafe {
        let mut table_ptr: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        let ret = GetIpNetTable2(AF_UNSPEC, &mut table_ptr);
        if ret.0 != 0 || table_ptr.is_null() {
            return Vec::new();
        }
        let table = &*table_ptr;
        let count = table.NumEntries as usize;
        let mut out = Vec::with_capacity(count);
        if count > 0 {
            let rows = std::slice::from_raw_parts(table.Table.as_ptr(), count);
            for r in rows {
                let family = r.Address.si_family;
                let ip = if family == AF_INET {
                    let sin = &r.Address.Ipv4;
                    let bytes = sin.sin_addr.S_un.S_addr.to_le_bytes();
                    IpAddr::V4(Ipv4Addr::from(bytes))
                } else if family == AF_INET6 {
                    let sin6 = &r.Address.Ipv6;
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte))
                } else {
                    continue;
                };

                // Skip entries that are obviously not useful for a
                // human inspector: multicast, link-local v4 (169.254/16,
                // which only shows up when DHCP failed), unspecified.
                if is_uninteresting_neighbor(&ip) {
                    continue;
                }

                let mut mac = [0u8; 6];
                let mac_len = r.PhysicalAddressLength.min(6) as u8;
                for i in 0..mac_len as usize {
                    mac[i] = r.PhysicalAddress[i];
                }

                let state = match r.State {
                    s if s == NlnsUnreachable => NeighborState::Unreachable,
                    s if s == NlnsIncomplete  => NeighborState::Incomplete,
                    s if s == NlnsProbe       => NeighborState::Probe,
                    s if s == NlnsDelay       => NeighborState::Delay,
                    s if s == NlnsStale       => NeighborState::Stale,
                    s if s == NlnsReachable   => NeighborState::Reachable,
                    s if s == NlnsPermanent   => NeighborState::Permanent,
                    other                     => NeighborState::Other(other.0),
                };

                out.push(Neighbor {
                    ip,
                    mac,
                    mac_len,
                    state,
                    interface_index: r.InterfaceIndex,
                });
            }
        }
        FreeMibTable(table_ptr as *const _);
        out
    }
}

fn is_uninteresting_neighbor(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254) // APIPA
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_multicast()
                // Solicited-node multicast & link-local "ff02::" / "fe80::" are
                // chatty IPv6 housekeeping; suppress.
                || v6.segments()[0] == 0xff02
        }
    }
}

// ---------------------------------------------------------------------------
// OUI vendor lookup — small embedded table covering common LAN devices.
// IEEE assigns the first 3 bytes of each MAC to a manufacturer. The full
// list is ~32 000 entries; we ship a curated subset that catches most of
// what a home or office LAN actually contains. Unknown OUIs return None
// — better honest blank than wrong guess.
// ---------------------------------------------------------------------------

/// `[u8; 3]` OUI → display vendor name. Sorted alphabetically by vendor
/// for editor sanity. Locally-administered MACs (the 0x02 bit of byte 0)
/// are handled separately by `oui_vendor`.
const OUI_TABLE: &[(&[u8; 3], &str)] = &[
    // Networking / routers
    (&[0xa4, 0x2b, 0x8c], "AVM (Fritz!Box)"),
    (&[0x00, 0x0c, 0x29], "VMware"),
    (&[0x00, 0x50, 0x56], "VMware"),
    (&[0x08, 0x00, 0x27], "VirtualBox"),
    (&[0x52, 0x54, 0x00], "QEMU/KVM"),
    (&[0xb8, 0x27, 0xeb], "Raspberry Pi"),
    (&[0xdc, 0xa6, 0x32], "Raspberry Pi"),
    (&[0xe4, 0x5f, 0x01], "Raspberry Pi"),
    (&[0x00, 0x1d, 0x0f], "TP-Link"),
    (&[0x14, 0xeb, 0xb6], "TP-Link"),
    (&[0x50, 0xc7, 0xbf], "TP-Link"),
    (&[0x68, 0xff, 0x7b], "TP-Link"),
    (&[0xb0, 0xbe, 0x76], "TP-Link"),
    (&[0xc4, 0xe9, 0x84], "TP-Link"),
    (&[0x00, 0x1f, 0x33], "Netgear"),
    (&[0x20, 0x4e, 0x7f], "Netgear"),
    (&[0xcc, 0x40, 0xd0], "Netgear"),
    (&[0x10, 0x7b, 0x44], "ASUS"),
    (&[0x2c, 0x4d, 0x54], "ASUS"),
    (&[0xbc, 0xae, 0xc5], "ASUS"),
    (&[0x14, 0xdd, 0xa9], "ASUS"),
    (&[0x00, 0x1a, 0x2b], "Cisco"),
    (&[0x00, 0x1b, 0x54], "Cisco"),
    (&[0x44, 0xd3, 0xca], "Cisco"),
    (&[0xfc, 0xec, 0xda], "Ubiquiti"),
    (&[0x24, 0x5a, 0x4c], "Ubiquiti"),
    (&[0x68, 0x72, 0x51], "Ubiquiti"),
    (&[0xb4, 0xfb, 0xe4], "Ubiquiti"),
    // PCs / laptops / NICs
    (&[0x00, 0x15, 0x5d], "Microsoft (Hyper-V)"),
    (&[0x00, 0x0d, 0x3a], "Microsoft"),
    (&[0x7c, 0x1e, 0x52], "Microsoft Surface"),
    (&[0x00, 0x1b, 0x21], "Intel"),
    (&[0xa0, 0xc5, 0x89], "Intel"),
    (&[0xb4, 0x69, 0x21], "Intel"),
    (&[0xc4, 0xd9, 0x87], "Intel"),
    (&[0x00, 0xe0, 0x4c], "Realtek"),
    (&[0xfc, 0x34, 0x97], "Realtek"),
    (&[0x00, 0x1e, 0xc2], "Apple"),
    (&[0x00, 0x23, 0xdf], "Apple"),
    (&[0x14, 0x10, 0x9f], "Apple"),
    (&[0x3c, 0x07, 0x54], "Apple"),
    (&[0x5c, 0xe9, 0x1e], "Apple"),
    (&[0x7c, 0x6d, 0xf8], "Apple"),
    (&[0xa4, 0x83, 0xe7], "Apple"),
    (&[0xf0, 0x18, 0x98], "Apple"),
    (&[0xf4, 0x0f, 0x24], "Apple"),
    // Phones / mobile
    (&[0x40, 0x4e, 0x36], "HTC"),
    (&[0x18, 0x3a, 0x2d], "Samsung"),
    (&[0x40, 0x16, 0x3b], "Samsung"),
    (&[0x90, 0x18, 0x7c], "Samsung"),
    (&[0x14, 0x9f, 0xe8], "Xiaomi"),
    (&[0x34, 0x80, 0xb3], "Xiaomi"),
    (&[0x88, 0x0f, 0x10], "Xiaomi"),
    (&[0x00, 0xe0, 0xfc], "Huawei"),
    (&[0x40, 0x4d, 0x8e], "Huawei"),
    (&[0x88, 0xa6, 0xc6], "Huawei"),
    // IoT / streaming / printers
    (&[0xb8, 0x27, 0xeb], "Raspberry Pi"),
    (&[0x00, 0x17, 0x88], "Philips Hue"),
    (&[0xec, 0xb5, 0xfa], "Philips Hue"),
    (&[0x18, 0x74, 0x2e], "Amazon"),
    (&[0x44, 0x65, 0x0d], "Amazon"),
    (&[0xa0, 0x02, 0xdc], "Amazon"),
    (&[0x68, 0x9a, 0x87], "Google Nest"),
    (&[0xf4, 0xf5, 0xd8], "Google"),
    (&[0xf8, 0x8f, 0xca], "Google"),
    (&[0xb8, 0x53, 0xac], "Roku"),
    (&[0xd0, 0x4d, 0x2c], "Roku"),
    (&[0x5c, 0xaa, 0xfd], "Sonos"),
    (&[0xb8, 0xe9, 0x37], "Sonos"),
    (&[0x00, 0x11, 0x32], "Synology NAS"),
    (&[0x24, 0x5e, 0xbe], "QNAP NAS"),
    (&[0xa4, 0x5e, 0x60], "Brother"),
    (&[0x00, 0x80, 0x77], "Brother"),
    (&[0x00, 0x1b, 0x78], "HP"),
    (&[0xa0, 0xd3, 0xc1], "HP"),
    (&[0xb0, 0x5a, 0xda], "HP"),
    (&[0x00, 0x14, 0x22], "Dell"),
    (&[0x18, 0x66, 0xda], "Dell"),
    (&[0x6c, 0x2b, 0x59], "Dell"),
    (&[0x00, 0x59, 0x07], "Lenovo"),
    (&[0xc8, 0x5b, 0x76], "Lenovo"),
    // Cameras / NVR
    (&[0xbc, 0xad, 0x28], "Hikvision"),
    (&[0xc0, 0x51, 0x7e], "Hikvision"),
    (&[0x4c, 0x11, 0xbf], "Dahua"),
    (&[0xa0, 0xbd, 0x1d], "Dahua"),
];

/// Return a short vendor name for the given MAC, or `None` if we can't
/// confidently attribute it.
pub fn oui_vendor(mac: &[u8; 6], mac_len: u8) -> Option<&'static str> {
    if mac_len < 3 {
        return None;
    }
    // Locally-administered MACs (bit 0x02 set in byte 0) aren't IEEE
    // assigned. Most often it's a modern phone or laptop using MAC
    // randomization on Wi-Fi.
    if (mac[0] & 0x02) != 0 {
        return Some("(randomized)");
    }
    let prefix: [u8; 3] = [mac[0], mac[1], mac[2]];
    OUI_TABLE
        .iter()
        .find(|(p, _)| **p == prefix)
        .map(|(_, name)| *name)
}

// ---------------------------------------------------------------------------
// Active discovery — ICMP ping + subnet enumeration
// ---------------------------------------------------------------------------

/// Pick the most likely "primary" IPv4 subnet of this machine. First up
/// adapter with a non-loopback IPv4 in the /16…/30 range wins.
pub fn primary_subnet_v4() -> Option<(Ipv4Addr, u8)> {
    for a in adapters() {
        if !a.is_up {
            continue;
        }
        for (ip, prefix) in &a.addresses {
            if let IpAddr::V4(v4) = ip {
                if *prefix >= 16
                    && *prefix <= 30
                    && !v4.is_loopback()
                    && !v4.is_link_local()
                    && !v4.is_unspecified()
                {
                    return Some((*v4, *prefix));
                }
            }
        }
    }
    None
}

/// Enumerate every host address in a `/prefix` subnet, excluding the
/// network and broadcast addresses. Capped: refuses subnets larger
/// than /22 (1022 hosts) so we don't try to ping a /16 (65k hosts).
pub fn subnet_hosts_v4(addr: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if !(22..=30).contains(&prefix) {
        return Vec::new();
    }
    let addr_u32 = u32::from_be_bytes(addr.octets());
    let mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    let network = addr_u32 & mask;
    let broadcast = addr_u32 | !mask;
    if network == broadcast {
        return vec![Ipv4Addr::from(network.to_be_bytes())];
    }
    let mut hosts = Vec::with_capacity((broadcast - network).saturating_sub(1) as usize);
    for i in (network + 1)..broadcast {
        hosts.push(Ipv4Addr::from(i.to_be_bytes()));
    }
    hosts
}

/// Send a single ICMP echo and wait up to `timeout_ms`. Returns `true`
/// if any reply came back (the host is up and reachable from this
/// interface). Creates a fresh ICMP handle per call — cheap.
pub fn ping_v4(ip: Ipv4Addr, timeout_ms: u32) -> bool {
    unsafe {
        let Ok(handle) = IcmpCreateFile() else { return false };
        let ok = ping_v4_with_handle(handle, ip, timeout_ms);
        let _ = IcmpCloseHandle(handle);
        ok
    }
}

/// Reuse-able ICMP echo. Used by `start_discover` so each worker
/// thread creates one handle and recycles it across many pings.
pub unsafe fn ping_v4_with_handle(handle: HANDLE, ip: Ipv4Addr, timeout_ms: u32) -> bool {
    ping_v4_with_handle_detailed(handle, ip, timeout_ms).is_some()
}

/// Ping returning the reply's TTL and round-trip time. `None` on
/// timeout / unreachable. TTL is what the *remote* placed in the IP
/// header; for a LAN host one hop away that's effectively the host's
/// default initial TTL, which is a reliable OS fingerprint hint:
/// 64 → Linux/BSD/macOS/iOS/Android, 128 → Windows, 255 → router/IOS.
pub unsafe fn ping_v4_with_handle_detailed(
    handle: HANDLE,
    ip: Ipv4Addr,
    timeout_ms: u32,
) -> Option<IcmpReply> {
    let dest: u32 = u32::from_le_bytes(ip.octets());
    let request = b"watchdog";
    let buf_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + request.len() + 32;
    let mut reply_buf = vec![0u8; buf_size];

    let count = IcmpSendEcho(
        handle,
        dest,
        request.as_ptr() as *const c_void,
        request.len() as u16,
        None,
        reply_buf.as_mut_ptr() as *mut c_void,
        reply_buf.len() as u32,
        timeout_ms,
    );
    if count == 0 {
        return None;
    }
    let reply = &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY);
    Some(IcmpReply {
        ttl: reply.Options.Ttl,
        rtt_ms: reply.RoundTripTime,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct IcmpReply {
    pub ttl: u8,
    pub rtt_ms: u32,
}

/// Best-effort guess of the host OS based on the initial TTL in its
/// ICMP reply. For a LAN host one hop away the received TTL equals the
/// remote's default; common defaults are 64 (Unix-family), 128
/// (Windows), and 255 (Cisco IOS / Solaris / many network devices).
/// One-hop assumption is reliable for LAN inventory but breaks across
/// the internet — we display it without overclaiming.
pub fn os_guess_from_ttl(ttl: u8) -> &'static str {
    match ttl {
        0          => "?",
        1..=64     => "Linux / macOS / Android / iOS / BSD",
        65..=128   => "Windows",
        _          => "router / Solaris / network device",
    }
}

/// One-shot ICMP probe (creates and closes a handle internally).
pub fn ping_v4_detailed(ip: Ipv4Addr, timeout_ms: u32) -> Option<IcmpReply> {
    unsafe {
        let Ok(handle) = IcmpCreateFile() else { return None };
        let r = ping_v4_with_handle_detailed(handle, ip, timeout_ms);
        let _ = IcmpCloseHandle(handle);
        r
    }
}

// ---------------------------------------------------------------------------
// Reverse DNS (getnameinfo).
// WSAStartup is required for any WinSock entry point; we run it once at
// first use, lazily, behind a `Once`.
// ---------------------------------------------------------------------------

fn ensure_winsock_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        let _ = WSAStartup(0x0202, &mut wsa); // WinSock 2.2
    });
}

/// Reverse DNS for a v4 address. Blocking; can take up to a few
/// seconds when the resolver has to time out. Returns `None` if the
/// host has no PTR record (very common on a LAN unless the router
/// publishes them via DHCP).
pub fn reverse_dns_v4(ip: Ipv4Addr) -> Option<String> {
    ensure_winsock_init();
    let sin = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_le_bytes(ip.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    let mut host_buf = [0u8; 256];
    let ret = unsafe {
        getnameinfo(
            &sin as *const _ as *const SOCKADDR,
            socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
            Some(&mut host_buf),
            None,
            NI_NAMEREQD as i32,
        )
    };
    if ret != 0 {
        return None;
    }
    let len = host_buf.iter().position(|&c| c == 0).unwrap_or(host_buf.len());
    let s = std::str::from_utf8(&host_buf[..len]).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Live state of an in-flight discover sweep. Counters are atomic so
/// the UI can read them on each render with zero locking.
pub struct DiscoverState {
    pub subnet_label: String, // e.g. "192.168.1.0/24"
    pub total: u32,
    pub scanned: Arc<AtomicU32>,
    pub responded: Arc<AtomicU32>,
    pub started_at: Instant,
    /// Frozen wall-clock duration in ms. `0` while the scan is still
    /// running; set exactly once by the worker that processes the
    /// final IP. Lets the UI stop showing a still-rising timer.
    pub total_ms: Arc<AtomicU64>,
}

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

impl DiscoverState {
    pub fn done(&self) -> bool {
        self.scanned.load(Ordering::Relaxed) >= self.total
    }

    /// Elapsed time to show in the UI: frozen value once the sweep
    /// completes, live `started_at.elapsed()` while it's still
    /// running.
    pub fn elapsed_ms(&self) -> u128 {
        let frozen = self.total_ms.load(Ordering::Relaxed);
        if frozen > 0 {
            frozen as u128
        } else {
            self.started_at.elapsed().as_millis()
        }
    }
}

/// Fire off a concurrent ping sweep against `(addr, prefix)`. Returns a
/// state handle the UI polls. Spawns `WORKERS` background threads —
/// they exit themselves when the host list is exhausted.
pub fn start_discover(addr: Ipv4Addr, prefix: u8) -> Option<Arc<DiscoverState>> {
    let hosts = subnet_hosts_v4(addr, prefix);
    if hosts.is_empty() {
        return None;
    }
    const WORKERS: usize = 32;
    const TIMEOUT_MS: u32 = 600;

    let total = hosts.len() as u32;
    let state = Arc::new(DiscoverState {
        subnet_label: format!("{addr}/{prefix}"),
        total,
        scanned: Arc::new(AtomicU32::new(0)),
        responded: Arc::new(AtomicU32::new(0)),
        started_at: Instant::now(),
        total_ms: Arc::new(AtomicU64::new(0)),
    });

    let hosts = Arc::new(hosts);
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for _ in 0..WORKERS {
        let state = Arc::clone(&state);
        let hosts = Arc::clone(&hosts);
        let next = Arc::clone(&next);
        std::thread::Builder::new()
            .name("watchdog-discover".into())
            .spawn(move || unsafe {
                let Ok(handle) = IcmpCreateFile() else { return };
                loop {
                    let idx = next.fetch_add(1, Ordering::SeqCst);
                    if idx >= hosts.len() {
                        break;
                    }
                    let ip = hosts[idx];
                    if ping_v4_with_handle(handle, ip, TIMEOUT_MS) {
                        state.responded.fetch_add(1, Ordering::Relaxed);
                    }
                    // fetch_add returns the previous value; if that was
                    // `total - 1`, we just processed the last host —
                    // exactly one worker satisfies this, so it freezes
                    // the timer without a race.
                    let prev = state.scanned.fetch_add(1, Ordering::SeqCst);
                    if prev + 1 == state.total {
                        let ms = state.started_at.elapsed().as_millis() as u64;
                        state.total_ms.store(ms.max(1), Ordering::SeqCst);
                    }
                }
                let _ = IcmpCloseHandle(handle);
            })
            .ok();
    }

    Some(state)
}


// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

pub fn adapters() -> Vec<Adapter> {
    // Family AF_UNSPEC gets both IPv4 and IPv6 addresses on each adapter.
    let family: u32 = AF_UNSPEC.0 as u32;
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;

    unsafe {
        // First call with null buffer to learn required size.
        let mut size: u32 = 0;
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut size);
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let ret = GetAdaptersAddresses(family, flags, None, Some(head), &mut size);
        if ret != 0 {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            let a = &*cur;
            out.push(convert_adapter(a));
            cur = a.Next;
        }
        out
    }
}

unsafe fn convert_adapter(a: &IP_ADAPTER_ADDRESSES_LH) -> Adapter {
    let friendly_name = read_pwstr(a.FriendlyName.0);
    let description = read_pwstr(a.Description.0);

    let mut mac = [0u8; 6];
    let mac_len = a.PhysicalAddressLength.min(6) as u8;
    for i in 0..mac_len as usize {
        mac[i] = a.PhysicalAddress[i];
    }

    let mut addresses: Vec<(IpAddr, u8)> = Vec::new();
    let mut ucur: *mut IP_ADAPTER_UNICAST_ADDRESS_LH = a.FirstUnicastAddress;
    while !ucur.is_null() {
        let u = &*ucur;
        if let Some(ip) = sockaddr_to_ip(&u.Address) {
            addresses.push((ip, u.OnLinkPrefixLength));
        }
        ucur = u.Next;
    }

    let mut gateways: Vec<IpAddr> = Vec::new();
    let mut gcur: *mut IP_ADAPTER_GATEWAY_ADDRESS_LH = a.FirstGatewayAddress;
    while !gcur.is_null() {
        let g = &*gcur;
        if let Some(ip) = sockaddr_to_ip(&g.Address) {
            gateways.push(ip);
        }
        gcur = g.Next;
    }

    let mut dns: Vec<IpAddr> = Vec::new();
    let mut dcur: *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP = a.FirstDnsServerAddress;
    while !dcur.is_null() {
        let d = &*dcur;
        if let Some(ip) = sockaddr_to_ip(&d.Address) {
            dns.push(ip);
        }
        dcur = d.Next;
    }

    let is_up = a.OperStatus == IfOperStatusUp;
    // TransmitLinkSpeed is in bits-per-second. Render as Mbps; treat
    // the canonical "unknown" sentinel as None.
    let link_speed_mbps = match a.TransmitLinkSpeed {
        0 | u64::MAX => None,
        bps => Some(bps / 1_000_000),
    };

    Adapter {
        friendly_name,
        description,
        mac,
        mac_len,
        addresses,
        gateways,
        dns_servers: dns,
        is_up,
        link_speed_mbps,
    }
}

unsafe fn sockaddr_to_ip(sa: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS) -> Option<IpAddr> {
    if sa.lpSockaddr.is_null() || sa.iSockaddrLength == 0 {
        return None;
    }
    let family = (*sa.lpSockaddr).sa_family;
    if family == AF_INET {
        if (sa.iSockaddrLength as usize) < std::mem::size_of::<SOCKADDR_IN>() {
            return None;
        }
        let sin = &*(sa.lpSockaddr as *const SOCKADDR_IN);
        // S_addr is u32 in network byte order; to_le_bytes gives those
        // four bytes in NBO sequence, which is exactly what Ipv4Addr
        // expects.
        let bytes = sin.sin_addr.S_un.S_addr.to_le_bytes();
        Some(IpAddr::V4(Ipv4Addr::from(bytes)))
    } else if family == AF_INET6 {
        if (sa.iSockaddrLength as usize) < std::mem::size_of::<SOCKADDR_IN6>() {
            return None;
        }
        let sin6 = &*(sa.lpSockaddr as *const SOCKADDR_IN6);
        let bytes = sin6.sin6_addr.u.Byte;
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

unsafe fn read_pwstr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 4096 { break; }
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

// ---------------------------------------------------------------------------
// TCP connection table — richer version of socket_table's snapshot
// ---------------------------------------------------------------------------

fn tcp_connections() -> Vec<TcpConnection> {
    let mut out = tcp_v4();
    out.extend(tcp_v6());
    out
}

fn tcp_v4() -> Vec<TcpConnection> {
    unsafe {
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(None, &mut size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr().cast::<c_void>()),
            &mut size,
            false,
            AF_INET.0 as u32,
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
            .map(|r| TcpConnection {
                local: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_le_bytes())),
                    (r.dwLocalPort as u16).swap_bytes(),
                ),
                remote: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_le_bytes())),
                    (r.dwRemotePort as u16).swap_bytes(),
                ),
                state: TcpState::from_raw(r.dwState),
                pid: r.dwOwningPid,
            })
            .collect()
    }
}

fn tcp_v6() -> Vec<TcpConnection> {
    unsafe {
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(None, &mut size, false, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr().cast::<c_void>()),
            &mut size,
            false,
            AF_INET6.0 as u32,
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
            .map(|r| TcpConnection {
                local: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    (r.dwLocalPort as u16).swap_bytes(),
                ),
                remote: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                    (r.dwRemotePort as u16).swap_bytes(),
                ),
                state: TcpState::from_raw(r.dwState),
                pid: r.dwOwningPid,
            })
            .collect()
    }
}

/// Pretty-print a MAC. Returns `"5c:e9:1e:..."`. Short MACs are padded
/// with `??`.
pub fn format_mac(mac: &[u8; 6], len: u8) -> String {
    let mut s = String::with_capacity(17);
    for i in 0..6 {
        if i > 0 {
            s.push(':');
        }
        if i < len as usize {
            s.push_str(&format!("{:02x}", mac[i]));
        } else {
            s.push_str("??");
        }
    }
    s
}
