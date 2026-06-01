//! TCP port probe + side-info gathering for a single host on the LAN.
//!
//! Spawns one thread per port from `COMMON_PORTS`, plus two extra
//! "side-info" threads: one for reverse DNS (hostname) and one for an
//! ICMP echo (TTL → OS-family hint and RTT). All workers share an
//! `Arc<Mutex<HostProbe>>` they fill in as results land. `completed_at`
//! is stamped exactly once when the *port* probe finishes; the side
//! info has its own per-task done flags so the UI can render partial
//! progress.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use watchdog_enrich::network_inspect;

/// Per-port TCP connect timeout.
const PORT_TIMEOUT: Duration = Duration::from_millis(500);
/// Single ICMP probe timeout for the side-info ping (OS hint + RTT).
const ICMP_TIMEOUT_MS: u32 = 800;

/// Service inventory we probe. ~110 ports covering the most common
/// LAN / IoT / server / dev services. Curated, not exhaustive.
pub const COMMON_PORTS: &[(u16, &str)] = &[
    (20,   "FTP-Data"),
    (21,   "FTP"),
    (22,   "SSH"),
    (23,   "Telnet"),
    (25,   "SMTP"),
    (53,   "DNS"),
    (67,   "DHCP"),
    (68,   "DHCP"),
    (69,   "TFTP"),
    (80,   "HTTP"),
    (88,   "Kerberos"),
    (110,  "POP3"),
    (111,  "RPC"),
    (113,  "Ident"),
    (119,  "NNTP"),
    (123,  "NTP"),
    (135,  "MS-RPC"),
    (137,  "NetBIOS-NS"),
    (138,  "NetBIOS-DGM"),
    (139,  "NetBIOS-SSN"),
    (143,  "IMAP"),
    (161,  "SNMP"),
    (179,  "BGP"),
    (199,  "SMUX"),
    (389,  "LDAP"),
    (427,  "SLP"),
    (443,  "HTTPS"),
    (445,  "SMB"),
    (465,  "SMTPS"),
    (513,  "rlogin"),
    (514,  "rsh"),
    (515,  "LPD"),
    (548,  "AFP"),
    (554,  "RTSP"),
    (587,  "SMTP-MSA"),
    (631,  "IPP"),
    (636,  "LDAPS"),
    (873,  "rsync"),
    (902,  "VMware"),
    (993,  "IMAPS"),
    (995,  "POP3S"),
    (1080, "SOCKS"),
    (1194, "OpenVPN"),
    (1234, "VLC"),
    (1433, "MSSQL"),
    (1434, "MSSQL-Mon"),
    (1521, "Oracle"),
    (1701, "L2TP"),
    (1723, "PPTP"),
    (1883, "MQTT"),
    (1900, "UPnP"),
    (2000, "Cisco"),
    (2049, "NFS"),
    (2082, "cPanel"),
    (2083, "cPanel-SSL"),
    (2121, "FTP-alt"),
    (2222, "SSH-alt"),
    (2375, "Docker"),
    (2376, "Docker-TLS"),
    (3128, "Squid"),
    (3260, "iSCSI"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (3478, "STUN"),
    (3690, "SVN"),
    (4443, "HTTPS-alt"),
    (4500, "IPsec-NAT"),
    (4848, "GlassFish"),
    (5000, "UPnP-alt"),
    (5060, "SIP"),
    (5061, "SIPS"),
    (5222, "XMPP"),
    (5269, "XMPP-S2S"),
    (5353, "mDNS"),
    (5357, "WSD"),
    (5432, "PostgreSQL"),
    (5555, "Android-ADB"),
    (5601, "Kibana"),
    (5800, "VNC-HTTP"),
    (5900, "VNC"),
    (5984, "CouchDB"),
    (6379, "Redis"),
    (6443, "Kubernetes"),
    (6667, "IRC"),
    (7000, "WebApp"),
    (7474, "Neo4j"),
    (8000, "HTTP-alt"),
    (8008, "HTTP-alt"),
    (8009, "Tomcat-AJP"),
    (8080, "HTTP-alt"),
    (8081, "HTTP-alt"),
    (8086, "InfluxDB"),
    (8088, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (8888, "HTTP-alt"),
    (9000, "PHP-FPM"),
    (9001, "Tor"),
    (9100, "Printer"),
    (9200, "Elasticsearch"),
    (9418, "Git"),
    (9999, "Misc"),
    (10000,"Webmin"),
    (11211,"Memcached"),
    (15672,"RabbitMQ"),
    (25565,"Minecraft"),
    (27017,"MongoDB"),
    (32400,"Plex"),
    (49152,"Win-RPC"),
    (49153,"Win-RPC"),
    (49154,"Win-RPC"),
];

#[derive(Debug)]
pub struct HostProbe {
    pub ip: IpAddr,
    pub started_at: Instant,
    /// Frozen completion timestamp for the *port* probe. None until
    /// every port has been probed.
    pub port_completed_at: Option<Instant>,
    pub probed: u32,
    pub total: u32,
    pub open_ports: Vec<u16>,

    /// Reverse-DNS resolution. `hostname_done == true` even if we got
    /// `None`, so the UI can stop showing "looking up…".
    pub hostname: Option<String>,
    pub hostname_done: bool,

    /// One-shot ICMP echo result. None means timeout / not reachable
    /// via ICMP (some hosts block it). RTT is provided in ms by the
    /// ICMP API; TTL drives the OS-family guess.
    pub icmp_ttl: Option<u8>,
    pub icmp_rtt_ms: Option<u32>,
    pub icmp_done: bool,
}

impl HostProbe {
    pub fn progress(&self) -> (u32, u32) {
        (self.probed, self.total)
    }

    /// Wall time the port probe took, frozen on completion. While in
    /// flight, the live elapsed time since start.
    pub fn elapsed_ms(&self) -> u128 {
        match self.port_completed_at {
            Some(end) => end.duration_since(self.started_at).as_millis(),
            None      => self.started_at.elapsed().as_millis(),
        }
    }

    pub fn completed(&self) -> bool {
        self.port_completed_at.is_some()
    }
}

/// Kick off port probe + hostname lookup + ICMP probe in parallel.
pub fn spawn(ip: IpAddr) -> Arc<Mutex<HostProbe>> {
    let probe = Arc::new(Mutex::new(HostProbe {
        ip,
        started_at: Instant::now(),
        port_completed_at: None,
        probed: 0,
        total: COMMON_PORTS.len() as u32,
        open_ports: Vec::new(),
        hostname: None,
        hostname_done: false,
        icmp_ttl: None,
        icmp_rtt_ms: None,
        icmp_done: false,
    }));

    let remaining = Arc::new(AtomicUsize::new(COMMON_PORTS.len()));

    for &(port, _name) in COMMON_PORTS {
        let probe = Arc::clone(&probe);
        let remaining = Arc::clone(&remaining);
        std::thread::Builder::new()
            .name(format!("watchdog-probe-{port}"))
            .spawn(move || {
                let addr = SocketAddr::new(ip, port);
                let is_open = TcpStream::connect_timeout(&addr, PORT_TIMEOUT).is_ok();
                {
                    let mut p = probe.lock().unwrap();
                    p.probed += 1;
                    if is_open {
                        p.open_ports.push(port);
                    }
                }
                let was = remaining.fetch_sub(1, Ordering::SeqCst);
                if was == 1 {
                    let mut p = probe.lock().unwrap();
                    p.open_ports.sort_unstable();
                    p.port_completed_at = Some(Instant::now());
                }
            })
            .ok();
    }

    // Reverse-DNS worker (only IPv4 for now; IPv6 PTR works the same
    // way but our reverse_dns helper is v4-only).
    if let IpAddr::V4(v4) = ip {
        let probe = Arc::clone(&probe);
        std::thread::Builder::new()
            .name("watchdog-probe-dns".into())
            .spawn(move || {
                let name = network_inspect::reverse_dns_v4(v4);
                let mut p = probe.lock().unwrap();
                p.hostname = name;
                p.hostname_done = true;
            })
            .ok();
    } else {
        probe.lock().unwrap().hostname_done = true;
    }

    // ICMP side-info: one echo, capture TTL and RTT for the OS hint.
    if let IpAddr::V4(v4) = ip {
        let probe = Arc::clone(&probe);
        std::thread::Builder::new()
            .name("watchdog-probe-icmp".into())
            .spawn(move || {
                let reply = network_inspect::ping_v4_detailed(v4, ICMP_TIMEOUT_MS);
                let mut p = probe.lock().unwrap();
                if let Some(r) = reply {
                    p.icmp_ttl = Some(r.ttl);
                    p.icmp_rtt_ms = Some(r.rtt_ms);
                }
                p.icmp_done = true;
            })
            .ok();
    } else {
        probe.lock().unwrap().icmp_done = true;
    }

    probe
}

pub fn service_name(port: u16) -> Option<&'static str> {
    COMMON_PORTS.iter().find(|(p, _)| *p == port).map(|(_, n)| *n)
}
