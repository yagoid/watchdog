//! Per-IP reverse-DNS cache with lazy background resolution.
//!
//! The Network view's NEIGHBORS panel renders a row per IP every frame.
//! Doing `getnameinfo` synchronously on each render would freeze the
//! UI (the resolver can take seconds per host). Instead we keep a
//! `HashMap<IpAddr, ResolutionStatus>`: first time the UI asks for an
//! IP we mark it `Pending` and spawn a one-shot resolver thread.
//! Subsequent frames just read the current state.
//!
//! Cache is unbounded in size but in practice tops out at one entry
//! per LAN host (rarely > a few dozen).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use watchdog_enrich::network_inspect;

#[derive(Debug, Clone)]
pub enum ResolutionStatus {
    Pending,
    Resolved(String),
    NoRecord,
}

pub struct DnsCache {
    cache: Arc<Mutex<HashMap<IpAddr, ResolutionStatus>>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Look up the current resolution for `ip`. Returns immediately;
    /// the first call for a given IP also schedules a background
    /// resolver thread (the next call after it finishes will see the
    /// final `Resolved` / `NoRecord`).
    pub fn lookup(&self, ip: IpAddr) -> ResolutionStatus {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(s) = cache.get(&ip) {
                return s.clone();
            }
        }
        // Not yet seen: mark Pending and spawn a worker. We only have
        // an IPv4 reverse helper today; IPv6 just stays `NoRecord` so
        // the UI shows nothing for it.
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(ip, ResolutionStatus::Pending);
        }
        let cache = Arc::clone(&self.cache);
        std::thread::Builder::new()
            .name("watchdog-rdns".into())
            .spawn(move || {
                let name = match ip {
                    IpAddr::V4(v4) => network_inspect::reverse_dns_v4(v4),
                    IpAddr::V6(_)  => None,
                };
                let status = name
                    .map(ResolutionStatus::Resolved)
                    .unwrap_or(ResolutionStatus::NoRecord);
                cache.lock().unwrap().insert(ip, status);
            })
            .ok();
        ResolutionStatus::Pending
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}
