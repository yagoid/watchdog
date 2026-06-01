//! In-memory state for the TUI: bounded scored-event ring buffer,
//! current selection (anchored to a stable sequence number, not an
//! index), filter (text + regex + source + min-score), pause flag,
//! stats, export feedback.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use crossterm::event::{KeyCode, KeyModifiers};

use watchdog_core::{EventPayload, EventSource, ProcessInfo, ScoredEvent, Severity};
use watchdog_detect::Baseline;
use watchdog_enrich::network_inspect::{self, DiscoverState, NetworkSnapshot};
use watchdog_enrich::ProcessTable;

#[cfg(windows)]
use crate::defenses::{classify_vpn_adapter, DefensesSnapshot, VpnStatus};
use crate::dns_cache::DnsCache;
use crate::export;
use crate::host_probe::{self, HostProbe};
use crate::incidents::Incidents;
use crate::network_footprint::NetworkFootprint;

const BUFFER_CAP: usize = 50_000;
const DEFAULT_MIN_SCORE: f32 = 0.30; // matches the plan default — hides "Quiet" noise
const SCORE_STEP: f32 = 0.05;
/// Score below which events are considered "noise" — when the buffer
/// is full and a new event needs space, we evict the *oldest noise*
/// event instead of the oldest event overall. The effect: a 5-second
/// burst of `ImageLoad` events from a Defender scan no longer wipes
/// the `WARN powershell.exe -EncodedCommand` from 20 min ago.
const SIGNAL_THRESHOLD: f32 = 0.30;
/// How long the "saved: <path>" badge stays visible after `x`.
const EXPORT_BADGE_TTL: Duration = Duration::from_secs(5);
/// Network snapshot cache age before we re-query iphlpapi.dll.
const NET_SNAPSHOT_TTL: Duration = Duration::from_secs(3);
/// Defenses snapshot cache age. Defender / firewall config doesn't
/// change minute-to-minute, so this can be cheap and slow.
const DEFENSES_TTL: Duration = Duration::from_secs(60);
/// WiFi scan refresh interval. The OS itself only does an active scan
/// every ~30s, so any faster is wasted.
const WIFI_TTL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct BufferedEvent {
    pub seq: u64,
    pub event: ScoredEvent,
}

/// Top-level pages: consumer-facing Summary, analyst Raw feed,
/// Network inspector, and Offensive toolkit (lab-use tools — WiFi
/// scan today, more later). `r` / `n` / `o` toggle Raw / Network /
/// Offensive; each returns to Summary when pressed again from its
/// own page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Summary,
    Raw,
    Network,
    Offensive,
}

/// Counters and sets we keep for the "Today" block at the top of the
/// Summary view. Reset only on process restart.
#[derive(Debug, Default)]
pub struct DailyStats {
    pub proc_starts: u64,
    pub crit_count: u64,
    pub warn_count: u64,
    pub info_count: u64,
    pub distinct_images: HashSet<String>,
}

/// Outcome of the last export operation. Drives the inline badge in
/// the filter bar; auto-expires after `EXPORT_BADGE_TTL`.
pub enum ExportStatus {
    Ok(PathBuf, Instant),
    Err(String, Instant),
}

impl ExportStatus {
    fn age(&self) -> Duration {
        match self {
            ExportStatus::Ok(_, t) | ExportStatus::Err(_, t) => t.elapsed(),
        }
    }
}

pub struct App {
    rx: Receiver<ScoredEvent>,
    pub table: Arc<ProcessTable>,
    pub baseline: Arc<Baseline>,
    pub learn_only: bool,
    pub buffer: VecDeque<BufferedEvent>,
    next_seq: u64,
    pub selected_seq: Option<u64>,
    pub paused: bool,
    pub filter: String,
    pub filter_editing: bool,
    pub min_score: f32,
    pub source_filter: Option<EventSource>,
    pub should_quit: bool,
    pub stats: Stats,
    pub dropped_etw: Arc<AtomicU64>,
    pub export_status: Option<ExportStatus>,
    /// Which top-level view is showing. Defaults to Summary so a
    /// non-analyst opening the app sees a verdict, not a firehose.
    pub view: ViewMode,
    pub incidents: Incidents,
    pub daily: DailyStats,
    /// Most recent network state snapshot. Refreshed lazily in
    /// `tick_stats` only when the Network view is active.
    pub network_snapshot: Option<NetworkSnapshot>,
    /// Identity of the selected neighbor in the Network view —
    /// stable across snapshot refreshes (we key by IP, not row index).
    pub network_selected_ip: Option<IpAddr>,
    /// In-flight ICMP sweep, if any. `None` once dismissed; the
    /// state itself reports `done()` while still kept around so the
    /// UI can render "scan complete, N hosts" briefly.
    pub discover_state: Option<Arc<DiscoverState>>,
    /// Per-host TCP probes. Populated by `Enter` on a neighbor.
    pub host_probes: HashMap<IpAddr, Arc<Mutex<HostProbe>>>,
    /// Vertical scroll offset for the HOST DETAIL panel (in rows).
    /// Reset to 0 whenever the selection changes.
    pub host_detail_scroll: u16,
    /// Vertical scroll offset for the TCP CONNECTIONS panel (used
    /// when no neighbor is selected so HOST DETAIL isn't on screen).
    pub tcp_scroll: u16,
    /// Vertical scroll offset for the INTERFACES panel.
    pub interfaces_scroll: u16,

    /// Rolling counters about network behaviour since session start
    /// — powers the NETWORK FOOTPRINT panel in the Summary view.
    pub footprint: NetworkFootprint,
    /// Async reverse-DNS cache. Populated lazily as the UI iterates
    /// over the NEIGHBORS panel.
    pub dns_cache: DnsCache,
    /// Cached WiFi scan results for the Offensive view. Refreshed on
    /// `tick_stats` when in that view; lazy elsewhere.
    pub wifi_snapshot: Option<(Vec<watchdog_enrich::wifi_scan::WifiNetwork>, Instant)>,
    /// SSID of the row currently selected in the OFFENSIVE / WIFI
    /// SCAN list. Selection identity is the SSID string — survives
    /// snapshot refreshes as long as that SSID still appears.
    pub wifi_selected_ssid: Option<String>,
    /// Cached read of the machine's defensive posture (Defender,
    /// firewall, UAC, last update). Refreshed every `DEFENSES_TTL`.
    #[cfg(windows)]
    pub defenses: Option<DefensesSnapshot>,
    #[cfg(windows)]
    defenses_refreshed_at: Option<Instant>,
}

pub struct Stats {
    pub started_at: Instant,
    pub events_total: u64,
    pub events_per_sec: u32,
    pub history: VecDeque<u64>,
    last_per_sec_ts: Instant,
    last_per_sec_count: u64,
}

const HISTORY_LEN: usize = 60;

impl App {
    pub fn new(
        rx: Receiver<ScoredEvent>,
        table: Arc<ProcessTable>,
        dropped_etw: Arc<AtomicU64>,
        baseline: Arc<Baseline>,
        learn_only: bool,
    ) -> Self {
        let now = Instant::now();
        Self {
            rx,
            table,
            baseline,
            learn_only,
            buffer: VecDeque::with_capacity(BUFFER_CAP),
            next_seq: 0,
            selected_seq: None,
            paused: false,
            filter: String::new(),
            filter_editing: false,
            min_score: DEFAULT_MIN_SCORE,
            source_filter: None,
            should_quit: false,
            stats: Stats {
                started_at: now,
                events_total: 0,
                events_per_sec: 0,
                history: VecDeque::with_capacity(HISTORY_LEN),
                last_per_sec_ts: now,
                last_per_sec_count: 0,
            },
            dropped_etw,
            export_status: None,
            view: ViewMode::Summary,
            incidents: Incidents::new(),
            daily: DailyStats::default(),
            network_snapshot: None,
            network_selected_ip: None,
            discover_state: None,
            host_probes: HashMap::new(),
            host_detail_scroll: 0,
            tcp_scroll: 0,
            interfaces_scroll: 0,
            footprint: NetworkFootprint::new(),
            dns_cache: DnsCache::new(),
            wifi_snapshot: None,
            wifi_selected_ssid: None,
            #[cfg(windows)]
            defenses: None,
            #[cfg(windows)]
            defenses_refreshed_at: None,
        }
    }

    pub fn ingest(&mut self) {
        let mut n: u64 = 0;
        while let Ok(ev) = self.rx.try_recv() {
            // Update daily counters before the event is moved into the buffer.
            self.update_daily(&ev);
            // Update network footprint counters for the Summary panel.
            self.footprint.observe(&ev);
            // Feed the incident aggregator. Below-threshold events return
            // without doing anything.
            self.incidents.ingest(&ev, self.next_seq);

            if self.buffer.len() == BUFFER_CAP {
                let popped = self.evict_one();
                if let (Some(sel_seq), Some(pp)) = (self.selected_seq, popped) {
                    if pp.seq == sel_seq {
                        self.selected_seq = None;
                    }
                }
            }
            let seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            self.buffer.push_back(BufferedEvent { seq, event: ev });
            n += 1;
        }
        self.stats.events_total += n;
    }

    /// Score-biased eviction. Walks the buffer from the front (oldest
    /// first) and removes the first noise-score event found. If the
    /// buffer is pure signal at the moment (unlikely but possible),
    /// falls back to evicting the oldest event regardless.
    ///
    /// Effect: alerted events have *effectively unbounded* retention
    /// while the buffer self-trims noise. Per-event cost is O(N)
    /// worst-case but typically O(few) because the front of the deque
    /// is the oldest events, which are the most likely to be noise.
    fn evict_one(&mut self) -> Option<BufferedEvent> {
        let idx = self
            .buffer
            .iter()
            .position(|b| b.event.score < SIGNAL_THRESHOLD);
        match idx {
            Some(i) => self.buffer.remove(i),
            None    => self.buffer.pop_front(),
        }
    }

    fn update_daily(&mut self, ev: &ScoredEvent) {
        match ev.severity {
            Severity::Crit  => self.daily.crit_count += 1,
            Severity::Warn  => self.daily.warn_count += 1,
            Severity::Info  => self.daily.info_count += 1,
            Severity::Quiet => {}
        }
        if matches!(ev.enriched.raw.payload, EventPayload::ProcessStart { .. }) {
            self.daily.proc_starts += 1;
            if let Some(p) = &ev.enriched.process {
                self.daily.distinct_images.insert(p.image_name.clone());
            }
        }
    }

    pub fn tick_stats(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.stats.last_per_sec_ts);
        if elapsed >= Duration::from_millis(1000) {
            let delta = self.stats.events_total - self.stats.last_per_sec_count;
            self.stats.events_per_sec = (delta as f64 / elapsed.as_secs_f64()).round() as u32;
            self.stats.last_per_sec_count = self.stats.events_total;
            self.stats.last_per_sec_ts = now;

            if self.stats.history.len() == HISTORY_LEN {
                self.stats.history.pop_front();
            }
            self.stats.history.push_back(self.stats.events_per_sec as u64);
        }

        // Expire the export badge.
        if let Some(s) = &self.export_status {
            if s.age() > EXPORT_BADGE_TTL {
                self.export_status = None;
            }
        }

        // Refresh the network snapshot if the user is currently on the
        // Network view and it's older than NET_SNAPSHOT_TTL. We don't
        // do it from inside the renderer because that takes `&App`.
        if self.view == ViewMode::Network {
            let stale = self
                .network_snapshot
                .as_ref()
                .map_or(true, |s| s.captured_at.elapsed() > NET_SNAPSHOT_TTL);
            if stale {
                self.network_snapshot = Some(network_inspect::snapshot());
            }
        }

        // Refresh the WiFi snapshot when on the Offensive view.
        if self.view == ViewMode::Offensive {
            let stale = self
                .wifi_snapshot
                .as_ref()
                .map_or(true, |(_, t)| t.elapsed() > WIFI_TTL);
            if stale {
                let nets = watchdog_enrich::wifi_scan::scan();
                self.wifi_snapshot = Some((nets, Instant::now()));
            }
        }

        // Refresh the defenses snapshot when stale. Defender / firewall
        // config is slow-changing so a 60-second cadence is plenty.
        #[cfg(windows)]
        {
            let stale = self
                .defenses_refreshed_at
                .map_or(true, |t| t.elapsed() > DEFENSES_TTL);
            if stale && self.view == ViewMode::Summary {
                let mut snap = DefensesSnapshot::read();
                snap.defender_process_seen = self.table.contains_image("msmpeng.exe");
                snap.vpn_status = detect_vpn();
                self.defenses = Some(snap);
                self.defenses_refreshed_at = Some(Instant::now());
            }
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped_etw.load(Ordering::Relaxed)
    }

    pub fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        if matches!(code, KeyCode::Char('c')) && mods.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return;
        }

        if self.filter_editing {
            match code {
                KeyCode::Esc => self.filter_editing = false,
                KeyCode::Enter => self.filter_editing = false,
                KeyCode::Backspace => { self.filter.pop(); }
                KeyCode::Char(c) if !mods.contains(KeyModifiers::CONTROL) => {
                    // Keep literal case: regex inside `/.../` is case-sensitive
                    // by convention; substring matching lowercases the
                    // haystack to do case-insensitive matching, so we
                    // lowercase the needle on the way in too.
                    if self.filter.starts_with('/') {
                        self.filter.push(c);
                    } else {
                        self.filter.push(c.to_ascii_lowercase());
                    }
                }
                _ => {}
            }
            if !matches!(code, KeyCode::Esc | KeyCode::Enter) {
                self.selected_seq = None;
            }
            return;
        }

        // Global keys (work from any view).
        match code {
            KeyCode::Char('q') => { self.should_quit = true; return; }
            KeyCode::Char('p') => { self.paused = !self.paused; return; }
            KeyCode::Char('r') => { self.toggle_view_raw(); return; }
            KeyCode::Char('n') => { self.toggle_view_network(); return; }
            KeyCode::Char('o') => { self.toggle_view_offensive(); return; }
            _ => {}
        }

        // View-specific keys.
        match (self.view, code) {
            // ---- Offensive view ----
            (ViewMode::Offensive, KeyCode::Down) | (ViewMode::Offensive, KeyCode::Char('j')) => {
                self.wifi_move(1);
            }
            (ViewMode::Offensive, KeyCode::Up) | (ViewMode::Offensive, KeyCode::Char('k')) => {
                self.wifi_move(-1);
            }
            (ViewMode::Offensive, KeyCode::Esc) => self.wifi_selected_ssid = None,

            // ---- Network view ----
            // Shift+↑/↓ scrolls the INTERFACES panel — has to come
            // before the plain ↑/↓ arms or match would shadow it.
            (ViewMode::Network, KeyCode::Down) if mods.contains(KeyModifiers::SHIFT) => {
                self.interfaces_scroll = self.interfaces_scroll.saturating_add(1);
            }
            (ViewMode::Network, KeyCode::Up) if mods.contains(KeyModifiers::SHIFT) => {
                self.interfaces_scroll = self.interfaces_scroll.saturating_sub(1);
            }
            (ViewMode::Network, KeyCode::Down) | (ViewMode::Network, KeyCode::Char('j')) => {
                self.network_move(1);
            }
            (ViewMode::Network, KeyCode::Up) | (ViewMode::Network, KeyCode::Char('k')) => {
                self.network_move(-1);
            }
            // PageUp/Down scroll the right-side panel: HOST DETAIL when
            // a neighbor is selected, otherwise TCP CONNECTIONS.
            (ViewMode::Network, KeyCode::PageDown) => {
                if self.network_selected_ip.is_some() {
                    self.host_detail_scroll = self.host_detail_scroll.saturating_add(5);
                } else {
                    self.tcp_scroll = self.tcp_scroll.saturating_add(5);
                }
            }
            (ViewMode::Network, KeyCode::PageUp) => {
                if self.network_selected_ip.is_some() {
                    self.host_detail_scroll = self.host_detail_scroll.saturating_sub(5);
                } else {
                    self.tcp_scroll = self.tcp_scroll.saturating_sub(5);
                }
            }
            (ViewMode::Network, KeyCode::Char('d')) => self.start_discover(),
            (ViewMode::Network, KeyCode::Enter)    => self.probe_selected_host(),
            (ViewMode::Network, KeyCode::Esc)      => self.network_selected_ip = None,

            // ---- Raw view ----
            (ViewMode::Raw, KeyCode::Char('/')) => self.filter_editing = true,
            (ViewMode::Raw, KeyCode::Char('s')) => self.cycle_source_filter(),
            (ViewMode::Raw, KeyCode::Char('x')) => self.export(),
            (ViewMode::Raw, KeyCode::Char('[')) => self.adjust_min_score(-SCORE_STEP),
            (ViewMode::Raw, KeyCode::Char(']')) => self.adjust_min_score(SCORE_STEP),
            (ViewMode::Raw, KeyCode::Down) | (ViewMode::Raw, KeyCode::Char('j')) => {
                self.move_selection(1);
            }
            (ViewMode::Raw, KeyCode::Up) | (ViewMode::Raw, KeyCode::Char('k')) => {
                self.move_selection(-1);
            }
            (ViewMode::Raw, KeyCode::PageDown) => self.move_selection(10),
            (ViewMode::Raw, KeyCode::PageUp)   => self.move_selection(-10),
            (ViewMode::Raw, KeyCode::Char('G')) | (ViewMode::Raw, KeyCode::End) => {
                let seqs: Vec<u64> = self.filtered_iter().map(|b| b.seq).collect();
                self.selected_seq = seqs.last().copied();
            }
            (ViewMode::Raw, KeyCode::Char('g')) | (ViewMode::Raw, KeyCode::Home) => {
                let first = self.filtered_iter().next().map(|b| b.seq);
                self.selected_seq = first;
            }
            (ViewMode::Raw, KeyCode::Esc) => self.selected_seq = None,

            _ => {}
        }
    }

    fn network_move(&mut self, delta: i32) {
        let Some(snap) = self.network_snapshot.as_ref() else { return };
        // Mirror the UI's own filter so navigation matches what the
        // user can see.
        let mut sorted: Vec<IpAddr> = snap
            .neighbors
            .iter()
            .filter(|n| network_inspect_neighbor_visible(n))
            .map(|n| n.ip)
            .collect();
        if sorted.is_empty() {
            self.network_selected_ip = None;
            return;
        }
        sorted.sort_by(|a, b| a.is_ipv4().cmp(&b.is_ipv4()).reverse().then(a.cmp(b)));
        let len = sorted.len();
        let cur = self
            .network_selected_ip
            .and_then(|ip| sorted.iter().position(|x| *x == ip))
            .unwrap_or(0);
        let new = (cur as i64 + delta as i64).clamp(0, (len - 1) as i64) as usize;
        let new_ip = sorted[new];
        // Selection changed → reset host detail scroll so the new host's
        // info starts at the top of the panel.
        if self.network_selected_ip != Some(new_ip) {
            self.host_detail_scroll = 0;
        }
        self.network_selected_ip = Some(new_ip);
    }

    fn start_discover(&mut self) {
        // Don't restart while one is still running.
        if let Some(s) = &self.discover_state {
            if !s.done() {
                return;
            }
        }
        if let Some((addr, prefix)) = network_inspect::primary_subnet_v4() {
            self.discover_state = network_inspect::start_discover(addr, prefix);
        }
    }

    fn probe_selected_host(&mut self) {
        let Some(ip) = self.network_selected_ip else { return };
        // Don't re-probe if we already have a recent result for this host.
        if let Some(existing) = self.host_probes.get(&ip) {
            let p = existing.lock().unwrap();
            if !p.completed() || p.started_at.elapsed() < Duration::from_secs(30) {
                return;
            }
        }
        let probe = host_probe::spawn(ip);
        self.host_probes.insert(ip, probe);
    }

    fn export(&mut self) {
        self.export_status = Some(match export::write_visible(self) {
            Ok(path) => ExportStatus::Ok(path, Instant::now()),
            Err(e) => ExportStatus::Err(e.to_string(), Instant::now()),
        });
    }

    fn toggle_view_raw(&mut self) {
        self.view = match self.view {
            ViewMode::Raw => ViewMode::Summary,
            _             => ViewMode::Raw,
        };
    }

    fn toggle_view_network(&mut self) {
        self.view = match self.view {
            ViewMode::Network => ViewMode::Summary,
            _                 => ViewMode::Network,
        };
    }

    fn toggle_view_offensive(&mut self) {
        self.view = match self.view {
            ViewMode::Offensive => ViewMode::Summary,
            _                   => ViewMode::Offensive,
        };
    }

    fn wifi_move(&mut self, delta: i32) {
        let Some((nets, _)) = self.wifi_snapshot.as_ref() else { return };
        if nets.is_empty() {
            self.wifi_selected_ssid = None;
            return;
        }
        let cur = self
            .wifi_selected_ssid
            .as_ref()
            .and_then(|ssid| nets.iter().position(|n| &n.ssid == ssid))
            .unwrap_or(0);
        let new = (cur as i64 + delta as i64).clamp(0, (nets.len() - 1) as i64) as usize;
        self.wifi_selected_ssid = Some(nets[new].ssid.clone());
    }

    fn adjust_min_score(&mut self, delta: f32) {
        self.min_score = (self.min_score + delta).clamp(0.0, 1.0);
        self.min_score = (self.min_score / SCORE_STEP).round() * SCORE_STEP;
    }

    fn cycle_source_filter(&mut self) {
        use EventSource::*;
        self.source_filter = match self.source_filter {
            None             => Some(Process),
            Some(Process)    => Some(File),
            Some(File)       => Some(Registry),
            Some(Registry)   => Some(Network),
            Some(Network)    => Some(Dns),
            Some(Dns)        => Some(Usb),
            Some(Usb)        => Some(Wmi),
            Some(Wmi)        => None,
        };
    }

    fn move_selection(&mut self, delta: i32) {
        let seqs: Vec<u64> = self.filtered_iter().map(|b| b.seq).collect();
        let len = seqs.len();
        if len == 0 {
            self.selected_seq = None;
            return;
        }
        let cur_pos = self
            .selected_seq
            .and_then(|seq| seqs.iter().position(|s| *s == seq))
            .unwrap_or(len.saturating_sub(1));
        let new_pos = (cur_pos as i64 + delta as i64).clamp(0, (len - 1) as i64) as usize;
        self.selected_seq = Some(seqs[new_pos]);
    }

    pub fn filtered_len(&self) -> usize {
        self.filtered_iter().count()
    }

    pub fn filtered_iter(&self) -> Box<dyn Iterator<Item = &BufferedEvent> + '_> {
        let matcher = Matcher::build(&self.filter);
        let min_score = self.min_score;
        let source_filter = self.source_filter;
        Box::new(
            self.buffer
                .iter()
                .filter(move |b| passes_filter(&b.event, source_filter, &matcher, min_score)),
        )
    }

    pub fn selected_position(&self) -> Option<usize> {
        let seq = self.selected_seq?;
        self.filtered_iter().position(|b| b.seq == seq)
    }

    pub fn selected_event(&self) -> Option<&ScoredEvent> {
        let seq = self.selected_seq?;
        self.filtered_iter().find_map(|b| if b.seq == seq { Some(&b.event) } else { None })
    }

    pub fn ancestry(&self, pid: u32) -> Vec<Arc<ProcessInfo>> {
        let mut chain = Vec::new();
        let mut current = pid;
        for _ in 0..16 {
            match self.table.lookup(current) {
                Some(info) => {
                    let next = info.ppid;
                    let same = next == current;
                    chain.push(info);
                    if next == 0 || same { break; }
                    current = next;
                }
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    /// Convenience for the UI: `true` if the current filter is a valid
    /// regex (so the filter bar can hint at it). `/.../`  syntax only.
    pub fn filter_is_regex(&self) -> bool {
        matches!(Matcher::build(&self.filter), Matcher::Regex(_))
    }
}

/// One of three matching strategies derived from `filter`:
/// - `None`        — show everything
/// - `Substring`   — case-insensitive substring (default)
/// - `Regex`       — `/.../` syntax, case-sensitive
enum Matcher {
    None,
    Substring(String),
    Regex(regex::Regex),
}

impl Matcher {
    fn build(filter: &str) -> Self {
        if filter.is_empty() {
            return Matcher::None;
        }
        if filter.len() >= 2 && filter.starts_with('/') && filter.ends_with('/') {
            let pattern = &filter[1..filter.len() - 1];
            if pattern.is_empty() {
                return Matcher::None;
            }
            if let Ok(re) = regex::Regex::new(pattern) {
                return Matcher::Regex(re);
            }
            // Bad regex: don't surface an error, fall back to literal
            // substring match on the user's typed string. They'll see
            // mismatched results which is its own signal.
        }
        Matcher::Substring(filter.to_string())
    }
}

fn passes_filter(
    ev: &ScoredEvent,
    source_filter: Option<EventSource>,
    matcher: &Matcher,
    min_score: f32,
) -> bool {
    if ev.score < min_score {
        return false;
    }
    if let Some(src) = source_filter {
        if ev.enriched.raw.src != src {
            return false;
        }
    }
    match matcher {
        Matcher::None => true,
        Matcher::Substring(needle) => substring_match(ev, needle),
        Matcher::Regex(re) => regex_match(ev, re),
    }
}

fn substring_match(ev: &ScoredEvent, needle: &str) -> bool {
    if let Some(p) = &ev.enriched.process {
        if p.image_name.contains(needle) { return true; }
        if p.image_path.to_string_lossy().to_ascii_lowercase().contains(needle) { return true; }
        if p.cmdline.to_ascii_lowercase().contains(needle) { return true; }
    }
    if let Some(p) = &ev.enriched.parent {
        if p.image_name.contains(needle) { return true; }
    }
    false
}

/// Walk the current adapter list and return `VpnStatus` based on which
/// (if any) tunnel-client adapter looks present. "Active" = matched
/// description + adapter is up + has an IP. "Inactive" = matched
/// description but no IP / not up (client installed, not connected).
#[cfg(windows)]
fn detect_vpn() -> VpnStatus {
    let adapters = watchdog_enrich::network_inspect::adapters();
    // First pass: an *active* tunnel beats any inactive one.
    let mut inactive: Option<String> = None;
    for a in &adapters {
        if let Some(name) = classify_vpn_adapter(&a.description) {
            if a.is_up && !a.addresses.is_empty() {
                return VpnStatus::Active(name.to_string());
            }
            inactive.get_or_insert_with(|| name.to_string());
        }
    }
    match inactive {
        Some(n) => VpnStatus::Inactive(n),
        None    => VpnStatus::None,
    }
}

/// Predicate the UI and the App both use to decide whether an ARP/NDP
/// entry is worth showing. After a `d` sweep, Windows leaves entries
/// for IPs that *didn't* respond in `INCOMPLETE` state with a zero
/// MAC. Those are confirmed-absent hosts; hiding them keeps the
/// NEIGHBORS panel honest.
pub fn network_inspect_neighbor_visible(
    n: &watchdog_enrich::network_inspect::Neighbor,
) -> bool {
    use watchdog_enrich::network_inspect::NeighborState;
    if matches!(n.state, NeighborState::Incomplete | NeighborState::Unreachable) {
        return false;
    }
    if n.mac_len == 0 || n.mac.iter().all(|b| *b == 0) {
        return false;
    }
    true
}

fn regex_match(ev: &ScoredEvent, re: &regex::Regex) -> bool {
    if let Some(p) = &ev.enriched.process {
        if re.is_match(&p.image_name) { return true; }
        if re.is_match(&p.image_path.to_string_lossy()) { return true; }
        if re.is_match(&p.cmdline) { return true; }
    }
    if let Some(p) = &ev.enriched.parent {
        if re.is_match(&p.image_name) { return true; }
    }
    false
}
