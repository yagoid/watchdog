//! Render the TUI in the "Bracket Frame" style: corner-only frames,
//! sparkline in the header, severity colours pulled from the new palette.

use std::time::SystemTime;

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Sparkline, Wrap};
use ratatui::Frame;

use chrono::{DateTime, Local};
use watchdog_core::{EventPayload, EventSource, ScoredEvent, Severity};

use crate::app::{App, ViewMode};
use crate::bracket_frame::{title_line, BracketFrame};
use crate::incidents::{pretty_ago, Incident, Verdict};
use crate::theme::*;

const CMDLINE_DISPLAY_LIMIT: usize = 200;

pub fn render(f: &mut Frame, app: &App) {
    match app.view {
        ViewMode::Summary   => render_summary(f, app),
        ViewMode::Raw       => render_raw(f, app),
        ViewMode::Network   => render_network(f, app),
        ViewMode::Offensive => render_offensive(f, app),
    }
}

// ---------------------------------------------------------------------------
// Offensive view — lab-use tools. Today: nearby WiFi networks. The
// view is read-only; we display what the OS's WLAN service has
// already cached (it refreshes every ~30s on its own).
// ---------------------------------------------------------------------------

fn render_offensive(f: &mut Frame, app: &App) {
    let area = f.area();
    let root = Layout::vertical([
        Constraint::Length(3),  // header
        Constraint::Min(8),     // panels
        Constraint::Length(1),  // hint
    ])
    .split(area);

    // Header
    let title = Line::from(vec![
        Span::styled("WATCHDOG", Style::new().fg(BRACKET).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled("OFFENSIVE", Style::new().fg(RED).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled("lab use only", Style::new().fg(DIM)),
    ]);
    let right = match app.wifi_snapshot.as_ref() {
        Some((nets, _)) => Line::from(vec![
            Span::styled("wifi  ", Style::new().fg(DIM)),
            Span::styled(format!("{} SSIDs", nets.len()), Style::new().fg(FG_BRIGHT)),
        ]),
        None => Line::from(Span::styled("scanning wifi…", Style::new().fg(DIM))),
    };
    f.render_widget(
        BracketFrame::new().title(title).title_right(right).color(RED),
        root[0],
    );

    // Two columns when a network is selected; full-width list otherwise.
    if app.wifi_selected_ssid.is_some() {
        let cols = Layout::horizontal([
            Constraint::Percentage(55),
            Constraint::Percentage(45),
        ])
        .split(root[1]);
        render_wifi_panel(f, cols[0], app);
        render_wifi_detail(f, cols[1], app);
    } else {
        render_wifi_panel(f, root[1], app);
    }
    render_hint(f, root[2], app);
}

fn render_wifi_panel(f: &mut Frame, area: Rect, app: &App) {
    use watchdog_enrich::wifi_scan::WifiEncryption;

    let frame = BracketFrame::new().title(title_line("WIFI SCAN", Some("↑↓/jk")));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some((nets, _)) = app.wifi_snapshot.as_ref() else {
        let p = Paragraph::new(
            "Waiting for WLAN service data. If there is no WiFi adapter \
             on this machine, this panel stays empty.",
        )
        .style(Style::new().fg(DIM))
        .wrap(Wrap { trim: false });
        f.render_widget(p, inner);
        return;
    };

    if nets.is_empty() {
        let p = Paragraph::new(
            "No WiFi networks visible. Your adapter may be off or the WLAN \
             service unavailable. If you don't expect WiFi on this machine \
             (wired PC), this is normal.",
        )
        .style(Style::new().fg(DIM))
        .wrap(Wrap { trim: false });
        f.render_widget(p, inner);
        return;
    }

    // Column widths: SSID 32, SIGNAL 14 (e.g. "100% ▁▂▃▄▅" + buffer),
    // ENCRYPT 9 ("WPA3" + buffer), FLAGS = rest.
    let header = Line::from(vec![
        Span::styled(format!("{:<32} ", "SSID"),    Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<14} ", "SIGNAL"),  Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<9} ", "ENCRYPT"),  Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled("FLAGS",                        Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
    ]);

    let selected_pos = app
        .wifi_selected_ssid
        .as_ref()
        .and_then(|ssid| nets.iter().position(|n| &n.ssid == ssid));

    let items: Vec<ListItem> = nets
        .iter()
        .map(|n| {
            let ssid_text = if n.ssid.is_empty() {
                "(hidden)".to_string()
            } else {
                n.ssid.clone()
            };
            let signal_bars = signal_bars(n.signal_pct);
            let signal_text = format!("{:>3}% {}", n.signal_pct, signal_bars);
            let enc_color = match n.encryption {
                WifiEncryption::Open  => RED,
                WifiEncryption::Wep   => RED,
                WifiEncryption::Wpa   => ORANGE,
                WifiEncryption::Wpa2  => GREEN,
                WifiEncryption::Wpa3  => GREEN,
                WifiEncryption::Other => DIM,
            };
            let flags = {
                let mut parts: Vec<&'static str> = Vec::new();
                if n.connected     { parts.push("CONNECTED"); }
                if n.saved_profile { parts.push("saved"); }
                parts.join(" · ")
            };
            let row_color = if n.connected { FG_BRIGHT } else { FG };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<32} ", truncate(&ssid_text, 31)), Style::new().fg(row_color)),
                Span::styled(format!("{:<14} ", signal_text),               Style::new().fg(signal_color(n.signal_pct))),
                Span::styled(format!("{:<9} ", n.encryption.label()),       Style::new().fg(enc_color).add_modifier(Modifier::BOLD)),
                Span::styled(flags,                                          if n.connected { Style::new().fg(GREEN).add_modifier(Modifier::BOLD) } else { Style::new().fg(MAGENTA) }),
            ]))
        })
        .collect();

    let header_area = Rect { x: inner.x, y: inner.y, width: inner.width, height: 1 };
    let list_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: inner.height.saturating_sub(1),
    };
    f.render_widget(Paragraph::new(header), header_area);

    let mut state = ListState::default();
    if let Some(pos) = selected_pos {
        state.select(Some(pos));
    }
    let list = List::new(items)
        .highlight_style(Style::new().bg(SELECT_BG).fg(FG_BRIGHT).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, list_area, &mut state);
}

fn render_wifi_detail(f: &mut Frame, area: Rect, app: &App) {
    use watchdog_enrich::wifi_scan::{signal_quality_to_dbm, WifiEncryption};

    let Some(sel_ssid) = app.wifi_selected_ssid.as_ref() else { return };
    let net = app
        .wifi_snapshot
        .as_ref()
        .and_then(|(nets, _)| nets.iter().find(|n| &n.ssid == sel_ssid));

    let display_ssid = if sel_ssid.is_empty() {
        "(hidden)".to_string()
    } else {
        sel_ssid.clone()
    };
    let title = Line::from(vec![
        Span::styled("WIFI", Style::new().fg(BRACKET).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(display_ssid.clone(), Style::new().fg(FG_BRIGHT).add_modifier(Modifier::BOLD)),
    ]);
    let frame = BracketFrame::new().title(title);
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some(net) = net else {
        let p = Paragraph::new("This network no longer appears in the latest scan.")
            .style(Style::new().fg(DIM));
        f.render_widget(p, inner);
        return;
    };

    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(kv_styled("SSID", display_ssid.clone(), FG_BRIGHT));

    // Encryption row with both the friendly label and the underlying algorithm.
    let enc_color = match net.encryption {
        WifiEncryption::Open | WifiEncryption::Wep => RED,
        WifiEncryption::Wpa  => ORANGE,
        WifiEncryption::Wpa2 | WifiEncryption::Wpa3 => GREEN,
        WifiEncryption::Other => DIM,
    };
    lines.push(kv_styled(
        "Encryption",
        net.encryption.label().to_string(),
        enc_color,
    ));

    // Signal with dBm conversion.
    let dbm = signal_quality_to_dbm(net.signal_pct);
    lines.push(kv_styled(
        "Signal",
        format!("{}%  ≈ {} dBm  {}", net.signal_pct, dbm, signal_bars(net.signal_pct)),
        signal_color(net.signal_pct),
    ));

    lines.push(kv_styled(
        "Connected",
        if net.connected { "yes".to_string() } else { "no".to_string() },
        if net.connected { GREEN } else { DIM },
    ));

    let saved_text = if net.saved_profile {
        if net.profile_name.is_empty() {
            "yes".to_string()
        } else {
            format!("yes (profile \"{}\")", net.profile_name)
        }
    } else {
        "no".to_string()
    };
    lines.push(kv_styled("Saved profile", saved_text,
        if net.saved_profile { FG_BRIGHT } else { DIM },
    ));

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        " SECURITY",
        Style::new().fg(CYAN).add_modifier(Modifier::BOLD),
    )));
    let (sec_color, sec_lines) = encryption_explanation(net.encryption);
    for txt in sec_lines {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled(txt.to_string(), Style::new().fg(sec_color)),
        ]));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        " ATTACK SURFACE",
        Style::new().fg(RED).add_modifier(Modifier::BOLD),
    )));
    for tip in attack_surface(net.encryption) {
        lines.push(Line::from(vec![
            Span::raw("  · "),
            Span::styled(tip.to_string(), Style::new().fg(FG)),
        ]));
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// Plain-English explanation of each encryption flavour. Returned as
/// (colour, list of lines) so the caller can render with the right
/// severity tint.
fn encryption_explanation(
    enc: watchdog_enrich::wifi_scan::WifiEncryption,
) -> (Color, &'static [&'static str]) {
    use watchdog_enrich::wifi_scan::WifiEncryption;
    match enc {
        WifiEncryption::Open => (
            RED,
            &[
                "No encryption. Anyone in range can see all HTTP traffic,",
                "DNS without DoH, SSH headers, etc. in plaintext.",
            ],
        ),
        WifiEncryption::Wep => (
            RED,
            &[
                "Broken since 2001. Crackable in minutes with",
                "aircrack-ng after capturing enough IVs.",
            ],
        ),
        WifiEncryption::Wpa => (
            ORANGE,
            &[
                "Vulnerable to KRACK (2017) and dictionary attacks",
                "offline if the PSK is weak. Discouraged.",
            ],
        ),
        WifiEncryption::Wpa2 => (
            GREEN,
            &[
                "Current standard. The only practical attack is capturing the",
                "handshake (deauth + airodump) and cracking offline against the",
                "PSK with hashcat. A long, random PSK is secure.",
            ],
        ),
        WifiEncryption::Wpa3 => (
            GREEN,
            &[
                "Gold standard. SAE (Simultaneous Authentication of Equals)",
                "eliminates offline attacks against the handshake. Only",
                "vulnerable to downgrade and implementation flaws.",
            ],
        ),
        WifiEncryption::Other => (
            DIM,
            &[
                "Unclassified algorithm. Review manually.",
            ],
        ),
    }
}

fn attack_surface(
    enc: watchdog_enrich::wifi_scan::WifiEncryption,
) -> &'static [&'static str] {
    use watchdog_enrich::wifi_scan::WifiEncryption;
    match enc {
        WifiEncryption::Open => &[
            "Passive sniffer (Wireshark + airmon-ng) sees all unencrypted non-HTTPS traffic",
            "Evil-twin / captive portal phishing trivial",
            "DNS manipulation without DoH",
        ],
        WifiEncryption::Wep => &[
            "IV capture and crack with aircrack-ng (minutes)",
            "Packet injection with replay attacks",
        ],
        WifiEncryption::Wpa | WifiEncryption::Wpa2 => &[
            "Handshake capture with deauth (aireplay-ng) + airodump-ng",
            "Offline brute-force with hashcat -m 22000 against the handshake",
            "PMKID attack against certain routers (no deauth required)",
            "KARMA / evil twin if clients remember the network",
        ],
        WifiEncryption::Wpa3 => &[
            "Downgrade to WPA2 if the AP supports transition mode",
            "Side-channel attacks (Dragonblood, patched in modern clients)",
        ],
        WifiEncryption::Other => &[
            "Manual inspection required — no automatic recommendations",
        ],
    }
}

fn signal_bars(pct: u32) -> &'static str {
    match pct {
        0..=20   => "▁",
        21..=40  => "▁▂",
        41..=60  => "▁▂▃",
        61..=80  => "▁▂▃▄",
        _        => "▁▂▃▄▅",
    }
}

fn signal_color(pct: u32) -> Color {
    match pct {
        0..=30   => RED,
        31..=60  => ORANGE,
        _        => GREEN,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// Network view — adapters + active TCP table. Read-only, refreshes
// every few seconds via tick_stats(); rendering itself is pure.
// ---------------------------------------------------------------------------

fn render_network(f: &mut Frame, app: &App) {
    use watchdog_enrich::network_inspect::NetworkSnapshot;

    let area = f.area();
    let root = Layout::vertical([
        Constraint::Length(3),  // header
        Constraint::Min(8),     // main columns
        Constraint::Length(1),  // hint bar
    ])
    .split(area);

    // Header — counters + active discover progress.
    let snap_opt: Option<&NetworkSnapshot> = app.network_snapshot.as_ref();
    let (adapter_count, tcp_count, neighbor_count) = match snap_opt {
        Some(s) => (s.adapters.len(), s.tcp.len(), s.neighbors.len()),
        None    => (0, 0, 0),
    };
    let title = Line::from(vec![
        Span::styled("WATCHDOG", Style::new().fg(BRACKET).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled("NETWORK", Style::new().fg(CYAN).add_modifier(Modifier::BOLD)),
    ]);
    let mut right_spans: Vec<Span<'static>> = vec![
        Span::styled("interfaces ", Style::new().fg(DIM)),
        Span::styled(format!("{adapter_count}"), Style::new().fg(FG_BRIGHT)),
        Span::styled("   neighbors ", Style::new().fg(DIM)),
        Span::styled(format!("{neighbor_count}"), Style::new().fg(FG_BRIGHT)),
        Span::styled("   tcp ", Style::new().fg(DIM)),
        Span::styled(format!("{tcp_count}"), Style::new().fg(FG_BRIGHT)),
    ];
    if let Some(disc) = &app.discover_state {
        right_spans.push(Span::raw("   "));
        if disc.done() {
            let elapsed_ms = disc.elapsed_ms();
            let responded = disc.responded.load(std::sync::atomic::Ordering::Relaxed);
            right_spans.push(Span::styled("scan done ", Style::new().fg(DIM)));
            right_spans.push(Span::styled(
                format!("{responded}/{} ({elapsed_ms}ms)", disc.total),
                Style::new().fg(GREEN).add_modifier(Modifier::BOLD),
            ));
        } else {
            let scanned = disc.scanned.load(std::sync::atomic::Ordering::Relaxed);
            right_spans.push(Span::styled("scanning ", Style::new().fg(DIM)));
            right_spans.push(Span::styled(
                format!("{scanned}/{} ({})", disc.total, disc.subnet_label),
                Style::new().fg(ORANGE).add_modifier(Modifier::BOLD),
            ));
        }
    }
    let right = Line::from(right_spans);
    f.render_widget(
        BracketFrame::new().title(title).title_right(right).color(CYAN),
        root[0],
    );

    // Main: two columns. Left = INTERFACES (top, small) + NEIGHBORS
    // (bottom, big, selectable). Right = HOST DETAIL when a neighbor
    // is selected, else TCP CONNECTIONS.
    let cols = Layout::horizontal([
        Constraint::Percentage(45),
        Constraint::Percentage(55),
    ])
    .split(root[1]);

    let left = Layout::vertical([
        Constraint::Percentage(45),
        Constraint::Percentage(55),
    ])
    .split(cols[0]);

    render_adapters_panel(f, left[0], snap_opt, app);
    render_neighbors_panel(f, left[1], snap_opt, app);

    if app.network_selected_ip.is_some() {
        render_host_detail(f, cols[1], snap_opt, app);
    } else {
        render_connections_panel(f, cols[1], snap_opt, app);
    }

    render_hint(f, root[2], app);
}

fn render_adapters_panel(
    f: &mut Frame,
    area: Rect,
    snap: Option<&watchdog_enrich::network_inspect::NetworkSnapshot>,
    app: &App,
) {
    use watchdog_enrich::network_inspect::format_mac;

    let frame = BracketFrame::new().title(title_line("INTERFACES", Some("⇧↑↓")));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some(snap) = snap else {
        let p = Paragraph::new("Loading network snapshot…").style(Style::new().fg(DIM));
        f.render_widget(p, inner);
        return;
    };

    // Skip adapters with no addresses AND no MAC — they're loopback /
    // tunnel placeholders that crowd the view.
    let mut lines: Vec<Line<'static>> = Vec::new();
    for a in &snap.adapters {
        if a.addresses.is_empty() && a.mac_len == 0 {
            continue;
        }
        let dot_color = if a.is_up { GREEN } else { DIM };
        let speed = a.link_speed_mbps
            .map(|m| format!("  {} Mbps", m))
            .unwrap_or_default();
        let mac = if a.mac_len > 0 { format_mac(&a.mac, a.mac_len) } else { String::new() };
        let mac_suffix = if mac.is_empty() { String::new() } else { format!("  MAC {mac}") };
        let header = Line::from(vec![
            Span::styled("● ", Style::new().fg(dot_color).add_modifier(Modifier::BOLD)),
            Span::styled(a.friendly_name.clone(), Style::new().fg(FG_BRIGHT).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  ({})", a.description), Style::new().fg(DIM)),
            Span::styled(mac_suffix, Style::new().fg(DIM)),
            Span::styled(speed, Style::new().fg(DIM)),
        ]);
        lines.push(header);
        for (ip, prefix) in &a.addresses {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    if ip.is_ipv4() { "IPv4 " } else { "IPv6 " },
                    Style::new().fg(DIM),
                ),
                Span::styled(format!("{ip}/{prefix}"), Style::new().fg(FG)),
            ]));
        }
        if !a.gateways.is_empty() {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled("gw   ", Style::new().fg(DIM)),
                Span::styled(
                    a.gateways.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(", "),
                    Style::new().fg(FG),
                ),
            ]));
        }
        if !a.dns_servers.is_empty() {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled("dns  ", Style::new().fg(DIM)),
                Span::styled(
                    a.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "),
                    Style::new().fg(FG),
                ),
            ]));
        }
        lines.push(Line::raw(""));
    }

    if lines.is_empty() {
        let p = Paragraph::new("No active interfaces with assigned addresses.")
            .style(Style::new().fg(DIM));
        f.render_widget(p, inner);
        return;
    }

    // Clamp scroll so we never go past the bottom of the content.
    let visible_rows = inner.height;
    let total_rows = lines.len() as u16;
    let max_scroll = total_rows.saturating_sub(visible_rows);
    let scroll = app.interfaces_scroll.min(max_scroll);

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
}

fn render_neighbors_panel(
    f: &mut Frame,
    area: Rect,
    snap: Option<&watchdog_enrich::network_inspect::NetworkSnapshot>,
    app: &App,
) {
    use watchdog_enrich::network_inspect::{format_mac, oui_vendor, NeighborState};

    let frame = BracketFrame::new().title(title_line("NEIGHBORS", Some("d  ↵")));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some(snap) = snap else {
        let p = Paragraph::new("…").style(Style::new().fg(DIM));
        f.render_widget(p, inner);
        return;
    };

    // Hide INCOMPLETE / UNREACHABLE entries — these are IPs we tried
    // to ARP (typically from a `d` sweep) that didn't reply. Showing
    // them clutters the panel with confirmed-absent hosts.
    let mut rows: Vec<&watchdog_enrich::network_inspect::Neighbor> = snap
        .neighbors
        .iter()
        .filter(|n| crate::app::network_inspect_neighbor_visible(n))
        .collect();

    if rows.is_empty() {
        let p = Paragraph::new(
            "The ARP/NDP cache is empty. Press `d` to launch an active \
             ping sweep of your subnet and discover all visible \
             devices.",
        )
        .style(Style::new().fg(DIM))
        .wrap(Wrap { trim: false });
        f.render_widget(p, inner);
        return;
    }

    // Sort: IPv4 first, then by IP. We *don't* sort reachable-first
    // because that would shuffle entries between snapshots (the state
    // flips REACH ↔ STALE every few minutes), which is jarring while
    // you're navigating with arrow keys.
    rows.sort_by(|a, b| {
        a.ip.is_ipv4().cmp(&b.ip.is_ipv4()).reverse()
            .then_with(|| a.ip.cmp(&b.ip))
    });

    // Selection position (if any).
    let selected_pos = app
        .network_selected_ip
        .and_then(|ip| rows.iter().position(|n| n.ip == ip));

    let total = rows.len();
    let inner_h = inner.height as usize;
    // 1 row for the header always. Decide upfront whether we'll need a
    // footer row: if so reserve it (last_y) so it never overlaps the
    // last data row.
    let header_h: usize = 1;
    let max_list_if_no_footer = inner_h.saturating_sub(header_h);
    let needs_footer = total > max_list_if_no_footer;
    let footer_h: usize = if needs_footer { 1 } else { 0 };
    let viewable = inner_h.saturating_sub(header_h + footer_h);
    let mut start = total.saturating_sub(viewable);
    if let Some(sel) = selected_pos {
        if sel < start {
            start = sel;
        } else if sel >= start + viewable {
            start = sel + 1 - viewable;
        }
    }
    let end = (start + viewable).min(total);
    let visible = &rows[start..end];

    let header = Line::from(vec![
        Span::styled(format!("{:<22} ", "IP"),  Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<17} ", "MAC"), Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled("HOSTNAME",                 Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
    ]);

    let items: Vec<ListItem> = visible
        .iter()
        .map(|n| {
            // Don't show the raw NDP/ARP state — REACH ↔ STALE ↔ PROBE
            // flapping every 30s is a kernel housekeeping concern, not
            // a "is this device on the network" answer. A visible row
            // already implies online (we filtered the dead ones).
            let mac_str = if n.mac_len > 0 {
                format_mac(&n.mac, n.mac_len)
            } else {
                "—".to_string()
            };
            let status_dot_color = match n.state {
                NeighborState::Permanent => MAGENTA, // static manual entry
                _                        => GREEN,   // any active variant
            };

            // Hostname column: prefer resolved PTR, fall back to OUI
            // vendor name (always available), distinguish visually so
            // the user knows what they're reading.
            let (host_text, host_color) = match app.dns_cache.lookup(n.ip) {
                crate::dns_cache::ResolutionStatus::Resolved(name) => {
                    (name, FG_BRIGHT)
                }
                crate::dns_cache::ResolutionStatus::Pending => {
                    let v = oui_vendor(&n.mac, n.mac_len).unwrap_or("…");
                    (v.to_string(), DIM)
                }
                crate::dns_cache::ResolutionStatus::NoRecord => {
                    let v = oui_vendor(&n.mac, n.mac_len).unwrap_or("");
                    (v.to_string(), MAGENTA)
                }
            };

            ListItem::new(Line::from(vec![
                Span::styled("● ", Style::new().fg(status_dot_color).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{:<20} ", n.ip.to_string()), Style::new().fg(FG_BRIGHT)),
                Span::styled(format!("{:<17} ", mac_str),           Style::new().fg(FG)),
                Span::styled(host_text,                              Style::new().fg(host_color)),
            ]))
        })
        .collect();

    // Render header at top, list in the middle, footer (if any) at the
    // explicit reserved row at the bottom.
    let header_area = Rect { x: inner.x, y: inner.y, width: inner.width, height: 1 };
    let list_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: viewable as u16,
    };
    f.render_widget(Paragraph::new(header), header_area);

    let mut state = ListState::default();
    if let Some(sel) = selected_pos {
        if sel >= start && sel < end {
            state.select(Some(sel - start));
        }
    }
    let list = List::new(items)
        .highlight_style(Style::new().bg(SELECT_BG).fg(FG_BRIGHT).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, list_area, &mut state);

    if needs_footer {
        let hidden_above = start;
        let hidden_below = total - end;
        let hint = if hidden_above > 0 && hidden_below > 0 {
            format!(" ↑ {hidden_above} above   ↓ {hidden_below} below")
        } else if hidden_above > 0 {
            format!(" ↑ {hidden_above} above")
        } else {
            format!(" ↓ {hidden_below} below")
        };
        let footer_area = Rect {
            x: inner.x,
            y: inner.y + inner.height - 1,
            width: inner.width,
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Span::styled(hint, Style::new().fg(DIM))),
            footer_area,
        );
    }
}

// HOST DETAIL — shown on the right when a neighbor is selected.
fn render_host_detail(
    f: &mut Frame,
    area: Rect,
    snap: Option<&watchdog_enrich::network_inspect::NetworkSnapshot>,
    app: &App,
) {
    use watchdog_enrich::network_inspect::{format_mac, os_guess_from_ttl, oui_vendor};

    let Some(ip) = app.network_selected_ip else { return };

    let title = Line::from(vec![
        Span::styled("HOST", Style::new().fg(BRACKET).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(ip.to_string(), Style::new().fg(FG_BRIGHT).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled("PgUp/PgDn", Style::new().fg(MAGENTA)),
        Span::raw(" "),
        Span::styled("scroll", Style::new().fg(DIM)),
    ]);
    let frame = BracketFrame::new().title(title);
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let neighbor = snap.and_then(|s| s.neighbors.iter().find(|n| n.ip == ip));

    let mut lines: Vec<Line<'static>> = Vec::new();

    if let Some(n) = neighbor {
        let mac_str = if n.mac_len > 0 { format_mac(&n.mac, n.mac_len) } else { "—".to_string() };
        let vendor  = oui_vendor(&n.mac, n.mac_len).unwrap_or("unknown");
        lines.push(kv("MAC",       Span::styled(mac_str,             Style::new().fg(FG_BRIGHT))));
        lines.push(kv("Vendor",    Span::styled(vendor.to_string(),  Style::new().fg(MAGENTA))));
        lines.push(kv("State",     Span::styled(n.state.label(),     Style::new().fg(FG))));
        lines.push(kv("Iface idx", Span::styled(format!("{}", n.interface_index), Style::new().fg(YELLOW))));
    } else {
        lines.push(kv("note", Span::styled(
            "this neighbor is no longer in the ARP cache",
            Style::new().fg(DIM),
        )));
    }

    // Side-info populated by background threads in HostProbe.
    if let Some(probe_lock) = app.host_probes.get(&ip) {
        let probe = probe_lock.lock().unwrap();

        // Hostname row
        let hostname_row = if !probe.hostname_done {
            Span::styled("resolving…", Style::new().fg(DIM))
        } else {
            match &probe.hostname {
                Some(name) => Span::styled(name.clone(), Style::new().fg(FG_BRIGHT)),
                None       => Span::styled("(no PTR)", Style::new().fg(DIM)),
            }
        };
        lines.push(kv("Hostname", hostname_row));

        // OS hint + RTT row
        if probe.icmp_done {
            match (probe.icmp_ttl, probe.icmp_rtt_ms) {
                (Some(ttl), Some(rtt)) => {
                    lines.push(kv(
                        "OS hint",
                        Span::styled(
                            format!("{} (TTL {ttl}, RTT {rtt}ms)", os_guess_from_ttl(ttl)),
                            Style::new().fg(CYAN),
                        ),
                    ));
                }
                _ => {
                    lines.push(kv(
                        "OS hint",
                        Span::styled("(no ICMP reply)", Style::new().fg(DIM)),
                    ));
                }
            }
        } else {
            lines.push(kv("OS hint", Span::styled("ping…", Style::new().fg(DIM))));
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        " PORT PROBE",
        Style::new().fg(CYAN).add_modifier(Modifier::BOLD),
    )));

    match app.host_probes.get(&ip) {
        None => {
            lines.push(Line::from(Span::styled(
                " Press Enter to scan the common ports of this machine.",
                Style::new().fg(DIM),
            )));
        }
        Some(probe_lock) => {
            let probe = probe_lock.lock().unwrap();
            let (done, total) = probe.progress();
            let elapsed_ms = probe.elapsed_ms();
            if probe.completed() {
                lines.push(Line::from(vec![
                    Span::raw(" "),
                    Span::styled("probe complete ", Style::new().fg(DIM)),
                    Span::styled(
                        format!("{done}/{total} probed in {elapsed_ms}ms"),
                        Style::new().fg(GREEN),
                    ),
                ]));
                if probe.open_ports.is_empty() {
                    lines.push(Line::raw(""));
                    lines.push(Line::from(Span::styled(
                        " No common ports open. May be behind a firewall, a silent device \
                          (sleeping phone), or only listening on ports outside the scan list.",
                        Style::new().fg(DIM),
                    )));
                } else {
                    lines.push(Line::raw(""));
                    for port in &probe.open_ports {
                        let svc = crate::host_probe::service_name(*port).unwrap_or("?");
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled("●", Style::new().fg(GREEN).add_modifier(Modifier::BOLD)),
                            Span::raw(" "),
                            Span::styled(format!("{:<6}", port), Style::new().fg(FG_BRIGHT)),
                            Span::styled(format!("  {svc}"),     Style::new().fg(CYAN)),
                        ]));
                    }
                }
            } else {
                lines.push(Line::from(vec![
                    Span::raw(" "),
                    Span::styled("probing ", Style::new().fg(DIM)),
                    Span::styled(format!("{done}/{total}"), Style::new().fg(ORANGE).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("   ({elapsed_ms}ms)"), Style::new().fg(DIM)),
                ]));
                if !probe.open_ports.is_empty() {
                    lines.push(Line::raw(""));
                    let mut found = probe.open_ports.clone();
                    found.sort_unstable();
                    for port in &found {
                        let svc = crate::host_probe::service_name(*port).unwrap_or("?");
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled("●", Style::new().fg(GREEN).add_modifier(Modifier::BOLD)),
                            Span::raw(" "),
                            Span::styled(format!("{:<6}", port), Style::new().fg(FG_BRIGHT)),
                            Span::styled(format!("  {svc}"),     Style::new().fg(CYAN)),
                        ]));
                    }
                }
            }
        }
    }

    // Clamp scroll so it doesn't go past the bottom of the content.
    let visible_rows = inner.height.saturating_sub(1);
    let total_rows = lines.len() as u16;
    let max_scroll = total_rows.saturating_sub(visible_rows);
    let scroll = app.host_detail_scroll.min(max_scroll);

    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).scroll((scroll, 0)),
        inner,
    );
}

fn render_connections_panel(
    f: &mut Frame,
    area: Rect,
    snap: Option<&watchdog_enrich::network_inspect::NetworkSnapshot>,
    app: &App,
) {
    use watchdog_enrich::network_inspect::TcpState;

    let frame = BracketFrame::new().title(title_line("TCP CONNECTIONS", Some("PgUp/PgDn")));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some(snap) = snap else {
        let p = Paragraph::new("…").style(Style::new().fg(DIM));
        f.render_widget(p, inner);
        return;
    };

    // Sort: LISTEN first (servers exposed), then ESTAB sorted by remote,
    // then everything else.
    let mut rows: Vec<&watchdog_enrich::network_inspect::TcpConnection> = snap.tcp.iter().collect();
    rows.sort_by_key(|c| match c.state {
        TcpState::Listen => 0,
        TcpState::Established => 1,
        _ => 2,
    });

    let header = Line::from(vec![
        Span::styled(format!(" {:<8} ", "STATE"), Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<23} ", "LOCAL"),  Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<23} ", "REMOTE"), Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<6} ",  "PID"),    Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        Span::styled("PROCESS",                    Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
    ]);

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(rows.len() + 1);
    lines.push(header);
    for c in &rows {
        let state_color = match c.state {
            TcpState::Established => GREEN,
            TcpState::Listen      => CYAN,
            TcpState::TimeWait | TcpState::CloseWait | TcpState::FinWait1 | TcpState::FinWait2 => DIM,
            _ => YELLOW,
        };
        let image = app
            .table
            .lookup(c.pid)
            .map(|p| p.image_name.clone())
            .unwrap_or_else(|| if c.pid == 0 || c.pid == 4 { "System".into() } else { "?".into() });
        let local_str  = format_endpoint(&c.local);
        let remote_str = format_endpoint(&c.remote);
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<8} ", c.state.label()), Style::new().fg(state_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:<23} ", local_str),       Style::new().fg(FG)),
            Span::styled(format!("{:<23} ", remote_str),      Style::new().fg(FG)),
            Span::styled(format!("{:<6} ",  c.pid),           Style::new().fg(YELLOW)),
            Span::styled(image,                                Style::new().fg(FG_BRIGHT)),
        ]));
    }

    // Clamp and apply scroll. The Paragraph widget renders only the
    // visible window, hiding everything above `scroll` and below the
    // inner height.
    let visible_rows = inner.height;
    let total_rows = lines.len() as u16;
    let max_scroll = total_rows.saturating_sub(visible_rows);
    let scroll = app.tcp_scroll.min(max_scroll);

    f.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

fn format_endpoint(sa: &std::net::SocketAddr) -> String {
    // Compact "0.0.0.0:445" form. Mark wildcard listeners visually.
    let ip = sa.ip();
    let port = sa.port();
    if ip.is_unspecified() && port != 0 {
        format!("*:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn render_raw(f: &mut Frame, app: &App) {
    let area = f.area();

    let root = Layout::vertical([
        Constraint::Length(3),  // header: brackets + title + stats + sparkline
        Constraint::Min(10),    // main columns
        Constraint::Length(3),  // filters
        Constraint::Length(1),  // hint bar (no frame)
    ])
    .split(area);

    render_header(f, root[0], app);
    render_main(f, root[1], app);
    render_filter(f, root[2], app);
    render_hint(f, root[3], app);
}

// ---------------------------------------------------------------------------
// Summary view — verdict + Today + Incidents.
// The face the app shows by default. Tells a non-analyst whether
// something is happening that they should care about, in plain English.
// ---------------------------------------------------------------------------

fn render_summary(f: &mut Frame, app: &App) {
    let area = f.area();

    let root = Layout::vertical([
        Constraint::Length(3),  // verdict header
        Constraint::Min(12),    // two-column body
        Constraint::Length(1),  // hint bar
    ])
    .split(area);

    render_verdict(f, root[0], app);

    let body = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(root[1]);

    // Left column: DEFENSES (top), TODAY, INCIDENTS (takes the rest).
    let left = Layout::vertical([
        Constraint::Length(10), // defenses (7 rows of checks + frame)
        Constraint::Length(4),  // today
        Constraint::Min(5),     // incidents
    ])
    .split(body[0]);

    render_defenses(f, left[0], app);
    render_today(f, left[1], app);
    render_incidents(f, left[2], app);

    // Right column: NETWORK FOOTPRINT (top), WATCHDOG HEALTH (bottom).
    let right = Layout::vertical([
        Constraint::Percentage(55),
        Constraint::Percentage(45),
    ])
    .split(body[1]);

    render_network_footprint(f, right[0], app);
    render_watchdog_health(f, right[1], app);

    render_hint(f, root[2], app);
}

fn render_verdict(f: &mut Frame, area: Rect, app: &App) {
    let (open_count, last_alert) = app.incidents.summary();
    let verdict = app.incidents.verdict();
    let (label, color) = match verdict {
        Verdict::Calm   => ("CALM",   GREEN),
        Verdict::Review => ("REVIEW", ORANGE),
        Verdict::Threat => ("THREAT", RED),
    };

    let context: String = match verdict {
        Verdict::Calm => match last_alert {
            None    => "no suspicious activity recorded".into(),
            Some(t) => format!("{} since the last alert", pretty_ago(t.elapsed())),
        },
        Verdict::Review => format!("{open_count} incidents pending review"),
        Verdict::Threat => format!("{open_count} active incidents · one or more recent critical"),
    };

    let mode_label = if app.learn_only { "LEARN" } else { "LIVE" };
    let mode_color = if app.learn_only { ORANGE } else { GREEN };

    let title = Line::from(vec![
        Span::styled("WATCHDOG", Style::new().fg(BRACKET).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(mode_label, Style::new().fg(mode_color).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(label, Style::new().fg(color).add_modifier(Modifier::BOLD)),
    ]);

    let uptime = app.stats.started_at.elapsed();
    let h = uptime.as_secs() / 3600;
    let m = (uptime.as_secs() % 3600) / 60;
    let s = uptime.as_secs() % 60;
    let stats = Line::from(vec![
        Span::styled(context, Style::new().fg(DIM)),
        Span::raw("     "),
        Span::styled("up ", Style::new().fg(DIM)),
        Span::styled(format!("{h:02}:{m:02}:{s:02}"), Style::new().fg(FG_BRIGHT)),
    ]);

    let frame = BracketFrame::new().title(title).title_right(stats).color(color);
    f.render_widget(frame, area);
}

fn render_today(f: &mut Frame, area: Rect, app: &App) {
    let frame = BracketFrame::new().title(title_line("TODAY", None));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let d = &app.daily;
    let line = Line::from(vec![
        Span::styled(format!("{}", d.proc_starts),         Style::new().fg(FG_BRIGHT)),
        Span::styled(" processes started · ",              Style::new().fg(DIM)),
        Span::styled(format!("{}", d.distinct_images.len()), Style::new().fg(FG_BRIGHT)),
        Span::styled(" distinct images · ",                Style::new().fg(DIM)),
        Span::styled(format!("{}", d.info_count),          Style::new().fg(CYAN)),
        Span::styled(" INFO · ",                            Style::new().fg(DIM)),
        Span::styled(format!("{}", d.warn_count),          Style::new().fg(ORANGE)),
        Span::styled(" WARN · ",                            Style::new().fg(DIM)),
        Span::styled(format!("{}", d.crit_count),          Style::new().fg(RED)),
        Span::styled(" CRIT",                               Style::new().fg(DIM)),
    ]);
    f.render_widget(Paragraph::new(line), inner);
}

// ---- DEFENSES panel --------------------------------------------------------

fn render_defenses(f: &mut Frame, area: Rect, app: &App) {
    use crate::defenses::DefenseHealth;

    let title_color = match app.defenses.as_ref().map(|d| d.health()) {
        Some(DefenseHealth::Good)    => GREEN,
        Some(DefenseHealth::Bad)     => RED,
        Some(DefenseHealth::Unknown) => ORANGE,
        None                         => DIM,
    };
    let frame = BracketFrame::new()
        .title(title_line("DEFENSES", None))
        .color(title_color);
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some(def) = app.defenses.as_ref() else {
        let p = Paragraph::new("reading system configuration…")
            .style(Style::new().fg(DIM));
        f.render_widget(p, inner);
        return;
    };

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(check_line(
        "Windows Defender",
        Some(def.defender_process_seen),
        if def.defender_process_seen { "running (MsMpEng)" } else { "MsMpEng.exe not seen" },
    ));
    lines.push(check_line(
        "Firewall · Domain",
        def.firewall_domain,
        match def.firewall_domain {
            Some(true)  => "enabled",
            Some(false) => "DISABLED",
            None        => "unknown",
        },
    ));
    lines.push(check_line(
        "Firewall · Private",
        def.firewall_private,
        match def.firewall_private {
            Some(true)  => "enabled",
            Some(false) => "DISABLED",
            None        => "unknown",
        },
    ));
    lines.push(check_line(
        "Firewall · Public",
        def.firewall_public,
        match def.firewall_public {
            Some(true)  => "enabled",
            Some(false) => "DISABLED",
            None        => "unknown",
        },
    ));
    lines.push(check_line(
        "UAC",
        def.uac_enabled,
        match def.uac_enabled {
            Some(true)  => "enabled",
            Some(false) => "DISABLED",
            None        => "unknown",
        },
    ));
    let upd_text = def
        .last_update_install
        .clone()
        .unwrap_or_else(|| "(unknown)".into());
    lines.push(check_line("Last Windows update", Some(true), &upd_text));

    // VPN — green dot for active tunnels, dim for none, magenta for
    // "configured but not connected" (informational; not a problem).
    let (vpn_ok, vpn_text): (Option<bool>, String) = match &def.vpn_status {
        crate::defenses::VpnStatus::Active(name)   => (Some(true), format!("active · {name}")),
        crate::defenses::VpnStatus::Inactive(name) => (None,        format!("installed, not connected · {name}")),
        crate::defenses::VpnStatus::None           => (None,        "no VPN client detected".into()),
    };
    lines.push(check_line("VPN", vpn_ok, &vpn_text));

    f.render_widget(Paragraph::new(lines), inner);
}

/// `● Label   info-text` row used in the DEFENSES panel.
fn check_line(label: &'static str, ok: Option<bool>, info: &str) -> Line<'static> {
    let color = match ok {
        Some(true)  => GREEN,
        Some(false) => RED,
        None        => ORANGE,
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled("●", Style::new().fg(color).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!("{label:<22}"), Style::new().fg(FG)),
        Span::styled(info.to_string(), Style::new().fg(FG_BRIGHT)),
    ])
}

// ---- NETWORK FOOTPRINT panel ----------------------------------------------

fn render_network_footprint(f: &mut Frame, area: Rect, app: &App) {
    let frame = BracketFrame::new().title(title_line("NETWORK FOOTPRINT", None));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let fp = &app.footprint;
    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(kv_styled(
        "Outbound connects",
        format!("{}", fp.outbound_connects),
        FG_BRIGHT,
    ));
    lines.push(kv_styled(
        "Unique remote IPs",
        format!("{}", fp.unique_remote_ips.len()),
        FG_BRIGHT,
    ));
    lines.push(kv_styled(
        "Unique domains",
        format!("{}", fp.unique_domains.len()),
        FG_BRIGHT,
    ));
    lines.push(kv_styled(
        "DNS queries",
        format!("{}", fp.dns_queries),
        FG_BRIGHT,
    ));
    lines.push(kv_styled(
        "Public / private",
        format!(
            "{}% public · {}% LAN",
            fp.public_ratio_pct(),
            100u32.saturating_sub(fp.public_ratio_pct())
        ),
        FG,
    ));
    lines.push(kv_styled(
        "Processes with net",
        format!("{}", fp.processes_with_egress.len()),
        FG_BRIGHT,
    ));

    if let Some((ip, c)) = fp.top_destination() {
        lines.push(Line::raw(""));
        lines.push(kv_styled("Top destination", format!("{ip} ({c} hits)"), CYAN));
    }
    if let Some((dom, c)) = fp.top_domain() {
        lines.push(kv_styled("Top domain", format!("{dom} ({c} queries)"), CYAN));
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

// ---- WATCHDOG HEALTH panel -------------------------------------------------

fn render_watchdog_health(f: &mut Frame, area: Rect, app: &App) {
    let frame = BracketFrame::new().title(title_line("WATCHDOG HEALTH", None));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let uptime = app.stats.started_at.elapsed();
    let up_h = uptime.as_secs() / 3600;
    let up_m = (uptime.as_secs() % 3600) / 60;
    let up_s = uptime.as_secs() % 60;
    let (mature, total_imgs) = app.baseline.stats();
    let dropped = app.dropped();
    let drop_pct = if app.stats.events_total == 0 {
        0.0
    } else {
        (dropped as f64 * 100.0) / app.stats.events_total as f64
    };

    let saved_text = match app.baseline.last_saved() {
        Some(t) => crate::incidents::pretty_ago(t.elapsed()),
        None    => "not yet saved".into(),
    };

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(kv_styled("Uptime",            format!("{up_h:02}h {up_m:02}m {up_s:02}s"), FG_BRIGHT));
    lines.push(kv_styled("Events ingested",   format!("{}", app.stats.events_total),        FG_BRIGHT));
    lines.push(kv_styled(
        "Drop rate",
        format!("{dropped} ({drop_pct:.2}%)"),
        if dropped > 0 { ORANGE } else { GREEN },
    ));
    lines.push(kv_styled(
        "Baseline maturity",
        format!("{mature}/{total_imgs} images ({}%)",
            if total_imgs == 0 { 0 } else { (mature * 100) / total_imgs }),
        FG_BRIGHT,
    ));
    lines.push(kv_styled("Baseline saved",    saved_text,                                   FG));
    lines.push(kv_styled("Active detectors",  "8".to_string(),                              FG_BRIGHT));
    lines.push(kv_styled("Mode",
        if app.learn_only { "LEARN".to_string() } else { "LIVE".to_string() },
        if app.learn_only { ORANGE } else { GREEN },
    ));

    f.render_widget(Paragraph::new(lines), inner);
}

/// Tiny helper for two-column "label   value" rows in the Summary
/// side panels. The label is dim, the value uses the passed colour.
fn kv_styled(key: &'static str, value: String, value_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {key:<20} "), Style::new().fg(DIM)),
        Span::styled(value, Style::new().fg(value_color)),
    ])
}

fn render_incidents(f: &mut Frame, area: Rect, app: &App) {
    let (open_count, _) = app.incidents.summary();
    let title = if open_count == 0 {
        title_line("INCIDENTS", None)
    } else {
        Line::from(vec![
            Span::styled("INCIDENTS", Style::new().fg(BRACKET)),
            Span::raw("   "),
            Span::styled(
                format!("{open_count} open"),
                Style::new().fg(ORANGE).add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let frame = BracketFrame::new().title(title);
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    if open_count == 0 {
        let p = Paragraph::new("Nothing to review. If watchdog just started, give it a few minutes for its baseline to learn what is normal on your machine.")
            .style(Style::new().fg(DIM))
            .wrap(Wrap { trim: false });
        f.render_widget(p, inner);
        return;
    }

    // Build a flat Paragraph of incident cards, newest first. Each
    // incident is a small visual block: severity dots + headline +
    // body wrapped + ago.
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut consumed_rows: u16 = 0;
    for inc in app.incidents.iter_newest() {
        // Stop pushing if we'd overflow the panel — we don't scroll in
        // the summary view.
        if consumed_rows + 4 > inner.height {
            break;
        }
        lines.extend(format_incident_card(inc));
        lines.push(Line::raw(""));
        consumed_rows = consumed_rows.saturating_add(5);
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn format_incident_card(inc: &Incident) -> Vec<Line<'static>> {
    let (dots, color, sev_text) = match inc.max_severity {
        Severity::Crit  => ("●●●", RED,    "CRIT"),
        Severity::Warn  => ("●● ", ORANGE, "WARN"),
        Severity::Info  => ("●  ", CYAN,   "INFO"),
        Severity::Quiet => ("·  ", DIM,    "----"),
    };
    let count_suffix = if inc.event_count > 1 {
        format!(" ({} events)", inc.event_count)
    } else {
        String::new()
    };
    let header = Line::from(vec![
        Span::raw("  "),
        Span::styled(dots, Style::new().fg(color).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(sev_text, Style::new().fg(color).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(inc.headline.clone(), Style::new().fg(FG_BRIGHT)),
        Span::styled(count_suffix, Style::new().fg(DIM)),
        Span::raw("     "),
        Span::styled(pretty_ago(inc.last_seen.elapsed()), Style::new().fg(DIM)),
    ]);
    let body = Line::from(vec![
        Span::raw("      "),
        Span::styled(inc.body.clone(), Style::new().fg(FG)),
    ]);
    let meta = Line::from(vec![
        Span::raw("      "),
        Span::styled(format!("detector: {}", inc.detector), Style::new().fg(DIM)),
    ]);
    vec![header, body, meta]
}

// ---------------------------------------------------------------------------
// Header — title, stats, and a one-row sparkline of events/s
// ---------------------------------------------------------------------------

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let uptime = app.stats.started_at.elapsed();
    let h = uptime.as_secs() / 3600;
    let m = (uptime.as_secs() % 3600) / 60;
    let s = uptime.as_secs() % 60;

    let (mature, total_imgs) = app.baseline.stats();

    let stats = Line::from(vec![
        Span::styled("events/s ", Style::new().fg(DIM)),
        Span::styled(format!("{}", app.stats.events_per_sec), Style::new().fg(FG_BRIGHT)),
        Span::styled("  total ",  Style::new().fg(DIM)),
        Span::styled(format!("{}", app.stats.events_total),   Style::new().fg(FG_BRIGHT)),
        Span::styled("  dropped ", Style::new().fg(DIM)),
        Span::styled(format!("{}", app.dropped()),           Style::new().fg(FG_BRIGHT)),
        Span::styled("  baseline ", Style::new().fg(DIM)),
        Span::styled(format!("{mature}/{total_imgs}"),       Style::new().fg(FG_BRIGHT)),
        Span::styled("  score ",  Style::new().fg(DIM)),
        Span::styled(format!("{:.2}", app.min_score),         Style::new().fg(score_color(app.min_score))),
        Span::styled("  up ",     Style::new().fg(DIM)),
        Span::styled(format!("{h:02}:{m:02}:{s:02}"),         Style::new().fg(FG_BRIGHT)),
        if app.paused {
            Span::styled("  PAUSED", Style::new().fg(ORANGE).add_modifier(Modifier::BOLD))
        } else {
            Span::raw("")
        },
    ]);

    let mode_label = if app.learn_only { "LEARN" } else { "LIVE" };
    let mode_color = if app.learn_only { ORANGE } else { GREEN };

    let title = Line::from(vec![
        Span::styled("WATCHDOG", Style::new().fg(BRACKET).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(mode_label, Style::new().fg(mode_color).add_modifier(Modifier::BOLD)),
    ]);

    let frame = BracketFrame::new()
        .title(title)
        .title_right(stats);
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    // Sparkline of events/s across recent seconds, centred in the
    // header's middle row.
    let data: Vec<u64> = app.stats.history.iter().copied().collect();
    if !data.is_empty() {
        let max = data.iter().copied().max().unwrap_or(1).max(1);
        // Trim to a reasonable max width so the sparkline doesn't span
        // the whole header on wide terminals — keeps it visually centred.
        let target = inner.width.min(60);
        let pad = inner.width.saturating_sub(target) / 2;
        let spark_area = Rect {
            x: inner.x + pad,
            y: inner.y,
            width: target,
            height: 1,
        };
        let sparkline = Sparkline::default()
            .data(&data)
            .max(max)
            .style(Style::new().fg(ACCENT));
        f.render_widget(sparkline, spark_area);
    }
}

// ---------------------------------------------------------------------------
// Main layout — feed / details / tree
// ---------------------------------------------------------------------------

fn render_main(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::horizontal([
        Constraint::Percentage(40),
        Constraint::Percentage(35),
        Constraint::Percentage(25),
    ])
    .split(area);

    render_feed(f, cols[0], app);
    render_details(f, cols[1], app);
    render_tree(f, cols[2], app);
}

fn render_feed(f: &mut Frame, area: Rect, app: &App) {
    let frame = BracketFrame::new().title(title_line("FEED", Some("f")));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let items: Vec<&ScoredEvent> = app.filtered_iter().map(|b| &b.event).collect();
    let len = items.len();
    if len == 0 {
        let hint = Paragraph::new("No events match current filter")
            .style(Style::new().fg(DIM))
            .alignment(Alignment::Center);
        f.render_widget(hint, inner);
        return;
    }

    let capacity = inner.height as usize;
    let selected_pos = app.selected_position();
    let mut start = len.saturating_sub(capacity);
    if let Some(sel) = selected_pos {
        if sel < start {
            start = sel;
        } else if sel >= start + capacity {
            start = sel + 1 - capacity;
        }
    }

    let visible = &items[start..];
    let list_items: Vec<ListItem> = visible.iter().map(|ev| ListItem::new(feed_line(ev))).collect();

    let mut state = ListState::default();
    if let Some(sel) = selected_pos {
        if sel >= start && sel < start + visible.len() {
            state.select(Some(sel - start));
        }
    }

    let list = List::new(list_items)
        .highlight_style(Style::new().bg(SELECT_BG).fg(FG_BRIGHT));

    f.render_stateful_widget(list, inner, &mut state);
}

fn feed_line(ev: &ScoredEvent) -> Line<'static> {
    let ts = format_ts_short(ev.enriched.raw.ts);
    let (kind, kind_color, summary) = match &ev.enriched.raw.payload {
        EventPayload::ProcessStart { .. } => {
            let img = ev.enriched.process.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            let par = ev.enriched.parent.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            ("PROC", GREEN, format!("{img}  ←  {par}"))
        }
        EventPayload::ProcessStop { exit_code, .. } => {
            let img = ev.enriched.process.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            ("PROC", DIM, format!("{img}  exit={exit_code:#x}"))
        }
        EventPayload::ImageLoad { image, .. } => {
            let owner = ev.enriched.process.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            let dll = basename(image);
            ("IMG ", CYAN, format!("{owner}  ←  {dll}"))
        }
        EventPayload::FileCreate { path } => {
            let owner = ev.enriched.process.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            ("FILE", YELLOW, format!("{owner}  ▸  {}", basename(path)))
        }
        EventPayload::RegistrySetValue { key_name, value_name } => {
            let owner = ev.enriched.process.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            let key_tail = basename(key_name);
            let v = if value_name.is_empty() { "<default>".to_string() } else { value_name.clone() };
            ("REG ", MAGENTA, format!("{owner}  ▸  {key_tail}\\{v}"))
        }
        EventPayload::NetworkConnect { remote_ip, remote_port, .. } => {
            let owner = ev.enriched.process.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            ("NET ", ORANGE, format!("{owner}  →  {remote_ip}:{remote_port}"))
        }
        EventPayload::DnsQuery { name, .. } => {
            let owner = ev.enriched.process.as_ref().map(|p| p.image_name.clone()).unwrap_or_else(|| "?".into());
            ("DNS ", CYAN, format!("{owner}  ?  {name}"))
        }
        EventPayload::RemovableDriveMounted { drive_letter } => {
            ("USB ", RED, format!("removable drive mounted as {drive_letter}:"))
        }
        EventPayload::Other { event_id } => ("?   ", GRAY, format!("eid={event_id}")),
    };

    let (sev_label, sev_color) = severity_style(ev.severity);

    Line::from(vec![
        // Severity bar at the row's leading edge — same colour as the
        // severity label, lets the eye spot WARN/CRIT rows at a glance.
        Span::styled("▎", Style::new().fg(sev_color)),
        Span::raw(" "),
        Span::styled(ts,                                       Style::new().fg(DIM)),
        Span::raw(" "),
        Span::styled(sev_label,                                Style::new().fg(sev_color).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!("{:.2}", ev.score),               Style::new().fg(score_color(ev.score))),
        Span::raw(" "),
        Span::styled(kind,                                     Style::new().fg(kind_color).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(summary,                                  Style::new().fg(FG)),
    ])
}

fn severity_style(sev: Severity) -> (&'static str, Color) {
    match sev {
        Severity::Crit  => ("CRIT", RED),
        Severity::Warn  => ("WARN", ORANGE),
        Severity::Info  => ("INFO", CYAN),
        Severity::Quiet => ("----", DIM),
    }
}

fn score_color(score: f32) -> Color {
    if score >= 0.70 { RED }
    else if score >= 0.40 { ORANGE }
    else if score >= 0.30 { CYAN }
    else { DIM }
}

// ---------------------------------------------------------------------------
// Details
// ---------------------------------------------------------------------------

fn render_details(f: &mut Frame, area: Rect, app: &App) {
    let frame = BracketFrame::new().title(title_line("DETAILS", Some("d")));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some(ev) = app.selected_event() else {
        let p = Paragraph::new("Select an event with ↑↓ / j k")
            .style(Style::new().fg(DIM))
            .alignment(Alignment::Center);
        f.render_widget(p, inner);
        return;
    };

    let lines = build_details(ev, inner.width as usize);
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(para, inner);
}

fn build_details(ev: &ScoredEvent, width: usize) -> Vec<Line<'static>> {
    let mut out: Vec<Line> = Vec::new();
    let ts = format_ts_full(ev.enriched.raw.ts);
    let (kind, kind_color) = match &ev.enriched.raw.payload {
        EventPayload::ProcessStart      { .. } => ("PROCESS START",    GREEN),
        EventPayload::ProcessStop       { .. } => ("PROCESS STOP",     DIM),
        EventPayload::ImageLoad         { .. } => ("IMAGE LOAD",       CYAN),
        EventPayload::FileCreate        { .. } => ("FILE CREATE",      YELLOW),
        EventPayload::RegistrySetValue  { .. } => ("REGISTRY SETVAL",  MAGENTA),
        EventPayload::NetworkConnect    { .. } => ("NETWORK CONNECT",  ORANGE),
        EventPayload::DnsQuery          { .. } => ("DNS QUERY",        CYAN),
        EventPayload::RemovableDriveMounted { .. } => ("DRIVE MOUNTED", RED),
        EventPayload::Other             { .. } => ("OTHER",            DIM),
    };

    let (sev_label, sev_color) = severity_style(ev.severity);

    out.push(kv("Event",    Span::styled(kind, Style::new().fg(kind_color).add_modifier(Modifier::BOLD))));
    out.push(kv("Severity", Span::styled(
        format!("{}  ({:.2})", sev_label, ev.score),
        Style::new().fg(sev_color).add_modifier(Modifier::BOLD),
    )));
    out.push(kv("Time", Span::styled(ts, Style::new().fg(FG_BRIGHT))));
    out.push(kv("PID",  Span::styled(format!("{}", ev.enriched.raw.pid), Style::new().fg(YELLOW))));

    if let Some(p) = &ev.enriched.process {
        out.push(kv("Image", Span::styled(p.image_path.display().to_string(), Style::new().fg(FG))));
        if !p.cmdline.is_empty() {
            out.push(kv("Cmdline", Span::styled(truncate_cmdline(&p.cmdline), Style::new().fg(FG))));
        }
        out.push(kv("PPID",    Span::styled(format!("{}", p.ppid),       Style::new().fg(YELLOW))));
        out.push(kv("Session", Span::styled(format!("{}", p.session_id), Style::new().fg(YELLOW))));
    } else {
        out.push(kv("Process", Span::styled("<unknown — gone or pre-snapshot>", Style::new().fg(DIM))));
    }

    if let Some(parent) = &ev.enriched.parent {
        out.push(kv("Parent", Span::styled(parent.image_path.display().to_string(), Style::new().fg(FG))));
    }

    match &ev.enriched.raw.payload {
        EventPayload::ImageLoad { image, base, size } => {
            out.push(kv("DLL",  Span::styled(image.clone(),               Style::new().fg(FG))));
            out.push(kv("Base", Span::styled(format!("{base:#018x}"),     Style::new().fg(YELLOW))));
            out.push(kv("Size", Span::styled(format!("{size}"),           Style::new().fg(YELLOW))));
        }
        EventPayload::ProcessStop { exit_code, .. } => {
            out.push(kv("Exit", Span::styled(format!("{exit_code:#x}"),   Style::new().fg(YELLOW))));
        }
        EventPayload::FileCreate { path } => {
            out.push(kv("Path", Span::styled(path.clone(),                Style::new().fg(FG))));
        }
        EventPayload::RegistrySetValue { key_name, value_name } => {
            out.push(kv("Key",   Span::styled(key_name.clone(),           Style::new().fg(FG))));
            let v = if value_name.is_empty() { "<default>".to_string() } else { value_name.clone() };
            out.push(kv("Value", Span::styled(v,                          Style::new().fg(FG))));
        }
        EventPayload::NetworkConnect { local_ip, local_port, remote_ip, remote_port } => {
            out.push(kv("Remote", Span::styled(format!("{remote_ip}:{remote_port}"), Style::new().fg(FG))));
            out.push(kv("Local",  Span::styled(format!("{local_ip}:{local_port}"),   Style::new().fg(FG))));
        }
        EventPayload::RemovableDriveMounted { drive_letter } => {
            out.push(kv("Drive", Span::styled(format!("{drive_letter}:"), Style::new().fg(FG))));
        }
        EventPayload::DnsQuery { name, query_type, status, results } => {
            out.push(kv("Query",  Span::styled(name.clone(),              Style::new().fg(FG))));
            out.push(kv("Type",   Span::styled(dns_type_label(*query_type), Style::new().fg(YELLOW))));
            out.push(kv("Status", Span::styled(format!("{status}"),       Style::new().fg(YELLOW))));
            if !results.is_empty() {
                out.push(kv("Results", Span::styled(results.clone(),       Style::new().fg(FG))));
            }
        }
        _ => {}
    }

    if !ev.reasons.is_empty() {
        out.push(Line::raw(""));
        // Dashed separator spanning the panel width, then "Why" label
        // in dim grey, then a blank gutter before the first reason.
        out.push(Line::from(Span::styled(
            "╌".repeat(width),
            Style::new().fg(DIM),
        )));
        out.push(Line::from(Span::styled(
            "Why",
            Style::new().fg(DIM).add_modifier(Modifier::BOLD),
        )));
        out.push(Line::raw(""));
        for r in &ev.reasons {
            out.push(Line::from(vec![
                Span::styled(format!(" {:.2}  ", r.sub_score), Style::new().fg(score_color(r.sub_score)).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{}  ", r.detector),      Style::new().fg(YELLOW)),
                Span::styled(r.explanation.clone(),            Style::new().fg(FG)),
            ]));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

fn render_tree(f: &mut Frame, area: Rect, app: &App) {
    let frame = BracketFrame::new().title(title_line("TREE", Some("t")));
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let Some(ev) = app.selected_event() else { return; };

    let chain = app.ancestry(ev.enriched.raw.pid);
    if chain.is_empty() {
        let p = Paragraph::new("<no ancestry — gone>")
            .style(Style::new().fg(DIM))
            .alignment(Alignment::Center);
        f.render_widget(p, inner);
        return;
    }

    let lines: Vec<Line> = chain
        .iter()
        .enumerate()
        .map(|(i, info)| {
            let indent = "  ".repeat(i);
            let prefix = if i == 0 { "" } else { "└ " };
            let is_target = info.pid == ev.enriched.raw.pid;
            Line::from(vec![
                Span::raw(format!("{indent}{prefix}")),
                Span::styled(
                    info.image_name.clone(),
                    if is_target { Style::new().fg(GREEN).add_modifier(Modifier::BOLD) }
                    else         { Style::new().fg(FG) },
                ),
                Span::styled(format!(" ({})", info.pid), Style::new().fg(DIM)),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(lines), inner);
}

// ---------------------------------------------------------------------------
// Filters bar + hint bar
// ---------------------------------------------------------------------------

fn render_filter(f: &mut Frame, area: Rect, app: &App) {
    let color = if app.filter_editing { ORANGE } else { BRACKET };
    let frame = BracketFrame::new().title(title_line("FILTERS", Some("/"))).color(color);
    let inner = frame.inner(area);
    f.render_widget(frame, area);

    let cursor = if app.filter_editing { "▏" } else { "" };
    let filter_span = if app.filter.is_empty() && !app.filter_editing {
        Span::styled("<all events>", Style::new().fg(DIM))
    } else {
        Span::styled(format!("{}{cursor}", app.filter), Style::new().fg(YELLOW))
    };

    // `re` badge after the text when the filter compiled as a regex.
    let regex_badge: Span = if app.filter_is_regex() {
        Span::styled(" re", Style::new().fg(MAGENTA).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };

    let source_color = if app.source_filter.is_some() { YELLOW } else { DIM };

    let mut spans: Vec<Span> = vec![
        Span::styled("text: ",       Style::new().fg(DIM)),
        filter_span,
        regex_badge,
        Span::raw("    "),
        Span::styled("source: ",     Style::new().fg(DIM)),
        Span::styled(source_label(app.source_filter), Style::new().fg(source_color).add_modifier(Modifier::BOLD)),
        Span::raw("    "),
        Span::styled("min-score: ",  Style::new().fg(DIM)),
        Span::styled(format!("{:.2}", app.min_score), Style::new().fg(score_color(app.min_score)).add_modifier(Modifier::BOLD)),
        Span::raw("    "),
        Span::styled(format!("matches {}/{}", app.filtered_len(), app.buffer.len()), Style::new().fg(DIM)),
    ];

    // Right-justified-ish export badge — appended after the last span
    // so the eye finds it without scanning.
    if let Some(status) = &app.export_status {
        spans.push(Span::raw("    "));
        match status {
            crate::app::ExportStatus::Ok(path, _) => {
                spans.push(Span::styled("saved: ", Style::new().fg(DIM)));
                spans.push(Span::styled(
                    path.display().to_string(),
                    Style::new().fg(GREEN).add_modifier(Modifier::BOLD),
                ));
            }
            crate::app::ExportStatus::Err(msg, _) => {
                spans.push(Span::styled("export failed: ", Style::new().fg(DIM)));
                spans.push(Span::styled(
                    msg.clone(),
                    Style::new().fg(RED).add_modifier(Modifier::BOLD),
                ));
            }
        }
    }

    f.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn render_hint(f: &mut Frame, area: Rect, app: &App) {
    let parts: &[(&str, &str)] = match app.view {
        ViewMode::Summary => &[
            ("q", "quit"),
            ("r", "raw feed"),
            ("n", "network"),
            ("o", "offensive"),
        ],
        ViewMode::Raw => &[
            ("q",      "quit"),
            ("r",      "summary"),
            ("n",      "network"),
            ("o",      "offensive"),
            ("p",      "pause"),
            ("↑↓/jk",  "select"),
            ("/",      "filter"),
            ("s",      "source"),
            ("[ ]",    "min-score"),
            ("x",      "export"),
            ("g/G",    "top/bottom"),
            ("Esc",    "deselect"),
        ],
        ViewMode::Network => &[
            ("q",          "quit"),
            ("n",          "summary"),
            ("r",          "raw"),
            ("o",          "offensive"),
            ("↑↓/jk",      "select"),
            ("d",          "discover"),
            ("↵",          "probe"),
            ("PgUp/PgDn",  "scroll right"),
            ("⇧↑↓",        "scroll iface"),
            ("Esc",        "deselect"),
        ],
        ViewMode::Offensive => &[
            ("q",      "quit"),
            ("o",      "summary"),
            ("r",      "raw feed"),
            ("n",      "network"),
            ("↑↓/jk",  "select"),
            ("Esc",    "deselect"),
        ],
    };
    let mut spans: Vec<Span> = vec![Span::raw(" ")];
    for (i, (k, v)) in parts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::new().fg(DIM)));
        }
        spans.push(Span::styled(k.to_string(), Style::new().fg(BRACKET).add_modifier(Modifier::BOLD)));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(v.to_string(), Style::new().fg(DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kv(key: &'static str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<8} "), Style::new().fg(DIM)),
        value,
    ])
}

fn basename(nt_path: &str) -> String {
    nt_path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(nt_path).to_string()
}

fn truncate_cmdline(cmdline: &str) -> String {
    let total = cmdline.chars().count();
    if total <= CMDLINE_DISPLAY_LIMIT {
        return cmdline.to_string();
    }
    let head: String = cmdline.chars().take(CMDLINE_DISPLAY_LIMIT).collect();
    let extra = total - CMDLINE_DISPLAY_LIMIT;
    format!("{head}…  (+{extra} chars)")
}

pub(crate) fn source_label(s: Option<EventSource>) -> &'static str {
    use EventSource::*;
    match s {
        None             => "ALL",
        Some(Process)    => "PROC",
        Some(File)       => "FILE",
        Some(Registry)   => "REG",
        Some(Network)    => "NET",
        Some(Dns)        => "DNS",
        Some(Usb)        => "USB",
        Some(Wmi)        => "WMI",
    }
}

fn dns_type_label(t: u32) -> String {
    match t {
        1  => "A".into(),
        2  => "NS".into(),
        5  => "CNAME".into(),
        6  => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        _  => format!("type-{t}"),
    }
}

fn format_ts_short(ts: SystemTime) -> String {
    let dt: DateTime<Local> = ts.into();
    dt.format("%H:%M:%S%.3f").to_string()
}

fn format_ts_full(ts: SystemTime) -> String {
    let dt: DateTime<Local> = ts.into();
    dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}
