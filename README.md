# Watchdog

Real-time behavioural security monitor for Windows. It watches your machine through Windows' own instrumentation (ETW), flags suspicious behaviour with heuristics and a baseline it learns at runtime, and presents everything in a terminal UI — or runs headless as a background service.

**No signature databases. No external threat-intelligence feeds.** Everything it reports comes from observing the local system and reasoning about behaviour, so it's useful from the first minute on any machine, offline.

> Status: pre-1.0, single-developer project. Windows-only by design.

---

## What it does

- **Observes** process starts/stops, image loads, file creates, registry writes, outbound TCP connections, DNS queries (via the Windows resolver) and removable-drive mounts — all through five real-time **ETW** providers plus a synthetic drive watcher.
- **Enriches** every event in flight: live process table, Authenticode signature, real command line, device-path → `C:\` canonicalisation, and socket → owning-PID resolution.
- **Detects** with eight behavioural heuristics (see below), combined into a single score; only events above a threshold surface, bucketed `INFO` / `WARN` / `CRIT`.
- **Learns** a per-binary baseline at runtime (usual parents/children, file-I/O ceilings, whether it ever phones home) so normal activity stops alerting after a short familiarisation period. LOLBins are excluded so an attacker can't "train" the tool to ignore them.
- **Shows** it all in a four-view TUI, or **sinks** it to logs when run as a service.

### Detectors

| Detector | Catches |
|---|---|
| `LolbinSpawn` | Signed-but-abusable binaries (mshta, rundll32, certutil, powershell…) with malware-style command lines (`-EncodedCommand`, `iex`, `DownloadString`, base64…) |
| `UnusualParentChild` | Rarely-benign chains: Office → cmd/powershell, browser → shell, lsass → anything |
| `RegistryPersistence` | Writes to known autostart locations (Run keys, IFEO, Winlogon, AppInit_DLLs, service ImagePath…) |
| `RapidFileTraversal` | A process touching ≥25 directories in 10s — ransomware / bulk exfiltration fingerprint (baseline-aware) |
| `EntropyBurst` | A process writing a burst of high-entropy (encrypted-looking) files — ransomware encryption in the act; complements RapidFileTraversal |
| `UnsignedFromUserPath` | Unsigned binary running from `%TEMP%`, `%APPDATA%`, Downloads, Desktop, Recycle Bin or an ADS |
| `NewNetworkEgress` | A previously-silent program making its first-ever outbound connection |
| `DnsAnomaly` | High-entropy / long / abused-TLD domains (DGA-style), multi-evidence |
| `UsbExfilHint` | A removable drive appears, then a process bulk-copies files to it within 5 minutes |
| `ProcessImpersonation` | A critical system image (svchost, lsass, services…) running outside System32, or svchost not launched by services.exe |
| `ImageLoadFromUnusualPath` | An unsigned/untrusted module (DLL) loaded from a user-writable path — DLL sideloading / search-order hijacking |
| `RareDestination` | A mature, focused program connecting to a network prefix it has never used before — C2-callback signal (chatty clients auto-excluded) |
| `OffHoursActivity` | An interactive process launched during an hour this host is normally idle — amplifies other signals (learned hour-of-day profile) |

### Views (TUI)

- **Summary** (default) — verdict bar, defensive posture (Defender/firewall/UAC/VPN), today's counters, an incident queue in plain language, network footprint, and Watchdog's own health.
- **Raw** (`r`) — analyst feed of every scored event with filters, regex, source/score filtering and JSONL export. Alerts survive noise bursts via score-biased buffer eviction.
- **Network** (`n`) — adapters, ARP/NDP neighbours (with reverse DNS + OUI vendor), live TCP table, per-host inspector (port probe + OS hint from TTL), and an ICMP discovery sweep of your subnet.
- **Offensive** (`o`) — lab-use WiFi scan with per-network security/attack-surface explanations. Read-only; no attack code.

---

## Requirements

- Windows 10 or 11.
- **Administrator privileges** — creating ETW real-time sessions and reading other processes' command lines require elevation. The binary carries a `requireAdministrator` manifest, so launching it raises the UAC prompt automatically.
- To build from source: the Rust toolchain (MSVC ABI) and the Visual Studio Build Tools (C++ / `link.exe`). No other native dependencies — all Windows APIs are linked against system DLLs.

---

## Install

### Scoop (terminal)

If you use [Scoop](https://scoop.sh/):

```powershell
scoop bucket add watchdog https://github.com/yagoid/watchdog
scoop install watchdog
```

`scoop update watchdog` later pulls new versions. Because Watchdog needs elevation and the Scoop shim doesn't auto-elevate, run it from an **elevated** terminal (`watchdog`) or launch the **Watchdog** Start Menu shortcut Scoop creates (which prompts for UAC).

### Download a release

Grab `watchdog.exe` from the [Releases](../../releases) page and run it from an elevated terminal (or just double-click and accept the UAC prompt).

> **SmartScreen note:** the binary is unsigned (no code-signing certificate), so the first run shows *"Windows protected your PC"*. Choose **More info → Run anyway**. The source is here for you to audit and build yourself if you prefer.

### Build from source

```powershell
# Install Rust (MSVC) if you don't have it
winget install Rustlang.Rustup

# Build the release binary
cargo build --release
# -> target\release\watchdog.exe
```

Release build is what you want — a debug build is far too slow for the event firehose.

---

## Usage

Run from a terminal opened **as Administrator** (or let the UAC prompt elevate it).

```powershell
# Interactive TUI (the main way to use it)
.\watchdog.exe

# Observe-only learning pass: feed the baseline without raising alerts.
# Useful for an initial calibration on a known-clean machine.
.\watchdog.exe --learn

# Show help
.\watchdog.exe --help
```

Keys: `r`/`n`/`o` switch views (and back to Summary), `p` pause the feed, `q` quit. In the Raw view: `↑↓`/`jk` to select, `/` filter, `s` cycle source, `[`/`]` min-score, `x` export.

### Background service (optional)

For an always-on monitor that starts at boot and survives logoff, install Watchdog as a Windows service. This is **entirely optional** — nothing runs as a service unless you ask for it. A service has no desktop, so instead of the TUI it writes incidents to the Windows Event Log and a rotating JSONL file.

```powershell
# Install + start (LocalSystem, auto-start, auto-restart on crash)
.\watchdog.exe install-service

# Check it (use sc.exe / Get-Service — NOT `sc`, which is a PowerShell alias for Set-Content)
sc.exe query Watchdog
Get-Service Watchdog

# Stop / remove
sc.exe stop Watchdog
.\watchdog.exe uninstall-service
```

When installed, the service binary is copied to `C:\Program Files\Watchdog\` and the data directory is locked down to SYSTEM + Administrators.

**Where to look for output (service mode):**

| Path / source | Contents |
|---|---|
| `%ProgramData%\Watchdog\incidents.jsonl` | Warn-and-above events, one JSON object per line |
| Event Viewer → Windows Logs → Application, source `Watchdog` | Crit-level alerts (`Get-WinEvent -ProviderName Watchdog`) |
| `%ProgramData%\Watchdog\service.log` | Service operational log (start/stop/errors) |
| `%ProgramData%\Watchdog\baseline.bin` | Learned baseline (shared with the TUI; persists across runs) |

The TUI (`Watchdog-RT`) and the service (`Watchdog-SVC`) use distinct ETW sessions, so you can run the TUI for a deep-dive while the service keeps watching.

---

## How it works

A four-stage pipeline, one thread per stage, connected by bounded channels:

```
ETW callbacks  →  enrichment  →  detection  →  ┌─ TUI (ratatui)            [default]
                                               └─ service sink (JSONL+Event Log) [run-service]
```

The hot path is deliberately synchronous (no async runtime) to keep ETW callback latency predictable. Detector sub-scores are combined as `1 − Π(1 − sᵢ)` so independent signals reinforce without saturating. Written in Rust — a security tool shouldn't itself be a memory-safety liability.

---

## Limitations

- **Windows-only** — ETW is the entire foundation.
- **Browser DNS-over-HTTPS is invisible** — Chrome/Edge/Brave bypass the Windows DNS resolver, so the DNS detector only sees system-resolver lookups.
- **No driver-level visibility** — stealthy process injection (the domain of `Microsoft-Windows-Threat-Intelligence`) needs a signed Protected Process; out of scope for an unsigned user-mode binary.
- **Defender real-time state** can't be read directly (tamper protection); presence of `MsMpEng.exe` is used as a proxy.
- The active discovery sweep refuses subnets larger than /22.

---

## Responsible use

The Network and Offensive views perform active reconnaissance (ICMP sweeps, TCP port probes, WiFi enumeration) against the local network. Use them only on networks you own or are authorised to test. The Offensive view is educational and read-only — it explains attack surface, it does not attack.

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
