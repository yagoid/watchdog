# Changelog

All notable changes to this project are documented here. The format roughly
follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-04

### Added
- Five more behavioural detectors (13 total): `EntropyBurst` (high-entropy
  write bursts — ransomware encrypting in the act), `ProcessImpersonation`
  (critical system images running from the wrong path/parent),
  `ImageLoadFromUnusualPath` (unsigned DLLs loaded from user-writable paths —
  sideloading), `RareDestination` (a focused image connecting to a network
  prefix it has never used), and `OffHoursActivity` (interactive launches
  during normally-idle hours).
- Baseline learns more: per-image network destination prefixes, a machine-wide
  hour-of-day activity profile, and a separate traversal-window counter.
- Kernel-File now emits write events (`FileWrite`), feeding `EntropyBurst`,
  alongside creates.
- Scrollable INCIDENTS panel in the Summary view (up/down).
- Scoop bucket manifest — `scoop bucket add` + `scoop install watchdog`.
- Project landing page under `docs/` for GitHub Pages.

### Changed
- Network view layout: NEIGHBORS promoted above INTERFACES, with column-width
  adjustments.
- Force a UTF-8 output code page and a TrueType (Consolas) console font so a
  double-clicked conhost renders box/block glyphs instead of `?`.

### Fixed
- `RapidFileTraversal` false positives: bulk reads of a process's own install
  tree or of read-only library/cache trees (`node_modules`, `site-packages`,
  `typeshed`, `.vscode\extensions`, `.cargo\registry`, …) no longer count, and
  the learned ceiling is now gated on observed traversal windows rather than
  process-spawn count (an IDE reindex was scoring full CRIT).
- Drop System (PID 4) file I/O at the ETW callback — kernel cache/paging I/O no
  longer spams the ransomware detectors and never matured in the baseline.
- Self-observation amplification loop: Watchdog inspecting a file emitted an
  event for its own PID that fed back into the detector that opened it.

[0.2.0]: https://github.com/yagoid/watchdog/releases/tag/v0.2.0

## [0.1.0] - 2026-06-01

First public release.

### Added
- Real-time behavioural monitoring through five ETW providers (Kernel-Process,
  Kernel-File, Kernel-Registry, Kernel-Network, DNS-Client) plus a synthetic
  removable-drive watcher.
- Eight behavioural detectors (`LolbinSpawn`, `UnusualParentChild`,
  `RegistryPersistence`, `RapidFileTraversal`, `UnsignedFromUserPath`,
  `NewNetworkEgress`, `DnsAnomaly`, `UsbExfilHint`) combined into a single
  probabilistic score — no signatures, no external threat feeds.
- Runtime-learned per-image baseline, persisted across runs, with a `--learn`
  observe-only mode. LOLBins excluded from the baseline by design.
- Four-view terminal UI (Summary / Raw / Network / Offensive): verdict and
  defensive-posture summary, analyst feed with filters and JSONL export, live
  network inventory with discovery sweep and per-host probe, and a read-only
  WiFi inspector.
- Opt-in headless Windows service mode (`install-service` / `uninstall-service`):
  LocalSystem auto-start with SCM failure-action recovery, incidents sinked to
  a rotating JSONL file and the Windows Event Log, and a hardened on-disk
  footprint (binary in Program Files, data dir locked to SYSTEM/Administrators).
- `requireAdministrator` manifest so launching auto-prompts for elevation.

[0.1.0]: https://github.com/yagoid/watchdog/releases/tag/v0.1.0
