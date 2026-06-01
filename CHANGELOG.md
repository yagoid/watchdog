# Changelog

All notable changes to this project are documented here. The format roughly
follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/).

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
