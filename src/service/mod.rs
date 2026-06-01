//! Opt-in Windows service mode. None of this runs unless the user explicitly
//! invokes `install-service` / `run-service`; the default binary launch is
//! the interactive TUI and is untouched by anything here.
//!
//! The service runs the same pipeline as the TUI (`crate::pipeline`) but,
//! living in Session 0, has no terminal — so instead of rendering it sinks
//! incidents to the Windows Event Log and a rotating JSONL file under
//! `%ProgramData%\Watchdog\`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use chrono::Local;

pub mod install;
pub mod run;
mod sink;

/// SCM service key name and the ETW session it runs (distinct from the TUI's
/// `Watchdog-RT` so the two never steal each other's real-time session).
pub const SERVICE_NAME: &str = "Watchdog";
pub const SERVICE_DISPLAY_NAME: &str = "Watchdog Behavioral Monitor";
pub const SERVICE_SESSION_NAME: &str = "Watchdog-SVC";

/// Windows Event Log source name. Registered under the Application log at
/// install time.
pub const EVENT_SOURCE: &str = "Watchdog";

/// `%ProgramData%\Watchdog\` — same root the baseline persists to.
pub fn data_dir() -> PathBuf {
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(pd).join("Watchdog")
}

/// Append a line to the service's own operational log. Best-effort: a
/// headless service has nowhere else to talk, but losing a log line must
/// never take the service down, so all errors are swallowed.
pub fn service_log(msg: &str) {
    let path = data_dir().join("service.log");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{} {}", Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"), msg);
    }
}
