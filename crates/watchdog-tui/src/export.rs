//! JSONL export of the currently-visible feed.
//!
//! One event per line. The event→JSON mapping lives in `watchdog-core`
//! (`scored_event_to_json`) because the service's incident sink needs the
//! same schema; this module just picks which events to dump and where.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use chrono::Local;
use watchdog_core::scored_event_to_json;

use crate::app::App;

/// Dump every event currently passing the filter to a JSONL file under
/// `%TEMP%`. Returns the path on success.
pub fn write_visible(app: &App) -> io::Result<PathBuf> {
    let ts = Local::now().format("%Y%m%d_%H%M%S");
    let path = std::env::temp_dir().join(format!("watchdog-{ts}.jsonl"));
    let file = File::create(&path)?;
    let mut w = BufWriter::new(file);
    for b in app.filtered_iter() {
        let v = scored_event_to_json(&b.event);
        // serde_json::to_writer doesn't add a trailing newline, which we
        // need for JSONL.
        serde_json::to_writer(&mut w, &v)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(path)
}
