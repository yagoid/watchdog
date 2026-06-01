//! Watchdog entry point. Default (no subcommand) launches the interactive
//! TUI; the `*-service` subcommands drive the optional, opt-in Windows
//! service mode (see `service`). Nothing about the service path runs unless
//! the user explicitly asks for it.

use std::sync::Arc;

use anyhow::Result;

use watchdog_tui::App;

mod pipeline;
mod service;

/// ETW real-time session name for the interactive TUI. The service uses a
/// distinct name so the two never steal each other's session.
const TUI_SESSION_NAME: &str = "Watchdog-RT";

fn main() -> Result<()> {
    env_logger::init();

    match std::env::args().nth(1).as_deref() {
        Some("install-service") => service::install::install(),
        Some("uninstall-service") => service::install::uninstall(),
        // Invoked by the SCM, not by hand — fails with error 1063 otherwise.
        Some("run-service") => service::run::dispatch(),
        Some("--help") | Some("-h") => {
            print_usage();
            Ok(())
        }
        _ => run_tui(),
    }
}

fn run_tui() -> Result<()> {
    let learn_only = std::env::args().any(|a| a == "--learn");

    let (pipeline, rx_scored) = pipeline::start(TUI_SESSION_NAME, learn_only)?;

    let app = App::new(
        rx_scored,
        Arc::clone(&pipeline.table),
        Arc::clone(&pipeline.dropped),
        Arc::clone(&pipeline.baseline),
        learn_only,
    );

    // `pipeline` is held until `run` returns; dropping it then stops ETW.
    watchdog_tui::run(app)
}

fn print_usage() {
    println!(
        "watchdog - real-time behavioral security monitor (Windows)\n\
         \n\
         USAGE:\n\
         \x20 watchdog                 Launch the interactive TUI (default)\n\
         \x20 watchdog --learn         TUI in observe-only baseline-learning mode\n\
         \x20 watchdog install-service Install + start the headless background service\n\
         \x20 watchdog uninstall-service  Stop + remove the service\n\
         \n\
         All modes require administrator privileges (ETW)."
    );
}
