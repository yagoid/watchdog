//! Terminal UI for the watchdog event feed.
//!
//! Enters raw mode + alternate screen, runs a 60-fps-capped draw/poll
//! loop, and yields when the user quits. A panic hook restores the
//! terminal so a crash doesn't leave the user with an unusable shell.

mod app;
mod bracket_frame;
#[cfg(windows)]
mod defenses;
mod dns_cache;
mod export;
mod host_probe;
mod incidents;
mod network_footprint;
mod theme;
mod ui;

pub use app::App;

use std::io::stdout;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::Terminal;

const TICK_RATE: Duration = Duration::from_millis(33); // ~30 FPS cap

pub fn run(mut app: App) -> Result<()> {
    install_panic_hook();

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut app);

    // Restore even on error — but ignore restore failures so we surface
    // the real cause.
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);

    result
}

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        app.ingest();
        app.tick_stats();

        if !app.paused {
            terminal.draw(|f| ui::render(f, app))?;
        } else {
            // When paused, redraw on a slower cadence so the stats header
            // still ticks (uptime, dropped) without blowing CPU.
            terminal.draw(|f| ui::render(f, app))?;
        }

        if event::poll(TICK_RATE)? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    app.handle_key(k.code, k.modifiers);
                }
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
        original(info);
    }));
}
