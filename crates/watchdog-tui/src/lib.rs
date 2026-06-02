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
    set_utf8_console();

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

/// Make a double-clicked console render our box-drawing and block glyphs
/// (▁▂▃▄▅, ┌┐, ●, ↑↓…) instead of `?`. Two independent legacy defaults
/// bite here:
///   1. OEM code page — fixed with `SetConsoleOutputCP(CP_UTF8)`.
///   2. The raster ("Terminal") font, which only has CP437 glyphs, so the
///      incremental blocks ▁▂▃▅ (absent from CP437; only ▄ and █ exist)
///      stay `?` even under UTF-8. Force a TrueType font (Consolas) which
///      has full coverage.
/// Windows Terminal already does both, so this is a no-op there. Every
/// step is best-effort — on failure we just keep the existing setting.
#[cfg(windows)]
fn set_utf8_console() {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Console::{
        GetStdHandle, SetConsoleOutputCP, SetCurrentConsoleFontEx, CONSOLE_FONT_INFOEX, COORD,
        STD_OUTPUT_HANDLE,
    };
    const CP_UTF8: u32 = 65001;
    // FF_MODERN | TMPF_VECTOR | TMPF_TRUETYPE. conhost silently ignores a
    // TrueType FaceName unless the TrueType family bits are set, so we
    // must build the struct from scratch rather than mutate the raster
    // font's (which carries FF_DONTCARE = 0).
    const TRUETYPE_FAMILY: u32 = 54;
    const FW_NORMAL: u32 = 400;

    unsafe {
        let _ = SetConsoleOutputCP(CP_UTF8);

        let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) else { return };
        let mut face = [0u16; 32];
        for (slot, ch) in face.iter_mut().zip("Consolas".encode_utf16()) {
            *slot = ch;
        }
        let font = CONSOLE_FONT_INFOEX {
            cbSize: std::mem::size_of::<CONSOLE_FONT_INFOEX>() as u32,
            nFont: 0,
            dwFontSize: COORD { X: 0, Y: 16 }, // 0 width = auto from height
            FontFamily: TRUETYPE_FAMILY,
            FontWeight: FW_NORMAL,
            FaceName: face,
        };
        let _ = SetCurrentConsoleFontEx(handle, BOOL(0), &font);
    }
}

#[cfg(not(windows))]
fn set_utf8_console() {}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
        original(info);
    }));
}
