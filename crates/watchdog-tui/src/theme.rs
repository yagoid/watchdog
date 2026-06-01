//! Color palette translated from the "Bracket Frame" reference design.
//!
//! Picking RGB constants directly (instead of named ANSI colors) means
//! every terminal that supports truecolor renders the design as
//! intended. Older 16-color terminals fall back to nearest neighbour.

use ratatui::style::Color;

// Base canvas
#[allow(dead_code)] // we rely on the terminal's own background today
pub const BG:        Color = Color::Rgb(0x06, 0x08, 0x0a);
pub const FG:        Color = Color::Rgb(0xa8, 0xa8, 0xb0);
pub const FG_BRIGHT: Color = Color::Rgb(0xe8, 0xe8, 0xee);
pub const DIM:       Color = Color::Rgb(0x5a, 0x5a, 0x64);

// Selection background fills the row but keeps fg readable.
pub const SELECT_BG: Color = Color::Rgb(0x2a, 0x2a, 0x30);

// Bracket frame accents — bright cyan for everything that's a frame
// corner. We keep a dim variant for future "out of focus" states.
pub const BRACKET:     Color = Color::Rgb(0x00, 0xe5, 0xff);
pub const BRACKET_DIM: Color = Color::Rgb(0x00, 0x55, 0x65);

// Severity / payload accents
pub const CYAN:    Color = Color::Rgb(0x00, 0xe5, 0xff); // INFO
pub const ORANGE:  Color = Color::Rgb(0xff, 0xbe, 0x2e); // WARN
pub const RED:     Color = Color::Rgb(0xff, 0x3d, 0x5e); // CRIT
pub const GREEN:   Color = Color::Rgb(0x4c, 0xff, 0x9e);
pub const MAGENTA: Color = Color::Rgb(0xff, 0x35, 0xb3);
pub const YELLOW:  Color = Color::Rgb(0xff, 0xbe, 0x2e); // alias for ORANGE
pub const ACCENT:  Color = Color::Rgb(0x1a, 0x8a, 0x9a); // sparkline body

// Aliases kept so existing call sites don't need to be touched all at
// once. GRAY in old palette ≈ DIM in new.
pub const GRAY: Color = DIM;
