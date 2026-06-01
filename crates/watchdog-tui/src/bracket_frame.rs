//! Custom widget: a rectangular frame with single-char corner glyphs
//! highlighted in the bright bracket accent, thinner edges in a dimmer
//! accent between them, and an optional title that sits in a "gap" of
//! the top edge.
//!
//! The title is padded with leading/trailing spaces on the way in so
//! the edge characters under it get overwritten — yielding the
//! reference look `┌  FEED   f  ───┐` instead of `┌──FEED   f────┐`.

use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

use crate::theme;

const CORNER_TL: &str = "┌";
const CORNER_TR: &str = "┐";
const CORNER_BL: &str = "└";
const CORNER_BR: &str = "┘";
const EDGE_H:    &str = "─";
const EDGE_V:    &str = "│";

/// Number of space cells we pad around the title text on each side.
const TITLE_GUTTER: usize = 2;

pub struct BracketFrame<'a> {
    title_left: Option<Line<'a>>,
    title_right: Option<Line<'a>>,
    color: ratatui::style::Color,
}

impl<'a> BracketFrame<'a> {
    pub fn new() -> Self {
        Self {
            title_left: None,
            title_right: None,
            color: theme::BRACKET,
        }
    }

    pub fn title<L: Into<Line<'a>>>(mut self, line: L) -> Self {
        self.title_left = Some(line.into());
        self
    }

    pub fn title_right<L: Into<Line<'a>>>(mut self, line: L) -> Self {
        self.title_right = Some(line.into());
        self
    }

    pub fn color(mut self, c: ratatui::style::Color) -> Self {
        self.color = c;
        self
    }

    /// Inner area: excludes the top/bottom edge rows, the left/right
    /// edge columns, and a 1-col gutter on each side so content doesn't
    /// kiss the edges.
    pub fn inner(&self, area: Rect) -> Rect {
        let w = area.width.saturating_sub(4);
        let h = area.height.saturating_sub(2);
        Rect {
            x: area.x + 2,
            y: area.y + 1,
            width: w,
            height: h,
        }
    }
}

impl<'a> Default for BracketFrame<'a> {
    fn default() -> Self { Self::new() }
}

impl<'a> Widget for BracketFrame<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 4 || area.height < 2 {
            return;
        }

        let corner_style = Style::new().fg(self.color);
        let edge_style   = Style::new().fg(theme::BRACKET_DIM);

        let right_x = area.x + area.width - 1;
        let bottom_y = area.y + area.height - 1;

        // 1. Edges — fill the full inner perimeter. Corners and title
        //    spaces will overwrite the relevant cells next.
        for x_pos in (area.x + 1)..right_x {
            buf.set_string(x_pos, area.y,   EDGE_H, edge_style);
            buf.set_string(x_pos, bottom_y, EDGE_H, edge_style);
        }
        for y_pos in (area.y + 1)..bottom_y {
            buf.set_string(area.x, y_pos, EDGE_V, edge_style);
            buf.set_string(right_x, y_pos, EDGE_V, edge_style);
        }

        // 2. Corner glyphs in the bright accent.
        buf.set_string(area.x,  area.y,   CORNER_TL, corner_style);
        buf.set_string(right_x, area.y,   CORNER_TR, corner_style);
        buf.set_string(area.x,  bottom_y, CORNER_BL, corner_style);
        buf.set_string(right_x, bottom_y, CORNER_BR, corner_style);

        // 3. Titles on the top edge — padded with spaces so they punch a
        //    visible gap through the edge characters rather than sitting
        //    flush against them.
        let title_area = Rect {
            x: area.x + 1,
            y: area.y,
            width: area.width.saturating_sub(2),
            height: 1,
        };
        if let Some(left) = self.title_left {
            Paragraph::new(pad_line(left))
                .alignment(Alignment::Left)
                .render(title_area, buf);
        }
        if let Some(right) = self.title_right {
            Paragraph::new(pad_line(right))
                .alignment(Alignment::Right)
                .render(title_area, buf);
        }
    }
}

fn pad_line(line: Line<'_>) -> Line<'_> {
    let mut spans: Vec<Span<'_>> = Vec::with_capacity(line.spans.len() + 2);
    spans.push(Span::raw(" ".repeat(TITLE_GUTTER)));
    spans.extend(line.spans);
    spans.push(Span::raw(" ".repeat(TITLE_GUTTER)));
    Line::from(spans)
}

/// "NAME   k" title — name in the bright bracket accent, hotkey in
/// magenta. Hotkey gets visual weight without competing with the panel
/// name for attention.
pub fn title_line<'a>(name: &'a str, hotkey: Option<&'a str>) -> Line<'a> {
    let mut spans = vec![
        Span::styled(name, Style::new().fg(theme::BRACKET)),
    ];
    if let Some(k) = hotkey {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(k, Style::new().fg(theme::MAGENTA)));
    }
    Line::from(spans)
}
