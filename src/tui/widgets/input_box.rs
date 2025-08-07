use ratatui::{
    layout::Rect,
    prelude::Frame,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};
use crate::tui::app::{App, FocusArea};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let input_widget = Paragraph::new(app.input.value())
        .style(Style::default().fg(Color::White))
        .block(Block::default()
            .borders(Borders::ALL)
            .title("Input")
            .border_style(if app.focus_area == FocusArea::InputBox {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            }));
    
    f.render_widget(input_widget, area);
    
    // Show cursor when input box is focused
    if app.focus_area == FocusArea::InputBox {
        let cursor_pos = app.input.visual_cursor();
        f.set_cursor(
            area.x + cursor_pos as u16 + 1,
            area.y + 1,
        );
    }
}