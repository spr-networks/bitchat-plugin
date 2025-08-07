use ratatui::{
    layout::Rect,
    prelude::Frame,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::app::{App, FocusArea};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let help_text = match app.focus_area {
        FocusArea::Sidebar => {
            vec![
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::raw(": Switch Focus | "),
                Span::styled("↑↓", Style::default().fg(Color::Cyan)),
                Span::raw(": Navigate | "),
                Span::styled("Enter", Style::default().fg(Color::Cyan)),
                Span::raw(": Select/Toggle | "),
                Span::styled("Ctrl+C", Style::default().fg(Color::Cyan)),
                Span::raw(": Quit"),
            ]
        }
        FocusArea::MainPanel => {
            vec![
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::raw(": Switch Focus | "),
                Span::styled("↑↓", Style::default().fg(Color::Cyan)),
                Span::raw(": Scroll | "),
                Span::styled("Ctrl+C", Style::default().fg(Color::Cyan)),
                Span::raw(": Quit"),
            ]
        }
        FocusArea::InputBox => {
            if app.popup_active {
                vec![
                    Span::styled("Enter", Style::default().fg(Color::Cyan)),
                    Span::raw(": Submit | "),
                    Span::styled("Esc", Style::default().fg(Color::Cyan)),
                    Span::raw(": Cancel"),
                ]
            } else {
                vec![
                    Span::styled("Tab", Style::default().fg(Color::Cyan)),
                    Span::raw(": Switch Focus | "),
                    Span::styled("Enter", Style::default().fg(Color::Cyan)),
                    Span::raw(": Send | "),
                    Span::styled("Ctrl+C", Style::default().fg(Color::Cyan)),
                    Span::raw(": Quit"),
                ]
            }
        }
    };
    
    let help_paragraph = Paragraph::new(Line::from(help_text))
        .style(Style::default().bg(Color::DarkGray));
    
    f.render_widget(help_paragraph, area);
}