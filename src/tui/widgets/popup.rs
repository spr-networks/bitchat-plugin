use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use crate::tui::app::{App, TuiPhase};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let popup_area = centered_rect(60, 50, area);
    
    f.render_widget(Clear, popup_area);
    
    if app.popup_active {
        // Render input popup
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Length(3),  // Input
                Constraint::Min(1),     // Space
            ])
            .split(popup_area);
        
        let title = Paragraph::new(app.popup_title.as_str())
            .style(Style::default().add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::TOP | Borders::LEFT | Borders::RIGHT));
        
        f.render_widget(title, chunks[0]);
        
        let input_widget = Paragraph::new(app.popup_input.value())
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL));
        
        f.render_widget(input_widget, chunks[1]);
        
        // Show cursor
        let cursor_pos = app.popup_input.visual_cursor();
        f.set_cursor(
            chunks[1].x + cursor_pos as u16 + 1,
            chunks[1].y + 1,
        );
    } else {
        match &app.phase {
            TuiPhase::Connecting => {
                let items: Vec<ListItem> = app.popup_messages
                    .iter()
                    .map(|msg| ListItem::new(Line::from(msg.as_str())))
                    .collect();
                
                let list = List::new(items)
                    .block(Block::default()
                        .borders(Borders::ALL)
                        .title("Connecting...")
                        .style(Style::default().fg(Color::Yellow)));
                
                f.render_widget(list, popup_area);
            }
            TuiPhase::Error(error) => {
                let error_widget = Paragraph::new(error.as_str())
                    .style(Style::default().fg(Color::Red))
                    .wrap(Wrap { trim: true })
                    .block(Block::default()
                        .borders(Borders::ALL)
                        .title("Error")
                        .style(Style::default().fg(Color::Red)));
                
                f.render_widget(error_widget, popup_area);
            }
            _ => {}
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}