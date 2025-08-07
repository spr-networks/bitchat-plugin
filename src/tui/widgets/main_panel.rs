use ratatui::{
    layout::Rect,
    prelude::Frame,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use crate::tui::app::{App, FocusArea, Message};

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    // Update viewport height
    app.message_viewport_height = area.height.saturating_sub(2) as usize;
    
    let (messages, dm_target, channel_name) = app.get_current_messages();
    
    // Calculate scroll position for title
    let scroll_indicator = if messages.len() > app.message_viewport_height {
        let current_pos = messages.len().saturating_sub(app.msg_scroll);
        format!(" [{}/{}]", current_pos, messages.len())
    } else {
        String::new()
    };
    
    let title = if let Some(user) = dm_target {
        format!("DM with {}{}", user, scroll_indicator)
    } else if let Some(channel) = channel_name {
        if app.connected {
            format!("{}{}", channel, scroll_indicator)
        } else {
            format!("{} (disconnected){}", channel, scroll_indicator)
        }
    } else {
        "No conversation selected".to_string()
    };
    
    let visible_messages = if messages.len() > app.message_viewport_height {
        let start = if app.msg_scroll > 0 {
            messages.len().saturating_sub(app.message_viewport_height + app.msg_scroll)
        } else {
            messages.len().saturating_sub(app.message_viewport_height)
        };
        let end = messages.len().saturating_sub(app.msg_scroll);
        &messages[start..end]
    } else {
        messages
    };
    
    let items: Vec<ListItem> = visible_messages
        .iter()
        .map(|msg| format_message(msg))
        .collect();
    
    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(if app.focus_area == FocusArea::MainPanel {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            }));
    
    f.render_widget(list, area);
    
    // Render scrollbar if there are more messages than can fit
    if messages.len() > app.message_viewport_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        
        let mut scrollbar_state = ScrollbarState::new(messages.len())
            .position(messages.len().saturating_sub(app.msg_scroll + app.message_viewport_height));
        
        f.render_stateful_widget(
            scrollbar,
            area.inner(&ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

fn format_message(msg: &Message) -> ListItem {
    // Check if this is a DM indicator (starts with → or ←)
    let is_dm_indicator = msg.sender.starts_with("→ ") || msg.sender.starts_with("← ");
    
    let style = if msg.is_self {
        // Our sent messages shown in blue
        Style::default().fg(Color::Blue)
    } else if msg.sender == "system" {
        // System messages in yellow
        Style::default().fg(Color::Yellow)
    } else {
        // Received messages from others shown in green
        Style::default().fg(Color::Green)
    };
    
    let sender_style = if msg.sender == "system" {
        style.add_modifier(Modifier::ITALIC)
    } else if is_dm_indicator {
        style.add_modifier(Modifier::BOLD)
    } else {
        style.add_modifier(Modifier::BOLD)
    };
    
    // Add trust indicator for:
    // 1. Received encrypted messages from trusted peers
    // 2. Sent encrypted messages to trusted peers (shown with → prefix)
    let trust_indicator = if msg.is_trusted {
        "✅ "
    } else {
        ""
    };
    
    let line = Line::from(vec![
        Span::styled(format!("[{}] ", msg.timestamp), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("<{}>", msg.sender), sender_style),
        Span::raw(" "),
        Span::raw(trust_indicator),
        Span::styled(&msg.content, style),
    ]);
    
    ListItem::new(line)
}