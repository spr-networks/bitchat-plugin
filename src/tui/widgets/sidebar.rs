use ratatui::{
    layout::Rect,
    prelude::Frame,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

use crate::tui::app::{App, FocusArea};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let mut items = Vec::new();
    let mut flat_idx = 0;
    
    // Public Channel Section
    let public_unread = app.get_unread_count("#public");
    let public_header = if app.sidebar_state.expanded[0] {
        format!("▼ Public {}", if public_unread > 0 { format!("({})", public_unread) } else { String::new() })
    } else {
        format!("▶ Public {}", if public_unread > 0 { format!("({})", public_unread) } else { String::new() })
    };
    
    let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
        Style::default().bg(Color::Blue).fg(Color::Black)
    } else {
        Style::default()
    };
    items.push(ListItem::new(Line::from(vec![Span::styled(public_header, style)])));
    flat_idx += 1;
    
    if app.sidebar_state.expanded[0] {
        let is_selected = app.sidebar_state.public_selected.unwrap_or(false);
        let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
            Style::default().bg(Color::Blue).fg(Color::Black)
        } else if is_selected {
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
        } else {
            Style::default()
        };
        
        let unread_str = if public_unread > 0 { format!(" ({})", public_unread) } else { String::new() };
        items.push(ListItem::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("#public{}", unread_str), style),
        ])));
        flat_idx += 1;
    }
    
    // Channels Section
    let channel_unread = app.get_section_unread_count(1);
    let channels_header = if app.sidebar_state.expanded[1] {
        format!("▼ Channels {}", if channel_unread > 0 { format!("({})", channel_unread) } else { String::new() })
    } else {
        format!("▶ Channels {}", if channel_unread > 0 { format!("({})", channel_unread) } else { String::new() })
    };
    
    let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
        Style::default().bg(Color::Blue).fg(Color::Black)
    } else {
        Style::default()
    };
    items.push(ListItem::new(Line::from(vec![Span::styled(channels_header, style)])));
    flat_idx += 1;
    
    if app.sidebar_state.expanded[1] {
        for (i, channel) in app.channels.iter().enumerate() {
            let is_selected = app.sidebar_state.channel_selected == Some(i);
            let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
                Style::default().bg(Color::Blue).fg(Color::Black)
            } else if is_selected {
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
            } else {
                Style::default()
            };
            
            let unread = app.get_unread_count(channel);
            let unread_str = if unread > 0 { format!(" ({})", unread) } else { String::new() };
            items.push(ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{}{}", channel, unread_str), style),
            ])));
            flat_idx += 1;
        }
    }
    
    // People Section
    let people_unread = app.get_section_unread_count(2);
    let people_header = if app.sidebar_state.expanded[2] {
        format!("▼ People {}", if people_unread > 0 { format!("({})", people_unread) } else { String::new() })
    } else {
        format!("▶ People {}", if people_unread > 0 { format!("({})", people_unread) } else { String::new() })
    };
    
    let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
        Style::default().bg(Color::Blue).fg(Color::Black)
    } else {
        Style::default()
    };
    items.push(ListItem::new(Line::from(vec![Span::styled(people_header, style)])));
    flat_idx += 1;
    
    if app.sidebar_state.expanded[2] {
        for (i, person) in app.people.iter().enumerate() {
            let is_selected = app.sidebar_state.people_selected == Some(i);
            let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
                Style::default().bg(Color::Blue).fg(Color::Black)
            } else if is_selected {
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)
            } else {
                Style::default()
            };
            
            let unread = app.get_unread_count(&format!("dm:{}", person));
            let unread_str = if unread > 0 { format!(" ({})", unread) } else { String::new() };
            items.push(ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{}{}", person, unread_str), style),
            ])));
            flat_idx += 1;
        }
    }
    
    // Blocked Section
    let blocked_header = if app.sidebar_state.expanded[3] {
        "▼ Blocked"
    } else {
        "▶ Blocked"
    };
    
    let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
        Style::default().bg(Color::Blue).fg(Color::Black)
    } else {
        Style::default()
    };
    items.push(ListItem::new(Line::from(vec![Span::styled(blocked_header, style)])));
    flat_idx += 1;
    
    if app.sidebar_state.expanded[3] {
        for blocked in &app.blocked {
            let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
                Style::default().bg(Color::Blue).fg(Color::Black)
            } else {
                Style::default().fg(Color::Red)
            };
            items.push(ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(blocked, style),
            ])));
            flat_idx += 1;
        }
    }
    
    // Settings Section
    let settings_header = if app.sidebar_state.expanded[4] {
        "▼ Settings"
    } else {
        "▶ Settings"
    };
    
    let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
        Style::default().bg(Color::Blue).fg(Color::Black)
    } else {
        Style::default()
    };
    items.push(ListItem::new(Line::from(vec![Span::styled(settings_header, style)])));
    flat_idx += 1;
    
    if app.sidebar_state.expanded[4] {
        let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
            Style::default().bg(Color::Blue).fg(Color::Black)
        } else {
            Style::default()
        };
        items.push(ListItem::new(Line::from(vec![
            Span::raw("  "),
            Span::styled("Edit Nickname", style),
        ])));
        flat_idx += 1;
        
        let style = if flat_idx == app.sidebar_flat_selected && app.focus_area == FocusArea::Sidebar {
            Style::default().bg(Color::Blue).fg(Color::Black)
        } else {
            Style::default()
        };
        items.push(ListItem::new(Line::from(vec![
            Span::raw("  "),
            Span::styled("Reconnect", style),
        ])));
    }
    
    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(format!("BitChat - {}", app.nickname))
            .border_style(if app.focus_area == FocusArea::Sidebar {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            }));
    
    f.render_widget(list, area);
}