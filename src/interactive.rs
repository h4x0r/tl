//! Interactive console interface for timeline data display
//! Adapted from csview's table formatting system with interactive navigation

use crate::types::TimelineEvent;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use std::io::{self, Stdout};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Format a number with comma separators
fn format_number_with_commas(mut num: u64) -> String {
    if num == 0 {
        return "0".to_string();
    }
    
    let mut result = String::new();
    let mut count = 0;
    
    while num > 0 {
        if count > 0 && count % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, (b'0' + (num % 10) as u8) as char);
        num /= 10;
        count += 1;
    }
    
    result
}



/// Color theme for the interactive viewer
struct Theme {
    /// Header and footer background
    header_bg: Color,
    /// Header and footer text
    header_fg: Color,
    /// Selected row background
    selected_bg: Color,
    /// Selected row foreground
    selected_fg: Color,
    /// Border color
    border: Color,
    /// Normal text color
    normal_text: Color,
    /// Details pane title
    details_title: Color,
    /// Column separator color
    separator_color: Color,
    /// Column colors for alternating highlighting
    column_colors: [Color; 6],
}

impl Theme {
    fn dark() -> Self {
        // Using Catppuccin Mocha palette for pastel colors
        Theme {
            header_bg: Color::Rgb(255, 255, 255), // Plain white background
            header_fg: Color::Rgb(0, 0, 0),       // Plain black text
            selected_bg: Color::Rgb(62, 61, 50),
            selected_fg: Color::Rgb(192, 192, 192),
            border: Color::Rgb(131, 148, 150),
            normal_text: Color::Rgb(192, 192, 192),
            details_title: Color::Rgb(137, 180, 250), // Catppuccin Blue
            separator_color: Color::Rgb(90, 90, 90), // Dark grey for separators
            column_colors: [
                Color::Rgb(250, 179, 135), // Catppuccin Peach (pastel orange) - Filename
                Color::Rgb(137, 180, 250), // Catppuccin Blue (pastel blue) - Timestamp
                Color::Rgb(203, 166, 247), // Catppuccin Mauve (pastel purple) - Event
                Color::Rgb(245, 194, 231), // Catppuccin Pink (pastel pink) - Record
                Color::Rgb(166, 227, 161), // Catppuccin Green (pastel green) - Size
                Color::Rgb(249, 226, 175), // Catppuccin Yellow (pastel yellow) - Location
            ],
        }
    }
}

/// Pre-formatted row for fast rendering
#[derive(Clone)]
pub struct FormattedRow {
    pub filename: String,
    pub timestamp: String,
    pub type_source: String,
    pub record: String,
    pub size: String,
    pub location: String,
    pub full_path: String, // Combined location + filename for efficient search
    pub is_deleted: bool, // Track if file is deleted for strikethrough formatting
}

/// Interactive timeline viewer with lazy loading
pub struct InteractiveViewer {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    events: Vec<TimelineEvent>,
    records: Vec<crate::types::MftRecord>,
    formatted_rows: Vec<FormattedRow>, // Pre-formatted data for fast rendering
    table_state: TableState,
    horizontal_scroll: usize,
    filter_text: String,
    filtered_events: Vec<usize>, // Indices of events that match current filter
    show_help: bool,
    terminal_width: u16,
    terminal_height: u16,
    data_source: String, // Store the data source for header display
    viewport_start: usize, // First visible row index
    viewport_size: usize,  // Number of visible rows
    current_column: usize, // Current column index for cell navigation (0-4)
    total_timeline_events: usize, // Total timeline events from source (before filtering)
    timezone: Tz, // Timezone for timestamp display
    theme: Theme, // Color theme
    // Lazy loading state
    timeline_ready: bool,
    // Search state
    search_mode: bool,
    search_query: String,
    search_results: Vec<usize>, // Indices of events that match search
    current_search_index: usize, // Current position in search results
}

impl InteractiveViewer {
    /// Create a new interactive viewer (legacy - slow startup)
    pub fn new(events: Vec<TimelineEvent>, records: Vec<crate::types::MftRecord>, timezone: Tz, data_source: String, total_timeline_events: usize) -> io::Result<Self> {
        // Setup terminal
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let filtered_events: Vec<usize> = (0..events.len()).collect();
        let mut table_state = TableState::default();
        table_state.select(Some(0));

        // Get terminal size
        let size = terminal.size()?;
        let viewport_size = (size.height as usize).saturating_sub(2); // Account for header/footer

        // Pre-format all data for fast rendering
        let formatted_rows = Self::preformat_events(&events, &records, timezone);

        Ok(Self {
            terminal,
            events,
            records,
            formatted_rows,
            table_state,
            horizontal_scroll: 0,
            filter_text: String::new(),
            filtered_events,
            show_help: false,
            terminal_width: size.width,
            terminal_height: size.height,
            data_source,
            viewport_start: 0,
            viewport_size,
            current_column: 0,
            total_timeline_events,
            timezone,
            theme: Theme::dark(),
            timeline_ready: true,
            // Initialize search state
            search_mode: false,
            search_query: String::new(),
            search_results: Vec::new(),
            current_search_index: 0,
        })
    }

    /// Create a new interactive viewer with fast startup (lazy loading)
    pub fn new_fast(records: Vec<crate::types::MftRecord>, timezone: Tz, data_source: String, total_timeline_events: usize) -> io::Result<Self> {
        // Don't setup terminal yet - wait until after timeline is built
        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(io::stdout()))?, // Placeholder, will be properly initialized later
            events: Vec::new(), // Empty - will be populated lazily
            records,
            formatted_rows: Vec::new(), // Empty - will be populated lazily
            table_state,
            horizontal_scroll: 0,
            filter_text: String::new(),
            filtered_events: Vec::new(),
            show_help: false,
            terminal_width: 80, // Default - will be updated when terminal is initialized
            terminal_height: 24, // Default - will be updated when terminal is initialized
            data_source,
            viewport_start: 0,
            viewport_size: 22, // Default - will be updated when terminal is initialized
            current_column: 0,
            total_timeline_events,
            timezone,
            theme: Theme::dark(),
            timeline_ready: false, // Timeline will be built first
            // Initialize search state
            search_mode: false,
            search_query: String::new(),
            search_results: Vec::new(),
            current_search_index: 0,
        })
    }






    /// Run the interactive viewer
    pub fn run(&mut self) -> io::Result<()> {
        // Build timeline if not ready (blocking)
        if !self.timeline_ready {
            self.build_timeline_simple();
        }
        
        // Now setup terminal after timeline is ready
        self.setup_terminal()?;
        
        loop {
            self.draw()?;

            // Poll for events with a short timeout to allow UI updates
            if event::poll(std::time::Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    match self.handle_key_event(key) {
                        KeyResult::Quit => break,
                        KeyResult::Continue => {}
                    }
                }
            }
        }

        // Cleanup
        terminal::disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            terminal::LeaveAlternateScreen,
            cursor::Show
        )?;

        Ok(())
    }

    /// Setup terminal after timeline is ready
    fn setup_terminal(&mut self) -> io::Result<()> {
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;
        let backend = CrosstermBackend::new(stdout);
        self.terminal = Terminal::new(backend)?;
        
        // Get terminal size and update viewport
        let size = self.terminal.size()?;
        self.terminal_width = size.width;
        self.terminal_height = size.height;
        self.viewport_size = (size.height as usize).saturating_sub(2);
        
        Ok(())
    }

    /// Build timeline with standard progress output
    fn build_timeline_simple(&mut self) {
        use rayon::prelude::*;
        
        // Extract timeline events with progress
        self.events = self.extract_timeline_events_with_progress();
        
        eprintln!("🔄 Sorting {} events chronologically...", self.events.len());
        
        // Sort events chronologically
        if self.events.len() > 10000 {
            self.events.par_sort_unstable_by(|a, b| {
                let timestamp_cmp = a.timestamp.cmp(&b.timestamp);
                if timestamp_cmp != std::cmp::Ordering::Equal {
                    return timestamp_cmp;
                }
                
                let type_cmp = a.timestamp_type.sort_priority().cmp(&b.timestamp_type.sort_priority());
                if type_cmp != std::cmp::Ordering::Equal {
                    return type_cmp;
                }
                
                a.timestamp_source.short_form().cmp(&b.timestamp_source.short_form())
            });
        } else {
            self.events.sort_unstable_by(|a, b| {
                let timestamp_cmp = a.timestamp.cmp(&b.timestamp);
                if timestamp_cmp != std::cmp::Ordering::Equal {
                    return timestamp_cmp;
                }
                
                let type_cmp = a.timestamp_type.sort_priority().cmp(&b.timestamp_type.sort_priority());
                if type_cmp != std::cmp::Ordering::Equal {
                    return type_cmp;
                }
                
                a.timestamp_source.short_form().cmp(&b.timestamp_source.short_form())
            });
        }
        
        // Pre-format events for display with ultra-fast formatter
        self.formatted_rows = crate::fast_formatter::format_events_ultra_fast(&self.events, &self.records, self.timezone);
        
        // Finalize
        self.filtered_events = (0..self.events.len()).collect();
        self.timeline_ready = true;
        
        // Launch interactive viewer
        eprintln!("🚀 Launching interactive timeline viewer...");
    }

    /// Extract timeline events with progress bar
    fn extract_timeline_events_with_progress(&self) -> Vec<TimelineEvent> {
        use rayon::prelude::*;
        
        let total_records = self.records.len();
        let chunk_size = (total_records / 100).max(1000); // Process in chunks for progress updates
        let mut all_events = Vec::new();
        
        // Process records in chunks to show progress
        for (chunk_idx, chunk) in self.records.chunks(chunk_size).enumerate() {
            let chunk_events: Vec<TimelineEvent> = chunk
                .par_iter()
                .flat_map(|record| record.extract_timeline_events())
                .collect();
            
            all_events.extend(chunk_events);
            
            // Show progress
            let processed = (chunk_idx + 1) * chunk_size.min(total_records);
            let progress = (processed as f32 / total_records as f32 * 100.0) as usize;
            let progress_bar_width = 30;
            let filled = (progress * progress_bar_width / 100).min(progress_bar_width);
            let progress_bar = "█".repeat(filled) + &"░".repeat(progress_bar_width - filled);
            
            eprint!("\r⏰ Building timeline [{}/{}] [{}] {:.0}%", 
                processed.min(total_records), total_records, progress_bar, 
                processed as f32 / total_records as f32 * 100.0);
        }
        
        eprintln!(); // New line when done
        all_events
    }

    /// Pre-format events with progress bar using the ultra-fast formatter
    fn preformat_events_with_progress(&self, events: &[TimelineEvent], records: &[crate::types::MftRecord]) -> Vec<FormattedRow> {
        // Use the ultra-fast formatter from fast_formatter module
        crate::fast_formatter::format_events_ultra_fast(events, records, self.timezone)
    }

    /// Pre-format all events for fast rendering (legacy method)
    fn preformat_events(events: &[TimelineEvent], records: &[crate::types::MftRecord], timezone: Tz) -> Vec<FormattedRow> {
        // Create a HashMap for O(1) MFT record lookup
        let mut record_map = std::collections::HashMap::new();
        for record in records {
            record_map.insert(record.record_number, record);
        }
        
        events
            .iter()
            .map(|event| {
                let formatted_time = {
                    let converted_time = crate::datetime::convert_to_timezone(event.timestamp, timezone);
                    crate::datetime::format_timestamp_human(&converted_time)
                };
                
                let timestamp_type_with_source = format!("{} ({})", 
                    event.timestamp_type.display_name(),
                    event.timestamp_source.short_form()
                );
                let record = event.mft_record_number.to_string();
                
                // Use file size and directory info directly from TimelineEvent
                let formatted_size = if event.is_directory {
                    // Use folder emoji with proper padding for wider column
                    format!("{}📁", " ".repeat(11))
                } else {
event.file_size.map_or("Unknown".to_string(), |s| {
                        format!("{:>13}", format_number_with_commas(s))
                    })
                };
                
                // Get deletion status from MFT record if available
                let mft_record = record_map.get(&event.mft_record_number);
                let is_deleted = mft_record.is_some_and(|rec| rec.is_deleted);
                
                // Construct full path by combining location and filename
                let full_path = if event.location.ends_with('\\') || event.location == "\\" {
                    format!("{}{}", event.location, event.filename)
                } else {
                    format!("{}\\{}", event.location, event.filename)
                };
                
                FormattedRow {
                    filename: event.filename.clone(),
                    timestamp: formatted_time,
                    type_source: timestamp_type_with_source,
                    record,
                    size: formatted_size,
                    location: event.location.clone(),
                    full_path,
                    is_deleted,
                }
            })
            .collect()
    }

    /// Draw the interface - optimized for speed
    fn draw(&mut self) -> io::Result<()> {
        self.draw_main_interface()
    }
    
    /// Draw the main interface content
    fn draw_main_interface(&mut self) -> io::Result<()> {
        
        // Only update terminal size if needed (expensive call)
        let size = self.terminal.size()?;
        if size.width != self.terminal_width || size.height != self.terminal_height {
            self.terminal_width = size.width;
            self.terminal_height = size.height;
            self.viewport_size = (size.height as usize).saturating_sub(2);
        }

        // Collect minimal data for drawing
        let total_events_len = self.total_timeline_events; // Total timeline events from source
        let filtered_len = self.filtered_events.len(); // Currently displayed events
        
        // Calculate viewport for visible rows only with smart centering
        let current_selection = self.table_state.selected().unwrap_or(0);
        let half_viewport = self.viewport_size / 2;
        
        // Smart viewport positioning to reduce unnecessary redraws
        if current_selection < half_viewport {
            self.viewport_start = 0;
        } else if current_selection + half_viewport >= filtered_len {
            self.viewport_start = filtered_len.saturating_sub(self.viewport_size);
        } else {
            self.viewport_start = current_selection.saturating_sub(half_viewport);
        }
        let show_help = self.show_help;
        let horizontal_scroll = self.horizontal_scroll;
        let data_source = self.data_source.clone();
        let _timezone = self.timezone;
        
        // Prepare details content for the current selection
        let details_content = if current_selection < self.filtered_events.len() {
            let event_index = self.filtered_events[current_selection];
            if event_index < self.events.len() {
                let event = &self.events[event_index];
                let record = self.records.iter().find(|r| r.record_number == event.mft_record_number);
                record.map(|r| self.build_details_content(r, event))
            } else { None }
        } else { None };
        
self.terminal.draw(|f| {
            let full_area = f.area();
            
            // Clear the entire screen area first
            f.render_widget(Clear, full_area);
            
            // Use full screen without borders - split into header, table, details pane, footer
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Header
                    Constraint::Min(1),     // Table (takes most space)
                    Constraint::Length(12), // Details pane (12 lines for basic info + timestamps + ADS info)
                    Constraint::Length(1),  // Footer
                ])
                .split(full_area);

            // Header: clear the line and display app name and data source
            let header_text = format!("tl - {}", data_source);
            let header = Paragraph::new(header_text)
                .style(Style::default()
                    .fg(self.theme.header_fg)
                    .bg(self.theme.header_bg)
                    .add_modifier(Modifier::BOLD));
            // Clear the header area first to remove any leftover text
            f.render_widget(Clear, chunks[0]);
            f.render_widget(header, chunks[0]);

// OPTIMIZATION: Only process visible rows (viewport culling)
            let visible_end = (self.viewport_start + self.viewport_size).min(filtered_len);
            let current_column = self.current_column;
            let current_selection = current_selection;
            
            let visible_rows: Vec<Row> = self.filtered_events[self.viewport_start..visible_end]
                .iter()
                .enumerate()
                .map(|(row_idx, &idx)| {
                    let formatted_row = &self.formatted_rows[idx];
                    
// Create properly aligned column cells with vertical line separators
                    let filename_text = if formatted_row.is_deleted {
                        // Add strikethrough using Unicode combining character for better terminal compatibility
                        // Also add [DELETED] prefix for clarity
                        let strikethrough_name = formatted_row.filename.chars()
                            .map(|c| format!("{}\u{0336}", c))
                            .collect::<String>();
                        format!("[DEL] {}", strikethrough_name)
                    } else {
                        formatted_row.filename.clone()
                    };
                    
                    let row_cells = vec![
                        Self::format_column_with_separator(&filename_text, 62, 0, current_column, horizontal_scroll), // Filename: 62 chars total
                        Self::format_timestamp_column(&formatted_row.timestamp, 1, current_column, horizontal_scroll), // Timestamp: 41 chars + separator = 42 total
                        Self::format_column_with_separator(&formatted_row.type_source, 62, 2, current_column, horizontal_scroll), // Event: 62 chars total
                        Self::format_column_with_separator(&formatted_row.record, 12, 3, current_column, horizontal_scroll), // Record: 12 chars total
                        Self::format_column_with_separator(&formatted_row.size, 14, 4, current_column, horizontal_scroll), // Size: 14 chars total (13 + 1 separator)
                        Self::format_column_no_separator(&formatted_row.location, 512, 5, current_column, horizontal_scroll), // Full Path: 512 chars, no separator
                    ];
                    
                    // Apply cell-based highlighting if this is the current row
                    let viewport_row_idx = self.viewport_start + row_idx;
                    
                    // Check if this row is a search result and if it's deleted
                    let is_search_result = self.search_results.contains(&viewport_row_idx);
                    let is_current_search = !self.search_results.is_empty() && 
                        self.current_search_index < self.search_results.len() &&
                        self.search_results[self.current_search_index] == viewport_row_idx;
                    let is_deleted = formatted_row.is_deleted;
                    
                    let cells: Vec<Cell> = if viewport_row_idx == current_selection {
                        row_cells.into_iter().enumerate().map(|(col_idx, content)| {
                            let base_style = if col_idx == current_column {
                                Style::default()
                                    .fg(self.theme.selected_fg)
                                    .bg(self.theme.selected_bg)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(self.theme.normal_text)
                            };
                            
                            // Add search highlighting and deleted file styling
                            let style = if is_current_search {
                                // Black text on orange background
                                base_style.bg(Color::Rgb(255, 165, 0)).fg(Color::Black).add_modifier(Modifier::UNDERLINED)
                            } else if is_search_result {
                                // Black background, keep original text color
                                base_style.bg(Color::Black)
                            } else if is_deleted {
                                // Dim the text for deleted files
                                base_style.add_modifier(Modifier::DIM).fg(Color::DarkGray)
                            } else {
                                base_style
                            };
                            
                            Cell::from(content).style(style)
                        }).collect()
                    } else {
                        row_cells.into_iter().enumerate().map(|(col_idx, content)| {
                            let color = self.theme.column_colors[col_idx % self.theme.column_colors.len()];
                            let base_style = Style::default().fg(color);
                            
                            // Add search highlighting and deleted file styling
                            let style = if is_current_search {
                                // Black text on orange background
                                base_style.bg(Color::Rgb(255, 165, 0)).fg(Color::Black).add_modifier(Modifier::BOLD)
                            } else if is_search_result {
                                // Black background, keep original text color
                                base_style.bg(Color::Black)
                            } else if is_deleted {
                                // Dim the text for deleted files with strikethrough effect
                                base_style.add_modifier(Modifier::DIM).fg(Color::DarkGray)
                            } else {
                                base_style
                            };
                            
                            Cell::from(content).style(style)
                        }).collect()
                    };
                    
                    Row::new(cells)
                })
                .collect();

// Create proper column headers with vertical line separators
            let table = Table::new(visible_rows, [
                Constraint::Length(62), // Filename: 62 chars total (61 + 1 separator)
                Constraint::Length(42), // Timestamp: 42 chars total (41 + 1 separator)
                Constraint::Length(62), // Event: 62 chars total (61 + 1 separator)
                Constraint::Length(12), // Record: 12 chars total (11 + 1 separator)
                Constraint::Length(14), // Size: 14 chars total (13 + 1 separator)
                Constraint::Min(50),    // Full Path: minimum 50, takes remaining space
            ])
.header(Row::new(vec![
                    Cell::from(format!("{:<61}┆", "Filename")).style(Style::default()
                        .fg(self.theme.header_fg)
                        .bg(self.theme.header_bg)
                        .add_modifier(Modifier::BOLD)), // 61 chars + separator = 62
                    Cell::from(format!("{:<41}┆", "Timestamp")).style(Style::default()
                        .fg(self.theme.header_fg)
                        .bg(self.theme.header_bg)
                        .add_modifier(Modifier::BOLD)), // 41 chars + separator = 42
                    Cell::from(format!("{:<61}┆", "Event")).style(Style::default()
                        .fg(self.theme.header_fg)
                        .bg(self.theme.header_bg)
                        .add_modifier(Modifier::BOLD)), // 61 chars + separator = 62
                    Cell::from(format!("{:<11}┆", "Record")).style(Style::default()
                        .fg(self.theme.header_fg)
                        .bg(self.theme.header_bg)
                        .add_modifier(Modifier::BOLD)), // 11 chars + separator = 12
                    Cell::from(format!("{:<13}┆", "Size")).style(Style::default()
                        .fg(self.theme.header_fg)
                        .bg(self.theme.header_bg)
                        .add_modifier(Modifier::BOLD)), // 13 chars + separator = 14
                    Cell::from("Full Path").style(Style::default()
                        .fg(self.theme.header_fg)
                        .bg(self.theme.header_bg)
                        .add_modifier(Modifier::BOLD)), // No separator for last column
                ]))
.column_spacing(0) // No additional spacing - separators are embedded in text
                .block(ratatui::widgets::Block::default().borders(ratatui::widgets::Borders::NONE))
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
                .highlight_symbol("");

// Don't use table state highlighting since we're doing cell-based highlighting
            let mut no_highlight_state = TableState::default();
            f.render_stateful_widget(table, chunks[1], &mut no_highlight_state);

// Footer: event counts, search status, and optional help
            let search_status = if !self.search_results.is_empty() {
                format!(" | Search: {} results ({}/{})", 
                    self.search_results.len(), 
                    self.current_search_index + 1,
                    self.search_results.len())
            } else if !self.search_query.is_empty() {
                " | Search: no results".to_string()
            } else {
                String::new()
            };
            
            let footer_text = if show_help {
                format!("Showing {} of {} events{} | Navigation: j/k/↑/↓=Row, Tab/Shift-Tab=Cell, /=Search, n/N=Next/Prev Search, Ctrl-F/B=Page, g/G=Top/Bottom, h/l/←/→=Scroll, ?=Help, q=Quit", 
                    filtered_len, total_events_len, search_status)
            } else {
                format!("Showing {} of {} events{} | Press '/' to search, '?' for help, 'q' to quit", 
                    filtered_len, total_events_len, search_status)
            };

            // Details pane: show current record details
            let details_text = if let Some(content) = &details_content {
                content.clone()
            } else {
                "No record selected or details unavailable".to_string()
            };
            
            let details_pane = Paragraph::new(details_text)
                .block(Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(self.theme.border))
                    .title(" Record Details ")
                    .title_style(Style::default()
                        .fg(self.theme.details_title)
                        .add_modifier(Modifier::BOLD)))
                .style(Style::default().fg(self.theme.normal_text))
                .wrap(Wrap { trim: true });
            
            f.render_widget(Clear, chunks[2]);
            f.render_widget(details_pane, chunks[2]);
            
            // Footer
            let footer = Paragraph::new(footer_text)
                .style(Style::default()
                    .fg(self.theme.header_fg)
                    .bg(self.theme.header_bg)
                    .add_modifier(Modifier::BOLD));
            // Clear the footer area first to remove any leftover text
            f.render_widget(Clear, chunks[3]);
            f.render_widget(footer, chunks[3]);
            
            // Draw search overlay if in search mode
            if self.search_mode {
                let area = f.area();
                let prompt_text = format!("Search: {}_", self.search_query);
                let search_paragraph = Paragraph::new(prompt_text)
                    .style(Style::default().fg(Color::Yellow).bg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL).title("Search"));
                    
                let search_area = ratatui::layout::Rect {
                    x: area.width / 4,  // Center the search box
                    y: area.height / 2,  // Place in middle of screen
                    width: area.width / 2,  // Half width for better visibility
                    height: 3,
                };
                
                f.render_widget(Clear, search_area); // Clear only the search area
                f.render_widget(search_paragraph, search_area);
            }
        })?;

        Ok(())
    }
    
    
    /// Build the content string for the details popup
    fn build_details_content(&self, record: &crate::types::MftRecord, _event: &TimelineEvent) -> String {
        let mut content = String::new();
        
        // Debug: Check if we actually have timestamp data (unused for now)
        let _has_si_timestamps = record.timestamps.created.is_some() || record.timestamps.modified.is_some() || 
                               record.timestamps.mft_modified.is_some() || record.timestamps.accessed.is_some();
        let _has_fn_timestamps = record.fn_timestamps.created.is_some() || record.fn_timestamps.modified.is_some() || 
                               record.fn_timestamps.mft_modified.is_some() || record.fn_timestamps.accessed.is_some();
        
        // Full path display
        let full_path = record.location.as_deref().unwrap_or("Unknown");
        content.push_str(&format!("Full Path: {}\n", full_path));
        
        // Basic information - more compact
        let size_display = if record.is_directory {
            "0".to_string()  // Show 0 for folders in details pane
        } else {
record.file_size.map_or("Unknown".to_string(), |s| format!("{} bytes", s))
        };
        
        
        content.push_str(&format!("Record: {} | Size: {} | {}{}\n", 
            record.record_number,
            size_display,
            if record.is_directory { "Folder" } else { "File" },
            if record.is_deleted { " (Deleted)" } else { "" }
        ));
        
        // Timestamps in fmt.txt format with exact spacing and alignment
        // Use non-breaking spaces (U+00A0) which shouldn't be trimmed by widgets
        let nbsp = '\u{00A0}'; // Non-breaking space
        let header_padding1 = nbsp.to_string().repeat(16);
        let header_padding2 = nbsp.to_string().repeat(22);
        let header_line = format!("{}$STANDARD_INFORMATION{}{}", header_padding1, header_padding2, "$FILE_NAME");
        content.push('\n'); // Add blank line above headers
        content.push_str(&format!("{}\n", header_line));
        
        // Format timestamps with explicit field widths using non-breaking spaces for leading padding
        let si_created = self.format_timestamp_for_popup_with_tz(&record.timestamps.created, self.timezone);
        let fn_created = self.format_timestamp_for_popup_with_tz(&record.fn_timestamps.created, self.timezone);
        let created_padding = nbsp.to_string().repeat(7); // 14 - 7 chars for "Created"
        let created_line = format!("{}Created: {:<43}{}", created_padding, si_created, fn_created);
        content.push_str(&format!("{}\n", created_line));
        
        let si_modified = self.format_timestamp_for_popup_with_tz(&record.timestamps.modified, self.timezone);
        let fn_modified = self.format_timestamp_for_popup_with_tz(&record.fn_timestamps.modified, self.timezone);
        let modified_padding = nbsp.to_string().repeat(6); // 14 - 8 chars for "Modified"
        let modified_line = format!("{}Modified: {:<43}{}", modified_padding, si_modified, fn_modified);
        content.push_str(&format!("{}\n", modified_line));
        
        let si_mft_modified = self.format_timestamp_for_popup_with_tz(&record.timestamps.mft_modified, self.timezone);
        let fn_mft_modified = self.format_timestamp_for_popup_with_tz(&record.fn_timestamps.mft_modified, self.timezone);
        let index_modified_line = format!("Index Modified: {:<43}{}", si_mft_modified, fn_mft_modified); // "Index Modified" is exactly 14 chars
        content.push_str(&format!("{}\n", index_modified_line));
        
        let si_accessed = self.format_timestamp_for_popup_with_tz(&record.timestamps.accessed, self.timezone);
        let fn_accessed = self.format_timestamp_for_popup_with_tz(&record.fn_timestamps.accessed, self.timezone);
        let accessed_padding = nbsp.to_string().repeat(6); // 14 - 8 chars for "Accessed"
        let accessed_line = format!("{}Accessed: {:<43}{}", accessed_padding, si_accessed, fn_accessed);
        content.push_str(&format!("{}\n\n", accessed_line));
        
        // Alternative Data Streams with aligned formatting
        if !record.alternate_data_streams.is_empty() {
            content.push_str("Alternative Data Streams:\n");
            for (i, ads) in record.alternate_data_streams.iter().enumerate() {
                content.push_str(&format!("  Stream {}: {}\n", i + 1, ads.name));
                content.push_str(&format!("{:>14}: {} bytes\n", "Size", ads.size));
                content.push_str(&format!("{:>14}: {}\n", "Resident", if ads.resident { "Yes" } else { "No" }));
                if i < record.alternate_data_streams.len() - 1 {
                    content.push('\n');
                }
            }
        } else {
            content.push_str("Alternative Data Streams: None");
        }
        
        // Details are always visible in the bottom pane
        
        content
    }
    
    /// Format a timestamp for the popup display
    fn format_timestamp_for_popup_with_tz(&self, timestamp: &Option<DateTime<Utc>>, timezone: Tz) -> String {
        match timestamp {
            Some(ts) => {
                let converted = crate::datetime::convert_to_timezone(*ts, timezone);
                crate::datetime::format_timestamp_human(&converted)
            }
            None => "<not set>".to_string(),
        }
    }

    // get_visible_rows function removed - functionality moved to draw() for optimization

    /// Handle keyboard input
    fn handle_key_event(&mut self, key: KeyEvent) -> KeyResult {
        match (key.code, key.modifiers) {
            // Quit commands
            (KeyCode::Char('q'), KeyModifiers::NONE) | 
            (KeyCode::Esc, KeyModifiers::NONE) if self.filter_text.is_empty() => KeyResult::Quit,
            
            // Help toggle
            (KeyCode::F(1), _) | (KeyCode::Char('?'), KeyModifiers::NONE) => {
                self.show_help = !self.show_help;
                KeyResult::Continue
            }


            // Vertical navigation - vi keys
            (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, _) => {
                self.next_item();
                KeyResult::Continue
            }

            (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, _) => {
                self.previous_item();
                KeyResult::Continue
            }

            // Page navigation - vi style
            (KeyCode::Char('f'), KeyModifiers::CONTROL) | (KeyCode::PageDown, _) => {
                self.page_down();
                KeyResult::Continue
            }

            (KeyCode::Char('b'), KeyModifiers::CONTROL) | (KeyCode::PageUp, _) => {
                self.page_up();
                KeyResult::Continue
            }

            // Jump to top/bottom - vi style
            (KeyCode::Char('g'), KeyModifiers::NONE) | (KeyCode::Home, _) => {
                self.table_state.select(Some(0));
                KeyResult::Continue
            }

            (KeyCode::Char('G'), KeyModifiers::SHIFT) | (KeyCode::End, _) => {
                if !self.filtered_events.is_empty() {
                    self.table_state.select(Some(self.filtered_events.len() - 1));
                }
                KeyResult::Continue
            }

            // Horizontal scrolling - vi style h/l + arrow keys
            (KeyCode::Char('h'), KeyModifiers::NONE) | (KeyCode::Left, _) => {
                if self.horizontal_scroll > 0 {
                    self.horizontal_scroll = self.horizontal_scroll.saturating_sub(5);
                }
                KeyResult::Continue
            }

            (KeyCode::Char('l'), KeyModifiers::NONE) | (KeyCode::Right, _) => {
                self.horizontal_scroll += 5;
                KeyResult::Continue
            }

            // Fast horizontal scrolling
            (KeyCode::Char('H'), KeyModifiers::SHIFT) => {
                self.horizontal_scroll = 0; // Jump to beginning of line
                KeyResult::Continue
            }

            (KeyCode::Char('L'), KeyModifiers::SHIFT) => {
                self.horizontal_scroll += 20; // Jump right quickly
                KeyResult::Continue
            }

            // Half page movements - vi style
            (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                self.half_page_down();
                KeyResult::Continue
            }

            (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                self.half_page_up();
                KeyResult::Continue
            }

// Center cursor - vi style
            (KeyCode::Char('z'), KeyModifiers::NONE) => {
                // Center the current selection in the view
                KeyResult::Continue
            }

            // Cell navigation - Tab/Shift-Tab for horizontal movement
            (KeyCode::Tab, KeyModifiers::NONE) => {
                self.next_column();
                KeyResult::Continue
            }

            (KeyCode::Tab, KeyModifiers::SHIFT) | (KeyCode::BackTab, _) => {
                self.previous_column();
                KeyResult::Continue
            }

            // Search functionality
            (KeyCode::Char('/'), KeyModifiers::NONE) => {
                if self.timeline_ready {
                    if let Err(_) = self.start_search() {
                        // Handle error gracefully - just continue
                    }
                }
                KeyResult::Continue
            }
            // Navigate search results
            (KeyCode::Char('n'), KeyModifiers::NONE) if self.timeline_ready && !self.search_results.is_empty() => {
                self.next_search_result();
                KeyResult::Continue
            }
            (KeyCode::Char('N'), KeyModifiers::SHIFT) if self.timeline_ready && !self.search_results.is_empty() => {
                self.previous_search_result();
                KeyResult::Continue
            }

            (KeyCode::Esc, KeyModifiers::NONE) => {
                // Clear filter and search
                self.filter_text.clear();
                self.search_query.clear();
                self.search_results.clear();
                self.update_filter();
                KeyResult::Continue
            }

            _ => KeyResult::Continue,
        }
    }

    /// Move to previous item
    fn previous_item(&mut self) {
        if self.filtered_events.is_empty() {
            return;
        }

        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_events.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Move to next item
    fn next_item(&mut self) {
        if self.filtered_events.is_empty() {
            return;
        }

        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.filtered_events.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Page up
    fn page_up(&mut self) {
        if self.filtered_events.is_empty() {
            return;
        }

        let page_size = (self.terminal_height as usize).saturating_sub(3); // Account for header/footer
        let i = match self.table_state.selected() {
            Some(i) => i.saturating_sub(page_size),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Page down
    fn page_down(&mut self) {
        if self.filtered_events.is_empty() {
            return;
        }

        let page_size = (self.terminal_height as usize).saturating_sub(3); // Account for header/footer
        let i = match self.table_state.selected() {
            Some(i) => std::cmp::min(i + page_size, self.filtered_events.len() - 1),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Half page up
    fn half_page_up(&mut self) {
        if self.filtered_events.is_empty() {
            return;
        }

        let half_page_size = (self.terminal_height as usize / 2).max(1);
        let i = match self.table_state.selected() {
            Some(i) => i.saturating_sub(half_page_size),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Half page down
    fn half_page_down(&mut self) {
        if self.filtered_events.is_empty() {
            return;
        }

        let half_page_size = (self.terminal_height as usize / 2).max(1);
        let i = match self.table_state.selected() {
            Some(i) => std::cmp::min(i + half_page_size, self.filtered_events.len() - 1),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

/// Update filter results
    fn update_filter(&mut self) {
        if self.filter_text.is_empty() {
            self.filtered_events = (0..self.events.len()).collect();
        } else {
            self.filtered_events = self.events
                .iter()
                .enumerate()
                .filter(|(_, event)| {
                    event.filename.to_lowercase().contains(&self.filter_text.to_lowercase()) ||
                    event.location.to_lowercase().contains(&self.filter_text.to_lowercase())
                })
                .map(|(idx, _)| idx)
                .collect();
        }

        // Reset selection
        if !self.filtered_events.is_empty() {
            self.table_state.select(Some(0));
        } else {
            self.table_state.select(None);
        }
    }

    /// Move to next column (Tab)
    fn next_column(&mut self) {
        self.current_column = (self.current_column + 1) % 6; // 6 columns: Filename, Timestamp, Event, Record, Size, Full Path
    }

    /// Move to previous column (Shift-Tab)
    fn previous_column(&mut self) {
        self.current_column = if self.current_column == 0 {
            5 // Wrap to last column
        } else {
            self.current_column - 1
        };
    }


    /// Truncate text to fit column width
    fn truncate_text(text: &str, max_width: usize) -> String {
        if text.width() <= max_width {
            text.to_string()
        } else {
            let mut truncated = String::new();
            let mut width = 0;
            
            for ch in text.chars() {
                let ch_width = ch.width().unwrap_or(0);
                if width + ch_width + 3 > max_width { // +3 for "..."
                    truncated.push_str("...");
                    break;
                }
                truncated.push(ch);
                width += ch_width;
            }
            
            truncated
        }
    }

/// Truncate text with horizontal scroll support - optimized for memory
    fn truncate_with_scroll(text: &str, max_width: usize, scroll_offset: usize) -> String {
        if scroll_offset >= text.len() {
            return String::new();
        }
        
        // Use char boundaries for proper UTF-8 handling
        let mut char_indices = text.char_indices();
        let start_pos = char_indices.nth(scroll_offset).map(|(i, _)| i).unwrap_or(text.len());
        
        if start_pos >= text.len() {
            return String::new();
        }
        
        let scrolled_text = &text[start_pos..];
        Self::truncate_text(scrolled_text, max_width)
    }
    
    
/// Format a column with separator, applying scrolling only if it's the current column
    fn format_column_with_separator(text: &str, width: usize, col_index: usize, current_col: usize, global_scroll: usize) -> String {
        let content_width = width - 1; // Reserve 1 char for separator
        
        let scroll_offset = if col_index == current_col { global_scroll } else { 0 };
        let content = Self::truncate_with_scroll(text, content_width, scroll_offset);
        
        // Pad to exact content width and add dim separator (total = width)
        format!("{:<content_width$}┆", content, content_width = content_width)
    }
    
/// Format timestamp column with special handling to preserve full timestamp width
    fn format_timestamp_column(text: &str, col_index: usize, current_col: usize, global_scroll: usize) -> String {
        let scroll_offset = if col_index == current_col { global_scroll } else { 0 };
        
        // For timestamp, show full content with proper padding and dim separator
        let content = if scroll_offset == 0 {
            // No scrolling - show full timestamp, pad to 41 chars + separator = 42 total
            format!("{:<41}┆", text)
        } else {
            // Apply scrolling by taking substring
            if scroll_offset >= text.len() {
                format!("{:<41}┆", "")
            } else {
                format!("{:<41}┆", &text[scroll_offset..])
            }
        };
        
        content
    }
    
    /// Format the last column without separator, applying scrolling only if it's the current column
    fn format_column_no_separator(text: &str, width: usize, col_index: usize, current_col: usize, global_scroll: usize) -> String {
        let scroll_offset = if col_index == current_col { global_scroll } else { 0 };
        Self::truncate_with_scroll(text, width, scroll_offset)
    }

    /// Start search mode and capture search input
    fn start_search(&mut self) -> io::Result<()> {
        self.search_mode = true;
        self.search_query.clear();
        self.search_results.clear();
        self.current_search_index = 0;
        
        // Draw immediately to show search overlay
        self.draw()?;
        
        // Capture input until Enter or Escape
        loop {
            if event::poll(std::time::Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) => match key.code {
                        KeyCode::Enter => {
                            self.search_mode = false;
                            if !self.search_query.is_empty() {
                                self.perform_search();
                                if !self.search_results.is_empty() {
                                    self.jump_to_search_result(0);
                                }
                            }
                            break;
                        },
                        KeyCode::Esc => {
                            self.search_mode = false;
                            self.search_query.clear();
                            self.search_results.clear();
                            break;
                        },
                        KeyCode::Backspace => {
                            if !self.search_query.is_empty() {
                                self.search_query.pop();
                                self.draw()?;
                            }
                        },
                        KeyCode::Char(c) => {
                            self.search_query.push(c);
                            self.draw()?;
                        },
                        _ => {}
                    }
                    _ => {}
                }
            }
        }
        
        Ok(())
    }
    
    /// Perform search on timeline events
    fn perform_search(&mut self) {
        if self.search_query.is_empty() {
            self.search_results.clear();
            return;
        }
        
        let query_lower = self.search_query.to_lowercase();
        self.search_results.clear();
        
        // Search through filtered events only
        for (display_index, &event_index) in self.filtered_events.iter().enumerate() {
            if event_index >= self.formatted_rows.len() {
                continue;
            }
            
            let row = &self.formatted_rows[event_index];
            
            // Search in full path (primary), filename, location, and other text fields
            if row.full_path.to_lowercase().contains(&query_lower) ||
               row.filename.to_lowercase().contains(&query_lower) ||
               row.location.to_lowercase().contains(&query_lower) ||
               row.type_source.to_lowercase().contains(&query_lower) {
                self.search_results.push(display_index);
            }
        }
        
        self.current_search_index = 0;
    }
    
    /// Jump to specific search result
    fn jump_to_search_result(&mut self, search_index: usize) {
        if search_index < self.search_results.len() {
            let result_index = self.search_results[search_index];
            self.table_state.select(Some(result_index));
            self.current_search_index = search_index;
        }
    }
    
    /// Go to next search result
    fn next_search_result(&mut self) {
        if !self.search_results.is_empty() {
            let next_index = (self.current_search_index + 1) % self.search_results.len();
            self.jump_to_search_result(next_index);
        }
    }
    
    /// Go to previous search result
    fn previous_search_result(&mut self) {
        if !self.search_results.is_empty() {
            let prev_index = if self.current_search_index == 0 {
                self.search_results.len() - 1
            } else {
                self.current_search_index - 1
            };
            self.jump_to_search_result(prev_index);
        }
    }

}

/// Result of key event handling
enum KeyResult {
    Continue,
    Quit,
}

/// Check if stdout is connected to an interactive terminal
pub fn is_interactive_terminal() -> bool {
    use is_terminal::IsTerminal;
    io::stdout().is_terminal()
}