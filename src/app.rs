//! Main application logic and orchestration.

use crate::{
    cli::Config,
    datetime::record_in_date_range,
    error::Result,
    interactive::{InteractiveViewer, is_interactive_terminal},
    mft::MftParser,
    output::{create_writer, OutputWriter},
    types::{MftRecord, ParsingConfig},
    parse_drive_letter,
};
use rayon::prelude::*;
use regex::Regex;
use std::path::Path;

#[cfg(windows)]
use crate::windows::LiveSystemAccess;

/// Main application runner
pub struct App {
    config: Config,
    parser: MftParser,
}

impl App {
    /// Create a new application instance with the given configuration
    pub fn new(config: Config) -> Self {
        let parsing_config = ParsingConfig::optimized();
        let parser = MftParser::with_config(parsing_config);
        
        Self { config, parser }
    }

    /// Run the application with the configured parameters
    pub fn run(mut self) -> Result<()> {
        // Parse MFT records from various sources
        let records = self.parse_mft_records()?;

        // Calculate total timeline events before filtering for accurate footer display
        let total_timeline_events: usize = records
            .par_iter()
            .map(|record| record.extract_timeline_events().len())
            .sum();

        // Apply filters efficiently
        let filtered_records = self.apply_filters(records);

        // Determine output mode and handle accordingly
        self.handle_output(filtered_records, total_timeline_events)
    }

    /// Parse MFT records from the configured input source
    fn parse_mft_records(&mut self) -> Result<Vec<MftRecord>> {
        if let Some(drive_letter) = parse_drive_letter(&self.config.mft_input) {
            self.parse_live_system(drive_letter)
        } else {
            self.parse_file_input()
        }
    }

    /// Parse from live system access
    #[cfg(windows)]
    fn parse_live_system(&mut self, drive_letter: char) -> Result<Vec<MftRecord>> {
        let live_access = LiveSystemAccess::open_drive(drive_letter)?;
        eprintln!("Accessing live system drive {}:", drive_letter);
        eprintln!("{}", live_access.drive_info());

        // Read the first 10,000 MFT records as a reasonable default
        let mft_data = live_access.read_mft_records(10000)?;
        self.parser.parse_mft_data(&mft_data)
    }

    #[cfg(not(windows))]
    fn parse_live_system(&mut self, _drive_letter: char) -> Result<Vec<MftRecord>> {
        Err(crate::error::Error::Generic(
            "Live system access is only available on Windows".to_string()
        ))
    }

    /// Parse from file input (supports .zip, .gz, and raw MFT files)
    fn parse_file_input(&mut self) -> Result<Vec<MftRecord>> {
        let path = Path::new(&self.config.mft_input);
        self.parser.parse_input(path, self.config.password.as_deref())
    }

    /// Apply command-line filters to the record set efficiently
    fn apply_filters(&self, records: Vec<MftRecord>) -> Vec<MftRecord> {
        // Use parallel processing for large datasets
        let should_use_parallel = records.len() > 1000;
        
        if should_use_parallel {
            records
                .into_par_iter()
                .filter(|record| self.record_passes_filters(record))
                .collect()
        } else {
            records
                .into_iter()
                .filter(|record| self.record_passes_filters(record))
                .collect()
        }
    }

    /// Check if a single record passes all filters
    fn record_passes_filters(&self, record: &MftRecord) -> bool {
        // Regex filter - check both filename and location
        if let Some(regex) = &self.config.filter_regex {
            if !self.matches_regex_filter(record, regex) {
                return false;
            }
        }

        // Date filters - check if any timestamp in the record falls within the date range
        if (self.config.after_date.is_some() || self.config.before_date.is_some()) && !record_in_date_range(record, &self.config.after_date, &self.config.before_date) {
            return false;
        }

        true
    }

    /// Check if record matches regex filter (filename or location)
    fn matches_regex_filter(&self, record: &MftRecord, regex: &Regex) -> bool {
        // Check filename first (more common case)
        if let Some(ref filename) = record.filename {
            if regex.is_match(filename) {
                return true;
            }
        }
        
        // Check location if filename didn't match
        if let Some(ref location) = record.location {
            if regex.is_match(location) {
                return true;
            }
        }
        
        false
    }

    /// Handle output based on configuration and terminal state
    fn handle_output(
        &self,
        filtered_records: Vec<MftRecord>,
        total_timeline_events: usize,
    ) -> Result<()> {
        let use_interactive = self.config.output.is_none() && is_interactive_terminal();

        if use_interactive {
            self.run_interactive_mode(filtered_records, total_timeline_events)
        } else {
            self.write_file_output(filtered_records)
        }
    }

    /// Run the interactive timeline viewer with optimized startup
    fn run_interactive_mode(
        &self,
        filtered_records: Vec<MftRecord>,
        total_timeline_events: usize,
    ) -> Result<()> {
        // Create viewer first for instant UI response
        let mut viewer = InteractiveViewer::new_fast(
            filtered_records,
            self.config.timezone,
            self.config.mft_input.clone(),
            total_timeline_events,
        )?;
        
        // Run viewer - timeline processing happens in background
        viewer.run().map_err(crate::error::Error::Io)
    }



    /// Write output to file or stdout
    fn write_file_output(&self, filtered_records: Vec<MftRecord>) -> Result<()> {
        let writer = create_writer(self.config.output.clone())?;
        OutputWriter::write_timeline(filtered_records, writer, self.config.timezone)
    }
}