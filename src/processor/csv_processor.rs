use super::{CheckpointManager, ProgressReporter, StandardProgressTracker};
use crate::database::traits::StatisticsOperations;
use crate::database::{Database, DatabaseStats};
use crate::errors::{AppError, AppResult};
use crate::types::statistics::ProcessingStats;
use crate::types::{Stage1Config, UtxoRecord};
use csv::ReaderBuilder;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::{info, warn};

/// CSV processor for extracting P2MS outputs
pub struct CsvProcessor {
    config: Stage1Config,
    database: Database,
}

impl CsvProcessor {
    /// Create a new CSV processor
    ///
    /// Stage 1 operations use the stub blocks table for FK constraint satisfaction.
    pub fn new(config: Stage1Config) -> AppResult<Self> {
        let database = Database::new(&config.database_path.to_string_lossy())?;

        info!("CSV Processor initialised");
        info!("Source CSV: {}", config.csv_path.display());
        info!("Database: {}", config.database_path.display());
        info!("Batch size: {}", config.batch_size);

        Ok(Self { config, database })
    }

    /// Check for existing checkpoints and prepare to resume if available
    pub fn check_for_checkpoint(&mut self) -> AppResult<Option<crate::database::Stage1Checkpoint>> {
        // Use the enhanced checkpoint manager for Stage 1
        match CheckpointManager::check_for_resume_stage1(&self.database)? {
            Some(checkpoint) => {
                info!(
                    "Found checkpoint: line={}, total_processed={}, batch={}, created={}",
                    checkpoint.csv_line_number,
                    checkpoint.total_processed,
                    checkpoint.batch_number,
                    checkpoint.created_at
                );
                Ok(Some(checkpoint))
            }
            None => {
                info!("No checkpoint found, starting from beginning");
                Ok(None)
            }
        }
    }

    /// Count total lines in CSV file (memory-efficient, portable)
    /// Skips comment lines (starting with #) and the CSV header line
    fn count_csv_lines(&self) -> AppResult<u64> {
        info!("Counting CSV records for progress tracking...");

        let file = File::open(&self.config.csv_path).map_err(AppError::Io)?;
        let reader = BufReader::with_capacity(8 * 1024 * 1024, file); // 8MB buffer

        let mut count = 0u64;
        let mut found_header = false;

        for line_result in reader.lines() {
            let line = line_result.map_err(AppError::Io)?;
            let trimmed = line.trim();

            // Skip comment lines (starting with #)
            if trimmed.starts_with('#') {
                continue;
            }

            // Skip the first non-comment line (CSV header)
            if !found_header {
                found_header = true;
                continue;
            }

            // Count data rows
            count += 1;
        }

        info!("CSV contains {} records", count);
        Ok(count)
    }

    /// Process the CSV file and extract P2MS outputs
    pub fn process_csv(&mut self) -> AppResult<ProcessingStats> {
        let mut stats = ProcessingStats::new();
        self.run_internal(&mut stats)
    }

    /// Get database statistics
    pub fn get_database_stats(&self) -> AppResult<DatabaseStats> {
        self.database.get_database_stats()
    }

    /// Internal processing logic
    fn run_internal(&mut self, stats: &mut ProcessingStats) -> AppResult<ProcessingStats> {
        info!("Starting CSV processing");

        // Check for existing checkpoint to resume from
        let checkpoint = self.check_for_checkpoint()?;
        let resume_from_line = checkpoint.as_ref().map(|c| c.csv_line_number).unwrap_or(0);
        let mut total_processed = checkpoint
            .as_ref()
            .map(|c| c.total_processed as u64)
            .unwrap_or(0);
        let mut batch_count = checkpoint.as_ref().map(|c| c.batch_number).unwrap_or(0);

        if resume_from_line > 0 {
            info!("Resuming from checkpoint at CSV line {}", resume_from_line);
        }

        // Count total lines for progress tracking
        let total_records = self.count_csv_lines()?;

        let file = File::open(&self.config.csv_path).map_err(AppError::Io)?;
        let buf_reader = BufReader::new(file);
        let mut csv_reader = ReaderBuilder::new()
            .comment(Some(b'#')) // Skip lines starting with #
            .has_headers(true) // First non-comment line is the header
            .from_reader(buf_reader);

        let mut batch = Vec::with_capacity(self.config.batch_size);

        // Initialise progress tracker
        let mut progress_tracker = StandardProgressTracker::new();
        progress_tracker.start();

        for (line_num, result) in csv_reader.deserialize::<UtxoRecord>().enumerate() {
            let current_line = line_num as u64;

            // Skip lines until we reach the resume point
            if current_line < resume_from_line {
                continue;
            }

            let record = result.map_err(AppError::Csv)?;

            // Check if this record should be processed (P2MS or nonstandard)
            if record.should_process_for_data() {
                match record.to_transaction_output() {
                    Ok(transaction_output) => {
                        batch.push(transaction_output);
                        if record.is_p2ms() {
                            stats.p2ms_found += 1;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse output at line {}: {}", line_num + 1, e);
                        stats.malformed_records += 1;
                        continue;
                    }
                }
            }

            total_processed += 1;
            stats.total_records += 1;

            // Process batch when full
            if batch.len() >= self.config.batch_size {
                self.database.insert_p2ms_batch(&batch)?;
                batch.clear();
                batch_count += 1;
                stats.batches_processed = batch_count;

                // Save checkpoint every batch (ensures we can resume from batch boundaries)
                use crate::database::traits::Stage1Operations;
                self.database.save_checkpoint_enhanced(
                    current_line,
                    total_processed as usize,
                    current_line + 1, // Next line to process
                    batch_count,
                )?;
            }

            // Timer-driven progress updates (~500ms) to keep output clean
            if progress_tracker.should_report() {
                let elapsed = progress_tracker.elapsed_seconds();
                let total_estimate = if total_records > 0 {
                    Some(total_records as usize)
                } else {
                    None
                };
                ProgressReporter::report_progress_with_metrics(
                    stats,
                    total_processed as usize,
                    total_estimate,
                    elapsed,
                )?;
            }
        }

        // Process remaining batch
        if !batch.is_empty() {
            self.database.insert_p2ms_batch(&batch)?;
            batch_count += 1;
            stats.batches_processed = batch_count;
        }

        // Clear checkpoint on successful completion
        use crate::database::traits::Stage1Operations;
        self.database.clear_checkpoint()?;
        info!("Checkpoint cleared - processing completed successfully");

        // Finalize timing
        stats.timing.finish();

        // Print a newline to end in-place progress
        ProgressReporter::finish_progress_line();

        info!("CSV processing completed");
        info!("Total records: {}", stats.total_records);
        info!("P2MS outputs found: {}", stats.p2ms_found);
        info!("Malformed records: {}", stats.malformed_records);

        Ok(stats.clone())
    }
}
