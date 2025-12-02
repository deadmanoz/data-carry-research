use crate::errors::{AppError, AppResult};
use std::time::Instant;
use tracing::{info, warn};

/// Progress tracking for long-running operations
pub struct StandardProgressTracker {
    start_time: Option<Instant>,
    last_report: Option<Instant>,
    report_interval_ms: u64,
}

impl Default for StandardProgressTracker {
    fn default() -> Self {
        Self {
            start_time: None,
            last_report: None,
            report_interval_ms: 500, // Report every 500ms
        }
    }
}

impl StandardProgressTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        let now = Instant::now();
        self.start_time = Some(now);
        self.last_report = Some(now);
    }

    pub fn should_report(&mut self) -> bool {
        let now = Instant::now();
        match self.last_report {
            Some(last) => {
                if now.duration_since(last).as_millis() > self.report_interval_ms as u128 {
                    self.last_report = Some(now);
                    true
                } else {
                    false
                }
            }
            None => {
                self.last_report = Some(now);
                true
            }
        }
    }

    pub fn elapsed_seconds(&self) -> f64 {
        match self.start_time {
            Some(start) => start.elapsed().as_secs_f64(),
            None => 0.0,
        }
    }
}

/// Configuration validation utilities
pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate_batch_config(batch_size: usize, progress_interval: usize) -> AppResult<()> {
        if batch_size == 0 {
            return Err(AppError::Config(
                "Batch size must be greater than 0".to_string(),
            ));
        }
        if progress_interval == 0 {
            return Err(AppError::Config(
                "Progress interval must be greater than 0".to_string(),
            ));
        }
        if batch_size > 100_000 {
            warn!(
                "Large batch size: {} - this may impact memory usage",
                batch_size
            );
        }
        Ok(())
    }

    pub fn log_config_summary(
        processor_name: &str,
        batch_size: usize,
        progress_interval: usize,
        additional_info: Option<&str>,
    ) {
        info!("=== {} Configuration ===", processor_name);
        info!("  Batch size: {}", batch_size);
        info!("  Progress interval: {}", progress_interval);
        if let Some(info) = additional_info {
            info!("  {}", info);
        }
    }
}

/// Trait for stage-specific metrics formatting
/// Each stage's statistics type implements this to provide custom metrics for progress reporting
pub trait StageMetrics {
    /// Format stage-specific metrics for progress display
    /// Returns a formatted string of metrics (e.g., "P2MS: 100 | Malformed: 5")
    fn format_custom_metrics(&self) -> String;
}

/// Progress reporting utilities
pub struct ProgressReporter;

impl ProgressReporter {
    /// Format elapsed seconds into human-readable time (days, hours, minutes, seconds)
    pub fn format_elapsed_time(elapsed_secs: f64) -> String {
        if elapsed_secs < 60.0 {
            // Less than a minute - show seconds only
            format!("{:.1}s", elapsed_secs)
        } else if elapsed_secs < 3600.0 {
            // Less than an hour - show minutes and seconds
            let minutes = (elapsed_secs / 60.0).floor();
            let seconds = elapsed_secs % 60.0;
            format!("{}m {:.0}s ({:.1}s)", minutes, seconds, elapsed_secs)
        } else if elapsed_secs < 86400.0 {
            // Less than a day - show hours, minutes, seconds
            let hours = (elapsed_secs / 3600.0).floor();
            let remaining = elapsed_secs % 3600.0;
            let minutes = (remaining / 60.0).floor();
            let seconds = remaining % 60.0;
            format!(
                "{}h {}m {:.0}s ({:.1}s)",
                hours, minutes, seconds, elapsed_secs
            )
        } else {
            // More than a day - show days, hours, minutes, seconds
            let days = (elapsed_secs / 86400.0).floor();
            let remaining = elapsed_secs % 86400.0;
            let hours = (remaining / 3600.0).floor();
            let remaining = remaining % 3600.0;
            let minutes = (remaining / 60.0).floor();
            let seconds = remaining % 60.0;
            format!(
                "{}d {}h {}m {:.0}s ({:.1}s)",
                days, hours, minutes, seconds, elapsed_secs
            )
        }
    }

    pub fn report_completion(
        operation: &str,
        total_processed: usize,
        total_found: usize,
        elapsed: f64,
    ) {
        let rate = if elapsed > 0.0 {
            total_processed as f64 / elapsed
        } else {
            0.0
        };
        info!("=== {} Completed ===", operation);
        info!("  Total processed: {}", total_processed);
        info!("  Total found: {}", total_found);
        info!("  Time elapsed: {:.2}s", elapsed);
        info!("  Average rate: {:.1} items/sec", rate);
    }

    pub fn finish_progress_line() {
        // Print a newline to end in-place progress (stdout progress line)
        println!();
    }

    pub fn format_standard_progress(
        processed_count: usize,
        total_estimate: Option<usize>,
        rate: f64,
        elapsed: f64,
        custom_metrics: &str,
    ) -> String {
        let progress_pct = if let Some(total) = total_estimate {
            if total > 0 {
                format!(" ({:.1}%)", (processed_count as f64 / total as f64) * 100.0)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let elapsed_formatted = Self::format_elapsed_time(elapsed);

        format!(
            "Processed: {}{} | Rate: {:.1}/sec | Elapsed: {} | {}",
            processed_count, progress_pct, rate, elapsed_formatted, custom_metrics
        )
    }

    pub fn print_progress_line(message: &str) -> AppResult<()> {
        print!("\r{}", message);
        use std::io::Write;
        std::io::stdout().flush().map_err(AppError::Io)?;
        Ok(())
    }

    /// Unified progress reporting using StageMetrics trait
    /// Consolidates progress reporting logic from all three processor stages
    pub fn report_progress_with_metrics<T: StageMetrics>(
        metrics: &T,
        processed_count: usize,
        total_estimate: Option<usize>,
        elapsed_secs: f64,
    ) -> AppResult<()> {
        let rate = if elapsed_secs > 0.0 {
            processed_count as f64 / elapsed_secs
        } else {
            0.0
        };

        let custom_metrics = metrics.format_custom_metrics();
        let progress_message = Self::format_standard_progress(
            processed_count,
            total_estimate,
            rate,
            elapsed_secs,
            &custom_metrics,
        );

        Self::print_progress_line(&progress_message)?;
        Ok(())
    }
}

/// Checkpoint management
pub struct CheckpointManager;

impl CheckpointManager {
    /// Check for Stage 1 checkpoint with enhanced resume capability
    /// This method is used by CSV processor to support crash recovery
    pub fn check_for_resume_stage1(
        database: &crate::database::Database,
    ) -> AppResult<Option<crate::database::Stage1Checkpoint>> {
        use crate::database::traits::Stage1Operations;
        database.get_checkpoint_enhanced()
    }

    /// Determine if a checkpoint should be saved based on processing progress
    pub fn should_save_checkpoint(processed: usize, interval: usize) -> bool {
        processed > 0 && processed.is_multiple_of(interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_elapsed_time_seconds() {
        // Less than a minute - show seconds only
        assert_eq!(ProgressReporter::format_elapsed_time(5.5), "5.5s");
        assert_eq!(ProgressReporter::format_elapsed_time(45.2), "45.2s");
    }

    #[test]
    fn test_format_elapsed_time_minutes() {
        // 1 minute 30 seconds
        assert_eq!(
            ProgressReporter::format_elapsed_time(90.0),
            "1m 30s (90.0s)"
        );
        // 5 minutes 45 seconds
        assert_eq!(
            ProgressReporter::format_elapsed_time(345.7),
            "5m 46s (345.7s)"
        );
        // 59 minutes 59 seconds
        assert_eq!(
            ProgressReporter::format_elapsed_time(3599.0),
            "59m 59s (3599.0s)"
        );
    }

    #[test]
    fn test_format_elapsed_time_hours() {
        // 1 hour
        assert_eq!(
            ProgressReporter::format_elapsed_time(3600.0),
            "1h 0m 0s (3600.0s)"
        );
        // 1 hour 30 minutes 45 seconds
        assert_eq!(
            ProgressReporter::format_elapsed_time(5445.0),
            "1h 30m 45s (5445.0s)"
        );
        // 11 hours 13 minutes 42 seconds (example from Stage 2: 40422.5s)
        assert_eq!(
            ProgressReporter::format_elapsed_time(40422.5),
            "11h 13m 42s (40422.5s)"
        );
        // 23 hours 59 minutes 59 seconds
        assert_eq!(
            ProgressReporter::format_elapsed_time(86399.0),
            "23h 59m 59s (86399.0s)"
        );
    }

    #[test]
    fn test_format_elapsed_time_days() {
        // 1 day
        assert_eq!(
            ProgressReporter::format_elapsed_time(86400.0),
            "1d 0h 0m 0s (86400.0s)"
        );
        // 1 day 5 hours 30 minutes 15 seconds
        assert_eq!(
            ProgressReporter::format_elapsed_time(106215.0),
            "1d 5h 30m 15s (106215.0s)"
        );
        // 2 days 12 hours 45 minutes 30 seconds
        assert_eq!(
            ProgressReporter::format_elapsed_time(218730.0),
            "2d 12h 45m 30s (218730.0s)"
        );
    }
}
