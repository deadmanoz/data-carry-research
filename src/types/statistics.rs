//! Consolidated statistics framework for all processing stages
//!
//! This module provides a unified statistics collection system with common traits
//! and implementations for all stages of the Bitcoin P2MS analysis pipeline.

use std::time::{Duration, Instant};

/// Common trait for all statistics collectors
pub trait StatisticsCollector {
    /// Reset all counters to zero
    fn reset(&mut self);

    /// Get the processing start time
    fn start_time(&self) -> Instant;

    /// Get the total processing duration
    fn duration(&self) -> Duration;

    /// Calculate the processing rate (items per second)
    fn processing_rate(&self) -> f64;

    /// Finalize statistics collection
    fn finish(&mut self);

    /// Get a summary of the statistics
    fn summary(&self) -> String;
}

/// Common timing information for all statistics
#[derive(Debug, Clone)]
pub struct TimingInfo {
    pub start_time: Instant,
    pub processing_duration: Duration,
}

impl Default for TimingInfo {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            processing_duration: Duration::default(),
        }
    }
}

impl TimingInfo {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            processing_duration: Duration::default(),
        }
    }

    pub fn finish(&mut self) {
        self.processing_duration = self.start_time.elapsed();
    }

    pub fn elapsed(&self) -> Duration {
        if self.processing_duration.is_zero() {
            self.start_time.elapsed()
        } else {
            self.processing_duration
        }
    }
}

/// Stage 1 processing statistics
#[derive(Debug, Clone)]
pub struct ProcessingStats {
    pub total_records: usize,
    pub p2ms_found: usize,
    pub malformed_records: usize,
    pub batches_processed: usize,
    pub timing: TimingInfo,
}

impl Default for ProcessingStats {
    fn default() -> Self {
        Self {
            total_records: 0,
            p2ms_found: 0,
            malformed_records: 0,
            batches_processed: 0,
            timing: TimingInfo::new(),
        }
    }
}

impl ProcessingStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn p2ms_rate(&self) -> f64 {
        if self.total_records > 0 {
            (self.p2ms_found as f64 / self.total_records as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_records > 0 {
            (self.malformed_records as f64 / self.total_records as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn records_per_batch(&self) -> f64 {
        if self.batches_processed > 0 {
            self.total_records as f64 / self.batches_processed as f64
        } else {
            0.0
        }
    }
}

/// Stage 1 (CSV Processing) metrics for unified progress reporting
impl crate::processor::StageMetrics for ProcessingStats {
    fn format_custom_metrics(&self) -> String {
        format!(
            "P2MS: {} | Malformed: {}",
            self.p2ms_found, self.malformed_records
        )
    }
}

impl StatisticsCollector for ProcessingStats {
    fn reset(&mut self) {
        self.total_records = 0;
        self.p2ms_found = 0;
        self.malformed_records = 0;
        self.batches_processed = 0;
        self.timing = TimingInfo::new();
    }

    fn start_time(&self) -> Instant {
        self.timing.start_time
    }

    fn duration(&self) -> Duration {
        self.timing.elapsed()
    }

    fn processing_rate(&self) -> f64 {
        let elapsed = self.timing.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_records as f64 / elapsed
        } else {
            0.0
        }
    }

    fn finish(&mut self) {
        self.timing.finish();
    }

    fn summary(&self) -> String {
        format!(
            "Stage 1: {} total records, {} P2MS found ({:.1}%), {} errors ({:.1}%), {:.1} records/sec",
            self.total_records,
            self.p2ms_found,
            self.p2ms_rate(),
            self.malformed_records,
            self.error_rate(),
            self.processing_rate()
        )
    }
}

/// Stage 2 processing statistics
#[derive(Debug, Default)]
pub struct Stage2Stats {
    pub transactions_processed: u64,
    pub burn_patterns_found: u64,
    pub total_fees_analysed: u64,
    pub total_p2ms_value: u64,
    pub rpc_calls_made: u64,
    pub rpc_errors_encountered: u64,
    pub cache_hit_rate: f64, // Updated from RPC client before progress reporting
    pub timing: TimingInfo,
}

impl Stage2Stats {
    pub fn new() -> Self {
        Self {
            timing: TimingInfo::new(),
            ..Default::default()
        }
    }

    pub fn rpc_success_rate(&self) -> f64 {
        if self.rpc_calls_made > 0 {
            let success_calls = self.rpc_calls_made - self.rpc_errors_encountered;
            (success_calls as f64 / self.rpc_calls_made as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn average_fee_per_transaction(&self) -> f64 {
        if self.transactions_processed > 0 {
            self.total_fees_analysed as f64 / self.transactions_processed as f64
        } else {
            0.0
        }
    }

    pub fn burn_pattern_rate(&self) -> f64 {
        if self.transactions_processed > 0 {
            (self.burn_patterns_found as f64 / self.transactions_processed as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn average_p2ms_value(&self) -> f64 {
        if self.transactions_processed > 0 {
            self.total_p2ms_value as f64 / self.transactions_processed as f64
        } else {
            0.0
        }
    }
}

/// Stage 2 (Transaction Enrichment) metrics for unified progress reporting
impl crate::processor::StageMetrics for Stage2Stats {
    fn format_custom_metrics(&self) -> String {
        format!(
            "Patterns: {} | RPC OK: {:.1}% | Cache hit: {:.1}%",
            self.burn_patterns_found,
            self.rpc_success_rate(),
            self.cache_hit_rate
        )
    }
}

impl StatisticsCollector for Stage2Stats {
    fn reset(&mut self) {
        self.transactions_processed = 0;
        self.burn_patterns_found = 0;
        self.total_fees_analysed = 0;
        self.total_p2ms_value = 0;
        self.rpc_calls_made = 0;
        self.rpc_errors_encountered = 0;
        self.timing = TimingInfo::new();
    }

    fn start_time(&self) -> Instant {
        self.timing.start_time
    }

    fn duration(&self) -> Duration {
        self.timing.elapsed()
    }

    fn processing_rate(&self) -> f64 {
        let elapsed = self.timing.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.transactions_processed as f64 / elapsed
        } else {
            0.0
        }
    }

    fn finish(&mut self) {
        self.timing.finish();
    }

    fn summary(&self) -> String {
        format!(
            "Stage 2: {} transactions, {} burn patterns ({:.1}%), {} RPC calls ({:.1}% success), {:.1} tx/sec",
            self.transactions_processed,
            self.burn_patterns_found,
            self.burn_pattern_rate(),
            self.rpc_calls_made,
            self.rpc_success_rate(),
            self.processing_rate()
        )
    }
}

/// Stage 3 processing statistics
#[derive(Debug, Default)]
pub struct Stage3Results {
    pub transactions_processed: u64,
    pub baseline_transactions: u64, // Already-classified transactions at resume start
    pub stamps_classified: u64,
    pub counterparty_classified: u64,
    pub ascii_identifier_protocols_classified: u64,
    pub omni_classified: u64,
    pub chancecoin_classified: u64,
    pub ppk_classified: u64,
    pub opreturn_signalled_classified: u64,
    pub datastorage_classified: u64,
    pub likely_data_storage_classified: u64,
    pub legitimate_classified: u64,
    pub unknown_classified: u64,
    pub errors_encountered: u64,
    pub timing: TimingInfo,
}

impl Stage3Results {
    pub fn new() -> Self {
        Self {
            timing: TimingInfo::new(),
            ..Default::default()
        }
    }

    pub fn total_classified(&self) -> u64 {
        self.stamps_classified
            + self.counterparty_classified
            + self.ascii_identifier_protocols_classified
            + self.omni_classified
            + self.chancecoin_classified
            + self.ppk_classified
            + self.opreturn_signalled_classified
            + self.datastorage_classified
            + self.likely_data_storage_classified
            + self.legitimate_classified
            + self.unknown_classified
    }

    #[allow(clippy::type_complexity)]
    pub fn classification_breakdown(
        &self,
    ) -> (f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64) {
        let total = self.total_classified() as f64;
        if total > 0.0 {
            (
                (self.stamps_classified as f64 / total) * 100.0,
                (self.counterparty_classified as f64 / total) * 100.0,
                (self.ascii_identifier_protocols_classified as f64 / total) * 100.0,
                (self.omni_classified as f64 / total) * 100.0,
                (self.chancecoin_classified as f64 / total) * 100.0,
                (self.ppk_classified as f64 / total) * 100.0,
                (self.opreturn_signalled_classified as f64 / total) * 100.0,
                (self.datastorage_classified as f64 / total) * 100.0,
                (self.likely_data_storage_classified as f64 / total) * 100.0,
                (self.legitimate_classified as f64 / total) * 100.0,
                (self.unknown_classified as f64 / total) * 100.0,
            )
        } else {
            (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.transactions_processed > 0 {
            (self.errors_encountered as f64 / self.transactions_processed as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn classification_rate(&self) -> f64 {
        if self.transactions_processed > 0 {
            (self.total_classified() as f64 / self.transactions_processed as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// Stage 3 (Protocol Classification) metrics for unified progress reporting
impl crate::processor::StageMetrics for Stage3Results {
    fn format_custom_metrics(&self) -> String {
        // Abbreviations: S=BitcoinStamps, CP=Counterparty, A=AsciiIdentifierProtocols,
        // O=OmniLayer, CC=Chancecoin, PPk=PPk, OP_RET=OpReturnSignalled,
        // DS=DataStorage (includes WikiLeaks Cablegate), LD=LikelyDataStorage,
        // Leg=LikelyLegitimateMultisig, Unk=Unknown
        format!(
            "S:{} CP:{} A:{} O:{} CC:{} PPk:{} OP_RET:{} DS:{} LD:{} Leg:{} Unk:{}",
            self.stamps_classified,
            self.counterparty_classified,
            self.ascii_identifier_protocols_classified,
            self.omni_classified,
            self.chancecoin_classified,
            self.ppk_classified,
            self.opreturn_signalled_classified,
            self.datastorage_classified,
            self.likely_data_storage_classified,
            self.legitimate_classified,
            self.unknown_classified
        )
    }

    fn stage_prefix(&self) -> Option<&str> {
        Some("[Stage 3]")
    }
}

impl StatisticsCollector for Stage3Results {
    fn reset(&mut self) {
        self.transactions_processed = 0;
        self.baseline_transactions = 0;
        self.stamps_classified = 0;
        self.counterparty_classified = 0;
        self.ascii_identifier_protocols_classified = 0;
        self.omni_classified = 0;
        self.chancecoin_classified = 0;
        self.ppk_classified = 0;
        self.opreturn_signalled_classified = 0;
        self.datastorage_classified = 0;
        self.likely_data_storage_classified = 0;
        self.legitimate_classified = 0;
        self.unknown_classified = 0;
        self.errors_encountered = 0;
        self.timing = TimingInfo::new();
    }

    fn start_time(&self) -> Instant {
        self.timing.start_time
    }

    fn duration(&self) -> Duration {
        self.timing.elapsed()
    }

    fn processing_rate(&self) -> f64 {
        let elapsed = self.timing.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            // Calculate rate based on newly processed transactions only (exclude baseline)
            let newly_processed = self
                .transactions_processed
                .saturating_sub(self.baseline_transactions);
            newly_processed as f64 / elapsed
        } else {
            0.0
        }
    }

    fn finish(&mut self) {
        self.timing.finish();
    }

    fn summary(&self) -> String {
        let (
            stamps_pct,
            cp_pct,
            cpv_pct,
            omni_pct,
            chancecoin_pct,
            ppk_pct,
            opreturn_signalled_pct,
            data_pct,
            likely_data_pct,
            legit_pct,
            unknown_pct,
        ) = self.classification_breakdown();

        let newly_processed = self
            .transactions_processed
            .saturating_sub(self.baseline_transactions);

        if self.baseline_transactions > 0 {
            format!(
                "Stage 3: {} transactions classified this run (baseline: {}, total: {}), {:.1}% classified (S:{:.1}%, CP:{:.1}%, ASCII:{:.1}%, O:{:.1}%, CC:{:.1}%, PPk:{:.1}%, ORS:{:.1}%, D:{:.1}%, LDS:{:.1}%, L:{:.1}%, U:{:.1}%), {:.1} tx/sec",
                newly_processed,
                self.baseline_transactions,
                self.transactions_processed,
                self.classification_rate(),
                stamps_pct,
                cp_pct,
                cpv_pct,
                omni_pct,
                chancecoin_pct,
                ppk_pct,
                opreturn_signalled_pct,
                data_pct,
                likely_data_pct,
                legit_pct,
                unknown_pct,
                self.processing_rate()
            )
        } else {
            format!(
                "Stage 3: {} transactions, {:.1}% classified (S:{:.1}%, CP:{:.1}%, ASCII:{:.1}%, O:{:.1}%, CC:{:.1}%, PPk:{:.1}%, ORS:{:.1}%, D:{:.1}%, LDS:{:.1}%, L:{:.1}%, U:{:.1}%), {:.1} tx/sec",
                self.transactions_processed,
                self.classification_rate(),
                stamps_pct,
                cp_pct,
                cpv_pct,
                omni_pct,
                chancecoin_pct,
                ppk_pct,
                opreturn_signalled_pct,
                data_pct,
                likely_data_pct,
                legit_pct,
                unknown_pct,
                self.processing_rate()
            )
        }
    }
}

/// Combined statistics for all stages
#[derive(Debug)]
pub struct CombinedStats {
    pub stage1: Option<ProcessingStats>,
    pub stage2: Option<Stage2Stats>,
    pub stage3: Option<Stage3Results>,
    pub overall_timing: TimingInfo,
}

impl Default for CombinedStats {
    fn default() -> Self {
        Self {
            stage1: None,
            stage2: None,
            stage3: None,
            overall_timing: TimingInfo::new(),
        }
    }
}

impl CombinedStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_stage1(&mut self, stats: ProcessingStats) {
        self.stage1 = Some(stats);
    }

    pub fn set_stage2(&mut self, stats: Stage2Stats) {
        self.stage2 = Some(stats);
    }

    pub fn set_stage3(&mut self, stats: Stage3Results) {
        self.stage3 = Some(stats);
    }

    pub fn overall_summary(&self) -> String {
        let mut summary = vec![];

        if let Some(ref s1) = self.stage1 {
            summary.push(s1.summary());
        }

        if let Some(ref s2) = self.stage2 {
            summary.push(s2.summary());
        }

        if let Some(ref s3) = self.stage3 {
            summary.push(s3.summary());
        }

        if summary.is_empty() {
            "No statistics available".to_string()
        } else {
            let total_duration = self.overall_timing.elapsed();
            summary.push(format!(
                "Total duration: {:.1}s",
                total_duration.as_secs_f64()
            ));
            summary.join("\n")
        }
    }
}

impl StatisticsCollector for CombinedStats {
    fn reset(&mut self) {
        if let Some(ref mut s1) = self.stage1 {
            s1.reset();
        }
        if let Some(ref mut s2) = self.stage2 {
            s2.reset();
        }
        if let Some(ref mut s3) = self.stage3 {
            s3.reset();
        }
        self.overall_timing = TimingInfo::new();
    }

    fn start_time(&self) -> Instant {
        self.overall_timing.start_time
    }

    fn duration(&self) -> Duration {
        self.overall_timing.elapsed()
    }

    fn processing_rate(&self) -> f64 {
        // Use stage 1 processing rate as the overall rate (since it processes the most items)
        if let Some(ref s1) = self.stage1 {
            s1.processing_rate()
        } else {
            0.0
        }
    }

    fn finish(&mut self) {
        if let Some(ref mut s1) = self.stage1 {
            s1.finish();
        }
        if let Some(ref mut s2) = self.stage2 {
            s2.finish();
        }
        if let Some(ref mut s3) = self.stage3 {
            s3.finish();
        }
        self.overall_timing.finish();
    }

    fn summary(&self) -> String {
        self.overall_summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_timing_info() {
        let mut timing = TimingInfo::new();
        let start = timing.start_time;

        // Simulate some processing time
        thread::sleep(StdDuration::from_millis(10));

        timing.finish();

        assert!(timing.processing_duration > Duration::from_millis(5));
        assert_eq!(timing.start_time, start);
    }

    #[test]
    fn test_processing_stats() {
        let mut stats = ProcessingStats::new();
        assert_eq!(stats.total_records, 0);
        assert_eq!(stats.p2ms_found, 0);
        assert_eq!(stats.malformed_records, 0);

        stats.total_records = 100;
        stats.p2ms_found = 10;
        stats.malformed_records = 2;
        stats.batches_processed = 5;

        assert!((stats.p2ms_rate() - 10.0).abs() < f64::EPSILON);
        assert!((stats.error_rate() - 2.0).abs() < f64::EPSILON);
        assert!((stats.records_per_batch() - 20.0).abs() < f64::EPSILON);

        let summary = stats.summary();
        assert!(summary.contains("100 total records"));
        assert!(summary.contains("10 P2MS found"));
    }

    #[test]
    fn test_stage2_stats() {
        let mut stats = Stage2Stats::new();
        stats.transactions_processed = 50;
        stats.burn_patterns_found = 5;
        stats.total_fees_analysed = 5000;
        stats.total_p2ms_value = 100000;
        stats.rpc_calls_made = 100;
        stats.rpc_errors_encountered = 5;

        assert!((stats.burn_pattern_rate() - 10.0).abs() < f64::EPSILON);
        assert!((stats.rpc_success_rate() - 95.0).abs() < f64::EPSILON);
        assert!((stats.average_fee_per_transaction() - 100.0).abs() < f64::EPSILON);
        assert!((stats.average_p2ms_value() - 2000.0).abs() < f64::EPSILON);

        let summary = stats.summary();
        assert!(summary.contains("50 transactions"));
        assert!(summary.contains("5 burn patterns"));
    }

    #[test]
    fn test_stage3_results() {
        let mut results = Stage3Results::new();
        results.transactions_processed = 100;
        results.stamps_classified = 20;
        results.counterparty_classified = 15;
        results.omni_classified = 10;
        results.datastorage_classified = 5;
        results.unknown_classified = 30;
        results.errors_encountered = 2;

        assert_eq!(results.total_classified(), 80);
        assert!((results.classification_rate() - 80.0).abs() < f64::EPSILON);
        assert!((results.error_rate() - 2.0).abs() < f64::EPSILON);

        let (
            stamps_pct,
            cp_pct,
            _cpv_pct,
            omni_pct,
            _chancecoin_pct,
            _ppk_pct,
            _opreturn_signalled_pct,
            data_pct,
            _likely_data_pct,
            _legit_pct,
            unknown_pct,
        ) = results.classification_breakdown();
        assert!((stamps_pct - 25.0).abs() < f64::EPSILON); // 20/80 * 100
        assert!((cp_pct - 18.75).abs() < f64::EPSILON); // 15/80 * 100
        assert!((omni_pct - 12.5).abs() < f64::EPSILON); // 10/80 * 100
        assert!((data_pct - 6.25).abs() < f64::EPSILON); // 5/80 * 100
        assert!((unknown_pct - 37.5).abs() < f64::EPSILON); // 30/80 * 100

        let summary = results.summary();
        assert!(summary.contains("100 transactions"));
        assert!(summary.contains("80.0% classified"));
    }

    #[test]
    fn test_statistics_collector_trait() {
        let mut stats = ProcessingStats::new();
        let start_time = stats.start_time();

        // Test reset
        stats.total_records = 100;
        // Add a small delay to ensure time difference
        thread::sleep(StdDuration::from_millis(1));
        stats.reset();
        assert_eq!(stats.total_records, 0);
        assert!(stats.start_time() > start_time);

        // Test finish
        stats.total_records = 50;
        thread::sleep(StdDuration::from_millis(10));
        stats.finish();

        assert!(stats.duration() > Duration::from_millis(5));
        assert!(stats.processing_rate() > 0.0);
    }

    #[test]
    fn test_combined_stats() {
        let mut combined = CombinedStats::new();

        let mut stage1 = ProcessingStats::new();
        stage1.total_records = 100;
        stage1.p2ms_found = 10;

        let mut stage2 = Stage2Stats::new();
        stage2.transactions_processed = 50;
        stage2.burn_patterns_found = 5;

        let mut stage3 = Stage3Results::new();
        stage3.transactions_processed = 50;
        stage3.stamps_classified = 20;

        combined.set_stage1(stage1);
        combined.set_stage2(stage2);
        combined.set_stage3(stage3);

        let summary = combined.overall_summary();
        assert!(summary.contains("Stage 1:"));
        assert!(summary.contains("Stage 2:"));
        assert!(summary.contains("Stage 3:"));
        assert!(summary.contains("Total duration:"));
    }
}
