//! Centralised analysis module for P2MS protocol analyser
//!
//! This module provides a comprehensive, type-safe analysis system that replaces
//! the scattered SQL commands in the justfile with structured Rust analysis.
//!
//! ## Overview
//!
//! The analysis module is organised around the `AnalysisEngine` which provides
//! the main API for all analysis operations:
//!
//! - **Burn Pattern Analysis** - Pattern detection and classification insights
//! - **Fee Analysis** - Transaction cost and storage fee analysis
//! - **Protocol Statistics** - Classification breakdown and distribution
//! - **Signature Analysis** - Protocol signature detection analysis
//! - **Report Generation** - Formatted output for console and JSON export
//!
//! ## Usage
//!
//! ```rust
//! use data_carry_research::analysis::AnalysisEngine;
//! use data_carry_research::errors::AppResult;
//!
//! fn example() -> AppResult<()> {
//!     // Create analysis engine
//!     let engine = AnalysisEngine::new("./database.db")?;
//!
//!     // Run individual analyses (replaces justfile commands)
//!     let burn_analysis = engine.analyse_burn_patterns()?;
//!     let fee_analysis = engine.analyse_fees()?;
//!     let classification_stats = engine.analyse_classifications()?;
//!     let signature_analysis = engine.analyse_signatures()?;
//!
//!     // Generate comprehensive report
//!     let full_report = engine.generate_full_report()?;
//!     Ok(())
//! }
//! ```

pub mod burn_detector;
pub mod burn_patterns;
pub mod content_type_analysis;
pub mod data_size_stats;
pub mod fee_analyser;
pub mod fee_analysis;
pub mod file_extension_stats;
pub mod multisig_config_stats;
pub mod protocol_stats;
pub mod pubkey_validator;
pub mod reports;
pub mod signature_analysis;
pub mod spendability_stats;
pub mod stamps_signature_stats;
pub mod stamps_transport_stats;
pub mod types;
pub mod value_analysis;

// Re-export main types and interfaces
pub use burn_detector::BurnPatternDetector;
pub use burn_patterns::BurnPatternAnalyser;
pub use content_type_analysis::ContentTypeAnalyser;
pub use data_size_stats::DataSizeAnalyser;
pub use fee_analyser::FeeAnalyser;
pub use fee_analysis::FeeAnalysisEngine;
pub use file_extension_stats::FileExtensionAnalyser;
pub use multisig_config_stats::MultisigConfigAnalyser;
pub use protocol_stats::ProtocolStatsAnalyser;
pub use pubkey_validator::{
    aggregate_validation_for_outputs, validate_from_metadata, validate_pubkeys,
    PubkeyValidationResult,
};
pub use reports::{OutputFormat, ReportFormatter};
pub use signature_analysis::SignatureAnalyser;
pub use spendability_stats::SpendabilityStatsAnalyser;
pub use stamps_signature_stats::{StampsSignatureAnalyser, StampsSignatureAnalysis};
pub use stamps_transport_stats::{StampsTransportAnalyser, StampsTransportAnalysis};
pub use types::{
    BurnPatternAnalysis, ClassificationStatsReport, ComprehensiveDataSizeReport,
    ContentTypeAnalysisReport, ContentTypeCategoryStats, ContentTypeProtocolStats,
    ContentTypeSpendabilityReport, ContentTypeStats, FeeAnalysisReport, FileExtensionReport,
    FullAnalysisReport, GlobalValueDistribution, MultisigConfigReport, MultisigConfiguration,
    ProtocolDataSizeReport, ProtocolValueDistribution, SignatureAnalysisReport,
    SpendabilityDataSizeReport, SpendabilityStatsReport, ValidNoneStats, ValueAnalysisReport,
    ValueBucket, ValueDistributionReport, ValuePercentiles,
};
pub use value_analysis::ValueAnalysisEngine;

use crate::database::Database;
use crate::errors::AppResult;
use std::time::{SystemTime, UNIX_EPOCH};

/// Main analysis engine providing comprehensive analysis capabilities
///
/// This is the primary interface for all analysis operations, replacing
/// the justfile SQL commands with structured, type-safe analysis.
pub struct AnalysisEngine {
    database: Database,
}

impl AnalysisEngine {
    /// Create a new analysis engine with the specified database
    ///
    /// # Arguments
    /// * `database_path` - Path to the SQLite database file
    ///
    /// # Returns
    /// * `AppResult<Self>` - Configured analysis engine or error
    pub fn new(database_path: &str) -> AppResult<Self> {
        let database = Database::new_v2(database_path)?;
        Ok(Self { database })
    }

    /// Analyse burn patterns detected in P2MS transactions
    ///
    /// **Replaces:** `justfile burn-patterns` command
    ///
    /// Provides comprehensive analysis of burn patterns including:
    /// - Pattern type distribution with percentages
    /// - Sample patterns with transaction context
    /// - Trend analysis over time
    ///
    /// # Returns
    /// * `AppResult<BurnPatternAnalysis>` - Comprehensive burn pattern insights
    pub fn analyse_burn_patterns(&self) -> AppResult<BurnPatternAnalysis> {
        BurnPatternAnalyser::analyse_patterns(&self.database)
    }

    /// Analyse transaction fees and storage costs
    ///
    /// **Replaces:** `justfile fee-analysis` command
    ///
    /// Provides comprehensive fee analysis including:
    /// - Total, average, and median fee calculations
    /// - Fee rate distributions (sat/byte, sat/KB)
    /// - Storage cost analysis for P2MS data
    /// - Coinbase vs regular transaction breakdown
    ///
    /// # Returns
    /// * `AppResult<FeeAnalysisReport>` - Comprehensive fee analysis
    pub fn analyse_fees(&self) -> AppResult<FeeAnalysisReport> {
        FeeAnalysisEngine::analyse_transaction_fees(&self.database)
    }

    /// Analyse value distribution across protocols
    ///
    /// **Replaces:** `justfile fee-analysis` (enhanced version)
    ///
    /// Provides comprehensive value analysis including:
    /// - Per-protocol BTC value locked in P2MS outputs
    /// - Output count distribution
    /// - Average, min, max values per protocol
    /// - Fee analysis context for economic insights
    ///
    /// # Returns
    /// * `AppResult<ValueAnalysisReport>` - Comprehensive value distribution analysis
    pub fn analyse_value(&self) -> AppResult<ValueAnalysisReport> {
        // First get fee analysis for context
        let fee_report = self.analyse_fees()?;
        // Then perform value analysis with fee context
        ValueAnalysisEngine::analyse_value_distribution(&self.database, fee_report)
    }

    /// Analyse detailed value distribution histograms
    ///
    /// Provides histogram data suitable for plotting value distributions:
    /// - Global distribution across all P2MS outputs
    /// - Per-protocol distributions
    /// - Value buckets with counts and percentages
    /// - Statistical percentiles
    ///
    /// # Returns
    /// * `AppResult<ValueDistributionReport>` - Comprehensive value distribution histograms
    pub fn analyse_value_distributions(&self) -> AppResult<ValueDistributionReport> {
        ValueAnalysisEngine::analyse_value_distributions(&self.database)
    }

    /// Analyse protocol classification statistics
    ///
    /// **Replaces:** `justfile classification-stats` command
    ///
    /// Provides comprehensive classification analysis including:
    /// - Protocol counts and percentages (BitcoinStamps, Counterparty, Omni, Unknown)
    /// - Classification method breakdown
    /// - Signature detection rates
    /// - Variant analysis within each protocol
    ///
    /// # Returns
    /// * `AppResult<ClassificationStatsReport>` - Comprehensive classification analysis
    pub fn analyse_classifications(&self) -> AppResult<ClassificationStatsReport> {
        ProtocolStatsAnalyser::analyse_classifications(&self.database)
    }

    /// Analyse protocol signature detection
    ///
    /// **Replaces:** `justfile signature-analysis` command
    ///
    /// Provides comprehensive signature analysis including:
    /// - Classification method distribution
    /// - Signature detection success rates
    /// - Burn pattern correlation with protocols
    /// - Confidence level analysis
    ///
    /// # Returns
    /// * `AppResult<SignatureAnalysisReport>` - Comprehensive signature analysis
    pub fn analyse_signatures(&self) -> AppResult<SignatureAnalysisReport> {
        SignatureAnalyser::analyse_signatures(&self.database)
    }

    /// AnalyseP2MS output spendability
    ///
    /// **Replaces:** `justfile spendability-stats` command
    ///
    /// Provides comprehensive spendability analysis including:
    /// - Overall spendable vs unspendable breakdown
    /// - Per-protocol spendability rates
    /// - Spendability reason distribution
    /// - Key count distributions (burn/data/real)
    /// - Transaction-level aggregation
    ///
    /// # Returns
    /// * `AppResult<SpendabilityStatsReport>` - Comprehensive spendability analysis
    pub fn analyse_spendability(&self) -> AppResult<SpendabilityStatsReport> {
        SpendabilityStatsAnalyser::analyse_spendability(&self.database)
    }

    /// Analyse file extensions and data-size usage across classified transactions
    pub fn analyse_file_extensions(&self) -> AppResult<FileExtensionReport> {
        FileExtensionAnalyser::analyse_file_types(&self.database)
    }

    /// Analyse Bitcoin Stamps transport mechanism breakdown
    ///
    /// **Replaces:** Manual SQL queries for Bitcoin Stamps transport statistics
    ///
    /// Provides comprehensive transport mechanism analysis including:
    /// - Pure Bitcoin Stamps vs Counterparty transport distribution
    /// - Variant breakdown within each transport type
    /// - Output-level spendability for each mechanism
    ///
    /// # Returns
    /// * `AppResult<StampsTransportAnalysis>` - Complete transport breakdown
    pub fn analyse_stamps_transport(&self) -> AppResult<StampsTransportAnalysis> {
        StampsTransportAnalyser::analyse_transport_breakdown(&self.database)
    }

    /// Analyse Bitcoin Stamps signature variant distribution
    ///
    /// Analyses the distribution of signature variants (stamp:, STAMP:, stamps:, STAMPS:)
    /// across all Bitcoin Stamps transactions. Provides breakdown by:
    /// - Overall distribution across all Stamps
    /// - Pure Bitcoin Stamps signature usage
    /// - Counterparty-transported Stamps signature usage
    ///
    /// # Returns
    /// * `AppResult<StampsSignatureAnalysis>` - Complete signature variant breakdown
    pub fn analyse_stamps_signatures(&self) -> AppResult<StampsSignatureAnalysis> {
        StampsSignatureAnalyser::analyse_signature_distribution(&self.database)
    }

    /// Analyse data sizes across protocols with spendability breakdown
    ///
    /// Provides protocol-level byte statistics including:
    /// - Total bytes per protocol (from script_size)
    /// - Transaction and output counts
    /// - Average/min/max bytes per output
    /// - Spendable vs unspendable byte distribution
    ///
    /// # Returns
    /// * `AppResult<ProtocolDataSizeReport>` - Protocol-level data size analysis
    pub fn analyse_protocol_data_sizes(&self) -> AppResult<ProtocolDataSizeReport> {
        DataSizeAnalyser::analyse_protocol_data_sizes(&self.database)
    }

    /// Analyse data sizes by spendability
    ///
    /// Provides spendability-focused byte statistics including:
    /// - Overall spendable vs unspendable bytes
    /// - Per-protocol spendability breakdown
    /// - Per-reason distribution (for unspendable outputs)
    ///
    /// # Returns
    /// * `AppResult<SpendabilityDataSizeReport>` - Spendability-level data size analysis
    pub fn analyse_spendability_data_sizes(&self) -> AppResult<SpendabilityDataSizeReport> {
        DataSizeAnalyser::analyse_spendability_data_sizes(&self.database)
    }

    /// Analyse data sizes by content type with spendability cross-analysis
    ///
    /// Provides content-type-focused byte statistics including:
    /// - Per-content-type byte totals
    /// - Spendable vs unspendable breakdown per content type
    /// - Category-level aggregation (Images, JSON, etc.)
    /// - Category-level transaction deduplication
    ///
    /// # Returns
    /// * `AppResult<ContentTypeSpendabilityReport>` - Content type data size analysis
    pub fn analyse_content_type_spendability(&self) -> AppResult<ContentTypeSpendabilityReport> {
        DataSizeAnalyser::analyse_content_type_spendability(&self.database)
    }

    /// Analyse comprehensive data sizes across all dimensions
    ///
    /// Combines protocol, spendability, and content type analyses into
    /// a unified report with consistency checks.
    ///
    /// # Returns
    /// * `AppResult<ComprehensiveDataSizeReport>` - Complete data size analysis
    pub fn analyse_comprehensive_data_sizes(&self) -> AppResult<ComprehensiveDataSizeReport> {
        DataSizeAnalyser::analyse_comprehensive_data_sizes(&self.database)
    }

    /// Analyse multisig configurations with exhaustive breakdown
    ///
    /// Provides complete analysis of all m-of-n multisig configurations including:
    /// - Key composition (compressed vs uncompressed)
    /// - Script size vs actual data capacity
    /// - Efficiency metrics showing overhead
    /// - Protocol distribution across configurations
    ///
    /// # Returns
    /// * `AppResult<MultisigConfigReport>` - Comprehensive multisig configuration analysis
    pub fn analyse_multisig_configurations(&self) -> AppResult<MultisigConfigReport> {
        MultisigConfigAnalyser::analyse_multisig_configurations(&self.database)
    }

    /// Analyse content type (MIME type) distribution across protocols
    ///
    /// **Replaces:** Old transaction-level content type queries
    ///
    /// Provides comprehensive content type analysis including:
    /// - Overall content type presence statistics
    /// - Breakdown by specific MIME type
    /// - Category grouping (image/*, text/*, application/*)
    /// - Protocol-specific content type distributions
    /// - Valid None cases (LikelyDataStorage, LikelyLegitimateMultisig, StampsUnknown)
    /// - Invalid None cases (missing content types that should exist)
    ///
    /// **IMPORTANT**: Analyses at **output level** (not transaction level) for accurate statistics.
    /// All queries filter by `is_spent = 0 AND script_type = 'multisig'` (unspent P2MS outputs only).
    ///
    /// # Returns
    /// * `AppResult<ContentTypeAnalysisReport>` - Comprehensive content type analysis
    pub fn analyse_content_types(&self) -> AppResult<ContentTypeAnalysisReport> {
        ContentTypeAnalyser::analyse_content_types(&self.database)
    }

    /// Generate a comprehensive analysis report including all analysis types
    ///
    /// This combines all individual analysis operations into a single comprehensive
    /// report for complete database insights.
    ///
    /// # Returns
    /// * `AppResult<FullAnalysisReport>` - Complete analysis of all data
    pub fn generate_full_report(&self) -> AppResult<FullAnalysisReport> {
        let burn_patterns = self.analyse_burn_patterns()?;
        let fee_analysis = self.analyse_fees()?;
        let classifications = self.analyse_classifications()?;
        let signatures = self.analyse_signatures()?;
        let spendability = self.analyse_spendability()?;
        let file_extensions = match self.analyse_file_extensions() {
            Ok(report) => Some(report),
            Err(e) => {
                if e.to_string().contains("no such column: content_type")
                    || e.to_string()
                        .contains("no such table: transaction_classifications")
                    || e.to_string().contains("no such table: transaction_outputs")
                {
                    None
                } else {
                    return Err(e);
                }
            }
        };

        // CRITICAL: Don't use .ok() - fail loudly on DB errors
        // Only suppress if it's a "not found" / "no data" scenario
        let stamps_transport = match self.analyse_stamps_transport() {
            Ok(stats) => Some(stats),
            Err(e) => {
                // Only suppress if column doesn't exist yet (pre-Stage 3 rerun)
                // Otherwise, propagate the error
                if e.to_string().contains("no such column: transport_protocol") {
                    None // Column not added yet - gracefully handle
                } else {
                    return Err(e); // Fail loudly on real errors
                }
            }
        };

        let stamps_signatures = match self.analyse_stamps_signatures() {
            Ok(stats) => Some(stats),
            Err(e) => {
                // Only suppress if signature variant field doesn't exist yet (pre-Stage 3 rerun)
                // Otherwise, propagate the error
                if e.to_string().contains("stamp_signature_variant")
                    || e.to_string().contains("no such column")
                {
                    None // Field not populated yet - gracefully handle
                } else {
                    return Err(e); // Fail loudly on real errors
                }
            }
        };

        // Generate timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(FullAnalysisReport {
            burn_patterns,
            fee_analysis,
            classifications,
            signatures,
            spendability,
            file_extensions,
            stamps_transport,
            stamps_signatures,
            data_size: Some(self.analyse_comprehensive_data_sizes()?),
            generated_at: format!("timestamp_{}", timestamp),
        })
    }

    /// Get direct access to the database for advanced queries
    ///
    /// This allows for custom analysis operations beyond the standard analysis types.
    ///
    /// # Returns
    /// * `&Database` - Reference to the underlying database connection
    pub fn database(&self) -> &Database {
        &self.database
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_engine_creation() {
        // Test that AnalysisEngine can be created with in-memory database
        let engine = AnalysisEngine::new(":memory:");
        assert!(engine.is_ok());
    }

    #[test]
    fn test_analysis_engine_api() {
        // Test that all analysis methods can be called (even if they return empty results)
        let engine = AnalysisEngine::new(":memory:").unwrap();

        // All methods should succeed with empty database (returning default values)
        assert!(engine.analyse_burn_patterns().is_ok());
        assert!(engine.analyse_fees().is_ok());
        assert!(engine.analyse_classifications().is_ok());
        assert!(engine.analyse_signatures().is_ok());
        assert!(engine.analyse_spendability().is_ok());
        assert!(engine.analyse_file_extensions().is_ok());
        assert!(engine.generate_full_report().is_ok());
    }

    #[test]
    fn test_full_report_generation() {
        let engine = AnalysisEngine::new(":memory:").unwrap();
        let report = engine.generate_full_report().unwrap();

        // Verify all components are present
        assert_eq!(report.burn_patterns.total_patterns, 0);
        assert_eq!(report.fee_analysis.total_transactions, 0);
        assert_eq!(report.classifications.total_classified, 0);
        assert_eq!(report.spendability.overall.total_outputs, 0);
        assert!(report
            .file_extensions
            .as_ref()
            .map(|ext| ext.total_transactions == 0 && ext.total_outputs == 0)
            .unwrap_or(false));
        assert!(!report.generated_at.is_empty());
    }
}
