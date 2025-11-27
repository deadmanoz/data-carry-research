//! Multisig configuration analysis functionality
//!
//! This module provides exhaustive analysis of P2MS multisig configurations,
//! showing the distribution of compressed vs uncompressed keys and calculating
//! actual data-carrying capacity vs blockchain script overhead.
//!
//! ## Data Capacity Calculation
//!
//! For m-of-n multisig scripts used for data storage (primarily 1-of-n):
//! - The first public key is assumed to be the real signing key
//! - The remaining (n-1) keys are used to carry embedded data
//! - Compressed keys (33 bytes total): 32 bytes of usable data capacity
//! - Uncompressed keys (65 bytes total): 64 bytes of usable data capacity
//!
//! Example: 1-of-3 with all compressed keys (CCC):
//! - Script size: 105 bytes (full P2MS script)
//! - Data capacity: 64 bytes (2 data keys × 32 bytes each)
//! - Efficiency: 60.95% (64/105)
//!
//! ## Efficiency Metrics
//!
//! Efficiency represents the ratio of actual data payload to blockchain storage cost:
//! - Efficiency = (data_capacity / script_size) × 100
//! - Higher efficiency means less blockchain overhead per byte of data
//! - Typical range: 45-70% efficiency for data-carrying configurations
//!
//! ## Why Efficiency Matters
//!
//! 1. **Economic Impact**: Lower efficiency means higher transaction fees per byte of data
//! 2. **Blockchain Bloat**: Inefficient encoding increases the blockchain size unnecessarily
//! 3. **Network Resources**: More script overhead means more data to transmit and validate
//! 4. **Protocol Optimisation**: Understanding efficiency helps protocol designers choose optimal configurations
//!
//! Example overhead factors:
//! - 1-of-2 CC: 2.22x overhead (45.1% efficiency) - least efficient common configuration
//! - 1-of-3 CCC: 1.64x overhead (60.95% efficiency) - most common configuration (87.63% of all P2MS)
//! - 1-of-3 CCU: 1.43x overhead (70.1% efficiency) - most efficient configuration
//!
//! ## Configuration Buckets
//!
//! We exhaustively map script sizes to exact key configurations because:
//! 1. **Precision**: Script size uniquely identifies the key composition for known m-of-n values
//! 2. **Verification**: Allows validation that detected configurations match expected patterns
//! 3. **Anomaly Detection**: Unknown sizes indicate non-standard or malformed scripts
//! 4. **Protocol Analysis**: Different protocols prefer different configurations (e.g., Stamps uses CCC)
//!
//! The configuration table covers all common patterns from 1-of-1 through 1-of-7,
//! with fallback estimation for higher-order or non-standard configurations.

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{MultisigConfigReport, MultisigConfiguration};
use std::collections::BTreeMap;

/// Multisig configuration analysis engine
pub struct MultisigConfigAnalyser;

impl MultisigConfigAnalyser {
    /// Analyse multisig configurations with exhaustive breakdown
    ///
    /// Provides complete analysis of all m-of-n multisig configurations including:
    /// - Key composition (compressed vs uncompressed)
    /// - Script size vs data capacity
    /// - Efficiency metrics
    /// - Protocol distribution
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<MultisigConfigReport>` - Comprehensive multisig configuration analysis
    pub fn analyse_multisig_configurations(db: &Database) -> AppResult<MultisigConfigReport> {
        let conn = db.connection();

        // Query for all configurations
        let mut stmt = conn.prepare(
            "SELECT
                json_extract(o.metadata_json, '$.required_sigs') as m,
                json_extract(o.metadata_json, '$.total_pubkeys') as n,
                o.script_size,
                tc.protocol,
                tc.variant,
                COUNT(*) as output_count,
                SUM(o.script_size) as total_script_bytes
            FROM transaction_outputs o
            LEFT JOIN transaction_classifications tc ON o.txid = tc.txid
            WHERE o.script_type = 'multisig'
                AND o.is_spent = 0
                AND o.metadata_json IS NOT NULL
                AND json_extract(o.metadata_json, '$.total_pubkeys') <= 20  -- Bitcoin protocol maximum
            GROUP BY m, n, o.script_size, tc.protocol, tc.variant
            ORDER BY COUNT(*) DESC",
        )?;

        let mut configurations = Vec::new();
        let rows = stmt.query_map([], |row| {
            let m: u32 = row.get(0)?;
            let n: u32 = row.get(1)?;
            let script_size: u32 = row.get(2)?;
            let protocol: Option<String> = row.get(3)?;
            let variant: Option<String> = row.get(4)?;
            let output_count: u64 = row.get(5)?;
            let total_script_bytes: u64 = row.get(6)?;

            // Determine key configuration based on known script sizes
            let (key_config, data_capacity) = Self::determine_configuration(m, n, script_size);

            Ok(MultisigConfiguration {
                m,
                n,
                key_config,
                script_size,
                data_capacity_bytes: data_capacity,
                efficiency_pct: if data_capacity > 0 {
                    (data_capacity as f64 / script_size as f64) * 100.0
                } else {
                    0.0
                },
                output_count,
                total_script_bytes,
                protocol,
                variant,
            })
        })?;

        for row in rows {
            configurations.push(row?);
        }

        // Calculate totals
        let total_outputs: u64 = configurations.iter().map(|c| c.output_count).sum();
        let total_script_bytes: u64 = configurations.iter().map(|c| c.total_script_bytes).sum();

        // Calculate total data capacity
        let total_data_capacity: u64 = configurations
            .iter()
            .map(|c| c.output_count * c.data_capacity_bytes as u64)
            .sum();

        // Group by m-of-n type for summary (only count outputs)
        let mut type_summary = BTreeMap::new();
        for config in &configurations {
            let key = format!("{}-of-{}", config.m, config.n);
            *type_summary.entry(key).or_insert(0u64) += config.output_count;
        }

        Ok(MultisigConfigReport {
            configurations,
            total_outputs,
            total_script_bytes,
            total_data_capacity,
            overall_efficiency: if total_script_bytes > 0 {
                (total_data_capacity as f64 / total_script_bytes as f64) * 100.0
            } else {
                0.0
            },
            type_summary,
        })
    }

    /// Determine key configuration and data capacity from script size
    ///
    /// Maps the combination of m (required signatures), n (total keys), and script_size
    /// to the exact key configuration and calculates the data-carrying capacity.
    ///
    /// **Coverage**:
    /// - Configurations 1-of-1 through 1-of-7: Exact mappings with precise capacity calculations
    /// - Configurations 1-of-8 through 1-of-20: Conservative estimation (indicated by "?" suffix)
    ///
    /// **Note**: This function is exposed publicly primarily for testing purposes,
    /// allowing tests to verify the configuration mapping logic directly without
    /// duplicating the implementation. While public, it's considered an internal
    /// implementation detail of the analyser rather than a stable public API.
    ///
    /// # Key Configuration Notation
    /// - `C` = Compressed key (33 bytes total: 1 byte prefix + 32 bytes X coordinate)
    /// - `U` = Uncompressed key (65 bytes total: 1 byte prefix + 32 bytes X + 32 bytes Y)
    /// - Examples: `CCC` = 3 compressed keys, `CCU` = 2 compressed + 1 uncompressed
    ///
    /// # Data Capacity Rules
    ///
    /// ## For 1-of-n configurations (data storage use case):
    /// - First key: Real signing key (not counted for data)
    /// - Remaining (n-1) keys: Data carriers
    /// - Each compressed data key: 32 bytes capacity (33 bytes - 1 byte prefix)
    /// - Each uncompressed data key: 64 bytes capacity (65 bytes - 1 byte prefix)
    ///
    /// ## For m-of-n where m == n (true multisig):
    /// - All keys are real signing keys
    /// - Data capacity: 0 (not used for data storage)
    ///
    /// ## For m-of-n where 1 < m < n (hybrid usage):
    /// - Can carry data but with reduced security
    /// - Data capacity calculated same as 1-of-n (for protocols that use it this way)
    ///
    /// # Script Size Calculation
    ///
    /// P2MS script structure:
    /// - OP_m (1 byte) + pubkey1 + pubkey2 + ... + pubkeyn + OP_n (1 byte) + OP_CHECKMULTISIG (1 byte)
    /// - Total: 3 bytes overhead + sum of pubkey sizes
    ///
    /// Examples:
    /// - 1-of-3 CCC: 3 + 33×3 = 105 bytes
    /// - 1-of-3 CCU: 3 + 33×2 + 65 = 137 bytes
    /// - 1-of-3 UUU: 3 + 65×3 = 201 bytes
    ///
    /// # Returns
    /// - `(config_string, data_capacity_bytes)`
    /// - config_string: Human-readable key composition (e.g., "CCC", "CCU")
    /// - data_capacity_bytes: Usable data storage in bytes
    pub fn determine_configuration(m: u32, n: u32, script_size: u32) -> (String, u32) {
        match (m, n, script_size) {
            // 1-of-1 configurations
            (1, 1, 37) => ("C".to_string(), 0),
            (1, 1, 69) => ("U".to_string(), 0),

            // 1-of-2 configurations
            (1, 2, 71) => ("CC".to_string(), 32),
            (1, 2, 103) => ("CU".to_string(), 64),
            (1, 2, 135) => ("UU".to_string(), 64),

            // 2-of-2 configurations (no data capacity - true multisig)
            (2, 2, 71) => ("CC".to_string(), 0),
            (2, 2, 103) => ("CU".to_string(), 0),
            (2, 2, 135) => ("UU".to_string(), 0),

            // 1-of-3 configurations
            (1, 3, 105) => ("CCC".to_string(), 64),  // 2×32
            (1, 3, 137) => ("CCU".to_string(), 96),  // 32+64
            (1, 3, 169) => ("CUU".to_string(), 128), // 64+64
            (1, 3, 201) => ("UUU".to_string(), 128), // 2×64

            // 2-of-3 configurations (data capacity same as 1-of-3 if used for data)
            (2, 3, 105) => ("CCC".to_string(), 64),
            (2, 3, 137) => ("CCU".to_string(), 96),
            (2, 3, 169) => ("CUU".to_string(), 128),
            (2, 3, 201) => ("UUU".to_string(), 128),

            // 3-of-3 configurations (no data capacity - true multisig)
            (3, 3, 105) => ("CCC".to_string(), 0),
            (3, 3, 137) => ("CCU".to_string(), 0),
            (3, 3, 169) => ("CUU".to_string(), 0),
            (3, 3, 201) => ("UUU".to_string(), 0),

            // 1-of-4 configurations
            (1, 4, 139) => ("CCCC".to_string(), 96),  // 3×32
            (1, 4, 171) => ("CCCU".to_string(), 128), // 2×32+64
            (1, 4, 203) => ("CCUU".to_string(), 160), // 32+2×64
            (1, 4, 235) => ("CUUU".to_string(), 192), // 3×64
            (1, 4, 267) => ("UUUU".to_string(), 192), // 3×64

            // 1-of-5 configurations
            (1, 5, 173) => ("CCCCC".to_string(), 128), // 4×32
            (1, 5, 205) => ("CCCCU".to_string(), 160), // 3×32+64
            (1, 5, 237) => ("CCCUU".to_string(), 192), // 2×32+2×64
            (1, 5, 269) => ("CCUUU".to_string(), 224), // 32+3×64
            (1, 5, 301) => ("CUUUU".to_string(), 256), // 4×64
            (1, 5, 333) => ("UUUUU".to_string(), 256), // 4×64

            // 1-of-6 configurations
            (1, 6, 207) => ("CCCCCC".to_string(), 160), // 5×32
            (1, 6, 239) => ("CCCCCU".to_string(), 192), // 4×32+64
            (1, 6, 271) => ("CCCCUU".to_string(), 224), // 3×32+2×64
            (1, 6, 303) => ("CCCUUU".to_string(), 256), // 2×32+3×64
            (1, 6, 335) => ("CCUUUU".to_string(), 288), // 32+4×64
            (1, 6, 367) => ("CUUUUU".to_string(), 320), // 5×64
            (1, 6, 399) => ("UUUUUU".to_string(), 320), // 5×64

            // 1-of-7 configurations
            (1, 7, 241) => ("CCCCCCC".to_string(), 192), // 6×32
            (1, 7, 273) => ("CCCCCCU".to_string(), 224), // 5×32+64
            (1, 7, 305) => ("CCCCCUU".to_string(), 256), // 4×32+2×64
            (1, 7, 337) => ("CCCCUUU".to_string(), 288), // 3×32+3×64
            (1, 7, 369) => ("CCCUUUU".to_string(), 320), // 2×32+4×64
            (1, 7, 401) => ("CCUUUUU".to_string(), 352), // 32+5×64
            (1, 7, 433) => ("CUUUUUU".to_string(), 384), // 6×64
            (1, 7, 465) => ("UUUUUUU".to_string(), 384), // 6×64

            // Unknown or higher-order configurations
            _ => {
                // Fallback for configurations not in our exhaustive mapping.
                // This handles:
                // 1. Higher-order multisig (1-of-8 through 1-of-20)
                // 2. Non-standard script sizes (malformed or custom scripts)
                // 3. Future protocol variations
                //
                // Estimation strategy:
                // - Format: "m-of-n" (e.g., "1-of-8") with "?" suffix to indicate estimation
                // - Data capacity: Conservative estimate assuming all compressed keys
                // - For 1-of-n: (n-1) × 32 bytes (minimum possible capacity)
                // - For m>1: 0 bytes (assume true multisig, not data storage)
                //
                // Note: This is a conservative underestimate. Actual capacity could be higher
                // if uncompressed keys are used, but without the exact script size mapping
                // we cannot determine the precise key composition.
                let config = format!("{}-of-{}?", m, n); // "?" suffix indicates estimated
                let capacity = if m == 1 && n > 1 {
                    // Conservative estimate: assume all compressed keys
                    (n - 1) * 32
                } else {
                    // For m>1, assume it's true multisig (not data storage)
                    0
                };
                (config, capacity)
            }
        }
    }
}
