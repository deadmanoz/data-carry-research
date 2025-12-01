//! Multisig configuration analysis types

use serde::{Deserialize, Serialize};

/// Individual multisig configuration entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigConfiguration {
    pub m: u32,                   // Required signatures
    pub n: u32,                   // Total keys
    pub key_config: String,       // e.g., "CCC", "CCU", "CUU", "UUU"
    pub script_size: u32,         // Total script size in bytes
    pub data_capacity_bytes: u32, // Actual data-carrying capacity
    pub efficiency_pct: f64,      // data_capacity / script_size * 100
    pub output_count: u64,        // Number of outputs with this configuration
    pub total_script_bytes: u64,  // Total blockchain footprint
    pub protocol: Option<String>, // Protocol classification
    pub variant: Option<String>,  // Protocol variant
}

/// Multisig configuration analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigConfigReport {
    pub configurations: Vec<MultisigConfiguration>,
    pub total_outputs: u64,
    pub total_script_bytes: u64,
    pub total_data_capacity: u64,
    pub overall_efficiency: f64,
    pub type_summary: std::collections::BTreeMap<String, u64>, // m-of-n -> count
}
