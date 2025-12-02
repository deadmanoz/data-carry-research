//! Bitcoin Stamps burn pattern types
//!
//! These correspond to the specific burn keys used in P2MS outputs.

use serde::{Deserialize, Serialize};

/// Bitcoin Stamps burn pattern types
/// These correspond to the specific burn keys used in P2MS outputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampsBurnPattern {
    /// 022222... pattern (most common)
    Stamps22,
    /// 033333... pattern
    Stamps33,
    /// 020202... alternating pattern
    Stamps0202,
    /// 030303... alternating pattern (two variants)
    Stamps0303,
}
