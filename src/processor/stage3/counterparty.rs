use crate::crypto::arc4;
use crate::database::traits::Stage2Operations;
use crate::database::Database;
use crate::types::content_detection::ContentType;
use crate::types::counterparty::{
    CounterpartyMessageType, CounterpartyP2msData, MultisigPattern, COUNTERPARTY_PREFIX,
};
use crate::types::stamps::validation as stamps_validation;
use crate::types::{ClassificationResult, EnrichedTransaction, ProtocolType, Stage3Config};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use super::filter_p2ms_for_classification;
use super::{ProtocolSpecificClassifier, SpendabilityAnalyser};
use crate::shared::PubkeyExtractor;

/// Counterparty classifier with comprehensive P2MS data extraction and ARC4 decryption
pub struct CounterpartyClassifier {
    pub(crate) tier2_config: crate::types::Tier2PatternsConfig,
}

impl CounterpartyClassifier {
    pub fn new(config: &Stage3Config) -> Self {
        Self {
            tier2_config: config.tier2_patterns_config.clone(),
        }
    }
}

impl ProtocolSpecificClassifier for CounterpartyClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        debug!("Counterparty classifier processing tx: {}", tx.txid);

        // Filter to P2MS outputs ONLY for protocol detection and classification
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);

        // Skip transactions with Bitcoin Stamps burn keys
        // These are Bitcoin Stamps using Counterparty as transport, not true Counterparty transactions
        let has_stamps_burn_keys = p2ms_outputs.iter().any(|output| {
            if let Some(info) = output.multisig_info() {
                info.pubkeys.len() >= 3 && stamps_validation::is_stamps_burn_key(&info.pubkeys[2])
            } else {
                false
            }
        });

        if has_stamps_burn_keys {
            debug!(
                "Skipping tx {} - has Bitcoin Stamps burn keys (will be handled by Stamps classifier)",
                tx.txid
            );
            return None;
        }

        if let Some(counterparty_data) = self.extract_p2ms_counterparty_data(tx, database) {
            let variant = counterparty_data.message_type.get_variant();

            // Detect content type from payload (used for both tx and output classifications)
            let content_type = ContentType::detect(&counterparty_data.payload)
                .map(|ct| ct.mime_type().to_string());

            // Track which vouts contain protocol data (already classified)
            let mut classified_vouts = HashSet::<u32>::new();
            let mut output_classifications = Vec::new();

            // Per-output classification(s) with per-output spendability analysis
            match &counterparty_data.multisig_pattern {
                crate::types::counterparty::MultisigPattern::MultiOutput {
                    output_indices, ..
                } => {
                    for vout in output_indices.iter() {
                        // Find the actual output for this vout
                        if let Some(output) = p2ms_outputs.iter().find(|o| o.vout == *vout) {
                            classified_vouts.insert(*vout);

                            // Analyse THIS output's spendability
                            let spendability_result =
                                SpendabilityAnalyser::analyse_counterparty_output(output);

                            let mut details = crate::types::OutputClassificationDetails::new(
                                Vec::new(),
                                true,
                                true,
                                format!(
                                    "Counterparty multi-output {:?}",
                                    counterparty_data.message_type
                                ),
                                spendability_result,
                            );

                            // Propagate transaction-level content type to THIS PROTOCOL's outputs only.
                            // IMPORTANT: This assumes all Counterparty outputs in a transaction share the same
                            // content type (multi-part payloads from one logical message). This is verified for
                            // Counterparty. Future protocols with mixed content per output or cross-protocol
                            // transactions (Counterparty+Stamps) would need per-output detection.
                            if let Some(ref ct) = content_type {
                                details = details.with_content_type(ct.clone());
                            }

                            output_classifications.push(
                                crate::types::OutputClassificationData::new(
                                    *vout,
                                    ProtocolType::Counterparty,
                                    Some(variant.clone()),
                                    details,
                                ),
                            );
                        } else {
                            tracing::warn!(
                                "Counterparty multi-output tx {} references vout {} but output not found",
                                tx.txid,
                                vout
                            );
                        }
                    }
                }
                _ => {
                    // Single-output case - find the specific output
                    if let Some(output) = p2ms_outputs
                        .iter()
                        .find(|o| o.vout == counterparty_data.vout_index)
                    {
                        classified_vouts.insert(counterparty_data.vout_index);

                        // Analyse THIS output's spendability
                        let spendability_result =
                            SpendabilityAnalyser::analyse_counterparty_output(output);

                        let mut details = crate::types::OutputClassificationDetails::new(
                            Vec::new(),
                            true,
                            true,
                            format!("Counterparty P2MS {:?}", counterparty_data.message_type),
                            spendability_result,
                        );

                        // Propagate transaction-level content type to THIS PROTOCOL's outputs only.
                        if let Some(ref ct) = content_type {
                            details = details.with_content_type(ct.clone());
                        }

                        output_classifications.push(crate::types::OutputClassificationData::new(
                            counterparty_data.vout_index,
                            ProtocolType::Counterparty,
                            Some(variant.clone()),
                            details,
                        ));
                    } else {
                        tracing::warn!(
                            "Counterparty single-output tx {} references vout {} but output not found",
                            tx.txid,
                            counterparty_data.vout_index
                        );
                    }
                }
            }

            // Classify remaining P2MS outputs in this transaction
            // These are "dust" outputs without protocol data, but should still be marked as Counterparty
            // NOTE: These outputs DO NOT get content_type because they carry NO protocol payload.
            // Only outputs with actual protocol data (protocol_signature_found=true) should have content types.
            for output in p2ms_outputs
                .iter()
                .filter(|o| !classified_vouts.contains(&o.vout))
            {
                let spendability_result = SpendabilityAnalyser::analyse_counterparty_output(output);

                let details = crate::types::OutputClassificationDetails::new(
                    Vec::new(),
                    true,
                    false, // No protocol signature - this is a dust/additional output
                    format!(
                        "Counterparty additional P2MS output (no protocol data) for {:?}",
                        counterparty_data.message_type
                    ),
                    spendability_result,
                );
                // No content_type propagation for dust outputs - they carry no data

                output_classifications.push(crate::types::OutputClassificationData::new(
                    output.vout,
                    ProtocolType::Counterparty,
                    Some(variant.clone()),
                    details,
                ));
            }

            let tx_classification = ClassificationResult {
                txid: tx.txid.clone(),
                protocol: ProtocolType::Counterparty,
                variant: Some(variant),
                classification_details: crate::types::ClassificationDetails {
                    burn_patterns_detected: Vec::new(), // Counterparty uses protocol identifiers, not burn patterns
                    height_check_passed: true,
                    protocol_signature_found: true,
                    classification_method: format!(
                        "Counterparty P2MS {:?} with message type {:?}",
                        counterparty_data.multisig_pattern, counterparty_data.message_type
                    ),
                    additional_metadata: Some(
                        serde_json::to_string(&counterparty_data).unwrap_or_default(),
                    ),
                    content_type,
                },
                classification_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            return Some((tx_classification, output_classifications));
        }

        // Counterparty does not use burn patterns for identification
        // It uses the "CNTRPRTY" identifier in P2MS data, which is handled above
        None
    }
}

impl CounterpartyClassifier {
    fn extract_p2ms_counterparty_data(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        debug!("extract_p2ms_counterparty_data for tx {}", tx.txid);

        // Filter to P2MS outputs ONLY
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
        let mut sorted_outputs: Vec<_> = p2ms_outputs.into_iter().cloned().collect();
        sorted_outputs.sort_by_key(|o| o.vout);

        if let Some(data) =
            self.extract_multi_output_counterparty_data(tx, &sorted_outputs, database)
        {
            return Some(data);
        }

        for output in &sorted_outputs {
            if let Some(info) = output.multisig_info() {
                if info.required_sigs == 1 && info.total_pubkeys == 3 && info.pubkeys.len() == 3 {
                    if let Some(data) = self.extract_1_of_3_multisig_data(tx, output, database) {
                        return Some(data);
                    }
                }
                if info.required_sigs == 1 && info.total_pubkeys == 2 && info.pubkeys.len() == 2 {
                    if let Some(data) = self.extract_1_of_2_multisig_data(tx, output, database) {
                        return Some(data);
                    }
                }
                if self.tier2_config.enable_2_of_2
                    && info.required_sigs == 2
                    && info.total_pubkeys == 2
                    && info.pubkeys.len() == 2
                {
                    if let Some(data) = self.extract_2_of_2_multisig_data(tx, output, database) {
                        return Some(data);
                    }
                }
            }
            if self.tier2_config.enable_2_of_3 {
                if let Some(info) = output.multisig_info() {
                    if info.required_sigs == 2 && info.total_pubkeys == 3 && info.pubkeys.len() == 3
                    {
                        if let Some(data) = self.extract_2_of_3_multisig_data(tx, output, database)
                        {
                            return Some(data);
                        }
                    }
                }
            }
            if self.tier2_config.enable_3_of_3 {
                if let Some(info) = output.multisig_info() {
                    if info.required_sigs == 3 && info.total_pubkeys == 3 && info.pubkeys.len() == 3
                    {
                        if let Some(data) = self.extract_3_of_3_multisig_data(tx, output, database)
                        {
                            return Some(data);
                        }
                    }
                }
            }
            if self.tier2_config.enable_3_of_2 {
                if let Some(info) = output.multisig_info() {
                    if info.required_sigs == 3 && info.total_pubkeys == 2 && info.pubkeys.len() == 2
                    {
                        if let Some(data) = self.extract_3_of_2_multisig_data(tx, output, database)
                        {
                            return Some(data);
                        }
                    }
                }
            }
        }
        None
    }

    // The following helpers mirror existing logic in stage3_processor.rs
    pub fn extract_multi_output_counterparty_data(
        &self,
        tx: &EnrichedTransaction,
        outputs: &[crate::types::TransactionOutput],
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        let mut combined_raw_data = Vec::new();
        let mut data_outputs = Vec::new();
        for output in outputs {
            if let Some(info) = output.multisig_info() {
                if info.required_sigs == 1 && info.total_pubkeys == 3 && info.pubkeys.len() == 3 {
                    if let Some(chunk_data) = self.extract_raw_data_chunk_1_of_3(output) {
                        combined_raw_data.extend_from_slice(&chunk_data);
                        data_outputs.push(output.vout);
                    }
                } else if self.tier2_config.enable_multi_output_tier2
                    && self.tier2_config.enable_2_of_3
                    && info.required_sigs == 2
                    && info.total_pubkeys == 3
                    && info.pubkeys.len() == 3
                {
                    if let Some(chunk_data) = self.extract_raw_data_chunk_2_of_3(output) {
                        combined_raw_data.extend_from_slice(&chunk_data);
                        data_outputs.push(output.vout);
                    }
                } else if self.tier2_config.enable_multi_output_tier2
                    && self.tier2_config.enable_2_of_2
                    && info.required_sigs == 2
                    && info.total_pubkeys == 2
                    && info.pubkeys.len() == 2
                {
                    if let Some(chunk_data) = self.extract_raw_data_chunk_2_of_2(output) {
                        combined_raw_data.extend_from_slice(&chunk_data);
                        data_outputs.push(output.vout);
                    }
                }
            }
        }
        if data_outputs.len() < 2 {
            return None;
        }
        if let Some(decrypted_data) =
            self.decrypt_and_validate_counterparty(tx, &combined_raw_data, database)
        {
            if let Some((message_type, payload)) = self.parse_counterparty_message(&decrypted_data)
            {
                let total_capacity = combined_raw_data.len();
                return Some(CounterpartyP2msData {
                    raw_data: combined_raw_data,
                    decrypted_data,
                    vout_index: data_outputs[0],
                    message_type,
                    payload,
                    multisig_pattern: MultisigPattern::MultiOutput {
                        primary_pattern: Box::new(MultisigPattern::OneOfThree {
                            data_capacity: 64,
                        }),
                        output_count: data_outputs.len() as u32,
                        output_indices: data_outputs,
                        total_capacity,
                    },
                });
            }
        }
        None
    }

    pub fn extract_raw_data_chunk_1_of_3(
        &self,
        output: &crate::types::TransactionOutput,
    ) -> Option<Vec<u8>> {
        let multisig_info = output.multisig_info()?;
        if multisig_info.pubkeys.len() != 3 {
            return None;
        }
        // Extract 31 bytes from each of the first two compressed pubkeys
        // Counterparty encoding uses bytes [1..32] (31 bytes) from each compressed pubkey
        let chunk1 = PubkeyExtractor::extract_p2ms_chunk(&multisig_info.pubkeys[0])?;
        let chunk2 = PubkeyExtractor::extract_p2ms_chunk(&multisig_info.pubkeys[1])?;

        let mut raw_data = Vec::with_capacity(62);
        raw_data.extend_from_slice(&chunk1); // 31 bytes
        raw_data.extend_from_slice(&chunk2); // 31 bytes
        Some(raw_data)
    }

    pub fn extract_raw_data_chunk_2_of_3(
        &self,
        output: &crate::types::TransactionOutput,
    ) -> Option<Vec<u8>> {
        let multisig_info = output.multisig_info()?;
        if multisig_info.pubkeys.len() != 3 {
            return None;
        }
        // Extract 31 bytes from each of the first two compressed pubkeys
        // For 33-byte compressed keys: [1..len-1] == [1..32] (31 bytes)
        let chunk1 = PubkeyExtractor::extract_p2ms_chunk(&multisig_info.pubkeys[0])?;
        let chunk2 = PubkeyExtractor::extract_p2ms_chunk(&multisig_info.pubkeys[1])?;

        let mut raw_data = Vec::with_capacity(62);
        raw_data.extend_from_slice(&chunk1); // 31 bytes
        raw_data.extend_from_slice(&chunk2); // 31 bytes
        Some(raw_data)
    }

    #[allow(dead_code)] // Used in tests
    pub fn extract_raw_data_chunk_1_of_2(
        &self,
        output: &crate::types::TransactionOutput,
    ) -> Option<Vec<u8>> {
        let multisig_info = output.multisig_info()?;
        if multisig_info.pubkeys.len() != 2 {
            return None;
        }
        // Extract data with length prefix from second pubkey
        PubkeyExtractor::extract_with_length_prefix(&multisig_info.pubkeys[1])
    }

    pub fn extract_raw_data_chunk_2_of_2(
        &self,
        output: &crate::types::TransactionOutput,
    ) -> Option<Vec<u8>> {
        let multisig_info = output.multisig_info()?;
        if multisig_info.pubkeys.len() != 2 {
            return None;
        }
        // Extract data with length prefix from second pubkey
        PubkeyExtractor::extract_with_length_prefix(&multisig_info.pubkeys[1])
    }

    pub fn extract_1_of_3_multisig_data(
        &self,
        tx: &EnrichedTransaction,
        output: &crate::types::TransactionOutput,
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        let multisig_info = output.multisig_info()?;
        let pubkeys: Vec<Vec<u8>> = multisig_info
            .pubkeys
            .iter()
            .filter_map(|hex| hex::decode(hex).ok())
            .collect();
        // Only check that we have 3 pubkeys and the FIRST TWO are compressed (33 bytes)
        // The third pubkey can be any format (compressed or uncompressed)
        if pubkeys.len() != 3 || pubkeys[0].len() != 33 || pubkeys[1].len() != 33 {
            return None;
        }
        let mut raw_data = Vec::with_capacity(62);
        raw_data.extend_from_slice(&pubkeys[0][1..pubkeys[0].len() - 1]);
        raw_data.extend_from_slice(&pubkeys[1][1..pubkeys[1].len() - 1]);
        if let Some(decrypted_data) =
            self.decrypt_and_validate_counterparty(tx, &raw_data, database)
        {
            if let Some((message_type, payload)) = self.parse_counterparty_message(&decrypted_data)
            {
                return Some(CounterpartyP2msData {
                    raw_data,
                    decrypted_data,
                    vout_index: output.vout,
                    message_type,
                    payload,
                    multisig_pattern: MultisigPattern::OneOfThree { data_capacity: 64 },
                });
            }
        }
        None
    }

    pub fn extract_1_of_2_multisig_data(
        &self,
        tx: &EnrichedTransaction,
        output: &crate::types::TransactionOutput,
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        let multisig_info = output.multisig_info()?;
        let pubkeys: Vec<Vec<u8>> = multisig_info
            .pubkeys
            .iter()
            .filter_map(|hex| hex::decode(hex).ok())
            .collect();
        if pubkeys.len() != 2 {
            return None;
        }
        let data_pubkey = &pubkeys[1];
        if data_pubkey.len() < 2 {
            return None;
        }
        let data_length = data_pubkey[0] as usize;
        if data_length + 1 > data_pubkey.len() {
            return None;
        }
        let raw_data = data_pubkey[1..=data_length].to_vec();
        if let Some(decrypted_data) =
            self.decrypt_and_validate_counterparty(tx, &raw_data, database)
        {
            if let Some((message_type, payload)) = self.parse_counterparty_message(&decrypted_data)
            {
                return Some(CounterpartyP2msData {
                    raw_data: raw_data.clone(),
                    decrypted_data,
                    vout_index: output.vout,
                    message_type,
                    payload,
                    multisig_pattern: MultisigPattern::OneOfTwo {
                        data_capacity: raw_data.len(),
                    },
                });
            }
        }
        None
    }

    pub fn extract_2_of_2_multisig_data(
        &self,
        tx: &EnrichedTransaction,
        output: &crate::types::TransactionOutput,
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        let raw_data = self.extract_raw_data_chunk_2_of_2(output)?;
        if let Some(decrypted_data) =
            self.decrypt_and_validate_counterparty(tx, &raw_data, database)
        {
            if let Some((message_type, payload)) = self.parse_counterparty_message(&decrypted_data)
            {
                return Some(CounterpartyP2msData {
                    raw_data: raw_data.clone(),
                    decrypted_data,
                    vout_index: output.vout,
                    message_type,
                    payload,
                    multisig_pattern: MultisigPattern::TwoOfTwo {
                        data_capacity: raw_data.len(),
                    },
                });
            }
        }
        None
    }

    pub fn extract_2_of_3_multisig_data(
        &self,
        tx: &EnrichedTransaction,
        output: &crate::types::TransactionOutput,
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        let raw_data = self.extract_raw_data_chunk_2_of_3(output)?;
        if let Some(decrypted_data) =
            self.decrypt_and_validate_counterparty(tx, &raw_data, database)
        {
            if let Some((message_type, payload)) = self.parse_counterparty_message(&decrypted_data)
            {
                return Some(CounterpartyP2msData {
                    raw_data: raw_data.clone(),
                    decrypted_data,
                    vout_index: output.vout,
                    message_type,
                    payload,
                    multisig_pattern: MultisigPattern::TwoOfThree {
                        data_capacity: raw_data.len(),
                    },
                });
            }
        }
        None
    }

    pub fn extract_3_of_3_multisig_data(
        &self,
        tx: &EnrichedTransaction,
        output: &crate::types::TransactionOutput,
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        let multisig_info = output.multisig_info()?;
        let pubkeys: Vec<Vec<u8>> = multisig_info
            .pubkeys
            .iter()
            .filter_map(|hex| hex::decode(hex).ok())
            .collect();
        if pubkeys.len() != 3 || !pubkeys.iter().all(|pk| pk.len() == 33) {
            return None;
        }
        let data_pubkey_1 = &pubkeys[0];
        let data_pubkey_2 = &pubkeys[1];
        let mut raw_data = Vec::with_capacity(62);
        raw_data.extend_from_slice(&data_pubkey_1[1..data_pubkey_1.len() - 1]);
        raw_data.extend_from_slice(&data_pubkey_2[1..data_pubkey_2.len() - 1]);
        if let Some(decrypted_data) =
            self.decrypt_and_validate_counterparty(tx, &raw_data, database)
        {
            if let Some((message_type, payload)) = self.parse_counterparty_message(&decrypted_data)
            {
                return Some(CounterpartyP2msData {
                    raw_data: raw_data.clone(),
                    decrypted_data,
                    vout_index: output.vout,
                    message_type,
                    payload,
                    multisig_pattern: MultisigPattern::ThreeOfThree {
                        data_capacity: raw_data.len(),
                    },
                });
            }
        }
        None
    }

    pub fn extract_3_of_2_multisig_data(
        &self,
        tx: &EnrichedTransaction,
        output: &crate::types::TransactionOutput,
        database: &Database,
    ) -> Option<CounterpartyP2msData> {
        self.extract_1_of_2_multisig_data(tx, output, database)
    }

    pub fn decrypt_and_validate_counterparty(
        &self,
        tx: &EnrichedTransaction,
        encrypted_data: &[u8],
        database: &Database,
    ) -> Option<Vec<u8>> {
        debug!(
            "🔍 Counterparty decrypt: txid={}, data_len={}",
            tx.txid,
            encrypted_data.len()
        );

        if encrypted_data.len() < COUNTERPARTY_PREFIX.len() {
            debug!("❌ Data too short for Counterparty prefix");
            return None;
        }
        if encrypted_data.starts_with(COUNTERPARTY_PREFIX) {
            debug!("✅ Found unencrypted Counterparty prefix");
            return Some(encrypted_data.to_vec());
        }

        let first_input_txid = database.get_first_input_txid(&tx.txid).ok()??;
        debug!("🔑 First input txid: {}", first_input_txid);

        let decryption_key = arc4::prepare_key_from_txid(&first_input_txid)?;
        debug!("🔑 ARC4 key length: {} bytes", decryption_key.len());

        let decrypted_data = arc4::decrypt(encrypted_data, &decryption_key)?;
        debug!(
            "🔓 ARC4 decryption succeeded, decrypted_len={}",
            decrypted_data.len()
        );

        // Show first few bytes for debugging
        let preview = if decrypted_data.len() >= 10 {
            format!("{:02x?}...", &decrypted_data[..10])
        } else {
            format!("{:02x?}", decrypted_data)
        };
        debug!("🔍 Decrypted data preview: {}", preview);

        let has_prefix_at_1 = decrypted_data.len() > COUNTERPARTY_PREFIX.len()
            && &decrypted_data[1..=COUNTERPARTY_PREFIX.len()] == COUNTERPARTY_PREFIX;
        let has_prefix_at_0 = decrypted_data.starts_with(COUNTERPARTY_PREFIX);

        debug!(
            "🔍 Prefix check: at_offset_1={}, at_offset_0={}",
            has_prefix_at_1, has_prefix_at_0
        );
        debug!("🔍 Expected prefix: {:02x?}", COUNTERPARTY_PREFIX);

        if has_prefix_at_1 || has_prefix_at_0 {
            debug!("✅ Counterparty signature validated!");
            Some(decrypted_data)
        } else {
            debug!("❌ Counterparty signature validation failed");
            None
        }
    }

    pub fn parse_counterparty_message(
        &self,
        decrypted_data: &[u8],
    ) -> Option<(CounterpartyMessageType, Vec<u8>)> {
        let message_data = if decrypted_data.len() > COUNTERPARTY_PREFIX.len()
            && &decrypted_data[1..=COUNTERPARTY_PREFIX.len()] == COUNTERPARTY_PREFIX
        {
            &decrypted_data[COUNTERPARTY_PREFIX.len() + 1..]
        } else if decrypted_data.starts_with(COUNTERPARTY_PREFIX) {
            &decrypted_data[COUNTERPARTY_PREFIX.len()..]
        } else {
            return None;
        };

        // Try 4-byte message type first (modern format)
        if message_data.len() >= 4 {
            let message_type_u32 = u32::from_be_bytes([
                message_data[0],
                message_data[1],
                message_data[2],
                message_data[3],
            ]);
            if let Some(mt) = CounterpartyMessageType::from_u32(message_type_u32) {
                return Some((mt, message_data[4..].to_vec()));
            }
        }

        // Fallback to single-byte message type (legacy format)
        if !message_data.is_empty() {
            let t = message_data[0];
            if let Some(mt) = CounterpartyMessageType::from_u32(t as u32) {
                return Some((mt, message_data[1..].to_vec()));
            }
        }

        None
    }

    // ===== TIER 1: CORE DATA EXTRACTION (DATABASE-FREE) =====

    /// Extract raw data from multiple P2MS outputs without database dependency
    ///
    /// This is the core multi-output extraction logic extracted from the original
    /// extract_multi_output_counterparty_data method. It concatenates raw data
    /// from multiple outputs based on pattern configuration.
    pub fn extract_multi_output_raw_data(
        &self,
        outputs: &[crate::types::TransactionOutput],
        tier2_config: &crate::types::Tier2PatternsConfig,
    ) -> Option<Vec<u8>> {
        let mut combined_raw_data = Vec::new();
        let mut data_outputs = Vec::new();

        for output in outputs {
            // Pattern matching logic from original extract_multi_output_counterparty_data
            if let Some(info) = output.multisig_info() {
                if info.required_sigs == 1 && info.total_pubkeys == 3 && info.pubkeys.len() == 3 {
                    if let Some(chunk_data) = self.extract_raw_data_chunk_1_of_3(output) {
                        combined_raw_data.extend_from_slice(&chunk_data);
                        data_outputs.push(output.vout);
                    }
                } else if tier2_config.enable_multi_output_tier2
                    && tier2_config.enable_2_of_3
                    && info.required_sigs == 2
                    && info.total_pubkeys == 3
                    && info.pubkeys.len() == 3
                {
                    if let Some(chunk_data) = self.extract_raw_data_chunk_2_of_3(output) {
                        combined_raw_data.extend_from_slice(&chunk_data);
                        data_outputs.push(output.vout);
                    }
                } else if tier2_config.enable_multi_output_tier2
                    && tier2_config.enable_2_of_2
                    && info.required_sigs == 2
                    && info.total_pubkeys == 2
                    && info.pubkeys.len() == 2
                {
                    if let Some(chunk_data) = self.extract_raw_data_chunk_2_of_2(output) {
                        combined_raw_data.extend_from_slice(&chunk_data);
                        data_outputs.push(output.vout);
                    }
                }
            }
        }

        // Must have at least 2 outputs for multi-output transaction
        if data_outputs.len() < 2 {
            return None;
        }

        Some(combined_raw_data)
    }

    /// Extract raw data from a single P2MS output using pattern-specific methods
    ///
    /// This covers all 6 multisig patterns and serves as fallback when
    /// multi-output extraction fails.
    pub fn extract_single_output_raw_data(
        &self,
        output: &crate::types::TransactionOutput,
        tier2_config: &crate::types::Tier2PatternsConfig,
    ) -> Option<Vec<u8>> {
        let info = output.multisig_info()?;
        match (info.required_sigs, info.total_pubkeys) {
            (1, 3) => self.extract_raw_data_chunk_1_of_3(output),
            (1, 2) => self.extract_raw_data_chunk_1_of_2(output),
            (2, 2) if tier2_config.enable_2_of_2 => self.extract_raw_data_chunk_2_of_2(output),
            (2, 3) if tier2_config.enable_2_of_3 => self.extract_raw_data_chunk_2_of_3(output),
            _ => {
                debug!(
                    "Unsupported or disabled multisig pattern: {}-of-{}",
                    info.required_sigs, info.total_pubkeys
                );
                None
            }
        }
    }

    // ===== TIER 2: DECRYPTION LAYER (MINIMAL DEPENDENCIES) =====

    /// Decrypt Counterparty data using first input TXID without database dependency
    ///
    /// This extracts the core decryption logic from decrypt_and_validate_counterparty
    /// but only requires the first input TXID, not database access.
    pub fn decrypt_counterparty_data_with_txid(
        &self,
        encrypted_data: &[u8],
        first_input_txid: &str,
    ) -> Option<Vec<u8>> {
        debug!(
            "🔍 Counterparty decrypt with TXID: first_input={}, data_len={}",
            first_input_txid,
            encrypted_data.len()
        );

        if encrypted_data.len() < COUNTERPARTY_PREFIX.len() {
            debug!("❌ Data too short for Counterparty prefix");
            return None;
        }

        // Check for unencrypted CNTRPRTY prefix first
        if encrypted_data.starts_with(COUNTERPARTY_PREFIX) {
            debug!("✅ Found unencrypted Counterparty prefix");
            return Some(encrypted_data.to_vec());
        }

        // Prepare ARC4 decryption key from first input TXID
        let decryption_key = arc4::prepare_key_from_txid(first_input_txid)?;
        debug!("🔑 ARC4 key length: {} bytes", decryption_key.len());

        // Per Electrum-Counterparty: Decrypt each 62-byte chunk separately
        // Each chunk has: [1-byte length] + [data]
        // The first chunk contains the CNTRPRTY prefix
        const CHUNK_SIZE: usize = 62;
        let mut decoded_message = Vec::new();

        for (chunk_idx, chunk) in encrypted_data.chunks(CHUNK_SIZE).enumerate() {
            // Decrypt this chunk with ARC4 (re-initialise cipher for each chunk)
            let decrypted_chunk = arc4::decrypt(chunk, &decryption_key)?;

            // First byte is length indicator
            if decrypted_chunk.is_empty() {
                continue;
            }

            let length = decrypted_chunk[0] as usize;
            if length == 0 {
                break; // End of message
            }

            // Extract data based on length
            let data_end = (1 + length).min(decrypted_chunk.len());
            let chunk_data = &decrypted_chunk[1..data_end];

            debug!(
                "Chunk {}: length={}, extracted {} bytes",
                chunk_idx,
                length,
                chunk_data.len()
            );

            // For first chunk, keep CNTRPRTY prefix; for subsequent chunks, remove it if present
            if chunk_idx == 0 {
                decoded_message.extend_from_slice(chunk_data);
            } else if chunk_data.starts_with(COUNTERPARTY_PREFIX) {
                // Skip CNTRPRTY prefix in continuation chunks
                decoded_message.extend_from_slice(&chunk_data[COUNTERPARTY_PREFIX.len()..]);
            } else {
                decoded_message.extend_from_slice(chunk_data);
            }
        }

        debug!(
            "🔓 ARC4 decryption succeeded, decoded_message_len={}",
            decoded_message.len()
        );

        // Validate that decoded message contains Counterparty signature
        if crate::decoder::protocol_detection::has_counterparty_signature(&decoded_message)
            .is_none()
        {
            debug!("❌ Decoded message does not contain CNTRPRTY prefix");
            return None;
        }

        debug!("✅ Valid Counterparty data decrypted");
        Some(decoded_message)
    }
}
