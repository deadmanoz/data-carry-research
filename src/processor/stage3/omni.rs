use crate::database::traits::Stage2Operations;
use crate::database::Database;
use crate::types::content_detection::ContentType;
use crate::types::omni::{OmniMessageType, OmniP2msData, OmniPacket};
use crate::types::{ClassificationResult, EnrichedTransaction, ProtocolType};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use super::filter_p2ms_for_classification;
use super::{ProtocolSpecificClassifier, SpendabilityAnalyser};
use crate::shared::PubkeyExtractor;

/// Omni Layer classifier focused on Class B (P2MS) transactions
pub struct OmniClassifier;

impl OmniClassifier {
    #[allow(dead_code)]
    pub async fn classify_with_rpc(
        &self,
        _tx: &EnrichedTransaction,
        _database: &Database,
        _rpc_client: &crate::rpc::BitcoinRpcClient,
    ) -> Option<ClassificationResult> {
        None
    }

    fn has_exodus_address_output(&self, tx: &EnrichedTransaction, database: &Database) -> bool {
        use crate::types::omni::EXODUS_ADDRESS;
        database
            .has_output_to_address(&tx.txid, EXODUS_ADDRESS)
            .unwrap_or_default()
    }

    fn extract_and_deobfuscate_p2ms_data(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<OmniP2msData> {
        debug!("extract_and_deobfuscate_p2ms_data for tx {}", tx.txid);

        // Filter to P2MS outputs ONLY (collect owned values for helper functions)
        let p2ms_outputs: Vec<_> = filter_p2ms_for_classification(&tx.outputs)
            .into_iter()
            .cloned()
            .collect();

        debug!("Input p2ms_outputs count: {}", p2ms_outputs.len());
        for (i, output) in p2ms_outputs.iter().enumerate() {
            let pubkeys = output
                .multisig_info()
                .map(|info| info.pubkeys.clone())
                .unwrap_or_else(Vec::new);
            debug!(
                "P2MS output {}: vout={}, pubkeys={:?}",
                i, output.vout, pubkeys
            );
        }

        let sender_address = match database.get_sender_address_from_largest_input(&tx.txid) {
            Ok(Some(addr)) => addr,
            _ => return None,
        };
        debug!("✅ Sender address found: {}", sender_address);

        let mut raw_packets = self.extract_p2ms_packets_no_sequence(&p2ms_outputs)?;
        debug!(
            "Extracted {} raw packets (sequence unknown)",
            raw_packets.len()
        );

        self.deobfuscate_packets_with_sequence_detection(&mut raw_packets, &sender_address)?;

        raw_packets.sort_by_key(|p| p.sequence_number);

        let mut combined_data = Vec::new();
        for packet in &raw_packets {
            if let Some(deobfuscated) = &packet.deobfuscated_data {
                combined_data.extend_from_slice(&deobfuscated[1..]);
            }
        }

        let (message_type, payload) = self.parse_omni_message(&combined_data)?;
        debug!("Parsed Omni message: {:?}", message_type);

        Some(OmniP2msData {
            raw_packets,
            deobfuscated_data: combined_data,
            sender_address: sender_address.to_string(),
            message_type,
            payload,
            total_packets: p2ms_outputs.len() as u8,
        })
    }

    pub fn parse_omni_message(&self, data: &[u8]) -> Option<(OmniMessageType, Vec<u8>)> {
        if data.len() < 4 {
            return None;
        }
        let version = u16::from_be_bytes([data[0], data[1]]);
        let message_type_u16 = u16::from_be_bytes([data[2], data[3]]);
        debug!(
            "Parsing Omni header: version {} type {}",
            version, message_type_u16
        );
        let message_type = OmniMessageType::from_u32(message_type_u16 as u32)?;
        let payload = data[4..].to_vec();
        Some((message_type, payload))
    }

    pub fn extract_p2ms_packets_no_sequence(
        &self,
        p2ms_outputs: &[crate::types::TransactionOutput],
    ) -> Option<Vec<OmniPacket>> {
        debug!(
            "extract_p2ms_packets_no_sequence: processing {} outputs",
            p2ms_outputs.len()
        );
        let mut packets = Vec::new();
        for output in p2ms_outputs {
            if let Some(info) = output.multisig_info() {
                debug!(
                    "Processing output vout={}, pubkeys_len={}",
                    output.vout,
                    info.pubkeys.len()
                );
                if info.pubkeys.len() > 1 {
                    if let Some(packet) =
                        self.extract_packet_from_pubkey_raw(&info.pubkeys[1], output.vout, 2)
                    {
                        packets.push(packet);
                    }
                }
                if info.pubkeys.len() > 2 {
                    if let Some(packet) =
                        self.extract_packet_from_pubkey_raw(&info.pubkeys[2], output.vout, 3)
                    {
                        packets.push(packet);
                    }
                }
            }
        }
        if packets.is_empty() {
            None
        } else {
            Some(packets)
        }
    }

    pub fn extract_packet_from_pubkey_raw(
        &self,
        pubkey_hex: &str,
        vout: u32,
        position: u8,
    ) -> Option<OmniPacket> {
        // Extract 31 bytes of Omni packet data from compressed pubkey (bytes 1-31)
        let data_chunk = PubkeyExtractor::extract_p2ms_chunk(pubkey_hex)?;

        let mut obfuscated_data = [0u8; 31];
        obfuscated_data.copy_from_slice(&data_chunk);
        Some(OmniPacket {
            vout,
            position,
            sequence_number: 0,
            obfuscated_data,
            deobfuscated_data: None,
        })
    }

    pub fn deobfuscate_packets_with_sequence_detection(
        &self,
        packets: &mut [OmniPacket],
        sender_address: &str,
    ) -> Option<()> {
        let mut success_count = 0usize;
        for packet in packets.iter_mut() {
            let mut found = false;
            for seq in 1..=255u8 {
                if let Some(deobfuscated) = self.deobfuscate_packet_with_sequence(
                    sender_address,
                    seq,
                    &packet.obfuscated_data,
                ) {
                    if deobfuscated[0] == seq {
                        packet.sequence_number = seq;
                        packet.deobfuscated_data = Some(deobfuscated);
                        found = true;
                        success_count += 1;
                        break;
                    }
                }
            }
            if !found { /* allow partial success */ }
        }
        if success_count == 0 {
            None
        } else {
            Some(())
        }
    }

    pub fn deobfuscate_packet_with_sequence(
        &self,
        sender_address: &str,
        sequence_number: u8,
        obfuscated_packet: &[u8; 31],
    ) -> Option<[u8; 31]> {
        let mut hash_input = sender_address.as_bytes().to_vec();
        let mut last_digest: Option<[u8; 32]> = None;
        for _ in 0..sequence_number {
            let mut hasher = Sha256::new();
            hasher.update(&hash_input);
            let digest = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&digest);
            last_digest = Some(arr);
            let hex_string = hex::encode_upper(digest);
            hash_input = hex_string.as_bytes().to_vec();
        }
        let final_hash = last_digest?;
        let deobfuscation_key = &final_hash[..31];
        let mut deobfuscated = [0u8; 31];
        for i in 0..31 {
            deobfuscated[i] = obfuscated_packet[i] ^ deobfuscation_key[i];
        }
        Some(deobfuscated)
    }
}

impl ProtocolSpecificClassifier for OmniClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        debug!("Omni classifier processing tx: {}", tx.txid);
        if !self.has_exodus_address_output(tx, database) {
            return None;
        }
        match self.extract_and_deobfuscate_p2ms_data(tx, database) {
            Some(omni_data) => {
                // Successful deobfuscation - classify with message type variant

                // Detect content type from payload (used for both tx and output classifications)
                let content_type =
                    ContentType::detect(&omni_data.payload).map(|ct| ct.mime_type().to_string());

                // Build per-output classifications: mark outputs that contributed packets
                // Each output gets its own spendability analysis for accurate key counts
                use std::collections::HashSet;
                let mut seen: HashSet<u32> = HashSet::new();
                let mut output_classifications = Vec::new();

                // Filter to P2MS outputs for classification
                let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);

                for packet in &omni_data.raw_packets {
                    if seen.insert(packet.vout) {
                        // Find the actual output for this vout
                        if let Some(output) = p2ms_outputs.iter().find(|o| o.vout == packet.vout) {
                            // Analyse THIS output's spendability
                            let spendability_result =
                                SpendabilityAnalyser::analyse_omni_output(output);

                            let mut details = crate::types::OutputClassificationDetails::new(
                                Vec::new(),
                                true,
                                true,
                                format!(
                                    "Omni Class B packet at vout {} (seq {})",
                                    packet.vout, packet.sequence_number
                                ),
                                spendability_result,
                            );

                            // Propagate transaction-level content type to THIS PROTOCOL's outputs only.
                            // IMPORTANT: This assumes all Omni outputs in a transaction share the same content type.
                            // Future protocols with mixed content per output would need per-output detection.
                            if let Some(ref ct) = content_type {
                                details = details.with_content_type(ct.clone());
                            }

                            output_classifications.push(
                                crate::types::OutputClassificationData::new(
                                    packet.vout,
                                    ProtocolType::OmniLayer,
                                    Some(omni_data.message_type.get_variant()),
                                    details,
                                ),
                            );
                        } else {
                            tracing::warn!(
                                "Omni Layer packet for tx {} references vout {} but output not found",
                                tx.txid,
                                packet.vout
                            );
                        }
                    }
                }
                let variant = omni_data.message_type.get_variant();

                let tx_classification = ClassificationResult {
                    txid: tx.txid.clone(),
                    protocol: ProtocolType::OmniLayer,
                    variant: Some(variant),
                    classification_details: crate::types::ClassificationDetails {
                        burn_patterns_detected: Vec::new(),
                        height_check_passed: true,
                        protocol_signature_found: true,
                        classification_method: format!(
                            "Exodus address + P2MS deobfuscation: {:?}",
                            omni_data.message_type
                        ),
                        additional_metadata: Some(
                            serde_json::to_string(&omni_data).unwrap_or_default(),
                        ),
                        content_type,
                    },
                    classification_timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                Some((tx_classification, output_classifications))
            }
            None => {
                // Deobfuscation failed, but Exodus address is present
                // Classify as OmniLayer with FailedDeobfuscation variant
                debug!(
                    "Omni deobfuscation failed for tx {} but Exodus address present",
                    tx.txid
                );

                // Build output classifications for P2MS outputs as Omni (even though we couldn't decode)
                let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
                let mut output_classifications = Vec::new();

                for output in p2ms_outputs {
                    let spendability_result = SpendabilityAnalyser::analyse_omni_output(output);
                    let details = crate::types::OutputClassificationDetails::new(
                        Vec::new(),
                        true,
                        true,
                        format!("Omni Layer (Exodus address present but deobfuscation failed at vout {})", output.vout),
                        spendability_result,
                    );

                    output_classifications.push(crate::types::OutputClassificationData::new(
                        output.vout,
                        ProtocolType::OmniLayer,
                        Some(crate::types::ProtocolVariant::OmniFailedDeobfuscation),
                        details,
                    ));
                }

                let tx_classification = ClassificationResult {
                    txid: tx.txid.clone(),
                    protocol: ProtocolType::OmniLayer,
                    variant: Some(crate::types::ProtocolVariant::OmniFailedDeobfuscation),
                    classification_details: crate::types::ClassificationDetails {
                        burn_patterns_detected: Vec::new(),
                        height_check_passed: true,
                        protocol_signature_found: true, // Exodus address IS the signature
                        classification_method:
                            "Exodus address present but P2MS deobfuscation failed".to_string(),
                        additional_metadata: None,
                        content_type: None,
                    },
                    classification_timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                Some((tx_classification, output_classifications))
            }
        }
    }
}
