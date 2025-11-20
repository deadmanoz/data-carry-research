//! Stage 3 Likely Legitimate Multisig Classification Tests
//!
//! Validates that legitimate multisig transactions (all valid EC points) are:
//! 1. Classified at transaction level
//! 2. Have per-output classifications created
//! 3. Include complete spendability analysis

use data_carry_research::database::traits::{Stage1Operations, Stage2Operations};
use data_carry_research::types::{
    EnrichedTransaction, ProtocolType, ProtocolVariant, TransactionOutput,
};
use serial_test::serial;

use crate::common::protocol_test_base::{
    run_stage3_processor, setup_protocol_test, verify_classification, verify_output_spendability,
};

#[tokio::test]
#[serial]
async fn test_legitimate_p2ms_creates_output_classifications() -> anyhow::Result<()> {
    let (mut test_db, config) = setup_protocol_test("legitimate_multisig_output_classifications")?;

    // Valid COMPRESSED EC point pubkeys (2-of-2 multisig) - MUST use different keys for each output to avoid LikelyDataStorage detection
    // Using compressed keys (33 bytes, 02/03 prefix) which are standard in modern Bitcoin
    let valid_pk1 = "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc"; // Compressed version
    let valid_pk2 = "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"; // Compressed version
    let valid_pk3 = "02e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606"; // Compressed version
    let valid_pk4 = "02678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"; // Compressed version (derived from Satoshi's key)

    let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // Create TransactionOutput structs with valid EC points
    let outputs = vec![
        TransactionOutput {
            txid: txid.to_string(),
            vout: 0,
            amount: 1000000,
            height: 400000,
            script_hex: "522103...ae".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 135,
            metadata: serde_json::json!({
                "pubkeys": [valid_pk1, valid_pk2],
                "required_sigs": 2,
                "total_pubkeys": 2
            }),
            address: None,
        },
        TransactionOutput {
            txid: txid.to_string(),
            vout: 1,
            amount: 500000,
            height: 400000,
            script_hex: "522103...ae".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 135,
            metadata: serde_json::json!({
                "pubkeys": [valid_pk3, valid_pk4],
                "required_sigs": 2,
                "total_pubkeys": 2
            }),
            address: None,
        },
    ];

    // CRITICAL: Must insert outputs FIRST using Stage 1 operations to mark them as unspent (is_spent = 0).
    // If we call insert_enriched_transactions_batch without pre-seeding, it marks multisig outputs
    // as spent (is_spent = 1) because they're not in the UTXO set from Stage 1.
    // Then get_p2ms_outputs_for_transaction filters by "WHERE is_spent = 0" and finds nothing!
    test_db
        .database_mut()
        .insert_transaction_output_batch(&outputs)?;

    // Schema V2: transaction_inputs has FK constraint to transaction_outputs(prev_txid, prev_vout)
    // For this test, we don't need inputs since we're only testing output classification
    let inputs = Vec::new();

    // Create enriched transaction
    let enriched_tx = EnrichedTransaction {
        txid: txid.to_string(),
        height: 400000,
        total_input_value: 2000000,
        total_output_value: 1500000,
        transaction_fee: 500000,
        fee_per_byte: 100.0,
        transaction_size_bytes: 500,
        fee_per_kb: 1000.0,
        total_p2ms_amount: 1500000,
        data_storage_fee_rate: 333333.33,
        p2ms_outputs_count: 2,
        input_count: 1,
        output_count: 2,
        is_coinbase: false,
        outputs: Vec::new(), // Not used in Stage 3
        burn_patterns_detected: Vec::new(),
    };

    // Insert enriched transaction (outputs already seeded above, so pass empty vec)
    test_db
        .database_mut()
        .insert_enriched_transactions_batch(&[(enriched_tx, inputs, Vec::new())])?;

    // Run Stage 3 classification
    run_stage3_processor(test_db.path(), config).await?;

    // Verify transaction-level classification
    verify_classification(
        &test_db,
        txid,
        ProtocolType::LikelyLegitimateMultisig,
        Some(ProtocolVariant::LegitimateMultisig),
    )?;

    // CRITICAL: Verify output-level classifications with spendability
    verify_output_spendability(&test_db, txid, ProtocolType::LikelyLegitimateMultisig)?;

    // Verify spendability details
    let conn = rusqlite::Connection::open(test_db.path())?;
    let mut stmt = conn.prepare(
        "SELECT vout, is_spendable, spendability_reason, real_pubkey_count
         FROM p2ms_output_classifications
         WHERE txid = ?1 AND protocol = 'LikelyLegitimateMultisig'
         ORDER BY vout",
    )?;

    let outputs_result: Result<Vec<_>, _> = stmt
        .query_map([txid], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u8>(3)?,
            ))
        })?
        .collect();

    let output_classifications = outputs_result?;
    assert_eq!(
        output_classifications.len(),
        2,
        "Should have 2 output classifications"
    );

    for (i, (vout, is_spendable, reason, real_count)) in output_classifications.iter().enumerate() {
        assert_eq!(*vout, i as u32);
        assert!(*is_spendable);
        assert_eq!(reason, "AllValidECPoints");
        assert_eq!(*real_count, 2);
    }

    Ok(())
}
