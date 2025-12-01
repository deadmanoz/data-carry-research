//! Stage 3 AsciiIdentifierProtocols Protocol Classification Tests
//!
//! Tests signature detection for TB0001, TEST01, Metronotes, and other ASCII identifier protocols.
//! Uses synthetic test data to verify classifier logic.

use data_carry_research::database::Database;
use data_carry_research::types::{
    script_metadata::MultisigInfo, EnrichedTransaction, ProtocolType, ProtocolVariant,
    TransactionOutput,
};
use serial_test::serial;

use crate::common::db_seeding::seed_enriched_transaction;
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    build_fake_ascii_tx, build_transaction_from_script_hex, run_stage3_processor,
    setup_protocol_test, verify_classification, verify_stage3_completion,
};

/// Create a synthetic multisig transaction with specified pubkeys
fn create_multisig_transaction(
    txid: &str,
    height: u32,
    pubkeys: Vec<String>,
) -> EnrichedTransaction {
    let info = MultisigInfo {
        pubkeys: pubkeys.clone(),
        required_sigs: 1,
        total_pubkeys: pubkeys.len() as u32,
    };

    let output = TransactionOutput {
        txid: txid.to_string(),
        vout: 1,
        height,
        amount: 10_000,
        script_hex: "dummy".to_string(),
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: 100,
        metadata: serde_json::to_value(info).unwrap(),
        address: None,
    };

    let mut tx = fixtures::create_test_enriched_transaction(txid);
    tx.outputs = vec![output];
    tx.p2ms_outputs_count = 1;
    tx
}

/// Run an ASCII identifier test with synthetic transaction
async fn run_ascii_test(
    tx: EnrichedTransaction,
    test_name: &str,
    expected_variant: ProtocolVariant,
) -> anyhow::Result<()> {
    let (mut test_db, config) = setup_protocol_test(test_name)?;

    seed_enriched_transaction(&mut test_db, &tx, Vec::new())?;

    let total_classified = run_stage3_processor(test_db.path(), config).await?;
    verify_stage3_completion(total_classified, 1, 1);

    verify_classification(
        &test_db,
        &tx.txid,
        ProtocolType::AsciiIdentifierProtocols,
        Some(expected_variant),
    )?;

    Ok(())
}

/// TB0001 signature tests (hex 544230303031 in second pubkey)
mod tb0001 {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_tb0001_1of2_detection() {
        let valid_pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let tb0001_pk = format!("02544230303031{}", "00".repeat(20));

        let tx = create_multisig_transaction(
            "0000000000000000000000000000000000000000000000000000000000000001",
            360_000,
            vec![valid_pk.to_string(), tb0001_pk],
        );

        run_ascii_test(tx, "tb0001_1of2", ProtocolVariant::AsciiIdentifierTB0001)
            .await
            .expect("TB0001 1-of-2 test failed");
    }

    #[tokio::test]
    #[serial]
    async fn test_tb0001_1of3_detection() {
        let pk1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let tb0001_pk = format!("02544230303031{}", "00".repeat(20));
        let pk3 = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        let tx = create_multisig_transaction(
            "0000000000000000000000000000000000000000000000000000000000000002",
            360_500,
            vec![pk1.to_string(), tb0001_pk, pk3.to_string()],
        );

        run_ascii_test(tx, "tb0001_1of3", ProtocolVariant::AsciiIdentifierTB0001)
            .await
            .expect("TB0001 1-of-3 test failed");
    }

    #[tokio::test]
    #[serial]
    async fn test_tb0001_first_pubkey_edge_case() {
        let script_hex = "5121025442303030310010f06710cb9e9eebbd325bd4a2e9299fc300000000000000122103b23751bb95b2559c816c8f01ddd5abf5104a5039da91c01317296fe1746ac73a52ae";

        let tx = build_transaction_from_script_hex(
            "67792f9c87eb1632408bc537c42517c98c5218216df8f2d295eb17d617eb2006",
            script_hex,
        )
        .expect("Failed to build TB0001 transaction");

        run_ascii_test(
            tx,
            "tb0001_first_pubkey",
            ProtocolVariant::AsciiIdentifierTB0001,
        )
        .await
        .expect("TB0001 first-pubkey test failed");
    }
}

/// TEST01 signature tests (hex 544553543031 in FIRST pubkey - critical difference!)
mod test01 {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_test01_1of2_detection() {
        let test01_pk = format!("02544553543031{}", "00".repeat(20));
        let valid_pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        let tx = create_multisig_transaction(
            "0000000000000000000000000000000000000000000000000000000000000006",
            355_000,
            vec![test01_pk, valid_pk.to_string()],
        );

        run_ascii_test(tx, "test01_1of2", ProtocolVariant::AsciiIdentifierTEST01)
            .await
            .expect("TEST01 1-of-2 test failed");
    }

    #[tokio::test]
    #[serial]
    async fn test_test01_1of3_detection() {
        let test01_pk = format!("02544553543031{}", "00".repeat(20));
        let pk2 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pk3 = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        let tx = create_multisig_transaction(
            "0000000000000000000000000000000000000000000000000000000000000007",
            356_000,
            vec![test01_pk, pk2.to_string(), pk3.to_string()],
        );

        run_ascii_test(tx, "test01_1of3", ProtocolVariant::AsciiIdentifierTEST01)
            .await
            .expect("TEST01 1-of-3 test failed");
    }
}

/// Metronotes signature tests (METROXMN = hex 4d4554524f584d4e)
mod metronotes {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_metronotes_detection() {
        let valid_pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let metronotes_pk = format!("4d4554524f584d4e{}", "00".repeat(25));

        let tx = create_multisig_transaction(
            "0000000000000000000000000000000000000000000000000000000000000003",
            350_000,
            vec![valid_pk.to_string(), metronotes_pk],
        );

        run_ascii_test(tx, "metronotes", ProtocolVariant::AsciiIdentifierMetronotes)
            .await
            .expect("Metronotes test failed");
    }
}

/// AsciiIdentifierOther tests (NEWBCOIN, PRVCY, etc.)
mod other_identifiers {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_newbcoin_detection() {
        let script_hex = "512102c0fc0285e4dc4300582ff0f9ff2c72be486ea3f36e68806750d503dedd2490f721164e455742434f494e00000029000000000098968000010000000000000000000052ae";

        let tx = build_transaction_from_script_hex(
            "9f73c7e16966905530f144fdcdc6be7e426ad1764df95d061710aaf5e7de5812",
            script_hex,
        )
        .expect("Failed to build NEWBCOIN transaction");

        run_ascii_test(tx, "newbcoin", ProtocolVariant::AsciiIdentifierOther)
            .await
            .expect("NEWBCOIN test failed");
    }

    #[tokio::test]
    #[serial]
    async fn test_prvcy_detection() {
        let script_hex = "51210250525643590100010000000251d75544b04a9471eec80d5c1b8f5e127b0935824104505256435901f094ce936bdef34e1d63109cf3fe8dd21801e4a470309da63dbf3a49955d957900000000000000000000000000000000000000000000000000002103613a80d61c79d4ba7e8704133f63e53435add99275bfd894bab1f700e90dc8fd53ae";

        let tx = build_transaction_from_script_hex(
            "42409ab67cd856ecf648e1c63eaff23bf99ad8a5e8793f31812bfa6eb30c6112",
            script_hex,
        )
        .expect("Failed to build PRVCY transaction");

        run_ascii_test(tx, "prvcy", ProtocolVariant::AsciiIdentifierOther)
            .await
            .expect("PRVCY test failed");
    }
}

/// False positive prevention tests
mod false_positives {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_ascii_identifier_false_positive() {
        let tx = build_fake_ascii_tx(
            "0000000000000000000000000000000000000000000000000000000000000099",
            "FOOBAR",
        )
        .expect("Failed to build fake ASCII tx");

        let (mut test_db, config) =
            setup_protocol_test("ascii_false_positive").expect("Failed to setup test");

        seed_enriched_transaction(&mut test_db, &tx, Vec::new())
            .expect("Failed to seed transaction");

        let total_classified = run_stage3_processor(test_db.path(), config)
            .await
            .expect("Stage 3 processing failed");

        let db = Database::new_v2(test_db.path()).unwrap();
        let ascii_id_count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'AsciiIdentifierProtocols'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(
            ascii_id_count, 0,
            "FOOBAR (not on allowlist) should NOT be classified as AsciiIdentifierProtocols"
        );
        assert!(
            total_classified > 0,
            "Transaction should still be classified (just not as AsciiIdentifier)"
        );
    }
}
