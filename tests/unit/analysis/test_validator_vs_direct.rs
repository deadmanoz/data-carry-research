/// Compare validate_pubkeys() results vs direct PublicKey::from_slice()
use bitcoin::secp256k1::PublicKey;
use data_carry_research::analysis::pubkey_validator::validate_pubkeys;

#[test]
fn compare_validator_vs_direct_tx1() {
    println!("\n=== TX1 (6ace2a99) Comparison ===\n");

    let pubkeys = vec![
        "02902964a794cda2cc9ae46e11b04a31d01d8cccbd1e34e43774fd6c5d3ccecaef".to_string(),
        "02f0d81d36524f24dcdb97009c96839b43ce92104739d58e37da35d1381d65fa78".to_string(),
        "031a220a10370ff716f21de2a69b6d410a52f91f737a0c9f9949859d2cf65f238d".to_string(),
    ];

    // Test via validator
    let validator_result = validate_pubkeys(&pubkeys);

    println!("VALIDATOR RESULTS:");
    println!(
        "  Valid keys: {}/{}",
        validator_result.valid_keys, validator_result.total_keys
    );
    println!(
        "  Invalid indices: {:?}",
        validator_result.invalid_key_indices
    );
    for err in &validator_result.validation_errors {
        println!("  {}", err);
    }

    // Test each key directly
    println!("\nDIRECT PUBLIC_KEY::FROM_SLICE() RESULTS:");
    for (i, pubkey_hex) in pubkeys.iter().enumerate() {
        let bytes = hex::decode(pubkey_hex).unwrap();
        let direct_result = PublicKey::from_slice(&bytes);

        let validator_says_invalid = validator_result.invalid_key_indices.contains(&i);

        println!("\n  Key {}: {}", i, pubkey_hex);
        println!(
            "    Validator: {}",
            if validator_says_invalid {
                "INVALID"
            } else {
                "VALID"
            }
        );
        println!(
            "    Direct:    {}",
            if direct_result.is_ok() {
                "VALID"
            } else {
                "INVALID"
            }
        );

        match direct_result {
            Ok(_) => println!("    Direct result: ✅ Valid EC point"),
            Err(e) => println!("    Direct result: ❌ {}", e),
        }

        // Check for mismatch
        let direct_says_invalid = direct_result.is_err();
        if validator_says_invalid != direct_says_invalid {
            println!("    ⚠️  MISMATCH DETECTED!");
        }
    }

    println!("\n=== End TX1 Comparison ===\n");
}

#[test]
fn compare_validator_vs_direct_tx2() {
    println!("\n=== TX2 (c240572d) Comparison ===\n");

    let pubkeys = vec![
        "036f2ebbcfcabb211bd0a4b0ac4d1b87f0552d13dfed53f3a99a18f5e29e913934".to_string(),
        "0289e61c0f95d1dfd7d8c05dae56b8799d2eb4d60bb7576a43b84aba56846e285b".to_string(),
        "02c10e5cee8a16071e2ff6d13010ef24d2b6431ffa04243bce86a17457b5cf177b".to_string(),
    ];

    let validator_result = validate_pubkeys(&pubkeys);

    println!("VALIDATOR RESULTS:");
    println!(
        "  Valid keys: {}/{}",
        validator_result.valid_keys, validator_result.total_keys
    );
    println!(
        "  Invalid indices: {:?}",
        validator_result.invalid_key_indices
    );

    println!("\nDIRECT RESULTS:");
    for (i, pubkey_hex) in pubkeys.iter().enumerate() {
        let bytes = hex::decode(pubkey_hex).unwrap();
        let direct_result = PublicKey::from_slice(&bytes);
        let validator_says_invalid = validator_result.invalid_key_indices.contains(&i);

        println!(
            "\n  Key {}: Validator={} Direct={}",
            i,
            if validator_says_invalid {
                "INVALID"
            } else {
                "VALID"
            },
            if direct_result.is_ok() {
                "VALID"
            } else {
                "INVALID"
            }
        );

        if validator_says_invalid != direct_result.is_err() {
            println!("    ⚠️  MISMATCH!");
        }
    }

    println!("\n=== End TX2 Comparison ===\n");
}

#[test]
fn compare_validator_vs_direct_tx3() {
    println!("\n=== TX3 (a8d1f414) Comparison ===\n");

    let pubkeys = vec![
        "02a202f91ccdc4c6482be4524af21037cab376b4e1bcfd0b0ad995c7c608d407d8".to_string(),
        "0209c550aa364ff2d8222f454b0cbdcc6653e3713a2558c80aec811a4dbc23338a".to_string(),
        "03824cf7489b4bba5d12d71c6692f7c6f46014d09767670e2febf7a1dcdac783fb".to_string(),
    ];

    let validator_result = validate_pubkeys(&pubkeys);

    println!("VALIDATOR RESULTS:");
    println!(
        "  Valid keys: {}/{}",
        validator_result.valid_keys, validator_result.total_keys
    );
    println!(
        "  Invalid indices: {:?}",
        validator_result.invalid_key_indices
    );

    println!("\nDIRECT RESULTS:");
    for (i, pubkey_hex) in pubkeys.iter().enumerate() {
        let bytes = hex::decode(pubkey_hex).unwrap();
        let direct_result = PublicKey::from_slice(&bytes);
        let validator_says_invalid = validator_result.invalid_key_indices.contains(&i);

        println!(
            "\n  Key {}: Validator={} Direct={}",
            i,
            if validator_says_invalid {
                "INVALID"
            } else {
                "VALID"
            },
            if direct_result.is_ok() {
                "VALID"
            } else {
                "INVALID"
            }
        );

        if validator_says_invalid != direct_result.is_err() {
            println!("    ⚠️  MISMATCH!");
        }
    }

    println!("\n=== End TX3 Comparison ===\n");
}
