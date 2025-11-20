/// Diagnostic test to understand the EC point validation bug
use bitcoin::secp256k1::PublicKey;

#[test]
fn diagnose_ec_validation_failure() {
    println!("\n=== Diagnostic: EC Validation Failure Analysis ===\n");

    // Keys that FAIL validation
    let failing_keys = vec![
        (
            "TX1 Key2",
            "02f0d81d36524f24dcdb97009c96839b43ce92104739d58e37da35d1381d65fa78",
        ),
        (
            "TX2 Key1",
            "036f2ebbcfcabb211bd0a4b0ac4d1b87f0552d13dfed53f3a99a18f5e29e913934",
        ),
        (
            "TX2 Key2",
            "0289e61c0f95d1dfd7d8c05dae56b8799d2eb4d60bb7576a43b84aba56846e285b",
        ),
        (
            "TX3 Key1",
            "02a202f91ccdc4c6482be4524af21037cab376b4e1bcfd0b0ad995c7c608d407d8",
        ),
    ];

    // Keys that PASS validation
    let passing_keys = vec![
        (
            "TX1 Key1",
            "02902964a794cda2cc9ae46e11b04a31d01d8cccbd1e34e43774fd6c5d3ccecaef",
        ),
        (
            "TX1 Key3",
            "031a220a10370ff716f21de2a69b6d410a52f91f737a0c9f9949859d2cf65f238d",
        ),
    ];

    println!("--- FAILING KEYS ---");
    for (label, hex) in &failing_keys {
        let bytes = hex::decode(hex).unwrap();
        println!("\n{}: {}", label, hex);
        println!("  Length: {} bytes", bytes.len());
        println!("  Prefix: 0x{:02x}", bytes[0]);
        println!("  Last byte: 0x{:02x}", bytes[bytes.len() - 1]);

        match PublicKey::from_slice(&bytes) {
            Ok(_) => println!("  ✅ UNEXPECTED: Passed validation!"),
            Err(e) => println!("  ❌ Expected failure: {}", e),
        }
    }

    println!("\n--- PASSING KEYS ---");
    for (label, hex) in &passing_keys {
        let bytes = hex::decode(hex).unwrap();
        println!("\n{}: {}", label, hex);
        println!("  Length: {} bytes", bytes.len());
        println!("  Prefix: 0x{:02x}", bytes[0]);
        println!("  Last byte: 0x{:02x}", bytes[bytes.len() - 1]);

        match PublicKey::from_slice(&bytes) {
            Ok(_) => println!("  ✅ Expected: Passed validation"),
            Err(e) => println!("  ❌ UNEXPECTED: Failed: {}", e),
        }
    }

    println!("\n--- PATTERN ANALYSIS ---");
    println!("Failing keys last bytes: ");
    for (label, hex) in &failing_keys {
        let bytes = hex::decode(hex).unwrap();
        println!("  {}: 0x{:02x}", label, bytes[bytes.len() - 1]);
    }

    println!("\nPassing keys last bytes: ");
    for (label, hex) in &passing_keys {
        let bytes = hex::decode(hex).unwrap();
        println!("  {}: 0x{:02x}", label, bytes[bytes.len() - 1]);
    }

    // Don't fail the test, just provide diagnostic output
    println!("\n=== Diagnostic Complete ===\n");
}

#[test]
fn test_last_byte_pattern() {
    println!("\n=== Testing Last Byte Pattern Hypothesis ===\n");

    // Hypothesis: Keys ending in certain bytes might fail
    // Let's check if the last byte is significant

    let test_cases = vec![
        // Failing keys
        (
            "FAIL1",
            "02f0d81d36524f24dcdb97009c96839b43ce92104739d58e37da35d1381d65fa78",
            0x78,
        ),
        (
            "FAIL2",
            "036f2ebbcfcabb211bd0a4b0ac4d1b87f0552d13dfed53f3a99a18f5e29e913934",
            0x34,
        ),
        (
            "FAIL3",
            "0289e61c0f95d1dfd7d8c05dae56b8799d2eb4d60bb7576a43b84aba56846e285b",
            0x5b,
        ),
        (
            "FAIL4",
            "02a202f91ccdc4c6482be4524af21037cab376b4e1bcfd0b0ad995c7c608d407d8",
            0xd8,
        ),
        // Passing keys
        (
            "PASS1",
            "02902964a794cda2cc9ae46e11b04a31d01d8cccbd1e34e43774fd6c5d3ccecaef",
            0xef,
        ),
        (
            "PASS2",
            "031a220a10370ff716f21de2a69b6d410a52f91f737a0c9f9949859d2cf65f238d",
            0x8d,
        ),
    ];

    for (label, hex, expected_last_byte) in test_cases {
        let bytes = hex::decode(hex).unwrap();
        let actual_last_byte = bytes[bytes.len() - 1];

        assert_eq!(
            actual_last_byte, expected_last_byte,
            "{}: Last byte mismatch",
            label
        );

        let result = PublicKey::from_slice(&bytes);
        println!(
            "{}: Last byte 0x{:02x} -> {}",
            label,
            actual_last_byte,
            if result.is_ok() { "PASS" } else { "FAIL" }
        );
    }

    println!("\nConclusion: Last byte does not determine pass/fail");
    println!("The issue must be in the EC point mathematics itself");
}
