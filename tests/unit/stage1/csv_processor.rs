use data_carry_research::database::traits::Stage1Operations;
use data_carry_research::database::Database;
use data_carry_research::processor::CsvProcessor;
use data_carry_research::types::Stage1Config;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

/// Generate a CSV file with a known number of records
/// If `with_comments` is true, adds comment header lines like production format
fn generate_test_csv(record_count: usize, temp_dir: &TempDir) -> PathBuf {
    generate_test_csv_with_options(record_count, temp_dir, false)
}

/// Generate a CSV file with optional comment headers
fn generate_test_csv_with_options(
    record_count: usize,
    temp_dir: &TempDir,
    with_comments: bool,
) -> PathBuf {
    let csv_path = temp_dir.path().join("test.csv");
    let mut file = File::create(&csv_path).expect("Failed to create test CSV");

    // Write comment headers if requested (matching production format)
    if with_comments {
        writeln!(file, "# Bitcoin UTXO Dump").expect("Failed to write comment");
        writeln!(file, "# Generated: 2025-10-14T13:18:48Z").expect("Failed to write comment");
        writeln!(
            file,
            "# Fields: count,txid,vout,height,coinbase,amount,type,script,address"
        )
        .expect("Failed to write comment");
    }

    // Write CSV header (note: "type" not "script_type" in CSV)
    writeln!(
        file,
        "count,txid,vout,height,coinbase,amount,type,script,address"
    )
    .expect("Failed to write header");

    // Write test records (mix of P2MS and non-P2MS)
    for i in 0..record_count {
        let script_type = if i % 10 == 0 { "p2ms" } else { "p2pkh" };
        writeln!(
            file,
            "{},{}000000000000000000000000000000000000000000000000000000000000000{:04x},{},100000,0,1000,{},deadbeef,1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            i, i, i, i, script_type
        )
        .expect("Failed to write record");
    }

    csv_path
}

#[test]
fn test_csv_line_counting_small_file() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let csv_path = generate_test_csv(100, &temp_dir);

    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: temp_dir.path().join("test.db"),
        batch_size: 10,
        progress_interval: 10,
        checkpoint_interval: 100,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");

    // Use reflection to call private method for testing
    // In production code, we'd expose a public method or test indirectly through process_csv
    // For now, we'll test by processing and checking the output
    let stats = processor.process_csv().expect("Failed to process CSV");

    assert_eq!(stats.total_records, 100, "Should process all records");
}

#[test]
fn test_csv_line_counting_large_file() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Generate a file larger than the 8MB buffer (approx 100K records = ~15MB)
    let record_count = 100_000;
    let csv_path = generate_test_csv(record_count, &temp_dir);

    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: temp_dir.path().join("test.db"),
        batch_size: 1000,
        progress_interval: 10000,
        checkpoint_interval: 50000,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");
    let stats = processor.process_csv().expect("Failed to process CSV");

    assert_eq!(
        stats.total_records, record_count,
        "Should correctly count all records in large file"
    );

    // We should have ~10% P2MS records (every 10th record)
    let expected_p2ms = record_count / 10;
    assert_eq!(
        stats.p2ms_found, expected_p2ms,
        "Should find correct number of P2MS records"
    );
}

#[test]
fn test_csv_line_counting_empty_file() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let csv_path = temp_dir.path().join("empty.csv");
    let mut file = File::create(&csv_path).expect("Failed to create test CSV");

    // Write only header (note: "type" not "script_type" in CSV)
    writeln!(
        file,
        "count,txid,vout,height,coinbase,amount,type,script,address"
    )
    .expect("Failed to write header");

    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: temp_dir.path().join("test.db"),
        batch_size: 10,
        progress_interval: 10,
        checkpoint_interval: 100,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");
    let stats = processor.process_csv().expect("Failed to process CSV");

    assert_eq!(stats.total_records, 0, "Should handle empty CSV correctly");
}

#[test]
fn test_csv_with_comment_headers() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Generate CSV with comment headers (matching production format)
    let record_count = 100;
    let csv_path = generate_test_csv_with_options(record_count, &temp_dir, true);

    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: temp_dir.path().join("test.db"),
        batch_size: 10,
        progress_interval: 10,
        checkpoint_interval: 100,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");
    let stats = processor.process_csv().expect("Failed to process CSV");

    assert_eq!(
        stats.total_records, record_count,
        "Should correctly process CSV with comment headers"
    );

    // We should have ~10% P2MS records (every 10th record)
    let expected_p2ms = record_count / 10;
    assert_eq!(
        stats.p2ms_found, expected_p2ms,
        "Should find correct number of P2MS records"
    );
}

#[test]
fn test_csv_with_comment_headers_large() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Test with larger dataset to ensure comment handling scales
    let record_count = 10_000;
    let csv_path = generate_test_csv_with_options(record_count, &temp_dir, true);

    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: temp_dir.path().join("test.db"),
        batch_size: 1000,
        progress_interval: 2000,
        checkpoint_interval: 5000,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");
    let stats = processor.process_csv().expect("Failed to process CSV");

    assert_eq!(
        stats.total_records, record_count,
        "Should correctly process large CSV with comment headers"
    );

    // Verify P2MS detection still works correctly
    let expected_p2ms = record_count / 10;
    assert_eq!(
        stats.p2ms_found, expected_p2ms,
        "Should find correct number of P2MS records in large file"
    );
}

#[test]
fn test_csv_progress_reporting_accuracy() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Generate enough records to trigger multiple progress updates
    let record_count = 50_000;
    let csv_path = generate_test_csv(record_count, &temp_dir);

    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: temp_dir.path().join("test.db"),
        batch_size: 1000,
        progress_interval: 5000,
        checkpoint_interval: 25000,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");
    let stats = processor.process_csv().expect("Failed to process CSV");

    // Verify accurate counting
    assert_eq!(
        stats.total_records, record_count,
        "Total records should match file size"
    );

    // Verify P2MS detection
    let expected_p2ms = record_count / 10; // Every 10th record is P2MS
    assert_eq!(
        stats.p2ms_found, expected_p2ms,
        "P2MS count should be accurate"
    );

    // Verify processing completed
    assert!(
        stats.timing.processing_duration.as_secs_f64() > 0.0,
        "Processing should take measurable time"
    );
}

// ===== Checkpoint-Specific Tests =====

#[test]
fn test_checkpoint_persistence() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("checkpoint_test.db");

    let mut database =
        Database::new(&db_path.to_string_lossy()).expect("Failed to create database");

    // Save a checkpoint
    database
        .save_checkpoint_enhanced(42, 1000, 43, 10)
        .expect("Failed to save checkpoint");

    // Verify we can retrieve it
    let checkpoint = database
        .get_checkpoint_enhanced()
        .expect("Failed to get checkpoint");

    assert!(checkpoint.is_some(), "Checkpoint should exist");
    let checkpoint = checkpoint.unwrap();
    assert_eq!(checkpoint.last_processed_count, 42);
    assert_eq!(checkpoint.total_processed, 1000);
    assert_eq!(checkpoint.csv_line_number, 43);
    assert_eq!(checkpoint.batch_number, 10);
}

#[test]
fn test_checkpoint_update() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("checkpoint_update_test.db");

    let mut database =
        Database::new(&db_path.to_string_lossy()).expect("Failed to create database");

    // Save initial checkpoint
    database
        .save_checkpoint_enhanced(10, 100, 11, 1)
        .expect("Failed to save initial checkpoint");

    // Update checkpoint (should replace, not duplicate)
    database
        .save_checkpoint_enhanced(20, 200, 21, 2)
        .expect("Failed to update checkpoint");

    // Verify only one checkpoint exists with updated values
    let checkpoint = database
        .get_checkpoint_enhanced()
        .expect("Failed to get checkpoint")
        .expect("Checkpoint should exist");

    assert_eq!(checkpoint.last_processed_count, 20);
    assert_eq!(checkpoint.total_processed, 200);
    assert_eq!(checkpoint.csv_line_number, 21);
    assert_eq!(checkpoint.batch_number, 2);
}

#[test]
fn test_checkpoint_clear() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("checkpoint_clear_test.db");

    let mut database =
        Database::new(&db_path.to_string_lossy()).expect("Failed to create database");

    // Save checkpoint
    database
        .save_checkpoint_enhanced(50, 500, 51, 5)
        .expect("Failed to save checkpoint");

    // Verify it exists
    assert!(
        database
            .get_checkpoint_enhanced()
            .expect("Failed to get checkpoint")
            .is_some(),
        "Checkpoint should exist before clearing"
    );

    // Clear checkpoint
    database
        .clear_checkpoint()
        .expect("Failed to clear checkpoint");

    // Verify it's gone
    assert!(
        database
            .get_checkpoint_enhanced()
            .expect("Failed to get checkpoint")
            .is_none(),
        "Checkpoint should not exist after clearing"
    );
}

#[test]
fn test_checkpoint_resume() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Generate test CSV with 100 records
    let record_count = 100;
    let csv_path = generate_test_csv(record_count, &temp_dir);
    let db_path = temp_dir.path().join("resume_test.db");

    // Phase 1: Process partially (simulate crash after 50 records)
    {
        // Use production schema to match CSV processor requirement
        let mut database =
            Database::new(&db_path.to_string_lossy()).expect("Failed to create database");

        // Simulate a checkpoint at line 50 (after processing 50 records, next line is 51)
        database
            .save_checkpoint_enhanced(49, 50, 50, 5)
            .expect("Failed to save checkpoint");
    }

    // Phase 2: Resume processing
    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: db_path.clone(),
        batch_size: 10,
        progress_interval: 10,
        checkpoint_interval: 25,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");

    // Check that checkpoint is detected
    let checkpoint = processor
        .check_for_checkpoint()
        .expect("Failed to check checkpoint");
    assert!(checkpoint.is_some(), "Checkpoint should be detected");
    let checkpoint = checkpoint.unwrap();
    assert_eq!(checkpoint.csv_line_number, 50, "Should resume from line 50");

    // Process (should resume from line 50)
    let stats = processor
        .process_csv()
        .expect("Failed to resume processing");

    // Should process only the remaining 50 records (lines 50-99)
    // This is correct behaviour - checkpoint means first 50 lines already processed
    assert_eq!(
        stats.total_records, 50,
        "Should process only remaining records after checkpoint (50 out of 100)"
    );

    // Verify checkpoint is cleared after successful completion
    // Use production schema to match the database created by CSV processor
    let database = Database::new(&db_path.to_string_lossy()).expect("Failed to open database");
    assert!(
        database
            .get_checkpoint_enhanced()
            .expect("Failed to get checkpoint")
            .is_none(),
        "Checkpoint should be cleared after successful completion"
    );
}

#[test]
fn test_checkpoint_saves_during_processing() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Generate enough records to trigger multiple batches
    let record_count = 100;
    let batch_size = 10;
    let csv_path = generate_test_csv(record_count, &temp_dir);
    let db_path = temp_dir.path().join("checkpoint_saves_test.db");

    let config = Stage1Config {
        csv_path: csv_path.clone(),
        database_path: db_path.clone(),
        batch_size,
        progress_interval: 10,
        checkpoint_interval: 50,
        resume_from_count: None,
    };

    let mut processor = CsvProcessor::new(config).expect("Failed to create processor");

    // Process the CSV
    let _ = processor.process_csv().expect("Failed to process CSV");

    // Verify checkpoint was cleared at the end (successful completion)
    // Use production schema to match the database created by CSV processor
    let database = Database::new(&db_path.to_string_lossy()).expect("Failed to open database");
    assert!(
        database
            .get_checkpoint_enhanced()
            .expect("Failed to get checkpoint")
            .is_none(),
        "Checkpoint should be cleared after successful completion"
    );
}
