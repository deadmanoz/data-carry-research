#[tokio::main]
async fn main() {
    if let Err(e) = data_carry_research::cli::run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
