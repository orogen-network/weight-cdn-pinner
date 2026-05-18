//! CLI: `weight-cdn-pinner pin <model-id> --sha256 <hex> --mirror <url>...`

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use weight_cdn_pinner::{ModelEntry, Pinner};

#[derive(Parser)]
#[command(name = "weight-cdn-pinner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long, default_value = "/var/lib/weight-cdn-pinner")]
    cache_dir: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Pin a model: fetch from mirrors, verify hash, cache locally.
    Pin {
        model_id: String,
        #[arg(long)]
        sha256: String,
        #[arg(long, required = true)]
        mirror: Vec<String>,
        #[arg(long)]
        size_bytes: Option<u64>,
    },
    /// Show cache root path.
    Where,
    /// Print pin path for a model id.
    Path { model_id: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let pinner = Pinner::new(&cli.cache_dir);
    match cli.cmd {
        Cmd::Pin { model_id, sha256, mirror, size_bytes } => {
            let mut expected = [0u8; 32];
            hex::decode_to_slice(sha256.trim_start_matches("0x"), &mut expected)?;
            let entry = ModelEntry {
                model_id,
                expected_sha256: expected,
                mirrors: mirror,
                size_bytes: size_bytes.unwrap_or(0),
            };
            let path = pinner.fetch_and_pin(&entry).await?;
            println!("{}", path.display());
        }
        Cmd::Where => {
            println!("{}", pinner.cache_root().display());
        }
        Cmd::Path { model_id } => {
            println!("{}", pinner.pin_path(&model_id).display());
        }
    }
    Ok(())
}
