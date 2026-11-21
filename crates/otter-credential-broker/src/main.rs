//! `otter-credential-broker`: secrets manager with an LLM proxy endpoint.
#![forbid(unsafe_code)]

mod telemetry;

use std::path::PathBuf;

use anyhow::Context;
use broker_core::Secret;
use broker_core::crypto::{KEY_LEN, LocalKeyProvider, random_bytes};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "otter-credential-broker", version, about = "Secrets manager with an LLM proxy endpoint")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP listeners (LLM proxy + worker, admin API, metrics).
    Serve {
        /// TOML config file (env `OCB_*` overrides it).
        #[arg(long, env = "OCB_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Apply database migrations and exit.
    Migrate {
        #[arg(long, env = "OCB_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Validate the configuration (providers, prices, TLS and key files) and exit.
    CheckConfig {
        #[arg(long, env = "OCB_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Print a new random 32-byte key (hex) for a KEK or token key file.
    Keygen,
    /// Print a new random admin bearer token (64 hex chars).
    GenToken,
}

fn load(config: Option<&std::path::Path>) -> anyhow::Result<broker_server::ServerConfig> {
    broker_server::ServerConfig::load(config).map_err(|e| anyhow::anyhow!("load config: {e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { config } => {
            let _guard = telemetry::init("otter-credential-broker")?;
            broker_server::serve(load(config.as_deref())?, config).await
        }
        Cmd::Migrate { config } => {
            let _guard = telemetry::init("otter-credential-broker")?;
            let cfg = load(config.as_deref())?;
            broker_server::connect_store(&cfg).await?.migrate().await.context("apply migrations")?;
            tracing::info!("migrations applied");
            Ok(())
        }
        Cmd::CheckConfig { config } => {
            let cfg = load(config.as_deref())?;
            // Validates providers and prices and reads the providers' TLS files.
            let proxy = broker_server::LlmProxy::new(&cfg.llm).map_err(|e| anyhow::anyhow!("llm: {e}"))?;
            let snapshot = proxy.snapshot();
            LocalKeyProvider::from_file(cfg.kek.id.clone(), &cfg.kek.file).context("current KEK")?;
            broker_core::auth::StaticTokenAuthenticator::from_file(&cfg.admin_tokens_file).context("admin tokens")?;
            broker_core::tokens::TokenHasher::from_file(&cfg.token_key_file).context("token key")?;
            broker_server::database_url(&cfg)?;
            println!(
                "config ok: {} provider(s), pricing {}, version {}",
                snapshot.providers().count(),
                if snapshot.prices().is_empty() { "empty" } else { "set" },
                snapshot.version()
            );
            Ok(())
        }
        Cmd::Keygen => {
            println!("{}", LocalKeyProvider::generate_hex()?.expose());
            Ok(())
        }
        Cmd::GenToken => {
            let b = Secret::new(random_bytes(KEY_LEN)?);
            println!("{}", Secret::new(hex::encode(b.expose())).expose());
            Ok(())
        }
    }
}
