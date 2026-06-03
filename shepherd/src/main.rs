#![allow(dead_code)]

mod accounts;
mod acme_client;
mod alerts;
mod assignments;
mod auth;
mod cas;
mod corgis;
mod cert_store;
mod config;
mod corgi_client;
mod dns_providers;
mod error;
mod issuance;
mod jwt;
mod log_middleware;
mod poll;
mod refresh_tokens;
mod renewal_jobs;
mod routes_api;
mod routes_corgi;
mod server;
mod state;
mod types;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use config::load_config;
use state::AppState;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "shepherd", about = "TLS certificate management control plane", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Server commands
    Server {
        #[command(subcommand)]
        cmd: ServerCommands,
    },
    /// Bootstrap commands
    Bootstrap {
        #[command(subcommand)]
        cmd: BootstrapCommands,
    },
    /// Certificate store commands
    Cert {
        #[command(subcommand)]
        cmd: CertCommands,
    },
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Start the Shepherd server
    Start,
    /// Validate config and exit
    CheckConfig,
}

#[derive(Subcommand)]
enum BootstrapCommands {
    /// Issue a cert for a new Corgi agent via Vigil bootstrap
    Corgi {
        #[arg(long)]
        name: String,
        #[arg(long)]
        identity_uri: String,
    },
    /// Issue an admin cert locally
    Admin {
        #[arg(long)]
        identity_uri: String,
        #[arg(long)]
        domain: String,
    },
}

#[derive(Subcommand)]
enum CertCommands {
    /// Trigger renewal for a certificate
    Renew { cert_name: String },
    /// List certstore entries
    Store,
    /// Inspect a certstore entry
    Inspect { cert_name: String },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Server { cmd } => match cmd {
            ServerCommands::Start => cmd_server_start().await,
            ServerCommands::CheckConfig => cmd_check_config().await,
        },
        Commands::Bootstrap { cmd } => match cmd {
            BootstrapCommands::Corgi { name, identity_uri } => {
                cmd_bootstrap_corgi(&name, &identity_uri).await
            }
            BootstrapCommands::Admin { identity_uri, domain } => {
                cmd_bootstrap_admin(&identity_uri, &domain).await
            }
        },
        Commands::Cert { cmd } => match cmd {
            CertCommands::Renew { cert_name } => cmd_cert_renew(&cert_name).await,
            CertCommands::Store => cmd_cert_store().await,
            CertCommands::Inspect { cert_name } => cmd_cert_inspect(&cert_name).await,
        },
    }
}

// ---------------------------------------------------------------------------
// server start
// ---------------------------------------------------------------------------

async fn cmd_server_start() -> Result<()> {
    let config = load_config().context("Loading config")?;
    init_logging(config.log_level);

    tracing::info!(
        agent_port = config.agent_port,
        dashboard_port = config.dashboard_port,
        bind = %config.bind,
        "Shepherd starting"
    );

    // Load JWT signing key (generate if absent)
    let jwt_keys = jwt::load_or_generate(&config.jwt_signing_key_path)
        .context("Loading JWT signing key")?;

    // Load accounts
    let account_list = accounts::load_accounts(&config.accounts_path)
        .context("Loading accounts")?;
    tracing::info!(count = account_list.len(), "Loaded accounts");

    // Load corgis
    let corgi_list = corgis::load_corgis(&config.corgis_config_path)
        .context("Loading corgis config")?;
    tracing::info!(count = corgi_list.len(), "Loaded corgis");

    // Load assignments
    let assignment_list = assignments::load_assignments(&config.assignments_config_path)
        .context("Loading assignments")?;
    tracing::info!(count = assignment_list.len(), "Loaded assignments");

    // Load CAs
    let ca_map = cas::load_cas(&config.ca_config_path)
        .context("Loading CA config")?;
    tracing::info!(count = ca_map.len(), "Loaded CAs");

    let state = AppState::new(config, jwt_keys, account_list, ca_map);
    *state.corgis.write().await = corgi_list;
    *state.assignments.write().await = assignment_list;

    tokio::spawn(poll::run_health_check_loop(state.clone()));
    tokio::spawn(poll::run_poll_loop(state.clone()));

    server::run(state).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// server check-config
// ---------------------------------------------------------------------------

async fn cmd_check_config() -> Result<()> {
    let config = load_config().context("Loading config")?;
    init_logging(config.log_level);

    println!("Config: {}", config.config_path.display());
    println!("  Agent port:     {}:{}", config.bind, config.agent_port);
    println!("  Dashboard port: {}:{}", config.bind, config.dashboard_port);
    println!("  Cert store:     {}", config.cert_store_dir.display());
    println!("  Renew before:   {} days", config.renew_before_days);
    println!("  Poll interval:  {}s", config.poll_interval_seconds);
    println!();

    let checks = config::validate_paths(&config);
    let mut all_ok = true;
    for (label, ok) in &checks {
        let tag = if *ok { "[ok]" } else { "[missing]" };
        println!("  {tag} {label}");
        if !ok {
            all_ok = false;
        }
    }
    println!();

    // Validate JWT key (generate if missing — that's fine)
    match jwt::load_or_generate(&config.jwt_signing_key_path) {
        Ok(_) => println!("  [ok] JWT signing key: {}", config.jwt_signing_key_path.display()),
        Err(e) => {
            println!("  [error] JWT signing key: {e}");
            all_ok = false;
        }
    }

    println!();
    if all_ok {
        println!("Config looks good.");
    } else {
        println!("Config has issues — see above.");
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bootstrap / cert commands (stubs)
// ---------------------------------------------------------------------------

async fn cmd_bootstrap_corgi(name: &str, identity_uri: &str) -> Result<()> {
    println!("Bootstrap corgi '{name}' with identity '{identity_uri}' — not yet implemented.");
    Ok(())
}

async fn cmd_bootstrap_admin(identity_uri: &str, domain: &str) -> Result<()> {
    println!("Bootstrap admin '{identity_uri}' for domain '{domain}' — not yet implemented.");
    Ok(())
}

async fn cmd_cert_renew(cert_name: &str) -> Result<()> {
    println!("Renew cert '{cert_name}' — not yet implemented.");
    Ok(())
}

async fn cmd_cert_store() -> Result<()> {
    let config = load_config().context("Loading config")?;
    let entries = cert_store::list_cert_store_entries(&config.cert_store_dir);
    if entries.is_empty() {
        println!("Cert store is empty or not yet initialized.");
    } else {
        for name in entries {
            println!("  {name}");
        }
    }
    Ok(())
}

async fn cmd_cert_inspect(cert_name: &str) -> Result<()> {
    let config = load_config().context("Loading config")?;
    match cert_store::read_cert_store_entry(&config.cert_store_dir, cert_name) {
        Some(entry) => println!("{}", serde_json::to_string_pretty(&entry)?),
        None => println!("Cert '{cert_name}' not found in store."),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Logging setup
// ---------------------------------------------------------------------------

fn init_logging(level: config::LogLevel) {
    credo_lib::log::init_logging(credo_lib::LogLevel::from_str(level.as_tracing_filter()));
}
