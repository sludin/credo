#![allow(dead_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use corgi::config::load_config;
use corgi::state::AppState;

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "corgi", about = "Distributed TLS certificate agent", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a private key + CSR for Shepherd enrollment
    Bootstrap {
        /// Write CSR to this file (stdout if omitted)
        #[arg(long)]
        out: Option<String>,
        /// Print what would happen without writing files
        #[arg(long)]
        dry_run: bool,
    },
    /// Server commands
    Server {
        #[command(subcommand)]
        server_cmd: ServerCommands,
    },
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Start the Corgi agent
    Start,
    /// Validate config and connectivity
    CheckConfig,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Commands::Bootstrap { out, dry_run } => cmd_bootstrap(out, dry_run).await,
        Commands::Server { server_cmd } => match server_cmd {
            ServerCommands::Start => cmd_server_start().await,
            ServerCommands::CheckConfig => cmd_check_config().await,
        },
    }
}

// ---------------------------------------------------------------------------
// bootstrap command
// ---------------------------------------------------------------------------

async fn cmd_bootstrap(_out: Option<String>, dry_run: bool) -> Result<()> {
    let config = load_config().context("Loading config")?;
    init_logging(config.log_level);

    if dry_run {
        println!(
            "Dry run: would start bootstrap server on {}:{}",
            config.bind, config.bootstrap_port
        );
        println!("  Node ID:     {}", config.node_id);
        println!("  Common name: {}", config.common_name);
        println!("  Key path:    {}", config.tls.cert_path.display());
        return Ok(());
    }

    corgi::bootstrap::run_bootstrap(Arc::new(config)).await?;
    println!("Bootstrap complete. Restart Corgi: corgi server start");
    Ok(())
}

// ---------------------------------------------------------------------------
// server start command
// ---------------------------------------------------------------------------

async fn cmd_server_start() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let config = load_config().context("Loading config")?;
    init_logging(config.log_level);

    tracing::info!(
        node_id = %config.node_id,
        common_name = %config.common_name,
        shepherd_url = %config.shepherd_url,
        "Corgi starting"
    );

    corgi::hooks::validate_hooks(&config);

    let state = AppState::new(config).context("Building AppState")?;

    tokio::spawn(corgi::sync::run_sync_loop(state.clone()));

    let mut hup = signal(SignalKind::hangup()).context("Registering SIGHUP handler")?;
    let mut tls_config = {
        let cfg = state.config.load_full();
        corgi::server::build_server_tls(&cfg).context("Building mTLS server config")?
    };

    loop {
        let cfg = state.config.load_full();
        let acceptor = TlsAcceptor::from(tls_config.clone());

        let control_listener = corgi::server::bind_tcp(&cfg.bind, cfg.mtls_port)
            .await
            .with_context(|| format!("Binding control API on {}:{}", cfg.bind, cfg.mtls_port))?;

        tracing::info!(
            addr = format!("{}:{}", cfg.bind, cfg.mtls_port),
            mode = ?cfg.auth.mode,
            "Control API listening"
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let challenge_handle = if cfg.http_challenge.enabled {
            let l = corgi::server::bind_tcp(&cfg.http_challenge.bind, cfg.http_challenge.port)
                .await
                .with_context(|| {
                    format!(
                        "Binding challenge server on {}:{}",
                        cfg.http_challenge.bind, cfg.http_challenge.port
                    )
                })?;
            tracing::info!(
                addr = format!("{}:{}", cfg.http_challenge.bind, cfg.http_challenge.port),
                "HTTP-01 challenge listener active"
            );
            let cr = corgi::server::build_challenge_router(state.clone());
            let rx = shutdown_rx.clone();
            Some(tokio::spawn(async move {
                corgi::server::serve_http(l, cr, rx).await;
            }))
        } else {
            None
        };

        let control_router = corgi::server::build_control_router(state.clone());
        let mut control_handle = tokio::spawn(async move {
            corgi::server::serve_tls(control_listener, acceptor, control_router, shutdown_rx).await;
        });

        tokio::select! {
            _ = hup.recv() => {
                tracing::info!("SIGHUP received — reloading config");
                match load_config() {
                    Ok(new_cfg) => {
                        match corgi::server::build_server_tls(&new_cfg) {
                            Ok(new_tls) => { tls_config = new_tls; }
                            Err(e) => tracing::warn!(error=%e, "TLS rebuild failed; keeping current TLS config"),
                        }
                        // Rebuild shepherd client with new mTLS credentials
                        match corgi::shepherd::build_shepherd_client(&new_cfg) {
                            Ok(new_client) => { *state.shepherd_client.write().await = new_client; }
                            Err(e) => tracing::warn!(error=%e, "Shepherd client rebuild failed"),
                        }
                        tracing::info!(
                            node_id = %new_cfg.node_id,
                            mtls_port = new_cfg.mtls_port,
                            "Config reloaded"
                        );
                        state.config.store(std::sync::Arc::new(new_cfg));
                    }
                    Err(e) => tracing::warn!(error=%e, "Config reload failed; keeping current config"),
                }
                let _ = shutdown_tx.send(true);
                let _ = (&mut control_handle).await;
                if let Some(h) = challenge_handle { let _ = h.await; }
            }
            _ = &mut control_handle => {
                if let Some(h) = challenge_handle { let _ = h.await; }
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// server check-config command
// ---------------------------------------------------------------------------

async fn cmd_check_config() -> Result<()> {
    let config = load_config().context("Loading config")?;
    init_logging(config.log_level);

    let ok = true;

    println!("Config: {}", config.config_path.display());
    println!("  Node ID:       {}", config.node_id);
    println!("  Common name:   {}", config.common_name);
    println!("  Shepherd URL:  {}", config.shepherd_url);
    println!("  Control port:  {}:{}", config.bind, config.mtls_port);
    println!(
        "  Challenge:     {} (port {})",
        if config.http_challenge.enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.http_challenge.port
    );
    println!("  Auth mode:     {:?}", config.auth.mode);
    println!("  Flock entries: {}", config.flock.len());
    println!();

    for (label, path) in &[
        ("TLS cert", &config.tls.cert_path),
        ("TLS key", &config.tls.cert_path),
        ("mTLS client cert", &config.mtls.cert_path),
        ("mTLS client key", &config.mtls.key_path),
    ] {
        if path.exists() {
            println!("  [ok] {}: {}", label, path.display());
        } else {
            println!("  [missing] {}: {}", label, path.display());
        }
    }

    if let Some(ca) = &config.mtls.ca_path {
        if ca.exists() {
            println!("  [ok] CA: {}", ca.display());
        } else {
            println!("  [missing] CA: {}", ca.display());
        }
    }

    println!();

    println!("Checking Shepherd connectivity...");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    match client
        .get(format!("{}/health", config.shepherd_url))
        .send()
        .await
    {
        Ok(resp) => {
            println!("  Shepherd responded: HTTP {}", resp.status());
        }
        Err(e) => {
            println!("  Shepherd unreachable: {}", e);
            println!("  (This is expected if Shepherd is not running or not yet configured.)");
        }
    }

    println!();
    if ok {
        println!("Config looks good.");
    } else {
        println!("Config has issues — see above.");
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Logging setup
// ---------------------------------------------------------------------------

fn init_logging(level: corgi::config::LogLevel) {
    credo_lib::log::init_logging(credo_lib::LogLevel::from_str(level.as_tracing_filter()));
}
