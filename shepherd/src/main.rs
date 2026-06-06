#![allow(dead_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand::Rng;

use shepherd::config::load_config;
use shepherd::state::AppState;

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
    /// Start Shepherd in bootstrap mode (prints one-time admin token)
    Server {
        #[arg(long)]
        vigil_secret: String,
    },
    /// Issue an admin cert via the running bootstrap server
    Admin {
        #[arg(long)]
        admin_token: String,
        #[arg(long)]
        identity_uri: String,
        #[arg(long)]
        out_cert: String,
        #[arg(long)]
        out_key: String,
        #[arg(long)]
        domain: String,
    },
    /// Enroll a Corgi node via the running bootstrap server
    Corgi {
        #[arg(long)]
        admin_token: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        identity_uri: String,
        #[arg(long)]
        corgi_url: String,
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
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    match cli.command {
        Commands::Server { cmd } => match cmd {
            ServerCommands::Start => cmd_server_start().await,
            ServerCommands::CheckConfig => cmd_check_config().await,
        },
        Commands::Bootstrap { cmd } => match cmd {
            BootstrapCommands::Server { vigil_secret } => {
                cmd_bootstrap_server_start(&vigil_secret).await
            }
            BootstrapCommands::Admin { admin_token, identity_uri, out_cert, out_key, domain } => {
                cmd_bootstrap_admin(&admin_token, &identity_uri, &out_cert, &out_key, &domain).await
            }
            BootstrapCommands::Corgi { admin_token, name, token, fingerprint, identity_uri, corgi_url } => {
                cmd_bootstrap_corgi(&admin_token, &name, &token, &fingerprint, &identity_uri, &corgi_url).await
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
    run_server(config).await
}

async fn run_server(config: shepherd::config::ShepherdConfig) -> Result<()> {
    let tls_config = shepherd::server::build_server_tls(&config)
        .context("Building mTLS server TLS config")?;
    run_server_with_tls(config, tls_config, None, None, None).await
}

async fn run_server_with_tls(
    config: shepherd::config::ShepherdConfig,
    tls_config: std::sync::Arc<rustls::ServerConfig>,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    admin_token: Option<String>,
) -> Result<()> {
    init_logging(config.log_level);

    tracing::info!(
        agent_port = config.agent_port,
        dashboard_port = config.dashboard_port,
        bind = %config.bind,
        "Shepherd starting"
    );

    let jwt_keys = shepherd::jwt::load_or_generate(&config.jwt_signing_key_path)
        .context("Loading JWT signing key")?;

    let account_list = shepherd::accounts::load_accounts(&config.accounts_path)
        .context("Loading accounts")?;
    tracing::info!(count = account_list.len(), "Loaded accounts");

    let corgi_list = shepherd::corgis::load_corgis(&config.corgis_config_path)
        .context("Loading corgis config")?;
    tracing::info!(count = corgi_list.len(), "Loaded corgis");

    let assignment_list = shepherd::assignments::load_assignments(&config.assignments_config_path)
        .context("Loading assignments")?;
    tracing::info!(count = assignment_list.len(), "Loaded assignments");

    let ca_map = shepherd::cas::load_cas(&config.ca_config_path)
        .context("Loading CA config")?;
    tracing::info!(count = ca_map.len(), "Loaded CAs");

    let state = AppState::new(config, jwt_keys, account_list, ca_map, cert_pem, key_pem, admin_token);
    *state.corgis.write().await = corgi_list;
    *state.assignments.write().await = assignment_list;

    tokio::spawn(shepherd::poll::run_health_check_loop(state.clone()));
    tokio::spawn(shepherd::poll::run_poll_loop(state.clone()));

    shepherd::server::run(state, tls_config).await?;
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

    let checks = shepherd::config::validate_paths(&config);
    let mut all_ok = true;
    for (label, ok) in &checks {
        let tag = if *ok { "[ok]" } else { "[missing]" };
        println!("  {tag} {label}");
        if !ok {
            all_ok = false;
        }
    }
    println!();

    match shepherd::jwt::load_or_generate(&config.jwt_signing_key_path) {
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
// bootstrap helpers
// ---------------------------------------------------------------------------

fn gen_key_and_csr(cn: &str, dns_sans: &[&str], uri_sans: &[&str]) -> Result<(String, String)> {
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};

    let mut params = CertificateParams::new(dns_sans.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    for uri in uri_sans {
        params.subject_alt_names.push(SanType::URI(uri.to_string()));
    }
    let cert = Certificate::from_params(params).context("Generating CSR params")?;
    let key_pem = cert.serialize_private_key_pem();
    let csr_pem = cert.serialize_request_pem().context("Serializing CSR")?;
    Ok((key_pem, csr_pem))
}

/// Build a plain (no client cert) HTTPS client that trusts the configured CA.
/// SNI is set to commonName so the cert validates against localhost connections.
fn build_shepherd_plain_client(config: &shepherd::config::ShepherdConfig) -> Result<reqwest::Client> {
    let ca_path = config.shepherd_ca_path.as_ref()
        .unwrap_or(&config.tls.client_ca_path);
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("Reading CA bundle: {}", ca_path.display()))?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
        .context("Parsing CA cert")?;
    let host = config.common_name.as_deref().unwrap_or("localhost");
    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .resolve(host, format!("127.0.0.1:{}", config.dashboard_port).parse()?)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Building plain shepherd API client")
}

// ---------------------------------------------------------------------------
// bootstrap commands
// ---------------------------------------------------------------------------

async fn cmd_bootstrap_server_start(vigil_secret: &str) -> Result<()> {
    let config = load_config().context("Loading config")?;

    let vigil_url = config.vigil_url.as_deref()
        .ok_or_else(|| anyhow::anyhow!("Config missing vigilUrl"))?;
    let common_name = config.common_name.as_deref()
        .ok_or_else(|| anyhow::anyhow!("Config missing commonName"))?;
    let identity_uri = config.identity_uri.as_deref().unwrap_or("");

    // Generate shepherd's identity key+CSR entirely in memory
    let (key_pem, csr_pem) = gen_key_and_csr(
        common_name,
        &[common_name],
        &[identity_uri],
    ).context("Generating shepherd key and CSR")?;

    // Bootstrap-enroll with Vigil using a plain (no client cert) connection
    let vigil_ca_path = config.shepherd_ca_path.as_ref()
        .unwrap_or(&config.tls.client_ca_path);
    let vigil_ca_pem = std::fs::read(vigil_ca_path)
        .with_context(|| format!("Reading Vigil CA: {}", vigil_ca_path.display()))?;
    let vigil_ca_cert = reqwest::Certificate::from_pem(&vigil_ca_pem)
        .context("Parsing Vigil CA cert")?;
    let plain_client = reqwest::Client::builder()
        .add_root_certificate(vigil_ca_cert)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Building plain Vigil client")?;

    let resp = plain_client
        .post(format!("{}/bootstrap", vigil_url))
        .json(&serde_json::json!({
            "secret": vigil_secret,
            "csr":    csr_pem,
            "sans":   [common_name],
        }))
        .send()
        .await
        .context("Calling vigil /bootstrap")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Vigil bootstrap returned {}: {}", status, body);
    }
    let body: serde_json::Value = resp.json().await.context("Parsing vigil bootstrap response")?;
    let cert_pem  = body["cert"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing 'cert' in vigil bootstrap response"))?;
    let chain_pem = body["chain"].as_str().unwrap_or("");
    let fullchain  = format!("{}{}", cert_pem, chain_pem);

    // Build TLS config entirely from in-memory PEM — nothing touches disk
    let tls_config = credo_lib::tls::build_server_tls_from_pem(
        &fullchain,
        &key_pem,
        Some(&config.tls.client_ca_path),
    ).context("Building bootstrap mTLS server TLS config")?;

    let admin_token = hex::encode({
        let mut b = [0u8; 32];
        rand::thread_rng().fill(&mut b);
        b
    });
    println!("\nShepherd bootstrap admin token: {}\n", admin_token);

    // Pass cert+key PEM to AppState so the vigil client can be built from memory,
    // and store the admin token for bootstrap API endpoint auth.
    run_server_with_tls(config, tls_config, Some(fullchain), Some(key_pem), Some(admin_token)).await
}

async fn cmd_bootstrap_admin(
    admin_token: &str,
    identity_uri: &str,
    out_cert: &str,
    out_key: &str,
    domain: &str,
) -> Result<()> {
    let config = load_config().context("Loading config")?;
    let shepherd_url = shepherd_dashboard_url(&config);

    // Generate the admin key+CSR locally — the private key never leaves this process
    let cn = format!("admin.{}", domain);
    let (key_pem, csr_pem) = gen_key_and_csr(&cn, &[&cn], &[identity_uri])
        .context("Generating admin CSR")?;

    // Ask the running shepherd server to sign the CSR via Vigil
    let client = build_shepherd_plain_client(&config)?;
    let resp = client
        .post(format!("{}/bootstrap/admin-cert", shepherd_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&serde_json::json!({ "csrPem": csr_pem, "days": 365 }))
        .send()
        .await
        .context("POST /bootstrap/admin-cert")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("bootstrap admin-cert returned {}: {}", status, body);
    }
    let body: serde_json::Value = resp.json().await.context("Parsing admin-cert response")?;
    let cert_pem = body["certPem"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing certPem in response"))?;

    for path in [out_cert, out_key] {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(out_cert, cert_pem).with_context(|| format!("Writing admin cert: {}", out_cert))?;
    std::fs::write(out_key,  &key_pem).with_context(|| format!("Writing admin key: {}",  out_key))?;

    println!("Admin cert issued:  {}", out_cert);
    println!("Admin key written:  {}", out_key);
    Ok(())
}

async fn cmd_bootstrap_corgi(
    admin_token: &str,
    name: &str,
    token: &str,
    fingerprint: &str,
    identity_uri: &str,
    corgi_url: &str,
) -> Result<()> {
    let config = load_config().context("Loading config")?;
    let shepherd_url = shepherd_dashboard_url(&config);

    // Delegate the full enrollment sequence to the running shepherd server
    let client = build_shepherd_plain_client(&config)?;
    let resp = client
        .post(format!("{}/bootstrap/corgi", shepherd_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&serde_json::json!({
            "name":        name,
            "token":       token,
            "fingerprint": fingerprint,
            "identityUri": identity_uri,
            "corgiUrl":    corgi_url,
        }))
        .send()
        .await
        .context("POST /bootstrap/corgi")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("bootstrap corgi returned {}: {}", status, body);
    }

    println!("Corgi '{}' enrolled successfully.", name);
    Ok(())
}

/// Derive the shepherd dashboard URL for CLI client commands.
/// Uses commonName as the TLS hostname; reqwest resolves it to 127.0.0.1 via .resolve().
fn shepherd_dashboard_url(config: &shepherd::config::ShepherdConfig) -> String {
    let host = config.common_name.as_deref().unwrap_or("localhost");
    format!("https://{}:{}", host, config.dashboard_port)
}

async fn cmd_cert_renew(cert_name: &str) -> Result<()> {
    println!("Renew cert '{cert_name}' — not yet implemented.");
    Ok(())
}

async fn cmd_cert_store() -> Result<()> {
    let config = load_config().context("Loading config")?;
    let entries = shepherd::cert_store::list_cert_store_entries(&config.cert_store_dir);
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
    match shepherd::cert_store::read_cert_store_entry(&config.cert_store_dir, cert_name) {
        Some(entry) => println!("{}", serde_json::to_string_pretty(&entry)?),
        None => println!("Cert '{cert_name}' not found in store."),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Logging setup
// ---------------------------------------------------------------------------

fn init_logging(level: shepherd::config::LogLevel) {
    credo_lib::log::init_logging(credo_lib::LogLevel::from_str(level.as_tracing_filter()));
}
