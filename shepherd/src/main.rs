use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand::Rng;

use shepherd::config::load_config;
use shepherd::state::AppState;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "shepherd",
    about = "TLS certificate management control plane",
    version
)]
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
    /// Account management commands
    Account {
        #[command(subcommand)]
        cmd: AccountCommands,
    },
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Start the Shepherd server
    Start,
    /// Stop a running Shepherd server
    Stop,
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
    /// Enroll a Corgi node
    ///
    /// Bootstrap window: supply --admin-token (one-time token from `bootstrap server`).
    /// Production: supply --admin-cert + --admin-key (your admin mTLS credentials).
    Corgi {
        /// One-time admin token (bootstrap window only)
        #[arg(long)]
        admin_token: Option<String>,
        /// Path to admin cert PEM (production mTLS auth)
        #[arg(long)]
        admin_cert: Option<String>,
        /// Path to admin key PEM (production mTLS auth)
        #[arg(long)]
        admin_key: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        identity_uri: String,
        /// Corgi API URL; if omitted, looked up from shepherd.corgis.json by name
        #[arg(long)]
        corgi_url: Option<String>,
        /// CA name to use for the corgi's own cert assignment (default: vigil)
        #[arg(long, default_value = "vigil")]
        ca: String,
    },
}

#[derive(Subcommand)]
enum CertCommands {
    /// Trigger renewal for a certificate
    Renew {
        cert_name: String,
        /// Path to admin PEM certificate for mTLS auth
        #[arg(long)]
        admin_cert: String,
        /// Path to admin PEM private key for mTLS auth
        #[arg(long)]
        admin_key: String,
    },
    /// List certstore entries
    Store,
    /// Inspect a certstore entry
    Inspect { cert_name: String },
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Issue a cert and register a new account (requires a running Shepherd)
    Add {
        /// Short account name — must be unique
        #[arg(long)]
        name: String,
        /// Human-readable display name
        #[arg(long)]
        display_name: String,
        /// Role: admin | operator | readonly
        #[arg(long, default_value = "admin")]
        role: String,
        /// URI SAN for the cert; defaults to vigil://credo/admin/<name>
        #[arg(long)]
        identity_uri: Option<String>,
        /// Path to write the issued cert PEM (prompted if absent)
        #[arg(long)]
        out_cert: Option<String>,
        /// Path to write the generated key PEM (prompted if absent)
        #[arg(long)]
        out_key: Option<String>,
        /// Path to admin cert PEM used to authenticate with Shepherd
        #[arg(long)]
        admin_cert: String,
        /// Path to admin key PEM used to authenticate with Shepherd
        #[arg(long)]
        admin_key: String,
    },
    /// Issue a new cert for an existing account, preserving its identity URIs
    Rotate {
        /// Account name to rotate the cert for
        #[arg(long)]
        name: String,
        /// Path to write the new cert PEM (prompted if absent)
        #[arg(long)]
        out_cert: Option<String>,
        /// Path to write the new key PEM (prompted if absent)
        #[arg(long)]
        out_key: Option<String>,
        /// Path to admin cert PEM (own cert or another admin's)
        #[arg(long)]
        admin_cert: String,
        /// Path to admin key PEM
        #[arg(long)]
        admin_key: String,
    },
    /// List all accounts
    List,
    /// Remove an account by name
    Remove {
        /// Account name to remove
        #[arg(long)]
        name: String,
    },
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
            ServerCommands::Stop => cmd_server_stop(),
            ServerCommands::CheckConfig => cmd_check_config().await,
        },
        Commands::Bootstrap { cmd } => match cmd {
            BootstrapCommands::Server { vigil_secret } => {
                cmd_bootstrap_server_start(&vigil_secret).await
            }
            BootstrapCommands::Admin {
                admin_token,
                identity_uri,
                out_cert,
                out_key,
                domain,
            } => {
                cmd_bootstrap_admin(&admin_token, &identity_uri, &out_cert, &out_key, &domain).await
            }
            BootstrapCommands::Corgi {
                admin_token,
                admin_cert,
                admin_key,
                name,
                token,
                fingerprint,
                identity_uri,
                corgi_url,
                ca,
            } => {
                cmd_bootstrap_corgi(BootstrapCorgiArgs {
                    admin_token: admin_token.as_deref(),
                    admin_cert: admin_cert.as_deref(),
                    admin_key: admin_key.as_deref(),
                    name: &name,
                    token: &token,
                    fingerprint: &fingerprint,
                    identity_uri: &identity_uri,
                    corgi_url: corgi_url.as_deref(),
                    ca: &ca,
                })
                .await
            }
        },
        Commands::Cert { cmd } => match cmd {
            CertCommands::Renew {
                cert_name,
                admin_cert,
                admin_key,
            } => cmd_cert_renew(&cert_name, &admin_cert, &admin_key).await,
            CertCommands::Store => cmd_cert_store().await,
            CertCommands::Inspect { cert_name } => cmd_cert_inspect(&cert_name).await,
        },
        Commands::Account { cmd } => match cmd {
            AccountCommands::Add {
                name,
                display_name,
                role,
                identity_uri,
                out_cert,
                out_key,
                admin_cert,
                admin_key,
            } => {
                cmd_account_add(AccountAddArgs {
                    name: &name,
                    display_name: &display_name,
                    role_str: &role,
                    identity_uri: identity_uri.as_deref(),
                    out_cert: out_cert.as_deref(),
                    out_key: out_key.as_deref(),
                    admin_cert: &admin_cert,
                    admin_key: &admin_key,
                })
                .await
            }
            AccountCommands::Rotate {
                name,
                out_cert,
                out_key,
                admin_cert,
                admin_key,
            } => {
                cmd_account_rotate(
                    &name,
                    out_cert.as_deref(),
                    out_key.as_deref(),
                    &admin_cert,
                    &admin_key,
                )
                .await
            }
            AccountCommands::List => cmd_account_list(),
            AccountCommands::Remove { name } => cmd_account_remove(&name),
        },
    }
}

// ---------------------------------------------------------------------------
// server start
// ---------------------------------------------------------------------------

async fn cmd_server_start() -> Result<()> {
    let pid_path = std::path::PathBuf::from("shepherd.pid");
    if pid_path.exists() {
        if let Ok(existing) = credo_lib::pid::read_pid(&pid_path) {
            if credo_lib::pid::is_running(existing) {
                anyhow::bail!("shepherd is already running (PID {})", existing);
            }
        }
        credo_lib::pid::remove_pid(&pid_path);
    }
    let _pid_guard = credo_lib::pid::PidGuard::new(pid_path)?;

    let config = load_config().context("Loading config")?;
    run_server(config).await
}

fn cmd_server_stop() -> Result<()> {
    let pid_path = std::path::PathBuf::from("shepherd.pid");
    credo_lib::pid::stop_service(&pid_path, 15)?;
    println!("shepherd stopped");
    Ok(())
}

async fn run_server(config: shepherd::config::ShepherdConfig) -> Result<()> {
    let tls_config =
        shepherd::server::build_server_tls(&config).context("Building mTLS server TLS config")?;
    run_server_with_tls(config, tls_config, None, None, None).await
}

async fn run_server_with_tls(
    config: shepherd::config::ShepherdConfig,
    initial_tls_config: std::sync::Arc<rustls::ServerConfig>,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    admin_token: Option<String>,
) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    credo_lib::log::init_logging(config.log_level);

    tracing::info!(
        agent_port = config.agent_port,
        dashboard_port = config.dashboard_port,
        bind = %config.bind,
        "Shepherd starting"
    );

    let jwt_keys = shepherd::jwt::load_or_generate(&config.jwt_signing_key_path)
        .context("Loading JWT signing key")?;

    let account_list =
        shepherd::accounts::load_accounts(&config.accounts_path).context("Loading accounts")?;
    tracing::info!(count = account_list.len(), "Loaded accounts");

    let corgi_list = shepherd::corgis::load_corgis(&config.corgis_config_path)
        .context("Loading corgis config")?;
    tracing::info!(count = corgi_list.len(), "Loaded corgis");

    let assignment_list = shepherd::assignments::load_assignments(&config.assignments_config_path)
        .context("Loading assignments")?;
    tracing::info!(count = assignment_list.len(), "Loaded assignments");

    let ca_map = shepherd::cas::load_cas(&config.ca_config_path).context("Loading CA config")?;
    tracing::info!(count = ca_map.len(), "Loaded CAs");

    let state = AppState::new(
        config,
        jwt_keys,
        account_list,
        ca_map,
        cert_pem,
        key_pem,
        admin_token,
    );
    *state.corgis.write().await = corgi_list;
    *state.assignments.write().await = assignment_list;

    tokio::spawn(shepherd::poll::run_health_check_loop(state.clone()));
    tokio::spawn(shepherd::poll::run_poll_loop(state.clone()));

    let mut hup = signal(SignalKind::hangup()).context("Registering SIGHUP handler")?;
    let mut tls_config = initial_tls_config;

    loop {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut server = tokio::spawn({
            let s = state.clone();
            let tls = tls_config.clone();
            let rx = shutdown_rx;
            async move { shepherd::server::run(s, tls, rx).await }
        });

        tokio::select! {
            _ = hup.recv() => {
                tracing::info!("SIGHUP received — reloading config");
                match shepherd::config::load_config() {
                    Ok(new_cfg) => {
                        // Rebuild TLS before swapping config so the new cert is ready
                        match shepherd::server::build_server_tls(&new_cfg) {
                            Ok(new_tls) => { tls_config = new_tls; }
                            Err(e) => tracing::warn!(error=%e, "TLS rebuild failed; keeping current TLS config"),
                        }
                        tracing::info!(
                            agent_port = new_cfg.agent_port,
                            dashboard_port = new_cfg.dashboard_port,
                            "Config reloaded"
                        );
                        state.config.store(std::sync::Arc::new(new_cfg));
                    }
                    Err(e) => tracing::warn!(error=%e, "Config reload failed; keeping current config"),
                }
                // Stop current servers; next loop iteration restarts them with new ports/TLS
                let _ = shutdown_tx.send(true);
                let _ = (&mut server).await;
            }
            result = &mut server => {
                return result.context("Server task panicked")?.context("Server error");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// server check-config
// ---------------------------------------------------------------------------

async fn cmd_check_config() -> Result<()> {
    let config = load_config().context("Loading config")?;
    credo_lib::log::init_logging(config.log_level);

    println!("Config: {}", config.config_path.display());
    println!("  Agent port:     {}:{}", config.bind, config.agent_port);
    println!(
        "  Dashboard port: {}:{}",
        config.bind, config.dashboard_port
    );
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
        Ok(_) => println!(
            "  [ok] JWT signing key: {}",
            config.jwt_signing_key_path.display()
        ),
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

    let mut params =
        CertificateParams::new(dns_sans.iter().map(|s| s.to_string()).collect::<Vec<_>>());
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
fn build_shepherd_plain_client(
    config: &shepherd::config::ShepherdConfig,
) -> Result<reqwest::Client> {
    let ca_path = config
        .shepherd_ca_path
        .as_ref()
        .unwrap_or(&config.tls.client_ca_path);
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("Reading CA bundle: {}", ca_path.display()))?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).context("Parsing CA cert")?;
    let host = config.common_name.as_deref().unwrap_or("localhost");
    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .resolve(
            host,
            format!("127.0.0.1:{}", config.dashboard_port).parse()?,
        )
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Building plain shepherd API client")
}

/// Build an mTLS HTTPS client that presents admin cert+key to the shepherd server.
fn build_shepherd_mtls_client(
    config: &shepherd::config::ShepherdConfig,
    cert_path: &str,
    key_path: &str,
) -> Result<reqwest::Client> {
    let ca_path = config
        .shepherd_ca_path
        .as_ref()
        .unwrap_or(&config.tls.client_ca_path);
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("Reading CA bundle: {}", ca_path.display()))?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).context("Parsing CA cert")?;
    let mut identity_pem =
        std::fs::read(cert_path).with_context(|| format!("Reading admin cert: {cert_path}"))?;
    identity_pem.extend_from_slice(
        &std::fs::read(key_path).with_context(|| format!("Reading admin key: {key_path}"))?,
    );
    let identity = reqwest::Identity::from_pem(&identity_pem).context("Building mTLS identity")?;
    let host = config.common_name.as_deref().unwrap_or("localhost");
    reqwest::Client::builder()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .resolve(
            host,
            format!("127.0.0.1:{}", config.dashboard_port).parse()?,
        )
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Building mTLS shepherd API client")
}

// ---------------------------------------------------------------------------
// bootstrap commands
// ---------------------------------------------------------------------------

async fn cmd_bootstrap_server_start(vigil_secret: &str) -> Result<()> {
    let config = load_config().context("Loading config")?;

    let vigil_url = config
        .vigil_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Config missing vigilUrl"))?;
    let common_name = config
        .common_name
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Config missing commonName"))?;
    let identity_uri = config.identity_uri.as_deref().unwrap_or("");

    // Generate shepherd's identity key+CSR entirely in memory
    let (key_pem, csr_pem) = gen_key_and_csr(common_name, &[common_name], &[identity_uri])
        .context("Generating shepherd key and CSR")?;

    // Bootstrap-enroll with Vigil using a plain (no client cert) connection
    let vigil_ca_path = config
        .shepherd_ca_path
        .as_ref()
        .unwrap_or(&config.tls.client_ca_path);
    let vigil_ca_pem = std::fs::read(vigil_ca_path)
        .with_context(|| format!("Reading Vigil CA: {}", vigil_ca_path.display()))?;
    let vigil_ca_cert =
        reqwest::Certificate::from_pem(&vigil_ca_pem).context("Parsing Vigil CA cert")?;
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
    let body: serde_json::Value = resp
        .json()
        .await
        .context("Parsing vigil bootstrap response")?;
    let cert_pem = body["cert"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing 'cert' in vigil bootstrap response"))?;
    let chain_pem = body["chain"].as_str().unwrap_or("");
    let fullchain = format!("{}{}", cert_pem, chain_pem);

    // Build TLS config entirely from in-memory PEM — nothing touches disk
    let tls_config = credo_lib::tls::build_server_tls_from_pem(
        &fullchain,
        &key_pem,
        Some(&config.tls.client_ca_path),
    )
    .context("Building bootstrap mTLS server TLS config")?;

    let admin_token = hex::encode({
        let mut b = [0u8; 32];
        rand::thread_rng().fill(&mut b);
        b
    });
    println!("\nShepherd bootstrap admin token: {}\n", admin_token);

    // Pass cert+key PEM to AppState so the vigil client can be built from memory,
    // and store the admin token for bootstrap API endpoint auth.
    run_server_with_tls(
        config,
        tls_config,
        Some(fullchain),
        Some(key_pem),
        Some(admin_token),
    )
    .await
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
    let (key_pem, csr_pem) =
        gen_key_and_csr(&cn, &[&cn], &[identity_uri]).context("Generating admin CSR")?;

    // Ask the running shepherd server to sign the CSR via Vigil
    let client = build_shepherd_plain_client(&config)?;
    let resp = client
        .post(format!("{}/bootstrap/admin-cert", shepherd_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&serde_json::json!({ "csrPem": csr_pem, "days": 365, "identityUri": identity_uri }))
        .send()
        .await
        .context("POST /bootstrap/admin-cert")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("bootstrap admin-cert returned {}: {}", status, body);
    }
    let body: serde_json::Value = resp.json().await.context("Parsing admin-cert response")?;
    let cert_pem = body["certPem"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing certPem in response"))?;

    for path in [out_cert, out_key] {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(out_cert, cert_pem)
        .with_context(|| format!("Writing admin cert: {}", out_cert))?;
    std::fs::write(out_key, &key_pem).with_context(|| format!("Writing admin key: {}", out_key))?;

    println!("Admin cert issued:  {}", out_cert);
    println!("Admin key written:  {}", out_key);
    Ok(())
}

struct BootstrapCorgiArgs<'a> {
    admin_token: Option<&'a str>,
    admin_cert: Option<&'a str>,
    admin_key: Option<&'a str>,
    name: &'a str,
    token: &'a str,
    fingerprint: &'a str,
    identity_uri: &'a str,
    corgi_url: Option<&'a str>,
    ca: &'a str,
}

async fn cmd_bootstrap_corgi(args: BootstrapCorgiArgs<'_>) -> Result<()> {
    let BootstrapCorgiArgs {
        admin_token,
        admin_cert,
        admin_key,
        name,
        token,
        fingerprint,
        identity_uri,
        corgi_url,
        ca,
    } = args;
    let config = load_config().context("Loading config")?;
    let shepherd_url = shepherd_dashboard_url(&config);

    // Resolve corgi URL: use explicit arg or look up from local corgis config by name
    let resolved_url: String = match corgi_url {
        Some(u) => u.to_string(),
        None => {
            let corgis = shepherd::corgis::load_corgis(&config.corgis_config_path)
                .context("Loading corgis config")?;
            corgis
                .into_iter()
                .find(|c| c.name == name)
                .map(|c| c.url)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Corgi '{name}' not found in corgis config; supply --corgi-url explicitly"
                    )
                })?
        }
    };

    let payload = serde_json::json!({
        "name":        name,
        "token":       token,
        "fingerprint": fingerprint,
        "identityUri": identity_uri,
        "corgiUrl":    resolved_url,
        "ca":          ca,
    });

    let (client, endpoint, auth_header) = match admin_token {
        Some(t) => (
            build_shepherd_plain_client(&config)?,
            format!("{shepherd_url}/bootstrap/corgi"),
            Some(format!("Bearer {t}")),
        ),
        None => {
            let cert = admin_cert.ok_or_else(|| {
                anyhow::anyhow!(
                    "Provide --admin-token (bootstrap mode) or --admin-cert + --admin-key (production)"
                )
            })?;
            let key = admin_key.ok_or_else(|| {
                anyhow::anyhow!("--admin-key is required when using --admin-cert")
            })?;
            (
                build_shepherd_mtls_client(&config, cert, key)?,
                format!("{shepherd_url}/admin/enroll-corgi"),
                None,
            )
        }
    };

    let mut req = client.post(&endpoint).json(&payload);
    if let Some(h) = auth_header {
        req = req.header("Authorization", h);
    }
    let resp = req.send().await.context("POST corgi enrollment")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("corgi enrollment returned {}: {}", status, body);
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

async fn cmd_cert_renew(cert_name: &str, admin_cert: &str, admin_key: &str) -> Result<()> {
    let config = load_config().context("Loading config")?;
    let shepherd_url = shepherd_dashboard_url(&config);
    let client = build_shepherd_mtls_client(&config, admin_cert, admin_key)?;
    let url = format!("{}/admin/renew/{}", shepherd_url, cert_name);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({}))
        .send()
        .await
        .context("POST /admin/renew")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("renew returned {}: {}", status, body);
    }
    let body: serde_json::Value = resp.json().await.context("Parsing response")?;
    println!(
        "Renewal triggered for '{}': job {}",
        cert_name,
        body["jobId"].as_str().unwrap_or("?")
    );
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
// account commands
// ---------------------------------------------------------------------------

/// Expand a leading `~/` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    path.to_string()
}

/// Print `prompt` and read a line; return `default` if the user enters nothing.
fn prompt_path(prompt: &str, default: &str) -> String {
    use std::io::{self, Write};
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Write `contents` to `path`, creating parent directories as needed.
fn write_file(path: &str, contents: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory for: {path}"))?;
    }
    std::fs::write(path, contents).with_context(|| format!("Writing: {path}"))?;
    Ok(())
}

struct AccountAddArgs<'a> {
    name: &'a str,
    display_name: &'a str,
    role_str: &'a str,
    identity_uri: Option<&'a str>,
    out_cert: Option<&'a str>,
    out_key: Option<&'a str>,
    admin_cert: &'a str,
    admin_key: &'a str,
}

async fn cmd_account_add(args: AccountAddArgs<'_>) -> Result<()> {
    let AccountAddArgs {
        name,
        display_name,
        role_str,
        identity_uri,
        out_cert,
        out_key,
        admin_cert,
        admin_key,
    } = args;
    let config = load_config().context("Loading config")?;
    let shepherd_url = shepherd_dashboard_url(&config);

    // Fail early if the account already exists
    let mut accounts =
        shepherd::accounts::load_accounts(&config.accounts_path).context("Loading accounts")?;
    if accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("Account '{name}' already exists");
    }

    // Derive identity URI: explicit flag or vigil://credo/admin/<name>
    let uri = identity_uri
        .map(str::to_string)
        .unwrap_or_else(|| format!("vigil://credo/admin/{}", name));

    // Resolve output paths (interactive prompt if not supplied)
    let out_cert = expand_tilde(&out_cert.map(str::to_string).unwrap_or_else(|| {
        prompt_path(
            &format!("Output cert path [~/.vigil/{name}.pem]: "),
            &format!("~/.vigil/{name}.pem"),
        )
    }));
    let out_key = expand_tilde(&out_key.map(str::to_string).unwrap_or_else(|| {
        prompt_path(
            &format!("Output key path [~/.vigil/{name}.key]: "),
            &format!("~/.vigil/{name}.key"),
        )
    }));

    // Generate key + CSR locally; private key never leaves this process
    let (key_pem, csr_pem) =
        gen_key_and_csr(name, &[], &[&uri]).context("Generating key and CSR")?;

    // Ask the running Shepherd to sign the CSR via Vigil
    let client = build_shepherd_mtls_client(&config, admin_cert, admin_key)?;
    let resp = client
        .post(format!("{}/admin/identity-cert", shepherd_url))
        .json(&serde_json::json!({ "csrPem": csr_pem, "days": 365 }))
        .send()
        .await
        .context("POST /admin/identity-cert")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("/admin/identity-cert returned {}: {}", status, body);
    }
    let body: serde_json::Value = resp.json().await.context("Parsing response")?;
    let cert_pem = body["certPem"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing certPem in response"))?;

    // Write cert and key to disk
    write_file(&out_cert, cert_pem)?;
    write_file(&out_key, &key_pem)?;

    // Register the account in shepherd.accounts.json
    let role = credo_lib::types::Role::from_str(role_str);
    let account = shepherd::types::Account {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        display_name: display_name.to_string(),
        role,
        active: true,
        identities: vec![uri.clone()],
        notes: String::new(),
        created_at: Some(chrono::Utc::now()),
    };
    shepherd::accounts::create_account(&mut accounts, account);
    shepherd::accounts::save_accounts(&config.accounts_path, &accounts)
        .context("Saving accounts")?;

    println!("Account '{name}' created.");
    println!("  Identity: {uri}");
    println!("  Cert:     {out_cert}");
    println!("  Key:      {out_key}");
    Ok(())
}

async fn cmd_account_rotate(
    name: &str,
    out_cert: Option<&str>,
    out_key: Option<&str>,
    admin_cert: &str,
    admin_key: &str,
) -> Result<()> {
    let config = load_config().context("Loading config")?;
    let shepherd_url = shepherd_dashboard_url(&config);

    // Load the existing account
    let accounts =
        shepherd::accounts::load_accounts(&config.accounts_path).context("Loading accounts")?;
    let account = accounts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| anyhow::anyhow!("No account named '{name}' found"))?;

    if account.identities.is_empty() {
        anyhow::bail!("Account '{name}' has no identity URIs — cannot rotate cert");
    }
    let uri_sans: Vec<&str> = account.identities.iter().map(String::as_str).collect();

    // Resolve output paths
    let out_cert = expand_tilde(&out_cert.map(str::to_string).unwrap_or_else(|| {
        prompt_path(
            &format!("Output cert path [~/.vigil/{name}.pem]: "),
            &format!("~/.vigil/{name}.pem"),
        )
    }));
    let out_key = expand_tilde(&out_key.map(str::to_string).unwrap_or_else(|| {
        prompt_path(
            &format!("Output key path [~/.vigil/{name}.key]: "),
            &format!("~/.vigil/{name}.key"),
        )
    }));

    // Generate new key + CSR, preserving the same URI SANs
    let (key_pem, csr_pem) =
        gen_key_and_csr(name, &[], &uri_sans).context("Generating key and CSR")?;

    // Sign via Shepherd → Vigil
    let client = build_shepherd_mtls_client(&config, admin_cert, admin_key)?;
    let resp = client
        .post(format!("{}/admin/identity-cert", shepherd_url))
        .json(&serde_json::json!({ "csrPem": csr_pem, "days": 365 }))
        .send()
        .await
        .context("POST /admin/identity-cert")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("/admin/identity-cert returned {}: {}", status, body);
    }
    let body: serde_json::Value = resp.json().await.context("Parsing response")?;
    let cert_pem = body["certPem"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing certPem in response"))?;

    // Write new cert and key to disk
    write_file(&out_cert, cert_pem)?;
    write_file(&out_key, &key_pem)?;

    println!("Cert rotated for '{name}'.");
    println!("  Cert: {out_cert}");
    println!("  Key:  {out_key}");
    println!("  Accounts file unchanged (identity URIs preserved).");
    Ok(())
}

fn cmd_account_list() -> Result<()> {
    let config = load_config().context("Loading config")?;
    let accounts =
        shepherd::accounts::load_accounts(&config.accounts_path).context("Loading accounts")?;

    if accounts.is_empty() {
        println!("No accounts found in {}", config.accounts_path.display());
        return Ok(());
    }

    for account in &accounts {
        let role_str = serde_json::to_value(&account.role)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let active = if account.active { "active" } else { "inactive" };
        println!(
            "{} ({}) — {} {}",
            account.name, account.display_name, role_str, active
        );
        for uri in &account.identities {
            println!("  {uri}");
        }
    }
    Ok(())
}

fn cmd_account_remove(name: &str) -> Result<()> {
    let config = load_config().context("Loading config")?;
    let mut accounts =
        shepherd::accounts::load_accounts(&config.accounts_path).context("Loading accounts")?;

    let id = accounts
        .iter()
        .find(|a| a.name == name)
        .map(|a| a.id.clone())
        .ok_or_else(|| anyhow::anyhow!("No account named '{name}' found"))?;

    shepherd::accounts::delete_account(&mut accounts, &id);
    shepherd::accounts::save_accounts(&config.accounts_path, &accounts)
        .context("Saving accounts")?;
    println!("Account '{name}' removed.");
    Ok(())
}
