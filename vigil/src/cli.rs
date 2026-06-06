use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "vigil", about = "Vigil private certificate authority", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start Vigil in bootstrap mode (ephemeral TLS cert + one-time enrollment secret)
    Bootstrap,
    /// Server commands
    Server {
        #[command(subcommand)]
        cmd: ServerCommands,
    },
    /// CA management commands
    Ca {
        #[command(subcommand)]
        cmd: CaCommands,
    },
    /// ACME client commands
    Acme {
        #[command(subcommand)]
        cmd: AcmeCommands,
    },
}

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Start the Vigil server
    Start {
        /// Start in bootstrap mode (generates ephemeral TLS cert + secret)
        #[arg(long)]
        bootstrap: bool,
    },
    /// Validate config and CA material
    CheckConfig,
    /// Print CA status summary
    Status,
}

#[derive(Subcommand)]
pub enum CaCommands {
    /// Register a user by public key file
    AddUser {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long = "public-key-pem-file")]
        public_key_pem_file: String,
        #[arg(long, default_value = "true")]
        active: bool,
    },
    /// Export the CRL
    ExportCrl {
        #[arg(long)]
        out: Option<String>,
        #[arg(long, default_value = "pem", value_parser = ["json", "pem", "der"])]
        format: String,
    },
    /// Check OCSP status
    OcspCheck {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        serial: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum AcmeCommands {
    /// Fetch ACME directory
    Directory {
        #[arg(long, default_value = "https://localhost:7020/acme/directory")]
        url: String,
    },
    /// Sign a CSR via ACME (none-01 flow)
    SignCsr {
        #[arg(long)]
        csr: String,
        #[arg(long, default_value = "https://localhost:7020/acme/directory")]
        url: String,
    },
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

pub async fn run_server_start(bootstrap: bool) -> Result<()> {
    let config = crate::config::load_config().context("Loading config")?;
    init_logging(config.log_level);

    // Ensure data directories exist
    crate::storage::ensure_users_db(&config.users_db_path)?;
    crate::storage::ensure_certs_db(&config.cert_db_path, &config.certs_dir)?;
    crate::storage::ensure_acme_accounts_db(&config.acme_accounts_db_path)?;

    // Load CA metadata
    let ca_metadata = crate::ca::load_ca_metadata(&config).context("Loading CA")?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        port = config.port,
        bind = %config.bind,
        fingerprint256 = %ca_metadata.fingerprint256,
        "Vigil CA service starting"
    );

    // Generate or load TLS material
    let (tls_key_pem, tls_cert_pem, bootstrap_secret) = if bootstrap {
        if config.common_name.is_empty() {
            anyhow::bail!("Bootstrap mode requires commonName in vigil.config.json");
        }
        tracing::info!("Bootstrap mode: generating ephemeral TLS cert...");
        let (key_pem, cert_pem, _chain_pem) =
            crate::ca::generate_bootstrap_server_cert(&config.common_name, &config)
                .context("Generating bootstrap cert")?;
        let secret = hex::encode((0..32).map(|_| rand::random::<u8>()).collect::<Vec<u8>>());
        println!("\nVigil bootstrap secret: {}\n", secret);
        (key_pem, cert_pem, Some(secret))
    } else {
        let key = std::fs::read_to_string(&config.tls.key_path)
            .with_context(|| format!("Reading TLS key: {}", config.tls.key_path.display()))?;
        let cert = std::fs::read_to_string(&config.tls.cert_path)
            .with_context(|| format!("Reading TLS cert: {}", config.tls.cert_path.display()))?;
        (key, cert, None)
    };

    // Write ephemeral TLS key/cert to temp files if in bootstrap mode
    // (rustls needs to read from paths or we build ServerConfig differently)
    // For simplicity we always use the config paths when not in bootstrap mode.
    // In bootstrap mode, we write to temp files.
    let tls_config = if bootstrap {
        build_bootstrap_tls(&tls_key_pem, &tls_cert_pem, &config)?
    } else {
        crate::server::build_server_tls(&config)?
    };

    let state = crate::state::AppState::new(config.clone(), ca_metadata, bootstrap_secret);

    // Restore persisted ACME accounts
    crate::acme::restore_accounts(&state).await?;

    let router = crate::routes::build_router(state);
    crate::server::run(&config, router, tls_config).await
}

fn build_bootstrap_tls(key_pem: &str, cert_pem: &str, config: &crate::config::VigilConfig) -> Result<std::sync::Arc<rustls::ServerConfig>> {
    credo_lib::tls::build_server_tls_from_pem(cert_pem, key_pem, Some(&config.tls.client_ca_path))
        .context("Building bootstrap TLS config from in-memory PEM")
}

pub fn run_check_config() -> Result<()> {
    let config = crate::config::load_config().context("Loading config")?;
    let mut errors = 0u32;
    let mut warnings = 0u32;

    let ok   = |msg: &str| println!("  ✓ {}", msg);
    let mut err  = |msg: &str| { println!("  ✗ {}", msg); errors += 1; };
    let _warn = |msg: &str| { println!("  ⚠ {}", msg); warnings += 1; };

    println!("\nVigil config check");
    println!("{}", "━".repeat(43));

    println!("\nvigil.config.json");
    if !config.common_name.is_empty() {
        ok(&format!("parsed  (commonName={}  port={})", config.common_name, config.port));
    } else {
        err("commonName is not set — required for bootstrap TLS cert generation");
        errors += 1;
    }

    println!("\nCA material");
    if config.ca_ecdsa_intermediate_key_path.exists() {
        ok(&format!("caEcdsaIntermediateKeyPath   {}", config.ca_ecdsa_intermediate_key_path.display()));
    } else {
        println!("  ✗ caEcdsaIntermediateKeyPath   {}  NOT FOUND", config.ca_ecdsa_intermediate_key_path.display());
        errors += 1;
    }
    if config.ca_ecdsa_intermediate_cert_path.exists() {
        ok(&format!("caEcdsaIntermediateCertPath  {}", config.ca_ecdsa_intermediate_cert_path.display()));
    } else {
        println!("  ✗ caEcdsaIntermediateCertPath  {}  NOT FOUND", config.ca_ecdsa_intermediate_cert_path.display());
        errors += 1;
    }

    println!("\nTLS output paths");
    if config.tls.key_path.exists() || config.tls.key_path.parent().map(|p| p.exists()).unwrap_or(false) {
        ok(&format!("tls.keyPath parent writable"));
    } else {
        println!("  ✗ tls.keyPath parent not writable: {}", config.tls.key_path.display());
        errors += 1;
    }

    println!("\nClient CA");
    if config.tls.client_ca_path.exists() {
        ok(&format!("tls.clientCaPath  {}  (exists)", config.tls.client_ca_path.display()));
    } else {
        println!("  ✗ tls.clientCaPath  {}  NOT FOUND", config.tls.client_ca_path.display());
        errors += 1;
    }

    println!("\nRBAC");
    if !config.rbac_identities.is_empty() {
        ok(&format!("rbacIdentities  {} identity(ies) configured", config.rbac_identities.len()));
    } else {
        println!("  ⚠ rbacIdentities is empty — Shepherd cannot authenticate to Vigil in non-ACME mode");
        warnings += 1;
    }

    println!("\nIssuance policy");
    if !config.issuance_policy.allowed_dns_suffixes.is_empty() {
        ok(&format!("allowedDnsSuffixes  {}", config.issuance_policy.allowed_dns_suffixes.join(", ")));
    } else {
        println!("  ✗ issuancePolicy.allowedDnsSuffixes is empty — no domain names will be allowed");
        errors += 1;
    }

    println!("\n{}", "━".repeat(43));
    let status = if errors > 0 { "NOT READY" } else { "READY" };
    println!("Result: {}  ({} error{}, {} warning{})\n",
        status, errors, if errors != 1 { "s" } else { "" },
        warnings, if warnings != 1 { "s" } else { "" });

    if errors > 0 { std::process::exit(1); }
    Ok(())
}

pub fn run_ca_add_user(id: &str, name: &str, public_key_pem_file: &str, active: bool) -> Result<()> {
    let config = crate::config::load_config().context("Loading config")?;
    let pem = std::fs::read_to_string(public_key_pem_file)
        .with_context(|| format!("Reading public key: {}", public_key_pem_file))?;
    let fingerprint = crate::storage::fingerprint_public_key_pem(&pem);

    let user = crate::types::VigilUser {
        id: id.to_string(),
        name: name.to_string(),
        role: crate::types::Role::Admin,
        active,
        public_key_pem: pem,
        public_key_fingerprint256: fingerprint,
    };
    crate::storage::ensure_users_db(&config.users_db_path)?;
    let created = crate::storage::add_user(&config.users_db_path, user)?;
    println!("User added: {} (fingerprint: {})", created.id, created.public_key_fingerprint256);
    Ok(())
}

pub fn run_ca_export_crl(out: Option<&str>, format: &str) -> Result<()> {
    let config = crate::config::load_config().context("Loading config")?;
    let ca_meta = crate::ca::load_ca_metadata(&config)?;

    match format {
        "json" => {
            let crl = crate::revocation::generate_crl(&config.cert_db_path, &ca_meta, config.ca.crl_next_update_hours)?;
            let json = serde_json::to_string_pretty(&crl)?;
            write_output(out, json.as_bytes())?;
        }
        "der" => {
            let der = crate::pki_wire::build_signed_crl_der(&ca_meta, config.ca.crl_next_update_hours, &config)?;
            write_output(out, &der)?;
        }
        _ => {
            let pem = crate::pki_wire::build_signed_crl_pem(&ca_meta, config.ca.crl_next_update_hours, &config)?;
            write_output(out, pem.as_bytes())?;
        }
    }
    Ok(())
}

pub fn run_ca_ocsp_check(id: Option<&str>, serial: Option<&str>) -> Result<()> {
    let config = crate::config::load_config().context("Loading config")?;
    let ocsp = if let Some(id) = id {
        crate::revocation::get_ocsp_status_by_cert_id(&config.cert_db_path, id, config.ca.ocsp_max_age_seconds)?
    } else if let Some(serial) = serial {
        crate::revocation::get_ocsp_status_by_serial(&config.cert_db_path, serial, config.ca.ocsp_max_age_seconds)?
    } else {
        anyhow::bail!("Either --id or --serial must be provided");
    };
    println!("{}", serde_json::to_string_pretty(&ocsp)?);
    Ok(())
}

fn write_output(path: Option<&str>, data: &[u8]) -> Result<()> {
    match path {
        Some(p) => std::fs::write(p, data).with_context(|| format!("Writing to {}", p)),
        None => {
            use std::io::Write;
            std::io::stdout().write_all(data).context("Writing to stdout")
        }
    }
}

fn init_logging(level: crate::config::LogLevel) {
    credo_lib::log::init_logging(credo_lib::LogLevel::from_str(level.as_tracing_filter()));
}
