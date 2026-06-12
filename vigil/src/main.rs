use anyhow::Result;
use clap::Parser;
use vigil::cli::{AcmeCommands, CaCommands, Cli, Commands, ServerCommands};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Commands::Bootstrap => vigil::cli::run_server_start(true).await,
        Commands::Server { cmd } => match cmd {
            ServerCommands::Start { bootstrap } => vigil::cli::run_server_start(bootstrap).await,
            ServerCommands::Stop => vigil::cli::run_server_stop(),
            ServerCommands::CheckConfig => vigil::cli::run_check_config(),
            ServerCommands::Status => {
                let config = vigil::config::load_config()?;
                let meta = vigil::ca::load_ca_metadata(&config)?;
                println!("CA subject:      {}", meta.subject);
                println!("CA serial:       {}", meta.serial_number);
                println!("CA valid to:     {}", meta.valid_to);
                println!("CA fingerprint:  {}", meta.fingerprint256);
                let (total, revoked, active) =
                    vigil::storage::certificate_stats(&config.cert_db_path)?;
                println!(
                    "Certificates:    total={} active={} revoked={}",
                    total, active, revoked
                );
                Ok(())
            }
        },

        Commands::Ca { cmd } => match cmd {
            CaCommands::AddUser {
                id,
                name,
                public_key_pem_file,
                active,
            } => vigil::cli::run_ca_add_user(&id, &name, &public_key_pem_file, active),
            CaCommands::ExportCrl { out, format } => {
                vigil::cli::run_ca_export_crl(out.as_deref(), &format)
            }
            CaCommands::OcspCheck { id, serial } => {
                vigil::cli::run_ca_ocsp_check(id.as_deref(), serial.as_deref())
            }
        },

        Commands::Acme { cmd } => {
            match cmd {
                AcmeCommands::Directory { url } => {
                    println!("ACME client commands require an mTLS-capable HTTP client.");
                    println!("Directory URL: {}", url);
                    println!("Use the vigil CLI or a standard ACME client pointed at this vigil instance.");
                    Ok(())
                }
                AcmeCommands::SignCsr { csr, url } => {
                    println!("ACME CSR signing via CLI is not yet implemented in vigil-rs.");
                    println!("CSR: {}", csr);
                    println!("URL: {}", url);
                    Ok(())
                }
            }
        }
    }
}
