use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use bronzewarden::api::BitwardenApi;
use bronzewarden::config::Config;
use bronzewarden::crypto::{EncString, MasterKey};
use bronzewarden::vault::Vault;
use bronzewarden::api::SyncResponse;

#[derive(Parser)]
#[command(name = "bronzewarden", version, about = "Minimal Bitwarden vault client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Log in to Bitwarden
    Login {
        /// Email address
        #[arg(short, long)]
        email: Option<String>,
        /// Server URL (for self-hosted)
        #[arg(long)]
        server: Option<String>,
    },
    /// Sync vault from server
    Sync,
    /// Show vault status
    Status,
    /// Search for logins
    Get {
        /// Domain or search term
        query: String,
        /// Show password in output
        #[arg(long)]
        password: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// List all logins (names only)
    List,
    /// Log out and clear stored data
    Logout,
}

fn prompt_password(prompt: &str) -> Result<String> {
    let password = rpassword::prompt_password(prompt)?;
    if password.is_empty() {
        return Err(anyhow!("Password cannot be empty"));
    }
    Ok(password)
}

fn prompt_input(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        return Err(anyhow!("Input cannot be empty"));
    }
    Ok(trimmed)
}

fn mask_username(username: &str) -> String {
    if username.contains('@') {
        let parts: Vec<&str> = username.splitn(2, '@').collect();
        let local = parts[0];
        let domain = parts.get(1).unwrap_or(&"");
        if local.len() <= 2 {
            format!("{}***@{}", &local[..1], domain)
        } else {
            format!("{}***{}@{}", &local[..1], &local[local.len() - 1..], domain)
        }
    } else if username.len() <= 3 {
        format!("{}***", &username[..1])
    } else {
        format!("{}***{}", &username[..1], &username[username.len() - 1..])
    }
}

fn unlock_vault(config: &Config) -> Result<(Vault, SyncResponse)> {
    let email = config
        .email
        .as_ref()
        .ok_or_else(|| anyhow!("Not logged in"))?;
    let encrypted_key = config
        .encrypted_user_key
        .as_ref()
        .ok_or_else(|| anyhow!("No user key stored. Run `bronzewarden login` first."))?;
    let kdf_params = config
        .kdf_params()
        .ok_or_else(|| anyhow!("No KDF params stored."))?;

    let password = prompt_password("Master password: ")?;
    let master_key = MasterKey::derive(&password, email, &kdf_params)?;
    let stretched = master_key.stretch()?;
    let user_key = EncString(encrypted_key.clone()).decrypt_to_key(&stretched)?;

    let cache = Config::load_vault_cache()?;
    let sync = SyncResponse {
        profile: bronzewarden::api::SyncProfile {
            id: String::new(),
            email: config.email.clone(),
            key: config.encrypted_user_key.clone(),
            private_key: None,
        },
        ciphers: cache.ciphers,
        folders: None,
    };

    Ok((Vault::new(user_key, &sync), sync))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Login { email, server } => {
            let mut config = Config::load().unwrap_or_default();

            let email = match email {
                Some(e) => e,
                None => prompt_input("Email: ")?,
            };

            if let Some(ref server) = server {
                let server = server.trim_end_matches('/');
                config.identity_url = format!("{}/identity", server);
                config.api_url = format!("{}/api", server);
            }

            let api = BitwardenApi::new(
                &config.identity_url,
                &config.api_url,
                &config.device_id,
            );

            eprintln!("Fetching KDF parameters...");
            let prelogin = api.prelogin(&email).await?;
            let kdf_params = prelogin.to_kdf_params();

            let password = prompt_password("Master password: ")?;

            eprintln!("Deriving master key...");
            let master_key = MasterKey::derive(&password, &email, &kdf_params)?;
            let hash = master_key.master_password_hash(&password);

            eprintln!("Authenticating...");
            let token = api.login(&email, &hash).await?;

            config.email = Some(email);
            config.access_token = Some(token.access_token);
            config.refresh_token = token.refresh_token;
            config.encrypted_user_key = token.key;
            config.kdf_type = token.kdf.or(Some(prelogin.kdf));
            config.kdf_iterations = token.kdf_iterations.or(Some(prelogin.kdf_iterations));
            config.kdf_memory = token.kdf_memory.or(prelogin.kdf_memory);
            config.kdf_parallelism = token.kdf_parallelism.or(prelogin.kdf_parallelism);
            config.save()?;

            eprintln!("Logged in. Syncing vault...");

            let sync = api
                .sync(config.access_token.as_ref().unwrap())
                .await?;

            let login_count = sync
                .ciphers
                .iter()
                .filter(|c| c.cipher_type == 1 && c.deleted_date.is_none())
                .count();

            config.save_vault_cache(&sync.ciphers)?;
            config.save()?;

            eprintln!(
                "✓ Vault synced: {} items ({} logins)",
                sync.ciphers.len(),
                login_count
            );
        }

        Commands::Sync => {
            let mut config = Config::load()?;
            if !config.is_logged_in() {
                return Err(anyhow!("Not logged in. Run `bronzewarden login` first."));
            }

            let api = BitwardenApi::new(
                &config.identity_url,
                &config.api_url,
                &config.device_id,
            );

            let access_token = config.access_token.as_ref().unwrap().clone();
            let sync_result = api.sync(&access_token).await;

            let sync = match sync_result {
                Ok(s) => s,
                Err(_) => {
                    if let Some(ref rt) = config.refresh_token {
                        eprintln!("Token expired, refreshing...");
                        let new_token = api.refresh_token(rt).await?;
                        config.access_token = Some(new_token.access_token.clone());
                        if let Some(rt) = new_token.refresh_token {
                            config.refresh_token = Some(rt);
                        }
                        config.save()?;
                        api.sync(&new_token.access_token).await?
                    } else {
                        return Err(anyhow!(
                            "Token expired and no refresh token. Run `bronzewarden login`."
                        ));
                    }
                }
            };

            let login_count = sync
                .ciphers
                .iter()
                .filter(|c| c.cipher_type == 1 && c.deleted_date.is_none())
                .count();

            config.save_vault_cache(&sync.ciphers)?;
            eprintln!(
                "✓ Vault synced: {} items ({} logins)",
                sync.ciphers.len(),
                login_count
            );
        }

        Commands::Status => {
            let config = Config::load()?;
            let logged_in = config.is_logged_in();
            let email = config.email.as_deref().unwrap_or("(none)");
            let has_cache = Config::load_vault_cache().is_ok();

            let cache_info = if let Ok(cache) = Config::load_vault_cache() {
                let logins = cache
                    .ciphers
                    .iter()
                    .filter(|c| c.cipher_type == 1 && c.deleted_date.is_none())
                    .count();
                format!("{} items ({} logins), synced at {}", cache.ciphers.len(), logins, cache.synced_at)
            } else {
                "no cache".to_string()
            };

            println!("Logged in: {}", logged_in);
            println!("Email: {}", email);
            println!("Server: {}", config.api_url);
            println!("Vault: {}", cache_info);
            println!("Has cache: {}", has_cache);
        }

        Commands::Get {
            query,
            password,
            json,
        } => {
            let config = Config::load()?;
            let (vault, _) = unlock_vault(&config)?;

            let results = vault.find_by_domain(&query);
            let results = if results.is_empty() {
                vault.search(&query)
            } else {
                results
            };

            if results.is_empty() {
                eprintln!("No logins found for '{}'", query);
                std::process::exit(1);
            }

            if json {
                let output: Vec<serde_json::Value> = results
                    .iter()
                    .map(|c| {
                        let mut obj = serde_json::json!({
                            "name": c.name,
                            "username": c.username,
                            "uris": c.uris,
                        });
                        if password {
                            obj["password"] = serde_json::json!(c.password);
                        }
                        obj
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                for (i, cred) in results.iter().enumerate() {
                    if i > 0 {
                        println!("---");
                    }
                    println!("Name: {}", cred.name);
                    println!("Username: {}", mask_username(&cred.username));
                    if password {
                        println!("Password: {}", cred.password);
                    }
                    for uri in &cred.uris {
                        println!("URI: {}", uri);
                    }
                }
            }
        }

        Commands::List => {
            let config = Config::load()?;
            let (vault, _) = unlock_vault(&config)?;

            let cache = Config::load_vault_cache()?;
            let mut count = 0;
            for cipher in &cache.ciphers {
                if cipher.cipher_type != 1 || cipher.deleted_date.is_some() {
                    continue;
                }
                if let Ok(Some(cred)) = vault.decrypt_cipher(cipher) {
                    println!(
                        "{} | {} | {}",
                        cred.name,
                        mask_username(&cred.username),
                        cred.uris.first().unwrap_or(&String::new())
                    );
                    count += 1;
                }
            }
            eprintln!("({} logins)", count);
        }

        Commands::Logout => {
            let mut config = Config::load()?;
            config.clear();
            config.save()?;

            let cache_path = Config::config_dir()?.join("vault.json");
            if cache_path.exists() {
                std::fs::remove_file(&cache_path)?;
            }

            eprintln!("Logged out and cleared vault cache.");
        }
    }

    Ok(())
}
