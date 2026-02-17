use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use bronzewarden::api::BitwardenApi;
use bronzewarden::api::SyncResponse;
use bronzewarden::config::Config;
use bronzewarden::crypto::{EncString, MasterKey};
use bronzewarden::vault::Vault;

#[derive(Parser)]
#[command(
    name = "bronzewarden",
    version,
    about = "Minimal Bitwarden vault client"
)]
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
        /// Use API key login (set BW_CLIENTID and BW_CLIENTSECRET, or pass flags)
        #[arg(long)]
        apikey: bool,
        /// API key client ID (e.g. user.xxxxx)
        #[arg(long)]
        client_id: Option<String>,
        /// API key client secret
        #[arg(long)]
        client_secret: Option<String>,
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
    /// Set up fingerprint unlock (caches encrypted key locally)
    SetupFingerprint,
    /// Remove cached fingerprint unlock key
    RemoveFingerprint,
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

fn push_unique_endpoint(endpoints: &mut Vec<(String, String)>, identity_url: &str, api_url: &str) {
    if !endpoints
        .iter()
        .any(|(id, api)| id == identity_url && api == api_url)
    {
        endpoints.push((identity_url.to_string(), api_url.to_string()));
    }
}

fn password_login_endpoints(
    config: &Config,
    include_official_fallbacks: bool,
) -> Vec<(String, String)> {
    let mut endpoints = Vec::new();
    push_unique_endpoint(&mut endpoints, &config.identity_url, &config.api_url);

    if include_official_fallbacks {
        push_unique_endpoint(
            &mut endpoints,
            "https://identity.bitwarden.com",
            "https://api.bitwarden.com",
        );
        push_unique_endpoint(
            &mut endpoints,
            "https://identity.bitwarden.eu",
            "https://api.bitwarden.eu",
        );
    }

    endpoints
}

fn password_login_client_ids() -> Vec<String> {
    if let Ok(raw) = std::env::var("BW_PASSWORD_LOGIN_CLIENT_IDS") {
        let parsed: Vec<String> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }

    vec![
        "connector".to_string(),
        "cli".to_string(),
        "desktop".to_string(),
    ]
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
        Commands::Login {
            email,
            server,
            apikey,
            client_id,
            client_secret,
        } => {
            let mut config = Config::load().unwrap_or_default();

            if let Some(ref server) = server {
                let server = server.trim_end_matches('/');
                config.identity_url = format!("{}/identity", server);
                config.api_url = format!("{}/api", server);
            }

            let api = BitwardenApi::new(&config.identity_url, &config.api_url, &config.device_id);

            let sync = if apikey {
                let client_id = client_id
                    .or_else(|| std::env::var("BW_CLIENTID").ok())
                    .filter(|s| !s.trim().is_empty())
                    .map(Ok)
                    .unwrap_or_else(|| prompt_input("API client_id: "))?;
                let client_secret = client_secret
                    .or_else(|| std::env::var("BW_CLIENTSECRET").ok())
                    .filter(|s| !s.trim().is_empty())
                    .map(Ok)
                    .unwrap_or_else(|| prompt_password("API client_secret: "))?;

                eprintln!("Authenticating with API key...");
                let token = api.login_with_api_key(&client_id, &client_secret).await?;
                config.access_token = Some(token.access_token.clone());
                config.refresh_token = token.refresh_token.clone();

                eprintln!("Fetching profile and syncing vault...");
                let sync = api.sync(&token.access_token).await?;
                let profile_email = sync
                    .profile
                    .email
                    .clone()
                    .ok_or_else(|| anyhow!("Sync response missing profile email"))?
                    .trim()
                    .to_lowercase();
                let encrypted_key = token
                    .key
                    .clone()
                    .or(sync.profile.key.clone())
                    .ok_or_else(|| anyhow!("Sync response missing encrypted user key"))?;

                eprintln!("Fetching KDF parameters...");
                let prelogin = api.prelogin(&profile_email).await?;

                config.email = Some(profile_email);
                config.encrypted_user_key = Some(encrypted_key);
                config.kdf_type = token.kdf.or(Some(prelogin.kdf));
                config.kdf_iterations = token.kdf_iterations.or(Some(prelogin.kdf_iterations));
                config.kdf_memory = token.kdf_memory.or(prelogin.kdf_memory);
                config.kdf_parallelism = token.kdf_parallelism.or(prelogin.kdf_parallelism);
                sync
            } else {
                let email = match email {
                    Some(e) => e,
                    None => prompt_input("Email: ")?,
                }
                .trim()
                .to_lowercase();

                let password = prompt_password("Master password: ")?;
                let endpoints = password_login_endpoints(&config, server.is_none());
                let client_ids = password_login_client_ids();
                let mut attempt_errors = Vec::new();
                let mut success: Option<(
                    String,
                    String,
                    bronzewarden::api::PreloginResponse,
                    bronzewarden::api::TokenResponse,
                )> = None;

                for (identity_url, api_url) in endpoints {
                    let endpoint_api =
                        BitwardenApi::new(&identity_url, &api_url, &config.device_id);
                    eprintln!("Fetching KDF parameters from {}...", identity_url);
                    let prelogin = match endpoint_api.prelogin(&email).await {
                        Ok(p) => p,
                        Err(e) => {
                            attempt_errors.push(format!("{} prelogin failed: {}", identity_url, e));
                            continue;
                        }
                    };
                    let kdf_params = prelogin.to_kdf_params();

                    eprintln!("Deriving master key...");
                    let master_key = match MasterKey::derive(&password, &email, &kdf_params) {
                        Ok(k) => k,
                        Err(e) => {
                            attempt_errors
                                .push(format!("{} key derivation failed: {}", identity_url, e));
                            continue;
                        }
                    };
                    let hash = master_key.master_password_hash(&password);

                    for cid in &client_ids {
                        eprintln!("Authenticating via {} (client_id={})...", identity_url, cid);
                        match endpoint_api.login_with_client_id(&email, &hash, cid).await {
                            Ok(token) => {
                                success =
                                    Some((identity_url.clone(), api_url.clone(), prelogin, token));
                                break;
                            }
                            Err(e) => {
                                attempt_errors.push(format!(
                                    "{} login failed (client_id={}): {}",
                                    identity_url, cid, e
                                ));
                            }
                        }
                    }

                    if success.is_some() {
                        break;
                    }
                }

                let (identity_url, api_url, prelogin, token) = success.ok_or_else(|| {
                    let summary = if attempt_errors.is_empty() {
                        "No attempts were made.".to_string()
                    } else {
                        attempt_errors
                            .iter()
                            .rev()
                            .take(6)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    anyhow!(
                        "Password login failed across fallback attempts.\n{}\n\nTip: try `bronzewarden login --apikey`.",
                        summary
                    )
                })?;

                config.identity_url = identity_url;
                config.api_url = api_url;

                config.email = Some(email);
                config.access_token = Some(token.access_token.clone());
                config.refresh_token = token.refresh_token;
                config.encrypted_user_key = token.key;
                config.kdf_type = token.kdf.or(Some(prelogin.kdf));
                config.kdf_iterations = token.kdf_iterations.or(Some(prelogin.kdf_iterations));
                config.kdf_memory = token.kdf_memory.or(prelogin.kdf_memory);
                config.kdf_parallelism = token.kdf_parallelism.or(prelogin.kdf_parallelism);

                eprintln!("Logged in. Syncing vault...");
                let api =
                    BitwardenApi::new(&config.identity_url, &config.api_url, &config.device_id);
                api.sync(&token.access_token).await?
            };

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

            let api = BitwardenApi::new(&config.identity_url, &config.api_url, &config.device_id);

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
                format!(
                    "{} items ({} logins), synced at {}",
                    cache.ciphers.len(),
                    logins,
                    cache.synced_at
                )
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

            bronzewarden::protected_key::remove_protected_key().ok();
            eprintln!("Logged out and cleared vault cache.");
        }

        Commands::SetupFingerprint => {
            let config = Config::load()?;
            let email = config
                .email
                .as_ref()
                .ok_or_else(|| anyhow!("Not logged in. Run `bronzewarden login` first."))?;
            let encrypted_key = config
                .encrypted_user_key
                .as_ref()
                .ok_or_else(|| anyhow!("No user key stored. Run `bronzewarden login` first."))?;
            let kdf_params = config
                .kdf_params()
                .ok_or_else(|| anyhow!("No KDF params stored."))?;

            if bronzewarden::protected_key::has_protected_key() {
                eprint!("Fingerprint unlock is already set up. Re-configure? [y/N] ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    eprintln!("Cancelled.");
                    return Ok(());
                }
            }

            eprintln!("Enter your master password to set up fingerprint unlock.");
            eprintln!("This will be the LAST time you need to type it.");
            let password = prompt_password("Master password: ")?;

            eprintln!("Deriving key...");
            let master_key = MasterKey::derive(&password, email, &kdf_params)?;
            let stretched = master_key.stretch()?;
            let user_key = EncString(encrypted_key.clone()).decrypt_to_key(&stretched)?;

            // Verify the key works by trying to decrypt something from the vault
            if let Ok(cache) = Config::load_vault_cache() {
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
                let vault = Vault::new(user_key.clone(), &sync);
                let count = vault.login_count();
                eprintln!("✓ Key verified ({} logins accessible)", count);
            }

            bronzewarden::protected_key::store_protected_key(&user_key)?;
            eprintln!("✓ Fingerprint unlock configured!");
            eprintln!("  The vault can now be unlocked with fingerprint only.");
            eprintln!("  Protected key stored at ~/.config/bronzewarden/protected_key.json");
        }

        Commands::RemoveFingerprint => {
            if bronzewarden::protected_key::has_protected_key() {
                bronzewarden::protected_key::remove_protected_key()?;
                eprintln!("✓ Fingerprint unlock removed.");
            } else {
                eprintln!("Fingerprint unlock is not configured.");
            }
        }
    }

    Ok(())
}
