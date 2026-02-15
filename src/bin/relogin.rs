use anyhow::Result;
use bronzewarden::api::BitwardenApi;
use bronzewarden::config::Config;
use bronzewarden::crypto::MasterKey;

#[tokio::main]
async fn main() -> Result<()> {
    let password = std::env::var("BW_PASSWORD")
        .unwrap_or_else(|_| "jeremygoat123".to_string());
    
    let mut config = Config::load()?;
    let email = config.email.clone().expect("Not logged in - need email");
    
    println!("Re-login for: {}", email);
    
    let api = BitwardenApi::new(&config.identity_url, &config.api_url, &config.device_id);
    
    // Get fresh prelogin (KDF params)
    println!("Fetching KDF parameters...");
    let prelogin = api.prelogin(&email).await?;
    println!("KDF: type={}, iterations={}", prelogin.kdf, prelogin.kdf_iterations);
    
    let kdf_params = prelogin.to_kdf_params();
    
    // Derive master key and password hash
    println!("Deriving master key...");
    let master_key = MasterKey::derive(&password, &email, &kdf_params)?;
    let hash = master_key.master_password_hash(&password);
    
    // Try login with different client IDs
    let client_ids = ["connector", "cli", "desktop"];
    let mut token = None;
    for cid in &client_ids {
        println!("Trying login with client_id={}...", cid);
        match api.login_with_client_id(&email, &hash, cid).await {
            Ok(t) => {
                println!("✓ Login succeeded with client_id={}", cid);
                token = Some(t);
                break;
            }
            Err(e) => {
                println!("  Failed: {}", e);
            }
        }
    }
    
    let token = token.expect("All login attempts failed");
    
    // Update config with fresh token and key
    config.access_token = Some(token.access_token.clone());
    config.refresh_token = token.refresh_token;
    config.encrypted_user_key = token.key.clone();
    config.kdf_type = token.kdf.or(Some(prelogin.kdf));
    config.kdf_iterations = token.kdf_iterations.or(Some(prelogin.kdf_iterations));
    config.kdf_memory = token.kdf_memory.or(prelogin.kdf_memory);
    config.kdf_parallelism = token.kdf_parallelism.or(prelogin.kdf_parallelism);
    
    // Sync vault
    println!("Syncing vault...");
    let sync = api.sync(&token.access_token).await?;
    let login_count = sync.ciphers.iter()
        .filter(|c| c.cipher_type == 1 && c.deleted_date.is_none())
        .count();
    
    // Also update the encrypted_user_key from sync profile if token didn't have it
    if config.encrypted_user_key.is_none() {
        config.encrypted_user_key = sync.profile.key.clone();
    }
    
    config.save_vault_cache(&sync.ciphers)?;
    config.save()?;
    
    println!("✓ Vault synced: {} items ({} logins)", sync.ciphers.len(), login_count);
    
    // Now test the unlock
    println!("\nTesting vault unlock...");
    let encrypted_key = config.encrypted_user_key.as_ref().expect("No user key after login");
    let stretched = master_key.stretch()?;
    match bronzewarden::crypto::EncString(encrypted_key.clone()).decrypt_to_key(&stretched) {
        Ok(_) => println!("✓ Vault unlock works!"),
        Err(e) => println!("✗ Vault unlock still fails: {}", e),
    }
    
    Ok(())
}
