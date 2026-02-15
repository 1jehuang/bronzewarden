use anyhow::Result;
use bronzewarden::api::BitwardenApi;
use bronzewarden::config::Config;
use bronzewarden::crypto::{EncString, MasterKey};

#[tokio::main]
async fn main() -> Result<()> {
    let password = "jeremygoat123";
    let client_id = "user.c8aac430-4d86-40ef-bf1e-b3df00290087";
    let client_secret = "nV5SBS5xK3Lx2fnjQCEKPaLEEfTP2m";
    
    let mut config = Config::load()?;
    let email = config.email.as_ref().expect("Not logged in").clone();
    
    let api = BitwardenApi::new(&config.identity_url, &config.api_url, &config.device_id);
    
    println!("Logging in with API key...");
    let token = api.login_with_api_key(client_id, client_secret).await?;
    println!("✓ Login succeeded!");
    println!("  Key present: {}", token.key.is_some());
    println!("  KDF: {:?}", token.kdf);
    println!("  KDF iterations: {:?}", token.kdf_iterations);
    
    // Update config
    config.access_token = Some(token.access_token.clone());
    config.refresh_token = token.refresh_token;
    if let Some(ref key) = token.key {
        let old_key = config.encrypted_user_key.as_ref().unwrap();
        println!("\n  New key: {}...", &key[..50]);
        println!("  Old key: {}...", &old_key[..50]);
        if key != old_key {
            println!("  ⚠ KEYS DIFFER! Updating.");
        } else {
            println!("  ✓ Keys match.");
        }
        config.encrypted_user_key = Some(key.clone());
    }
    if token.kdf.is_some() { config.kdf_type = token.kdf; }
    if token.kdf_iterations.is_some() { config.kdf_iterations = token.kdf_iterations; }
    if token.kdf_memory.is_some() { config.kdf_memory = token.kdf_memory; }
    if token.kdf_parallelism.is_some() { config.kdf_parallelism = token.kdf_parallelism; }
    
    // Sync
    println!("\nSyncing vault...");
    let sync = api.sync(&token.access_token).await?;
    let login_count = sync.ciphers.iter()
        .filter(|c| c.cipher_type == 1 && c.deleted_date.is_none())
        .count();
    println!("✓ {} items ({} logins)", sync.ciphers.len(), login_count);
    
    // Use profile key if available
    if let Some(ref profile_key) = sync.profile.key {
        if Some(profile_key.clone()) != config.encrypted_user_key {
            println!("  Profile key differs from token key, using profile key.");
            config.encrypted_user_key = Some(profile_key.clone());
        }
    }
    
    config.save_vault_cache(&sync.ciphers)?;
    config.save()?;
    println!("✓ Saved config and vault cache.");
    
    // Decrypt
    println!("\nDecrypting vault with '{}'...", password);
    let kdf_params = config.kdf_params().expect("No KDF params");
    let master_key = MasterKey::derive(password, &email, &kdf_params)?;
    let stretched = master_key.stretch()?;
    let encrypted_key = config.encrypted_user_key.as_ref().unwrap();
    
    match EncString(encrypted_key.clone()).decrypt_to_key(&stretched) {
        Ok(user_key) => {
            println!("✓ VAULT UNLOCKED!");
            let vault = bronzewarden::vault::Vault::new(user_key, &sync);
            println!("  {} logins", vault.login_count());
            let results = vault.find_by_domain("github.com");
            for r in &results {
                println!("  GitHub: {} ({})", r.name, r.username);
            }
        }
        Err(e) => {
            println!("✗ Decrypt failed: {}", e);
        }
    }
    
    Ok(())
}
