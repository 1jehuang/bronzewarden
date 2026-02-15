use anyhow::Result;
use bronzewarden::api::BitwardenApi;
use bronzewarden::config::Config;
use bronzewarden::crypto::{EncString, MasterKey};

#[tokio::main]
async fn main() -> Result<()> {
    let password = "jeremygoat123";
    
    let mut config = Config::load()?;
    let email = config.email.as_ref().expect("Not logged in").clone();
    
    // Use the refresh token from the official Bitwarden extension
    let refresh_token = "CCC42CA9C7DEA33C42A93EA21EA962B0432416CEC242A5277933062FDB2483B2-1";
    
    let api = BitwardenApi::new(&config.identity_url, &config.api_url, &config.device_id);
    
    println!("Refreshing token...");
    let new_token = api.refresh_token(refresh_token).await?;
    println!("✓ Got new access token!");
    println!("  Key present: {}", new_token.key.is_some());
    println!("  KDF: {:?}", new_token.kdf);
    println!("  KDF iterations: {:?}", new_token.kdf_iterations);
    
    // Update config
    config.access_token = Some(new_token.access_token.clone());
    if let Some(ref rt) = new_token.refresh_token {
        config.refresh_token = Some(rt.clone());
    }
    if let Some(ref key) = new_token.key {
        println!("\n  New encrypted_user_key: {}", &key[..60]);
        println!("  Old encrypted_user_key: {}", &config.encrypted_user_key.as_ref().unwrap()[..60]);
        if key != config.encrypted_user_key.as_ref().unwrap() {
            println!("  ⚠ KEYS DIFFER!");
        }
        config.encrypted_user_key = Some(key.clone());
    }
    if new_token.kdf.is_some() {
        config.kdf_type = new_token.kdf;
    }
    if new_token.kdf_iterations.is_some() {
        config.kdf_iterations = new_token.kdf_iterations;
    }
    
    // Sync vault
    println!("\nSyncing vault...");
    let sync = api.sync(&new_token.access_token).await?;
    let login_count = sync.ciphers.iter()
        .filter(|c| c.cipher_type == 1 && c.deleted_date.is_none())
        .count();
    println!("✓ Synced: {} items ({} logins)", sync.ciphers.len(), login_count);
    
    // Check profile key
    if let Some(ref profile_key) = sync.profile.key {
        println!("\nProfile encrypted_user_key: {}", &profile_key[..60]);
        config.encrypted_user_key = Some(profile_key.clone());
    }
    
    config.save_vault_cache(&sync.ciphers)?;
    config.save()?;
    println!("✓ Config and vault cache saved.");
    
    // Now try to decrypt
    println!("\nTrying to decrypt vault with '{}'...", password);
    let kdf_params = config.kdf_params().expect("No KDF params");
    let master_key = MasterKey::derive(password, &email, &kdf_params)?;
    let stretched = master_key.stretch()?;
    let encrypted_key = config.encrypted_user_key.as_ref().unwrap();
    
    match EncString(encrypted_key.clone()).decrypt_to_key(&stretched) {
        Ok(user_key) => {
            println!("✓ VAULT UNLOCKED!");
            let vault = bronzewarden::vault::Vault::new(user_key, &sync);
            println!("  {} logins available", vault.login_count());
            
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
