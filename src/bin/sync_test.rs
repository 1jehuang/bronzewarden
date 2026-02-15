use anyhow::Result;
use bronzewarden::api::BitwardenApi;
use bronzewarden::config::Config;
use bronzewarden::crypto::{EncString, MasterKey};

#[tokio::main]
async fn main() -> Result<()> {
    let password = "jeremygoat123";
    
    let mut config = Config::load()?;
    let email = config.email.as_ref().expect("Not logged in").clone();
    
    // Use the existing access token to sync
    let api = BitwardenApi::new(&config.identity_url, &config.api_url, &config.device_id);
    let access_token = config.access_token.as_ref().expect("No access token").clone();
    
    println!("Syncing with existing access token...");
    let sync_result = api.sync(&access_token).await;
    
    let sync = match sync_result {
        Ok(s) => s,
        Err(e) => {
            println!("Sync failed (token may be expired): {}", e);
            // Try refresh
            if let Some(ref rt) = config.refresh_token {
                println!("Trying refresh token...");
                let new_token = api.refresh_token(rt).await?;
                config.access_token = Some(new_token.access_token.clone());
                if let Some(rt) = new_token.refresh_token {
                    config.refresh_token = Some(rt);
                }
                config.save()?;
                api.sync(&new_token.access_token).await?
            } else {
                println!("No refresh token available.");
                println!("Need to re-login with API key.");
                return Err(e);
            }
        }
    };
    
    // Check profile key
    println!("Profile email: {:?}", sync.profile.email);
    println!("Profile key present: {}", sync.profile.key.is_some());
    
    if let Some(ref profile_key) = sync.profile.key {
        println!("Profile encrypted_user_key: {}", &profile_key[..60]);
        println!("Config encrypted_user_key:  {}", &config.encrypted_user_key.as_ref().unwrap()[..60]);
        
        if profile_key != config.encrypted_user_key.as_ref().unwrap() {
            println!("\n⚠ KEYS ARE DIFFERENT! Profile has newer key.");
            println!("Updating config with profile key...");
            config.encrypted_user_key = Some(profile_key.clone());
            config.save()?;
        } else {
            println!("\n✓ Keys match.");
        }
        
        // Try to decrypt with the profile key
        let kdf_params = config.kdf_params().expect("No KDF params");
        let master_key = MasterKey::derive(password, &email, &kdf_params)?;
        let stretched = master_key.stretch()?;
        
        match EncString(profile_key.clone()).decrypt_to_key(&stretched) {
            Ok(user_key) => {
                println!("✓ Profile key decrypts successfully!");
                
                // Save updated vault
                config.save_vault_cache(&sync.ciphers)?;
                config.save()?;
                
                let vault = bronzewarden::vault::Vault::new(user_key, &sync);
                println!("Vault unlocked: {} logins", vault.login_count());
                
                let results = vault.find_by_domain("github.com");
                println!("GitHub results: {}", results.len());
                for r in &results {
                    println!("  - {} ({})", r.name, r.username);
                }
            }
            Err(e) => {
                println!("✗ Profile key also fails: {}", e);
                println!("\nThe password 'jeremygoat123' truly does not decrypt this vault.");
                println!("Either the password is wrong, or the email/KDF params are mismatched.");
            }
        }
    }
    
    Ok(())
}
