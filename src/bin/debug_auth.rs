use anyhow::Result;
use bronzewarden::api::BitwardenApi;
use bronzewarden::config::Config;
use bronzewarden::crypto::{EncString, MasterKey};

#[tokio::main]
async fn main() -> Result<()> {
    let password = "jeremygoat123";
    
    let config = Config::load()?;
    let email = config.email.as_ref().expect("Not logged in").clone();
    let device_id = config.device_id.clone();
    
    println!("Email: '{}'", email);
    println!("Email bytes: {:?}", email.as_bytes());
    println!("Password: '{}'", password);
    println!("Password bytes: {:?}", password.as_bytes());
    
    // Check the stored encrypted_user_key
    let encrypted_key = config.encrypted_user_key.as_ref().expect("No key");
    println!("\nEncrypted user key: {}", encrypted_key);
    
    // Parse the enc string to see its type
    let parts: Vec<&str> = encrypted_key.split('.').collect();
    println!("Enc type: {}", parts[0]);
    let data_parts: Vec<&str> = parts[1].split('|').collect();
    println!("Data parts: {} (iv | ct | mac)", data_parts.len());
    
    // Try prelogin to get fresh KDF params
    let api = BitwardenApi::new(
        "https://identity.bitwarden.com",
        "https://api.bitwarden.com", 
        &device_id
    );
    
    println!("\nFetching prelogin...");
    let prelogin = api.prelogin(&email).await?;
    println!("Server KDF: type={}, iterations={}", prelogin.kdf, prelogin.kdf_iterations);
    println!("Config KDF: type={:?}, iterations={:?}", config.kdf_type, config.kdf_iterations);
    
    // Compare KDF params
    if config.kdf_type != Some(prelogin.kdf) || config.kdf_iterations != Some(prelogin.kdf_iterations) {
        println!("⚠ KDF PARAMS MISMATCH! Config is stale.");
    } else {
        println!("✓ KDF params match");
    }
    
    let kdf_params = prelogin.to_kdf_params();
    
    // Derive with server's params
    println!("\nDeriving master key with server params...");
    let master_key = MasterKey::derive(password, &email, &kdf_params)?;
    let hash = master_key.master_password_hash(password);
    println!("Password hash (first 20 chars): {}...", &hash[..20]);
    
    // Try password login to verify the password itself is correct
    println!("\nTrying password login to verify password...");
    
    // Try with different endpoints and client IDs
    for cid in &["web", "browser", "connector", "cli", "desktop", "mobile"] {
        match api.login_with_client_id(&email, &hash, cid).await {
            Ok(token) => {
                println!("✓ Login succeeded with client_id={}", cid);
                println!("  Token key present: {}", token.key.is_some());
                if let Some(ref key) = token.key {
                    println!("  Token encrypted_user_key: {}", &key[..40]);
                    println!("  Config encrypted_user_key: {}", &encrypted_key[..40]);
                    if key == encrypted_key {
                        println!("  ✓ Keys match!");
                    } else {
                        println!("  ⚠ Keys DIFFER! Config key is stale.");
                        // Try decrypt with the NEW key
                        let stretched = master_key.stretch()?;
                        match EncString(key.clone()).decrypt_to_key(&stretched) {
                            Ok(_) => println!("  ✓ NEW key decrypts successfully!"),
                            Err(e) => println!("  ✗ NEW key also fails: {}", e),
                        }
                    }
                }
                break;
            }
            Err(e) => {
                println!("  client_id={}: {}", cid, e);
            }
        }
    }
    
    // Also try decrypting with config params (in case they differ)
    let config_kdf = config.kdf_params().expect("No KDF params in config");
    let config_mk = MasterKey::derive(password, &email, &config_kdf)?;
    let config_stretched = config_mk.stretch()?;
    println!("\nDecrypt with config KDF params:");
    match EncString(encrypted_key.clone()).decrypt_to_key(&config_stretched) {
        Ok(_) => println!("  ✓ Works!"),
        Err(e) => println!("  ✗ {}", e),
    }
    
    Ok(())
}
