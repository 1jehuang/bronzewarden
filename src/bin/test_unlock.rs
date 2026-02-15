use bronzewarden::config::Config;
use bronzewarden::crypto::{EncString, MasterKey};
use bronzewarden::vault::Vault;
use bronzewarden::api::SyncResponse;

fn main() {
    let password = "jeremygoat123";
    
    let config = Config::load().expect("Failed to load config");
    let email = config.email.as_ref().expect("Not logged in");
    let encrypted_key = config.encrypted_user_key.as_ref().expect("No user key");
    let kdf_params = config.kdf_params().expect("No KDF params");
    
    println!("Email: {}", email);
    println!("KDF type: {:?}", kdf_params.kdf_type);
    println!("KDF iterations: {}", kdf_params.iterations);
    println!("Encrypted key: {}", &encrypted_key[..40]);
    
    println!("\nDeriving master key...");
    let master_key = MasterKey::derive(password, email, &kdf_params).expect("Key derivation failed");
    
    println!("Stretching key...");
    let stretched = master_key.stretch().expect("Stretch failed");
    
    println!("Decrypting user key...");
    match EncString(encrypted_key.clone()).decrypt_to_key(&stretched) {
        Ok(user_key) => {
            println!("✓ User key decrypted successfully!");
            
            let cache = Config::load_vault_cache().expect("No vault cache");
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
            
            let vault = Vault::new(user_key, &sync);
            println!("Vault unlocked: {} logins", vault.login_count());
            
            let results = vault.find_by_domain("github.com");
            println!("GitHub results: {}", results.len());
            for r in &results {
                println!("  - {} ({})", r.name, r.username);
            }
        }
        Err(e) => {
            println!("✗ Failed to decrypt user key: {}", e);
        }
    }
}
