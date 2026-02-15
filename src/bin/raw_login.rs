use anyhow::Result;
use bronzewarden::api::BitwardenApi;
use bronzewarden::config::Config;
use bronzewarden::crypto::MasterKey;

#[tokio::main]
async fn main() -> Result<()> {
    let password = "jeremygoat123";
    
    let config = Config::load()?;
    let email = config.email.as_ref().expect("Not logged in").clone();
    let device_id = config.device_id.clone();
    
    let api = BitwardenApi::new(
        "https://identity.bitwarden.com",
        "https://api.bitwarden.com", 
        &device_id
    );
    
    println!("Fetching prelogin...");
    let prelogin = api.prelogin(&email).await?;
    println!("Server: kdf_type={}, iterations={}", prelogin.kdf, prelogin.kdf_iterations);
    
    let kdf_params = prelogin.to_kdf_params();
    let master_key = MasterKey::derive(password, &email, &kdf_params)?;
    let hash = master_key.master_password_hash(password);
    
    println!("Hash: {}", hash);
    
    // Try the raw HTTP request to see the full error response
    let client = reqwest::Client::new();
    let auth_email = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        email.trim().to_lowercase().as_bytes()
    );
    
    println!("\nAuth-Email header: {}", auth_email);
    println!("Username: {}", email.trim().to_lowercase());
    
    let resp = client
        .post("https://identity.bitwarden.com/connect/token")
        .header("Auth-Email", &auth_email)
        .form(&[
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "10"),
            ("deviceIdentifier", &device_id),
            ("deviceName", "bronzewarden"),
            ("grant_type", "password"),
            ("username", email.trim().to_lowercase().as_str()),
            ("password", &hash),
        ])
        .send()
        .await?;
    
    let status = resp.status();
    let body = resp.text().await?;
    println!("\nStatus: {}", status);
    println!("Response: {}", body);
    
    Ok(())
}
