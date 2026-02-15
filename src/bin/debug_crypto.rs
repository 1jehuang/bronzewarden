use bronzewarden::crypto::{EncString, KdfParams, KdfType, MasterKey};
use base64::Engine;

fn main() {
    let password = "jeremygoat123";
    let email = "jeremyhuang55555@gmail.com";
    let encrypted_key = "2.Pp2WwptfV23sh73PZyWowQ==|b2VNh6BUuoYA9rXrsx5zjbumiugFISw02OBgAVCcgFhMZn90bQxpH+pQBdvpDV8XTiZinZuDiIk0CRqQ3wI8UT5mN4WU0hIvjMO7hkIjn9g=|5q1B+WO20ZPszWN68GitSoRysZQoFjJeKzaFgY87afQ=";
    
    let params = KdfParams {
        kdf_type: KdfType::Pbkdf2,
        iterations: 600_000,
        memory: None,
        parallelism: None,
    };
    
    let master_key = MasterKey::derive(password, email, &params).unwrap();
    let stretched = master_key.stretch().unwrap();
    
    // Print the stretched key bytes
    let b64 = base64::engine::general_purpose::STANDARD;
    println!("Stretched enc_key: {}", b64.encode(&stretched.enc_key));
    println!("Stretched mac_key: {}", b64.encode(&stretched.mac_key));
    
    // Now manually parse the encrypted_user_key
    let parts: Vec<&str> = encrypted_key.split('.').collect();
    let enc_type: u8 = parts[0].parse().unwrap();
    println!("\nEnc type: {}", enc_type);
    
    let data_parts: Vec<&str> = parts[1].split('|').collect();
    let iv = b64.decode(data_parts[0]).unwrap();
    let ct = b64.decode(data_parts[1]).unwrap();
    let mac = b64.decode(data_parts[2]).unwrap();
    
    println!("IV len: {}", iv.len());
    println!("CT len: {}", ct.len());
    println!("MAC len: {}", mac.len());
    
    // Manually compute HMAC
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    
    let mut hmac = HmacSha256::new_from_slice(&stretched.mac_key).unwrap();
    hmac.update(&iv);
    hmac.update(&ct);
    let computed_mac = hmac.finalize().into_bytes();
    
    println!("\nComputed MAC: {}", b64.encode(&computed_mac));
    println!("Expected MAC: {}", b64.encode(&mac));
    println!("MACs match: {}", computed_mac.as_slice() == mac.as_slice());
    
    // Also try without stretching (raw 32-byte key split into enc+mac)
    // Maybe the key format is different
    println!("\n--- Trying raw master key as enc_key (no HKDF) ---");
    // Actually, let's check: what if the official SDK test vector for 
    // the decrypt path uses a different stretch?
    
    // Let me also try: official SDK test uses password "asdfasdfasdf" with
    // legacy type 0 key. Our key is type 2. The stretch should be HKDF.
    // Let me just dump the raw master key bytes for comparison
    let hash = master_key.master_password_hash(password);
    println!("Master password hash: {}", hash);
}
