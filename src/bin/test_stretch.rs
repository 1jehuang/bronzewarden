use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

fn main() {
    let b64 = base64::engine::general_purpose::STANDARD;
    
    // Official SDK test key
    let key: [u8; 32] = [
        31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167,
        69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
    ];
    
    // Expected from official SDK
    let expected_enc: [u8; 32] = [
        111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
        134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96
    ];
    let expected_mac: [u8; 32] = [
        221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
        166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155
    ];
    
    // Our implementation
    let hk = Hkdf::<Sha256>::new(None, &key);
    let mut our_enc = [0u8; 32];
    let mut our_mac = [0u8; 32];
    hk.expand(b"enc", &mut our_enc).unwrap();
    hk.expand(b"mac", &mut our_mac).unwrap();
    
    println!("=== Stretch key test (official SDK test vector) ===");
    println!("Our enc_key: {:?}", our_enc);
    println!("Expected:    {:?}", expected_enc);
    println!("Match: {}", our_enc == expected_enc);
    println!();
    println!("Our mac_key: {:?}", our_mac);
    println!("Expected:    {:?}", expected_mac);
    println!("Match: {}", our_mac == expected_mac);
    
    // Now check what hkdf_expand does in the official SDK
    // They call: hkdf_expand(key, Some("enc"))
    // Let's check if they use the info as bytes differently
    // From the source: hkdf_expand(key, Some("enc"))
    // The official util.rs should have hkdf_expand
}
