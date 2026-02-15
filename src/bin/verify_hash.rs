use bronzewarden::crypto::{KdfParams, KdfType, MasterKey};

fn main() {
    // Test case from official Bitwarden SDK:
    // password = "asdfasdf", salt = "test@bitwarden.com", 
    // iterations = 100000, expected hash = "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw="
    let params = KdfParams {
        kdf_type: KdfType::Pbkdf2,
        iterations: 100_000,
        memory: None,
        parallelism: None,
    };
    
    let mk = MasterKey::derive("asdfasdf", "test@bitwarden.com", &params).unwrap();
    let hash = mk.master_password_hash("asdfasdf");
    
    println!("Our hash:      {}", hash);
    println!("Expected hash: wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=");
    
    if hash == "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=" {
        println!("✓ PBKDF2 + hash implementation matches official Bitwarden SDK!");
    } else {
        println!("✗ MISMATCH! Our implementation is wrong.");
    }
    
    // Now test with our actual credentials
    let params = KdfParams {
        kdf_type: KdfType::Pbkdf2,
        iterations: 600_000,
        memory: None,
        parallelism: None,
    };
    
    let mk = MasterKey::derive("jeremygoat123", "jeremyhuang55555@gmail.com", &params).unwrap();
    let hash = mk.master_password_hash("jeremygoat123");
    println!("\nActual hash for jeremygoat123: {}", hash);
}
