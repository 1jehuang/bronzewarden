use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

use crate::crypto::SymmetricKey;

#[derive(Serialize, Deserialize)]
pub struct ProtectedKeyFile {
    pub version: u32,
    pub enc_key: String,
    pub mac_key: String,
    pub machine_key: String,
    pub iv_enc: String,
    pub iv_mac: String,
    pub mac_enc: String,
    pub mac_mac: String,
}

fn protected_key_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("No config directory"))?
        .join("bronzewarden");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("protected_key.json"))
}

fn generate_random_bytes<const N: usize>() -> [u8; N] {
    use std::fs::File;
    use std::io::Read;
    let mut buf = [0u8; N];
    File::open("/dev/urandom")
        .expect("Failed to open /dev/urandom")
        .read_exact(&mut buf)
        .expect("Failed to read random bytes");
    buf
}

fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
    encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let mut buf = ciphertext.to_vec();
    let pt = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow!("Decrypt error: {}", e))?;
    Ok(pt.to_vec())
}

fn hmac_sign(mac_key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC init");
    mac.update(iv);
    mac.update(ct);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_verify(mac_key: &[u8], iv: &[u8], ct: &[u8], expected: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|e| anyhow!("HMAC init: {}", e))?;
    mac.update(iv);
    mac.update(ct);
    mac.verify_slice(expected)
        .map_err(|_| anyhow!("HMAC verification failed — protected key is corrupt or tampered"))
}

pub fn store_protected_key(user_key: &SymmetricKey) -> Result<()> {
    let machine_key: [u8; 32] = generate_random_bytes();
    let machine_mac: [u8; 32] = generate_random_bytes();

    let iv_enc: [u8; 16] = generate_random_bytes();
    let iv_mac: [u8; 16] = generate_random_bytes();

    let ct_enc = aes_cbc_encrypt(&machine_key, &iv_enc, &user_key.enc_key);
    let ct_mac = aes_cbc_encrypt(&machine_key, &iv_mac, &user_key.mac_key);

    let mac_enc = hmac_sign(&machine_mac, &iv_enc, &ct_enc);
    let mac_mac = hmac_sign(&machine_mac, &iv_mac, &ct_mac);

    let combined_machine_key = [machine_key.as_slice(), machine_mac.as_slice()].concat();

    let file = ProtectedKeyFile {
        version: 1,
        enc_key: B64.encode(&ct_enc),
        mac_key: B64.encode(&ct_mac),
        machine_key: B64.encode(&combined_machine_key),
        iv_enc: B64.encode(iv_enc),
        iv_mac: B64.encode(iv_mac),
        mac_enc: B64.encode(&mac_enc),
        mac_mac: B64.encode(&mac_mac),
    };

    let path = protected_key_path()?;
    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(&path, &json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub fn load_protected_key() -> Result<SymmetricKey> {
    let path = protected_key_path()?;
    let json = std::fs::read_to_string(&path)
        .map_err(|_| anyhow!("No protected key found. Run `bronzewarden setup-fingerprint` first."))?;
    let file: ProtectedKeyFile = serde_json::from_str(&json)?;

    if file.version != 1 {
        return Err(anyhow!("Unsupported protected key version: {}", file.version));
    }

    let combined_machine_key = B64.decode(&file.machine_key)?;
    if combined_machine_key.len() != 64 {
        return Err(anyhow!("Invalid machine key length"));
    }
    let mut machine_key = [0u8; 32];
    let mut machine_mac = [0u8; 32];
    machine_key.copy_from_slice(&combined_machine_key[..32]);
    machine_mac.copy_from_slice(&combined_machine_key[32..]);

    let ct_enc = B64.decode(&file.enc_key)?;
    let ct_mac = B64.decode(&file.mac_key)?;
    let iv_enc_bytes = B64.decode(&file.iv_enc)?;
    let iv_mac_bytes = B64.decode(&file.iv_mac)?;
    let mac_enc = B64.decode(&file.mac_enc)?;
    let mac_mac = B64.decode(&file.mac_mac)?;

    let iv_enc: [u8; 16] = iv_enc_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid IV length"))?;
    let iv_mac: [u8; 16] = iv_mac_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid IV length"))?;

    hmac_verify(&machine_mac, &iv_enc, &ct_enc, &mac_enc)?;
    hmac_verify(&machine_mac, &iv_mac, &ct_mac, &mac_mac)?;

    let enc_key_bytes = aes_cbc_decrypt(&machine_key, &iv_enc, &ct_enc)?;
    let mac_key_bytes = aes_cbc_decrypt(&machine_key, &iv_mac, &ct_mac)?;

    if enc_key_bytes.len() != 32 || mac_key_bytes.len() != 32 {
        return Err(anyhow!("Decrypted key has wrong length"));
    }

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_bytes);
    mac_key.copy_from_slice(&mac_key_bytes);

    Ok(SymmetricKey { enc_key, mac_key })
}

pub fn has_protected_key() -> bool {
    protected_key_path()
        .map(|p| p.exists())
        .unwrap_or(false)
}

pub fn remove_protected_key() -> Result<()> {
    let path = protected_key_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key = SymmetricKey {
            enc_key: generate_random_bytes(),
            mac_key: generate_random_bytes(),
        };

        store_protected_key(&key).unwrap();
        let loaded = load_protected_key().unwrap();

        assert_eq!(key.enc_key, loaded.enc_key);
        assert_eq!(key.mac_key, loaded.mac_key);

        remove_protected_key().unwrap();
    }
}
