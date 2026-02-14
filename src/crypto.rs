use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Clone)]
pub struct SymmetricKey {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

pub struct MasterKey {
    key: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncString(pub String);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub kdf_type: KdfType,
    pub iterations: u32,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

impl MasterKey {
    pub fn derive(password: &str, email: &str, params: &KdfParams) -> Result<Self> {
        let email_lower = email.trim().to_lowercase();
        let mut key = [0u8; 32];

        match params.kdf_type {
            KdfType::Pbkdf2 => {
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    password.as_bytes(),
                    email_lower.as_bytes(),
                    params.iterations,
                    &mut key,
                );
            }
            KdfType::Argon2id => {
                use argon2::Argon2;
                use sha2::Digest;

                let salt = Sha256::digest(email_lower.as_bytes());
                let memory = params.memory.unwrap_or(64) * 1024;
                let parallelism = params.parallelism.unwrap_or(4);
                let argon = Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    argon2::Params::new(memory, params.iterations, parallelism, Some(32))
                        .map_err(|e| anyhow!("Argon2 params error: {}", e))?,
                );
                argon
                    .hash_password_into(password.as_bytes(), &salt, &mut key)
                    .map_err(|e| anyhow!("Argon2 error: {}", e))?;
            }
        }

        Ok(MasterKey { key })
    }

    pub fn master_password_hash(&self, password: &str) -> String {
        let mut hash = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&self.key, password.as_bytes(), 1, &mut hash);
        B64.encode(hash)
    }

    pub fn stretch(&self) -> Result<SymmetricKey> {
        let hk = Hkdf::<Sha256>::new(None, &self.key);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        hk.expand(b"enc", &mut enc_key)
            .map_err(|e| anyhow!("HKDF expand enc: {}", e))?;
        hk.expand(b"mac", &mut mac_key)
            .map_err(|e| anyhow!("HKDF expand mac: {}", e))?;
        Ok(SymmetricKey { enc_key, mac_key })
    }
}

impl EncString {
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Vec<u8>> {
        let s = &self.0;

        let (enc_type, rest) = s
            .split_once('.')
            .ok_or_else(|| anyhow!("Invalid enc string: no type prefix"))?;

        let enc_type: u8 = enc_type
            .parse()
            .map_err(|_| anyhow!("Invalid enc type: {}", enc_type))?;

        match enc_type {
            0 => {
                let parts: Vec<&str> = rest.split('|').collect();
                if parts.len() != 2 {
                    return Err(anyhow!(
                        "Type 0 enc string: expected 2 parts, got {}",
                        parts.len()
                    ));
                }
                let iv = B64.decode(parts[0])?;
                let ct = B64.decode(parts[1])?;
                aes_cbc_decrypt(&key.enc_key, &iv, &ct)
            }
            2 => {
                let parts: Vec<&str> = rest.split('|').collect();
                if parts.len() != 3 {
                    return Err(anyhow!(
                        "Type 2 enc string: expected 3 parts, got {}",
                        parts.len()
                    ));
                }
                let iv = B64.decode(parts[0])?;
                let ct = B64.decode(parts[1])?;
                let mac = B64.decode(parts[2])?;

                verify_hmac(&key.mac_key, &iv, &ct, &mac)?;
                aes_cbc_decrypt(&key.enc_key, &iv, &ct)
            }
            _ => Err(anyhow!("Unsupported enc type: {}", enc_type)),
        }
    }

    pub fn decrypt_to_string(&self, key: &SymmetricKey) -> Result<String> {
        let bytes = self.decrypt(key)?;
        String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 decode error: {}", e))
    }

    pub fn decrypt_to_key(&self, key: &SymmetricKey) -> Result<SymmetricKey> {
        let bytes = self.decrypt(key)?;
        if bytes.len() != 64 {
            return Err(anyhow!("Expected 64-byte key, got {} bytes", bytes.len()));
        }
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&bytes[..32]);
        mac_key.copy_from_slice(&bytes[32..]);
        Ok(SymmetricKey { enc_key, mac_key })
    }
}

fn verify_hmac(mac_key: &[u8], iv: &[u8], ct: &[u8], expected_mac: &[u8]) -> Result<()> {
    let mut mac =
        HmacSha256::new_from_slice(mac_key).map_err(|e| anyhow!("HMAC init error: {}", e))?;
    mac.update(iv);
    mac.update(ct);
    mac.verify_slice(expected_mac)
        .map_err(|_| anyhow!("HMAC verification failed"))?;
    Ok(())
}

fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let iv_arr: [u8; 16] = iv
        .try_into()
        .map_err(|_| anyhow!("Invalid IV length: {}", iv.len()))?;
    let decryptor = Aes256CbcDec::new(key.into(), &iv_arr.into());
    let mut buf = ct.to_vec();
    let pt = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow!("AES-CBC decrypt error: {}", e))?;
    Ok(pt.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_pbkdf2() {
        let params = KdfParams {
            kdf_type: KdfType::Pbkdf2,
            iterations: 600000,
            memory: None,
            parallelism: None,
        };
        let mk = MasterKey::derive("password123", "test@example.com", &params).unwrap();
        let hash = mk.master_password_hash("password123");
        assert!(!hash.is_empty());

        let stretched = mk.stretch().unwrap();
        assert_ne!(stretched.enc_key, [0u8; 32]);
        assert_ne!(stretched.mac_key, [0u8; 32]);
    }
}
