use anyhow::{anyhow, Result};

use crate::api::{SyncCipher, SyncResponse};
use crate::crypto::{EncString, SymmetricKey};

#[derive(Debug, Clone)]
pub struct Credential {
    pub name: String,
    pub username: String,
    pub password: String,
    pub uris: Vec<String>,
    pub totp: Option<String>,
}

pub struct Vault {
    user_key: SymmetricKey,
    ciphers: Vec<SyncCipher>,
}

impl Vault {
    pub fn new(user_key: SymmetricKey, sync: &SyncResponse) -> Self {
        Self {
            user_key,
            ciphers: sync.ciphers.clone(),
        }
    }

    pub fn cipher_count(&self) -> usize {
        self.ciphers.len()
    }

    pub fn login_count(&self) -> usize {
        self.ciphers
            .iter()
            .filter(|c| c.cipher_type == 1 && c.deleted_date.is_none())
            .count()
    }

    fn resolve_key(&self, cipher: &SyncCipher) -> Result<SymmetricKey> {
        if cipher.organization_id.is_some() {
            return Err(anyhow!("Organization ciphers not yet supported"));
        }

        if let Some(ref cipher_key_str) = cipher.key {
            let enc = EncString(cipher_key_str.clone());
            return enc.decrypt_to_key(&self.user_key);
        }

        Ok(self.user_key.clone())
    }

    fn decrypt_field(&self, field: &Option<String>, key: &SymmetricKey) -> Option<String> {
        field.as_ref().and_then(|s| {
            if s.is_empty() {
                return None;
            }
            EncString(s.clone()).decrypt_to_string(key).ok()
        })
    }

    pub fn decrypt_cipher(&self, cipher: &SyncCipher) -> Result<Option<Credential>> {
        if cipher.cipher_type != 1 || cipher.deleted_date.is_some() {
            return Ok(None);
        }

        let login = match &cipher.login {
            Some(l) => l,
            None => return Ok(None),
        };

        let key = self.resolve_key(cipher)?;

        let name = self.decrypt_field(&cipher.name, &key).unwrap_or_default();
        let username = self
            .decrypt_field(&login.username, &key)
            .unwrap_or_default();
        let password = self
            .decrypt_field(&login.password, &key)
            .unwrap_or_default();
        let totp = self.decrypt_field(&login.totp, &key);

        let uris: Vec<String> = login
            .uris
            .as_ref()
            .map(|uris| {
                uris.iter()
                    .filter_map(|u| self.decrypt_field(&u.uri, &key))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(Credential {
            name,
            username,
            password,
            uris,
            totp,
        }))
    }

    pub fn search(&self, query: &str) -> Vec<Credential> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for cipher in &self.ciphers {
            if cipher.cipher_type != 1 || cipher.deleted_date.is_some() {
                continue;
            }

            let cred = match self.decrypt_cipher(cipher) {
                Ok(Some(c)) => c,
                _ => continue,
            };

            let matches = cred.name.to_lowercase().contains(&query_lower)
                || cred.username.to_lowercase().contains(&query_lower)
                || cred
                    .uris
                    .iter()
                    .any(|u| u.to_lowercase().contains(&query_lower));

            if matches {
                results.push(cred);
            }
        }

        results
    }

    pub fn find_by_domain(&self, domain: &str) -> Vec<Credential> {
        let domain_lower = domain.to_lowercase();
        let mut results = Vec::new();

        for cipher in &self.ciphers {
            if cipher.cipher_type != 1 || cipher.deleted_date.is_some() {
                continue;
            }

            let cred = match self.decrypt_cipher(cipher) {
                Ok(Some(c)) => c,
                _ => continue,
            };

            let uri_matches = cred.uris.iter().any(|uri| {
                if let Ok(parsed) = url::Url::parse(uri) {
                    if let Some(host) = parsed.host_str() {
                        return host.to_lowercase() == domain_lower
                            || host.to_lowercase().ends_with(&format!(".{}", domain_lower));
                    }
                }
                uri.to_lowercase().contains(&domain_lower)
            });

            let name_matches = cred.name.to_lowercase().contains(&domain_lower);

            if uri_matches || name_matches {
                results.push(cred);
            }
        }

        results
    }
}
