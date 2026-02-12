use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::api::SyncCipher;
use crate::crypto::KdfParams;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub device_id: String,
    pub email: Option<String>,
    pub identity_url: String,
    pub api_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_user_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultCache {
    pub ciphers: Vec<SyncCipher>,
    pub synced_at: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_id: uuid::Uuid::new_v4().to_string(),
            email: None,
            identity_url: "https://identity.bitwarden.com".to_string(),
            api_url: "https://api.bitwarden.com".to_string(),
            access_token: None,
            refresh_token: None,
            encrypted_user_key: None,
            kdf_type: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
        }
    }
}

impl Config {
    pub fn config_dir() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("bronzewarden");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.json"))
    }

    fn vault_cache_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("vault.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    pub fn is_logged_in(&self) -> bool {
        self.access_token.is_some() && self.email.is_some()
    }

    pub fn kdf_params(&self) -> Option<KdfParams> {
        Some(KdfParams {
            kdf_type: match self.kdf_type? {
                1 => crate::crypto::KdfType::Argon2id,
                _ => crate::crypto::KdfType::Pbkdf2,
            },
            iterations: self.kdf_iterations?,
            memory: self.kdf_memory,
            parallelism: self.kdf_parallelism,
        })
    }

    pub fn save_vault_cache(&self, ciphers: &[SyncCipher]) -> Result<()> {
        let cache = VaultCache {
            ciphers: ciphers.to_vec(),
            synced_at: chrono_now(),
        };
        let path = Self::vault_cache_path()?;
        let content = serde_json::to_string(&cache)?;
        std::fs::write(&path, content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    pub fn load_vault_cache() -> Result<VaultCache> {
        let path = Self::vault_cache_path()?;
        if !path.exists() {
            return Err(anyhow!("No vault cache found. Run `bronzewarden sync` first."));
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn clear(&mut self) {
        self.access_token = None;
        self.refresh_token = None;
        self.encrypted_user_key = None;
        self.email = None;
        self.kdf_type = None;
        self.kdf_iterations = None;
        self.kdf_memory = None;
        self.kdf_parallelism = None;
    }
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}
