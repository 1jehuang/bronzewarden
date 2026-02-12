use anyhow::{anyhow, Result};
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::crypto::{KdfParams, KdfType};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub struct BitwardenApi {
    client: Client,
    pub identity_url: String,
    pub api_url: String,
    device_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PreloginResponse {
    #[serde(rename = "kdf")]
    pub kdf: u32,
    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "kdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(rename = "kdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    #[serde(rename = "Key")]
    pub key: Option<String>,
    #[serde(rename = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(rename = "Kdf")]
    pub kdf: Option<u32>,
    #[serde(rename = "KdfIterations")]
    pub kdf_iterations: Option<u32>,
    #[serde(rename = "KdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct SyncResponse {
    pub profile: SyncProfile,
    pub ciphers: Vec<SyncCipher>,
    pub folders: Option<Vec<SyncFolder>>,
}

#[derive(Debug, Deserialize)]
pub struct SyncProfile {
    pub id: String,
    pub email: Option<String>,
    #[serde(rename = "key")]
    pub key: Option<String>,
    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCipher {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: u32,
    pub name: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    pub login: Option<SyncCipherLogin>,
    pub notes: Option<String>,
    pub fields: Option<Vec<SyncCipherField>>,
    pub key: Option<String>,
    #[serde(rename = "revisionDate")]
    pub revision_date: Option<String>,
    #[serde(rename = "deletedDate")]
    pub deleted_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCipherLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<SyncCipherUri>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCipherUri {
    pub uri: Option<String>,
    #[serde(rename = "match")]
    pub match_type: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCipherField {
    #[serde(rename = "type")]
    pub field_type: u32,
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncFolder {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    #[serde(rename = "error_description")]
    error_description: Option<String>,
    #[serde(rename = "ErrorModel")]
    error_model: Option<ErrorModel>,
    #[serde(rename = "Message")]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorModel {
    #[serde(rename = "Message")]
    message: Option<String>,
}

impl PreloginResponse {
    pub fn to_kdf_params(&self) -> KdfParams {
        KdfParams {
            kdf_type: if self.kdf == 1 {
                KdfType::Argon2id
            } else {
                KdfType::Pbkdf2
            },
            iterations: self.kdf_iterations,
            memory: self.kdf_memory,
            parallelism: self.kdf_parallelism,
        }
    }
}

impl BitwardenApi {
    pub fn new(identity_url: &str, api_url: &str, device_id: &str) -> Self {
        Self {
            client: Client::new(),
            identity_url: identity_url.to_string(),
            api_url: api_url.to_string(),
            device_id: device_id.to_string(),
        }
    }

    pub fn official() -> Self {
        Self::new(
            "https://identity.bitwarden.com",
            "https://api.bitwarden.com",
            &uuid::Uuid::new_v4().to_string(),
        )
    }

    pub fn with_device_id(mut self, device_id: &str) -> Self {
        self.device_id = device_id.to_string();
        self
    }

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        let url = format!("{}/accounts/prelogin", self.identity_url);
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({"email": email}))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Prelogin failed: {}", text));
        }

        Ok(resp.json().await?)
    }

    pub async fn login(
        &self,
        email: &str,
        master_password_hash: &str,
    ) -> Result<TokenResponse> {
        let url = format!("{}/connect/token", self.identity_url);
        let auth_email = B64.encode(email.as_bytes());

        let resp = self
            .client
            .post(&url)
            .header("Auth-Email", &auth_email)
            .form(&[
                ("scope", "api offline_access"),
                ("client_id", "connector"),
                ("deviceType", "10"),
                ("deviceIdentifier", &self.device_id),
                ("deviceName", "bronzewarden"),
                ("grant_type", "password"),
                ("username", email),
                ("password", master_password_hash),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<ErrorResponse>(&text) {
                let msg = err
                    .error_description
                    .or(err.message)
                    .or(err.error_model.and_then(|m| m.message))
                    .unwrap_or(text.clone());
                return Err(anyhow!("Login failed: {}", msg));
            }
            return Err(anyhow!("Login failed: {}", text));
        }

        Ok(resp.json().await?)
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let url = format!("{}/connect/token", self.identity_url);
        let resp = self
            .client
            .post(&url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", "connector"),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed: {}", text));
        }

        Ok(resp.json().await?)
    }

    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        let url = format!("{}/sync", self.api_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .header("Device-Type", "10")
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Sync failed ({}): {}", status, text));
        }

        Ok(resp.json().await?)
    }
}
