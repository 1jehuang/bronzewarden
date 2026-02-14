# bronzewarden

A minimal [Bitwarden](https://bitwarden.com)-compatible vault client written in Rust.

Born from the discontinuation of [Goldwarden](https://github.com/quexten/goldwarden) — bronzewarden reimplements the core vault access functionality from scratch in Rust, with a focus on simplicity and embeddability.

## Features

- **Login** with email + master password (PBKDF2 and Argon2id KDF)
- **Login with personal API key** (`BW_CLIENTID` + `BW_CLIENTSECRET`)
- **Sync** vault from Bitwarden servers (official or self-hosted)
- **Search** credentials by domain, name, or username
- **Decrypt** vault items locally — your master password never leaves your machine
- **Library + CLI** — use as a Rust crate or standalone command-line tool

## Security Model

- Master password is used only for key derivation, never stored
- Vault data is cached locally in encrypted form (decrypted on-demand with master password)
- Config files are stored with `0600` permissions
- No credentials are ever logged or exposed in process arguments

## Install

```bash
cargo install --path .
```

## Usage

```bash
# Log in (prompts for master password)
bronzewarden login -e you@example.com

# API key login (useful if password login is challenged)
export BW_CLIENTID="user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export BW_CLIENTSECRET="your_client_secret"
bronzewarden login --apikey

# Or run without env vars and enter API key interactively
bronzewarden login --apikey

# Sync vault
bronzewarden sync

# Look up credentials (prompts for master password to decrypt)
bronzewarden get github.com

# Show full password
bronzewarden get github.com --password

# JSON output
bronzewarden get github.com --json

# Check status
bronzewarden status

# Log out
bronzewarden logout
```

### Self-hosted servers

```bash
bronzewarden login -e you@example.com --server https://bw.example.com
```

## As a Library

```rust
use bronzewarden::{Config, Vault};
use bronzewarden::api::BitwardenApi;
use bronzewarden::crypto::{MasterKey, EncString};

// Load config and unlock vault
let config = Config::load()?;
let kdf = config.kdf_params().unwrap();
let master_key = MasterKey::derive("password", "email", &kdf)?;
let user_key = EncString(encrypted_key).decrypt_to_key(&master_key.stretch()?)?;

let cache = Config::load_vault_cache()?;
let vault = Vault::new(user_key, &sync_response);

// Search by domain
let creds = vault.find_by_domain("github.com");
```

## How It Works

1. **Pre-login**: Fetches KDF parameters (PBKDF2 iterations or Argon2id params) from the server
2. **Key derivation**: Derives master key from password + email using the KDF
3. **Authentication**: Sends master password hash (not the password) to get an access token
4. **Sync**: Downloads the encrypted vault using the access token
5. **Decryption**: Uses HKDF-expanded master key to decrypt the user symmetric key, then AES-256-CBC-HMAC-SHA256 to decrypt individual vault items

## License

MIT
