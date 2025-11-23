use std::{env, fs};
use std::path::Path;
use serde::Serializer;
use base64::{Engine, engine::general_purpose};
use crate::auth::password_auth::Password;

/// Serializes a Password to a boolean
pub fn serialize_password_hash<S>(password_hash: &Option<Password>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bool(password_hash.is_some())
}

/// Get secret
pub fn get_secret(name: &str) -> anyhow::Result<String> {
    if let Ok(env_var) = env::var(name) {
        Ok(if Path::new(&env_var).exists() {
            fs::read_to_string(env_var)
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            env_var
        })
    } else {
        // Try to read from Docker secrets location
        if let Ok(content) = fs::read_to_string("/run/secrets/".to_string() + name) {
            Ok(content.trim().to_string())
        } else {
            // For development, generate a default secret if none is provided
            if name == "VAULTLS_API_SECRET" {
                // Rocket requires the secret_key to be base64-encoded
                // Use a fixed base64-encoded 32-byte development secret for consistency during development
                Ok(general_purpose::STANDARD.encode("0123456789abcdef0123456789abcdef"))
            } else {
                Err(anyhow::anyhow!("Secret '{name}' not found in environment variable, file, or Docker secrets"))
            }
        }
    }
}
