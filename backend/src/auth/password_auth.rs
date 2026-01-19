use crate::constants::ARGON2;
use crate::ApiError;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{password_hash, PasswordHasher, PasswordVerifier};
use std::fmt::Display;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use tracing::warn;

#[derive(Clone, Debug)]
pub enum Password {
    V1(PasswordHashString),
    V2(PasswordHashString)
}

impl Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Password::V1(p) => write!(f, "v1{p}"),
            Password::V2(p) => write!(f, "v2{p}")
        }
    }
}

impl TryFrom<&str> for Password {
    type Error = password_hash::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(extract) = s.strip_prefix("v1") {
            Ok(Password::V1(PasswordHashString::new(extract)?))
        } else if let Some(extract) = s.strip_prefix("v2") {
            Ok(Password::V2(PasswordHashString::new(extract)?))
        } else {
            Ok(Password::V1(PasswordHashString::new(s)?))
        }
    }
}

impl FromSql for Password {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Text(s) => {
                let s = String::from_utf8_lossy(s).to_string();
                Password::try_from(s.as_str()).map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

impl Password {
    /// Verify password hash with corresponding password
    /// SECURITY: V2 password hashes are no longer accepted for security reasons.
    /// Users with V2 hashes must re-authenticate and their passwords will be rehashed to V1.
    pub(crate) fn verify(&self, password: &str) -> bool {
        match self {
            Password::V1(inner) => {
                // V1: Direct server-side hash verification
                ARGON2.verify_password(password.as_bytes(), &inner.password_hash()).is_ok()
            },
            Password::V2(_) => {
                // SECURITY: V2 password hashes are rejected due to hardcoded salt vulnerability
                // Users with V2 hashes will fail authentication and need to reset their passwords
                warn!("Attempted login with deprecated V2 password hash - password rehash required");
                false
            },
        }
    }

    /// Check if this password hash is using the deprecated V2 scheme
    pub(crate) fn is_v2_hash(&self) -> bool {
        matches!(self, Password::V2(_))
    }


    
    /// Hashes a password using Argon2 server-side with random salt
    pub(crate) fn new_server_hash(password: &str) -> Result<Password, ApiError> {
        let salt = SaltString::generate(&mut OsRng);

        let password_hash_string = ARGON2.hash_password(password.as_bytes(), &salt)
            .map_err(|_| ApiError::Other("Failed to hash password".to_string()))?
            .serialize();

        // Always create V1 (single server-side hash) for new passwords
        Ok(Password::V1(password_hash_string))
    }
    

}
