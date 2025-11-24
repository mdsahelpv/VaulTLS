use num_enum::TryFromPrimitive;
use rocket_okapi::JsonSchema;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, TryFromPrimitive, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserRole {
    User = 0,
    Admin = 1
}

impl FromSql for UserRole {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                UserRole::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum MailEncryption {
    #[default]
    None = 0,
    TLS = 1,
    STARTTLS = 2
}

impl From<String> for MailEncryption {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str()
        {
            "TLS" => MailEncryption::TLS,
            "STARTTLS" => MailEncryption::STARTTLS,
            _ => MailEncryption::None
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum PasswordRule {
    #[default]
    Optional = 0,
    Required = 1,
    System = 2
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateType {
    #[default]
    Client = 0,
    Server = 1,
    SubordinateCA = 2
}

impl FromSql for CertificateType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateType::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateRenewMethod {
    #[default]
    None = 0,
    Notify = 1,
    Renew = 2,
    RenewAndNotify = 3
}

impl FromSql for CertificateRenewMethod {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateRenewMethod::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateFormat {
    #[default]
    PKCS12 = 0,
    PEM = 1,
    DER = 2,
    PemKey = 3
}

impl CertificateFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            CertificateFormat::PKCS12 => "p12",
            CertificateFormat::PEM => "pem",
            CertificateFormat::DER => "der",
            CertificateFormat::PemKey => "zip",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "pkcs12" => Ok(CertificateFormat::PKCS12),
            "pem" => Ok(CertificateFormat::PEM),
            "der" => Ok(CertificateFormat::DER),
            "pem_key" => Ok(CertificateFormat::PemKey),
            _ => Err(format!("Invalid certificate format: {s}")),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateRevocationReason {
    #[default]
    Unspecified = 0,
    CertificateHold = 1,
    Specify = 2,
}

impl CertificateRevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificateRevocationReason::Unspecified => "Unspecified",
            CertificateRevocationReason::CertificateHold => "Certificate Hold",
            CertificateRevocationReason::Specify => "Specify (custom reason)",
        }
    }

    /// Convert u8 value from database to enum with backward compatibility for RFC5280 reasons
    pub fn from_u8_with_rfc5280_support(value: u8, custom_reason: Option<String>) -> (Self, Option<String>) {
        match value {
            0 => (CertificateRevocationReason::Unspecified, custom_reason),
            1 => (CertificateRevocationReason::CertificateHold, custom_reason),
            2 => (CertificateRevocationReason::Specify, custom_reason),
            // Map legacy RFC5280 reasons to appropriate current values
            3 => (CertificateRevocationReason::Specify, Some("Affiliation Changed".to_string())), // affiliationChanged
            4 => (CertificateRevocationReason::Specify, Some("Superseded".to_string())),          // superseded
            5 => (CertificateRevocationReason::Specify, Some("Cessation of Operation".to_string())), // cessationOfOperation
            6 => (CertificateRevocationReason::CertificateHold, custom_reason),                   // certificateHold
            8 => (CertificateRevocationReason::Specify, Some("Remove from CRL".to_string())),      // removeFromCRL
            9 => (CertificateRevocationReason::Specify, Some("Privilege Withdrawn".to_string())), // privilegeWithdrawn
            10 => (CertificateRevocationReason::Specify, Some("AA Compromise".to_string())),       // aaCompromise
            _ => (CertificateRevocationReason::Unspecified, custom_reason),
        }
    }

    /// Get human-readable reason text with legacy RFC5280 support
    pub fn human_readable_reason(&self, custom_reason: Option<&str>) -> String {
        match (self, custom_reason) {
            (CertificateRevocationReason::Unspecified, _) => "Unspecified".to_string(),
            (CertificateRevocationReason::CertificateHold, _) => "Certificate Hold".to_string(),
            (CertificateRevocationReason::Specify, Some(reason)) => format!("Specify - {}", reason),
            (CertificateRevocationReason::Specify, None) => "Specify (custom reason)".to_string(),
        }
    }
}

impl FromSql for CertificateRevocationReason {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateRevocationReason::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}
