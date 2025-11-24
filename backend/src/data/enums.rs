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
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 7,
    PrivilegeWithdrawn = 8,
    AACompromise = 9,
}

impl CertificateRevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificateRevocationReason::Unspecified => "Unspecified",
            CertificateRevocationReason::KeyCompromise => "Key Compromise",
            CertificateRevocationReason::CACompromise => "CA Compromise",
            CertificateRevocationReason::AffiliationChanged => "Affiliation Changed",
            CertificateRevocationReason::Superseded => "Superseded",
            CertificateRevocationReason::CessationOfOperation => "Cessation of Operation",
            CertificateRevocationReason::CertificateHold => "Certificate Hold",
            CertificateRevocationReason::RemoveFromCRL => "Remove from CRL",
            CertificateRevocationReason::PrivilegeWithdrawn => "Privilege Withdrawn",
            CertificateRevocationReason::AACompromise => "AA Compromise",
        }
    }

    /// Convert u8 value from database to enum with backward compatibility for old internal reasons
    pub fn from_u8_with_rfc5280_support(value: u8, custom_reason: Option<String>) -> (Self, Option<String>) {
        match value {
            // Standard RFC 5280 reasons - direct mapping
            0 => (CertificateRevocationReason::Unspecified, custom_reason),
            1 => (CertificateRevocationReason::KeyCompromise, custom_reason),
            2 => (CertificateRevocationReason::CACompromise, custom_reason),
            3 => (CertificateRevocationReason::AffiliationChanged, custom_reason),
            4 => (CertificateRevocationReason::Superseded, custom_reason),
            5 => (CertificateRevocationReason::CessationOfOperation, custom_reason),
            6 => (CertificateRevocationReason::CertificateHold, custom_reason),
            7 => (CertificateRevocationReason::RemoveFromCRL, custom_reason),
            8 => (CertificateRevocationReason::PrivilegeWithdrawn, custom_reason),
            9 => (CertificateRevocationReason::AACompromise, custom_reason),
            // Backward compatibility: map old internal reasons to standard ones
            10 => (CertificateRevocationReason::Unspecified, custom_reason), // used to be old unspecified
            254 => (CertificateRevocationReason::CertificateHold, custom_reason), // used to be old certificateHold
            255 => (CertificateRevocationReason::Unspecified, custom_reason), // used to be old specify (no value provided)
            _ => (CertificateRevocationReason::Unspecified, custom_reason),
        }
    }

    /// Get human-readable reason text
    pub fn human_readable_reason(&self, custom_reason: Option<&str>) -> String {
        self.as_str().to_string()
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
