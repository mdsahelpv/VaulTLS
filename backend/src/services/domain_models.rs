use crate::data::error::ApiError;
use std::fmt;

/// Domain model for certificate names with built-in validation and sanitization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateName(String);

impl CertificateName {
    const MAX_LENGTH: usize = 255;

    /// Create a new certificate name with validation and sanitization
    pub fn new(name: &str) -> Result<Self, ApiError> {
        // Length validation
        if name.is_empty() {
            return Err(ApiError::BadRequest("Certificate name cannot be empty".to_string()));
        }

        if name.len() > Self::MAX_LENGTH {
            return Err(ApiError::BadRequest(format!(
                "Certificate name is too long (maximum {} characters, got {})",
                Self::MAX_LENGTH,
                name.len()
            )));
        }

        // Sanitization
        let sanitized = Self::sanitize_name(name);

        // Final validation after sanitization
        if sanitized.is_empty() {
            return Err(ApiError::BadRequest("Certificate name cannot be empty after sanitization".to_string()));
        }

        Ok(CertificateName(sanitized))
    }

    /// Sanitize a certificate name by removing dangerous characters
    fn sanitize_name(name: &str) -> String {
        let mut sanitized = name.to_string();

        // Remove dangerous characters that could cause injection
        sanitized = sanitized.replace("../", "");
        sanitized = sanitized.replace("..\\", "");
        sanitized = sanitized.replace("./", "");
        sanitized = sanitized.replace(".\\", "");

        let dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '[', ']', '{', '}', '\'', '"', '\\', '\n', '\r', '\t'];
        for &ch in &dangerous_chars {
            sanitized = sanitized.replace(ch, "");
        }

        sanitized.trim().to_string()
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to owned string
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CertificateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for CertificateName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Domain model for DNS names with validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsName(String);

impl DnsName {
    const MAX_LENGTH: usize = 253;

    /// Create a new DNS name with validation
    pub fn new(name: &str) -> Result<Self, ApiError> {
        let trimmed = name.trim();

        // Length validation
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest("DNS name cannot be empty".to_string()));
        }

        if trimmed.len() > Self::MAX_LENGTH {
            return Err(ApiError::BadRequest(format!(
                "DNS name '{}' is too long (maximum {} characters)",
                trimmed,
                Self::MAX_LENGTH
            )));
        }

        // Format validation
        if trimmed.contains("..") || trimmed.starts_with('.') || trimmed.ends_with('.') {
            return Err(ApiError::BadRequest(format!(
                "Invalid DNS name format: '{}'. DNS names cannot start/end with '.' or contain '..'",
                trimmed
            )));
        }

        // Character validation
        if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.') {
            return Err(ApiError::BadRequest(format!(
                "Invalid DNS name '{}'. Only alphanumeric characters, hyphens, and dots are allowed",
                trimmed
            )));
        }

        // Additional validation: must contain at least one dot (basic domain validation)
        if !trimmed.contains('.') {
            return Err(ApiError::BadRequest(format!(
                "Invalid DNS name '{}'. Must contain at least one dot for domain validation",
                trimmed
            )));
        }

        Ok(DnsName(trimmed.to_string()))
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for DnsName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Domain model for IP addresses with validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddress(String);

impl IpAddress {
    const MAX_LENGTH: usize = 45; // IPv6 addresses can be up to 45 chars

    /// Create a new IP address with validation
    pub fn new(ip: &str) -> Result<Self, ApiError> {
        let trimmed = ip.trim();

        // Length validation
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest("IP address cannot be empty".to_string()));
        }

        if trimmed.len() > Self::MAX_LENGTH {
            return Err(ApiError::BadRequest(format!(
                "IP address '{}' is too long (maximum {} characters)",
                trimmed,
                Self::MAX_LENGTH
            )));
        }

        // Basic format validation
        if !Self::is_valid_ip_format(trimmed) {
            return Err(ApiError::BadRequest(format!(
                "Invalid IP address format: '{}'",
                trimmed
            )));
        }

        Ok(IpAddress(trimmed.to_string()))
    }

    /// Basic IP address format validation (IPv4 and IPv6)
    fn is_valid_ip_format(ip: &str) -> bool {
        // IPv4 validation
        if ip.contains('.') {
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() != 4 {
                return false;
            }
            for part in parts {
                if part.is_empty() || part.len() > 3 {
                    return false;
                }
                if let Ok(num) = part.parse::<u8>() {
                    // Valid 0-255 range
                    continue;
                } else {
                    return false;
                }
            }
            return true;
        }

        // IPv6 validation (basic check)
        if ip.contains(':') {
            // Remove zone identifier if present
            let ip_without_zone = ip.split('%').next().unwrap_or(ip);

            // Count colons
            let colon_count = ip_without_zone.chars().filter(|&c| c == ':').count();

            // IPv6 should have between 2 and 7 colons (or 8 groups with double colon)
            if colon_count < 2 || colon_count > 7 {
                return false;
            }

            // Basic format check (hex digits, colons, double colon)
            let valid_chars = ip_without_zone.chars().all(|c|
                c.is_ascii_hexdigit() || c == ':' || c == '%'
            );

            return valid_chars;
        }

        false
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for IpAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Domain model for certificate validity periods
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidityPeriod {
    years: u64,
}

impl ValidityPeriod {
    const MIN_YEARS: u64 = 1;
    const MAX_YEARS: u64 = 10;

    /// Create a new validity period with validation
    pub fn new_years(years: u64) -> Result<Self, ApiError> {
        if years < Self::MIN_YEARS {
            return Err(ApiError::BadRequest(format!(
                "Certificate validity must be at least {} year(s), got {}",
                Self::MIN_YEARS, years
            )));
        }

        if years > Self::MAX_YEARS {
            return Err(ApiError::BadRequest(format!(
                "Certificate validity cannot exceed {} years, got {}",
                Self::MAX_YEARS, years
            )));
        }

        Ok(ValidityPeriod { years })
    }

    /// Create from days (for CSR signing)
    pub fn new_days(days: i64) -> Result<Self, ApiError> {
        const MIN_DAYS: i64 = 1;
        const MAX_DAYS: i64 = 3650; // 10 years

        if days < MIN_DAYS {
            return Err(ApiError::BadRequest(format!(
                "Certificate validity must be at least {} day(s), got {}",
                MIN_DAYS, days
            )));
        }

        if days > MAX_DAYS {
            return Err(ApiError::BadRequest(format!(
                "Certificate validity cannot exceed {} days (10 years), got {}",
                MAX_DAYS, days
            )));
        }

        // Convert days to years (approximate)
        let years = (days as f64 / 365.0).ceil() as u64;
        Ok(ValidityPeriod { years })
    }

    /// Get the validity in years
    pub fn years(&self) -> u64 {
        self.years
    }

    /// Get the validity in days (approximate)
    pub fn days(&self) -> u64 {
        self.years * 365
    }
}

impl fmt::Display for ValidityPeriod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} year(s)", self.years)
    }
}

/// Domain model for key specifications with validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa,
    Ecdsa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpec {
    algorithm: KeyAlgorithm,
    size: u32,
}

impl KeySpec {
    /// Create a new key specification with validation
    pub fn new(algorithm: KeyAlgorithm, size: u32) -> Result<Self, ApiError> {
        match algorithm {
            KeyAlgorithm::Rsa => {
                if ![2048, 3072, 4096].contains(&size) {
                    return Err(ApiError::BadRequest(format!(
                        "Invalid RSA key size '{}'. Supported sizes: 2048, 3072, 4096",
                        size
                    )));
                }
            },
            KeyAlgorithm::Ecdsa => {
                if ![256, 384].contains(&size) {
                    return Err(ApiError::BadRequest(format!(
                        "Invalid ECDSA key size '{}'. Supported sizes: 256, 384",
                        size
                    )));
                }
            }
        }

        Ok(KeySpec { algorithm, size })
    }

    /// Create from string representations
    pub fn from_strings(algorithm: &str, size: &str) -> Result<Self, ApiError> {
        let algorithm = match algorithm.to_lowercase().as_str() {
            "rsa" => KeyAlgorithm::Rsa,
            "ecdsa" => KeyAlgorithm::Ecdsa,
            _ => return Err(ApiError::BadRequest(format!(
                "Invalid key algorithm '{}'. Supported algorithms: rsa, ecdsa",
                algorithm
            ))),
        };

        let size = size.parse::<u32>().map_err(|_| {
            ApiError::BadRequest(format!("Invalid key size '{}'. Must be a number", size))
        })?;

        Self::new(algorithm, size)
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> &KeyAlgorithm {
        &self.algorithm
    }

    /// Get the key size
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Get a string representation suitable for CertificateBuilder
    pub fn to_string_pair(&self) -> (String, String) {
        let alg_str = match self.algorithm {
            KeyAlgorithm::Rsa => "RSA",
            KeyAlgorithm::Ecdsa => "ECDSA",
        };
        (alg_str.to_string(), self.size.to_string())
    }
}

impl fmt::Display for KeySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg_str = match self.algorithm {
            KeyAlgorithm::Rsa => "RSA",
            KeyAlgorithm::Ecdsa => "ECDSA",
        };
        write!(f, "{}-{}", alg_str, self.size)
    }
}

/// Collection of domain models for reuse across the application
pub mod validators {
    use super::*;

    /// Validate a collection of DNS names
    pub fn validate_dns_names(dns_names: &[String]) -> Result<Vec<DnsName>, ApiError> {
        let mut validated = Vec::new();
        for dns_name in dns_names {
            if !dns_name.trim().is_empty() {
                validated.push(DnsName::new(dns_name)?);
            }
        }
        Ok(validated)
    }

    /// Validate a collection of IP addresses
    pub fn validate_ip_addresses(ip_addresses: &[String]) -> Result<Vec<IpAddress>, ApiError> {
        let mut validated = Vec::new();
        for ip_addr in ip_addresses {
            if !ip_addr.trim().is_empty() {
                validated.push(IpAddress::new(ip_addr)?);
            }
        }
        Ok(validated)
    }

    /// Validate SAN entries (combination of DNS names and IP addresses)
    pub fn validate_subject_alternative_names(
        dns_names: &[String],
        ip_addresses: &[String]
    ) -> Result<(Vec<DnsName>, Vec<IpAddress>), ApiError> {
        // Check total number of SAN entries (reasonable limit)
        let total_san_entries = dns_names.len() + ip_addresses.len();
        const MAX_SAN_ENTRIES: usize = 100;

        if total_san_entries > MAX_SAN_ENTRIES {
            return Err(ApiError::BadRequest(format!(
                "Too many Subject Alternative Name entries (maximum {}, got {})",
                MAX_SAN_ENTRIES, total_san_entries
            )));
        }

        // For server certificates, SAN is required
        if dns_names.is_empty() && ip_addresses.is_empty() {
            return Err(ApiError::BadRequest(
                "Server certificates must include at least one valid DNS name or IP address".to_string()
            ));
        }

        let validated_dns = validate_dns_names(dns_names)?;
        let validated_ips = validate_ip_addresses(ip_addresses)?;

        Ok((validated_dns, validated_ips))
    }
}
