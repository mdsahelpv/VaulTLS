use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::anyhow;
use anyhow::Result;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::{X509Name, X509NameBuilder, X509};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::X509Builder;
use passwords::PasswordGenerator;
use rocket_okapi::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use crate::constants::{CA_FILE_PATH, CRL_DIR_PATH, CURRENT_CRL_FILE_PATH};
use crate::data::enums::{CertificateRenewMethod, CertificateType};
use crate::data::enums::CertificateType::{Client, Server};
use crate::ApiError;

#[derive(Default, Clone, Serialize, Deserialize, JsonSchema, Debug)]
/// Certificate can be either CA or user certificate.
pub struct Certificate {
    pub id: i64,
    pub name: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub certificate_type: CertificateType,
    pub user_id: i64,
    pub renew_method: CertificateRenewMethod,
    #[serde(skip)]
    pub pkcs12: Vec<u8>,
    #[serde(skip)]
    pub pkcs12_password: String,
    #[serde(skip)]
    pub ca_id: i64,
    pub is_revoked: bool,
    pub revoked_on: Option<i64>,
    pub revoked_reason: Option<crate::data::enums::CertificateRevocationReason>,
    pub revoked_by: Option<i64>,
    pub custom_revocation_reason: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct CA {
    pub id: i64,
    pub created_on: i64,
    pub valid_until: i64,
    pub creation_source: i32, // 0: self-signed, 1: imported
    pub can_create_subordinate_ca: bool, // Whether this CA can create subordinate CAs
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub cert_chain: Vec<Vec<u8>>, // Full certificate chain in DER format: [end_entity, intermediate1, intermediate2, ..., root]
    #[serde(skip)]
    pub key: Vec<u8>,
    pub aia_url: Option<String>, // Authority Information Access URL
    pub cdp_url: Option<String>, // CRL Distribution Points URL
}

#[derive(Clone, Debug)]
pub struct CRL {
    pub version: i32,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_certificates: Vec<CRLEntry>,
    pub ca_cert: Vec<u8>,
    pub ca_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CRLEntry {
    pub serial_number: Vec<u8>,
    pub revocation_date: i64,
    pub reason: crate::data::enums::CertificateRevocationReason,
}

#[derive(Clone, Debug)]
pub struct OCSPRequest {
    pub version: i32,
    pub requestor_name: Option<String>,
    pub certificate_id: OcspCertid,
    pub extensions: Vec<OCSPExtension>,
}

#[derive(Clone, Debug)]
pub struct OcspCertid {
    pub hash_algorithm: String, // e.g., "sha1", "sha256"
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    pub serial_number: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct OCSPExtension {
    pub extn_id: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct OCSPResponse {
    pub version: i32,
    pub response_status: OCSPResponseStatus,
    pub response_bytes: Option<OCSPSingleResponse>,
    pub produced_at: i64,
    pub extensions: Vec<OCSPExtension>,
}

#[derive(Clone, Debug)]
pub enum OCSPResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

#[derive(Clone, Debug)]
pub struct OCSPSingleResponse {
    pub cert_id: OcspCertid,
    pub cert_status: OCSPCertStatus,
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub extensions: Vec<OCSPExtension>,
}

#[derive(Clone, Debug)]
pub enum OCSPCertStatus {
    Good,
    Revoked { revocation_time: i64, revocation_reason: Option<crate::data::enums::CertificateRevocationReason> },
    Unknown,
}

pub struct CertificateBuilder {
    x509: X509Builder,
    private_key: PKey<Private>,
    created_on: i64,
    valid_until: Option<i64>,
    name: Option<String>,
    pkcs12_password: String,
    ca: Option<CA>,
    user_id: Option<i64>,
    renew_method: CertificateRenewMethod,
    key_size: Option<String>,
    hash_algorithm: Option<String>,
    // DN fields for CA certificates
    country: Option<String>,
    state: Option<String>,
    locality: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<String>,
    common_name: Option<String>,
    email: Option<String>,
    // Advanced PKI extensions
    certificate_policies_oid: Option<String>,
    certificate_policies_cps_url: Option<String>,
    // AIA and CDP extensions for CA certificates
    authority_info_access: Option<String>,
    crl_distribution_points: Option<String>,
}

impl CertificateBuilder {
    /// Create a CA from a PKCS#12 file containing a CA certificate
    /// Extract AIA (Authority Information Access) and CDP (CRL Distribution Point) URLs from certificate extensions
    fn extract_aia_and_cdp_from_cert(cert: &X509) -> Result<(Option<String>, Option<String>), anyhow::Error> {
        let mut aia_url: Option<String> = None;
        let mut cdp_url: Option<String> = None;

        debug!("Extracting AIA and CDP URLs from imported certificate extensions");

        // Convert certificate to PEM and then use openssl command-line to extract extensions
        let pem = cert.to_pem()
            .map_err(|e| anyhow!("Failed to convert certificate to PEM: {e}"))?;

        let pem_str = String::from_utf8(pem)
            .map_err(|e| anyhow!("Failed to convert PEM to string: {e}"))?;

        // Write certificate to a temporary file
        let temp_cert_path = std::env::temp_dir().join(format!("cert_ext_import_{}.pem", std::process::id()));
        std::fs::write(&temp_cert_path, &pem_str)
            .map_err(|e| anyhow!("Failed to write temp certificate: {e}"))?;

        // Use openssl command to extract extensions
        let output = std::process::Command::new("openssl")
            .args([
                "x509",
                "-in", &temp_cert_path.to_string_lossy(),
                "-text",
                "-noout"
            ])
            .output()
            .map_err(|e| anyhow!("Failed to run openssl command: {e}"))?;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_cert_path);

        if !output.status.success() {
            debug!("OpenSSL command failed to extract extensions, returning None for URLs");
            return Ok((None, None)); // Return None instead of error for missing extensions
        }

        let text_output = String::from_utf8(output.stdout)
            .map_err(|e| anyhow!("Failed to parse openssl output: {e}"))?;

        debug!("Extracted certificate text: {} characters", text_output.len());

        // Parse the text output to find AIA and CDP URLs
        for line in text_output.lines() {
            let line_trimmed = line.trim();

            // Extract any URI line containing http
            if let Some(http_start) = line_trimmed.find("URI:") {
                if let Some(url_start_pos) = line_trimmed[http_start..].find("http") {
                    let actual_url_start = http_start + url_start_pos;
                    let url = &line_trimmed[actual_url_start..];

                    // Check what type of URL this is by examining the context in the line
                    if line_trimmed.contains("Authority Information Access") || line_trimmed.contains("authorityInfoAccess") ||
                       line_trimmed.contains("CA Issuers") || line_trimmed.contains("caIssuers") ||
                       url.contains("ca.cert") {
                        // This is an AIA (Authority Information Access) URL
                        if aia_url.is_none() && url.starts_with("http") { // Only set if not already set and starts with http
                            debug!("Found AIA URL during import: {}", url);
                            aia_url = Some(url.trim_end_matches(':').trim().to_string());
                        }
                    } else if line_trimmed.contains("CRL Distribution Points") || line_trimmed.contains("crlDistributionPoints") ||
                       url.contains(".crl") || url.contains("/crl/") {
                        // This is a CDP (CRL Distribution Points) URL
                        if cdp_url.is_none() && url.starts_with("http") { // Only set if not already set and starts with http
                            debug!("Found CDP URL during import: {}", url);
                            cdp_url = Some(url.trim_end_matches(':').trim().to_string());
                        }
                    }
                }
            }

            // Also check for lines that directly contain http without "URI:" prefix
            // This handles some certificate formats where the URI marker might not be present
            if !line_trimmed.contains("URI:") && line_trimmed.contains("http") {
                if let Some(http_start) = line_trimmed.find("http") {
                    let url = &line_trimmed[http_start..];

                    if line_trimmed.contains("CA Issuers") || line_trimmed.contains("authorityInfoAccess") || url.contains("ca.cert") {
                        if aia_url.is_none() && url.starts_with("http") {
                            debug!("Found AIA URL (alternative) during import: {}", url);
                            aia_url = Some(url.trim_end_matches(':').trim().to_string());
                        }
                    } else if (line_trimmed.contains("CRL Distribution Points") || url.contains(".crl") || url.contains("/crl/"))
                        && cdp_url.is_none() && url.starts_with("http") {
                            debug!("Found CDP URL (alternative) during import: {}", url);
                            cdp_url = Some(url.trim_end_matches(':').trim().to_string());
                        }
                }
            }
        }

        debug!("Extracted URLs from imported certificate - AIA: {:?}, CDP: {:?}", aia_url, cdp_url);
        Ok((aia_url, cdp_url))
    }

    pub fn from_pfx(pfx_data: &[u8], password: Option<&str>, ca_name: Option<&str>) -> Result<CA, anyhow::Error> {
        debug!("Starting PFX import process (file size: {} bytes)", pfx_data.len());
        if let Some(name) = ca_name {
            debug!("Importing CA with name: {}", name);
        }

        let password = password.unwrap_or("");
        debug!("Password provided: {}", !password.is_empty());

        // Parse the PKCS#12 file
        let pkcs12 = Pkcs12::from_der(pfx_data)
            .map_err(|e| {
                error!("Failed to parse PKCS#12 DER data: {}", e);
                anyhow!("Invalid PKCS#12 file format: {e}")
            })?;

        debug!("PKCS#12 file parsed successfully");

        // Try to parse with the provided password
        let parsed = if password.is_empty() {
            debug!("Attempting to parse PKCS#12 without password");
            match pkcs12.parse2("") {
                Ok(parsed) => {
                    debug!("Successfully parsed PKCS#12 without password");
                    parsed
                },
                Err(e1) => {
                    debug!("Failed to parse without password: {}", e1);
                    match pkcs12.parse2("") {
                        Ok(parsed) => {
                            debug!("Successfully parsed PKCS#12 on second attempt without password");
                            parsed
                        },
                        Err(e2) => {
                            error!("Failed to parse PKCS#12 without password: first={}, second={}", e1, e2);
                            return Err(anyhow!("PKCS#12 file requires a password. Please provide the correct password for the keystore."));
                        }
                    }
                }
            }
        } else {
            debug!("Attempting to parse PKCS#12 with provided password");
            pkcs12.parse2(password)
                .map_err(|e| {
                    error!("Failed to parse PKCS#12 with password: {}", e);
                    anyhow!("Incorrect password for PKCS#12 file. Please check the keystore password and try again.")
                })?
        };

        debug!("PKCS#12 content parsed successfully");

        // Extract the certificate
        let cert = parsed.cert
            .ok_or_else(|| {
                error!("No certificate found in PKCS#12");
                anyhow!("No certificate found in PKCS#12 file. The file may be corrupted or invalid.")
            })?;

        debug!("Certificate extracted from PKCS#12: subject={:?}", cert.subject_name());

        // Extract the full certificate chain (including intermediate certificates if present)
        let mut cert_chain = Vec::new();

        // Start with the end-entity certificate
        cert_chain.push(cert.to_der().map_err(|e| {
            error!("Failed to encode end-entity certificate to DER: {}", e);
            anyhow!("Failed to process end-entity certificate: {e}")
        })?);

        // Add any intermediate certificates from the PFX chain
        if let Some(chain) = parsed.ca {
            debug!("Found {} certificate(s) in PFX chain", chain.len());
            for (idx, intermediate_cert) in chain.iter().enumerate() {
                debug!("Processing intermediate certificate {}: subject={:?}",
                       idx + 1, intermediate_cert.subject_name());
                cert_chain.push(intermediate_cert.to_der().map_err(|e| {
                    error!("Failed to encode intermediate certificate {} to DER: {}", idx + 1, e);
                    anyhow!("Failed to process intermediate certificate {}: {}", idx + 1, e)
                })?);
                debug!("Successfully added intermediate certificate {} to chain", idx + 1);
            }
            debug!("Final chain length: {} certificates (1 end-entity + {} intermediates)",
                   cert_chain.len(), chain.len());
        } else {
            debug!("No intermediate certificates found in PFX (single certificate chain)");
        }

        // Extract the private key
        let pkey = parsed.pkey
            .ok_or_else(|| {
                error!("No private key found in PKCS#12");
                anyhow!("No private key found in PKCS#12 file. The file may be missing the private key or be corrupted.")
            })?;

        debug!("Private key extracted from PKCS#12");

        // Extract AIA and CDP URLs from the certificate
        let (aia_url, cdp_url) = Self::extract_aia_and_cdp_from_cert(&cert).unwrap_or((None, None));

        // Get certificate validity timestamps
        // Use current time as approximation since parsing ASN.1 time can be complex
        let created_on = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Get the not_after field from the certificate
        let not_after = cert.not_after();
        // Get the current time as an Asn1Time object
        let now = Asn1Time::from_unix(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )
        .unwrap();
        // Calculate the difference in seconds
        let diff = not_after.diff(&now).unwrap();

        // Handle potential overflow by clamping the values
        let days_seconds = if diff.days > 0 {
            // Certificate is not expired, calculate future expiration
            let days_u64 = diff.days as u64;
            // Prevent overflow by limiting to reasonable maximum (100 years)
            let clamped_days = days_u64.min(365 * 100);
            clamped_days * 24 * 60 * 60
        } else {
            // Certificate is expired or expires today, use a default validity period
            365 * 24 * 60 * 60 // 1 year in seconds
        };

        // Handle seconds with bounds checking
        let secs_u64 = if diff.secs > 0 {
            (diff.secs as u64).min(24 * 60 * 60) // Max 1 day in seconds
        } else {
            0 // Ignore negative seconds (expired)
        };

        let total_seconds = days_seconds + secs_u64;

        // Calculate the valid_until timestamp
        let valid_until = (SystemTime::now()
            + std::time::Duration::from_secs(total_seconds))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        debug!("Certificate validity: created_on={}, valid_until={}", created_on, valid_until);

        let ca_cert_der = cert.to_der().map_err(|e| {
            error!("Failed to encode certificate to DER: {}", e);
            anyhow!("Failed to process certificate: {e}")
        })?;

        let ca_key_der = pkey.private_key_to_der().map_err(|e| {
            error!("Failed to encode private key to DER: {}", e);
            anyhow!("Failed to process private key: {e}")
        })?;

        debug!("CA certificate and key processed successfully");
        debug!("AIA URL: {:?}, CDP URL: {:?}", aia_url, cdp_url);

        Ok(CA {
            id: -1,
            created_on,
            valid_until,
            creation_source: 1, // 1 = imported
            can_create_subordinate_ca: false, // Imported CAs don't get subordinate CA creation by default
            cert: ca_cert_der,
            cert_chain,
            key: ca_key_der,
            aia_url,
            cdp_url,
        })
    }
}
impl CertificateBuilder {
    pub fn new_with_ca(ca: Option<&CA>) -> Result<Self> {
        Self::new_with_ca_and_key_type_size(ca, None, None)
    }

    pub fn new_with_ca_and_key_type_size(ca: Option<&CA>, key_type: Option<&str>, key_size: Option<&str>) -> Result<Self> {
        let private_key = match (ca, key_type, key_size) {
            // If no key type/size specified, default based on whether we have a CA or not
            (None, None, _) | (None, _, None) => generate_rsa_private_key_of_size(2048)?,

            // If CA is provided and no key params specified, use CA's key type for backward compatibility with sub-CAs
            (Some(ca), None, _) | (Some(ca), _, None) => {
                let ca_key = PKey::private_key_from_der(&ca.key)?;
                if ca_key.rsa().is_ok() {
                    generate_rsa_private_key()?
                } else if ca_key.ec_key().is_ok() {
                    generate_ecdsa_private_key(Nid::X9_62_PRIME256V1)?
                } else {
                    return Err(anyhow!("Unsupported CA key type"));
                }
            },

            // User explicitly specified key type and size - use that regardless of CA
            (_, Some("RSA") | Some("rsa"), key_size) => {
                let size = match key_size {
                    Some("2048") => 2048,
                    Some("4096") => 4096,
                    _ => 2048, // Default to 2048
                };
                generate_rsa_private_key_of_size(size)?
            },
            (_, Some("ECDSA") | Some("ecdsa"), key_size) => {
                let nid = match key_size {
                    Some("p-256"|"P-256") => Nid::X9_62_PRIME256V1,
                    Some("p-521"|"P-521") => Nid::SECP521R1,
                    _ => Nid::X9_62_PRIME256V1, // Default to P-256
                };
                generate_ecdsa_private_key(nid)?
            },
            (_, _, _) => generate_rsa_private_key_of_size(2048)?, // Default fallback
        };
        let asn1_serial = generate_serial_number()?;
        let (created_on_unix, created_on_openssl) = get_timestamp(0)?;

        let mut x509 = X509Builder::new()?;
        x509.set_version(2)?;
        x509.set_serial_number(&asn1_serial)?;
        x509.set_not_before(&created_on_openssl)?;
        x509.set_pubkey(&private_key)?;

        Ok(Self {
            x509,
            private_key,
            created_on: created_on_unix,
            valid_until: None,
            name: None,
            pkcs12_password: String::new(),
            ca: None,
            user_id: None,
            renew_method: Default::default(),
            key_size: key_size.map(|s| s.to_string()),
            hash_algorithm: None,
            country: None,
            state: None,
            locality: None,
            organization: None,
            organizational_unit: None,
            common_name: None,
            email: None,
            certificate_policies_oid: None,
            certificate_policies_cps_url: None,
            authority_info_access: None,
            crl_distribution_points: None,
        })
    }

    /// Copy information over from an existing certificate
    /// Fields set are:\
    ///     - Name\
    ///     - Validity\
    ///     - PKCS#12 Password\
    ///     - Renew Method\
    ///     - User ID\
    pub fn try_from(old_cert: &Certificate) -> Result<Self> {
        let validity_in_years = ((old_cert.valid_until - old_cert.created_on) / 1000 / 60 / 60 / 24 / 365).max(1);

    Self::new_with_ca_and_key_type_size(None, None, None)?
            .set_name(&old_cert.name)?
            .set_valid_until(validity_in_years as u64)?
            .set_pkcs12_password(&old_cert.pkcs12_password)?
            .set_renew_method(old_cert.renew_method)?
            .set_user_id(old_cert.user_id)

    }

    pub fn set_name(mut self, name: &str) -> Result<Self, anyhow::Error> {
        self.name = Some(name.to_string());
        let common_name = create_cn(name)?;
        self.x509.set_subject_name(&common_name)?;
        Ok(self)
    }

    pub fn set_valid_until(mut self, years: u64) -> Result<Self, anyhow::Error> {
        let (valid_until_unix, valid_until_openssl) = if years != 0 {
            get_timestamp(years)?
        } else {
            get_short_lifetime()?
        };
        self.valid_until = Some(valid_until_unix);
        self.x509.set_not_after(&valid_until_openssl)?;
        Ok(self)
    }

    pub fn set_pkcs12_password(mut self, password: &str) -> Result<Self, anyhow::Error> {
        self.pkcs12_password = password.to_string();
        Ok(self)
    }

    pub fn set_dns_san(mut self, dns_names: &Vec<String>) -> Result<Self, anyhow::Error> {
        let mut san_builder = SubjectAlternativeName::new();
        for dns in dns_names {
            san_builder.dns(dns);
        }
        let san = san_builder.build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(san)?;

        Ok(self)
    }

    pub fn set_email_san(mut self, email: &str) -> Result<Self, anyhow::Error> {
        let san = SubjectAlternativeName::new()
            .email(email)
            .build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(san)?;

        Ok(self)
    }

    pub fn set_ca(mut self, ca: &CA) -> Result<Self, anyhow::Error> {
        self.ca = Some(ca.clone());
        Ok(self)
    }

    pub fn set_user_id(mut self, user_id: i64) -> Result<Self, anyhow::Error> {
        self.user_id = Some(user_id);
        Ok(self)
    }

    pub fn set_renew_method(mut self, renew_method: CertificateRenewMethod) -> Result<Self, anyhow::Error> {
        self.renew_method = renew_method;
        Ok(self)
    }

    pub fn set_country(mut self, country: &str) -> Result<Self, anyhow::Error> {
        self.country = Some(country.to_string());
        Ok(self)
    }

    pub fn set_state(mut self, state: &str) -> Result<Self, anyhow::Error> {
        self.state = Some(state.to_string());
        Ok(self)
    }

    pub fn set_locality(mut self, locality: &str) -> Result<Self, anyhow::Error> {
        self.locality = Some(locality.to_string());
        Ok(self)
    }

    pub fn set_organization(mut self, organization: &str) -> Result<Self, anyhow::Error> {
        self.organization = Some(organization.to_string());
        Ok(self)
    }

    pub fn set_organizational_unit(mut self, organizational_unit: &str) -> Result<Self, anyhow::Error> {
        self.organizational_unit = Some(organizational_unit.to_string());
        Ok(self)
    }

    pub fn set_common_name(mut self, common_name: &str) -> Result<Self, anyhow::Error> {
        self.common_name = Some(common_name.to_string());
        Ok(self)
    }

    pub fn set_email(mut self, email: &str) -> Result<Self, anyhow::Error> {
        self.email = Some(email.to_string());
        Ok(self)
    }

    pub fn set_certificate_policies_oid(mut self, oid: &str) -> Result<Self, anyhow::Error> {
        self.certificate_policies_oid = Some(oid.to_string());
        Ok(self)
    }

    pub fn set_certificate_policies_cps_url(mut self, url: &str) -> Result<Self, anyhow::Error> {
        self.certificate_policies_cps_url = Some(url.to_string());
        Ok(self)
    }

    pub fn set_hash_algorithm(mut self, hash_algorithm: &str) -> Result<Self, anyhow::Error> {
        self.hash_algorithm = Some(hash_algorithm.to_string());
        Ok(self)
    }

    pub fn set_authority_info_access(mut self, aia_url: &str) -> Result<Self, anyhow::Error> {
        self.authority_info_access = Some(aia_url.to_string());
        Ok(self)
    }

    pub fn set_crl_distribution_points(mut self, cdp_url: &str) -> Result<Self, anyhow::Error> {
        self.crl_distribution_points = Some(cdp_url.to_string());
        Ok(self)
    }

    /// Build the full subject DN using stored DN fields
    fn build_subject_name(&self) -> Result<X509Name, anyhow::Error> {
        let mut name_builder = X509NameBuilder::new()?;

        // Add DN fields in the standard order (RFC 4514)
        if let Some(country) = &self.country {
            name_builder.append_entry_by_text("C", country)?;
        }
        if let Some(state) = &self.state {
            name_builder.append_entry_by_text("ST", state)?;
        }
        if let Some(locality) = &self.locality {
            name_builder.append_entry_by_text("L", locality)?;
        }
        if let Some(organization) = &self.organization {
            name_builder.append_entry_by_text("O", organization)?;
        }
        if let Some(organizational_unit) = &self.organizational_unit {
            name_builder.append_entry_by_text("OU", organizational_unit)?;
        }
        if let Some(common_name) = &self.common_name {
            name_builder.append_entry_by_text("CN", common_name)?;
        }
        if let Some(email) = &self.email {
            name_builder.append_entry_by_text("emailAddress", email)?;
        }

        Ok(name_builder.build())
    }

    pub fn build_ca(self) -> Result<CA, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;

        // Use OpenSSL command-line tool with a temporary configuration file
        // This ensures all settings from openssl_rootca.cnf are applied
        use std::process::Command;

        // Create temporary files for the private key, certificate, and config
        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join(format!("ca_key_{}.pem", self.created_on));
        let cert_path = temp_dir.join(format!("ca_cert_{}.pem", self.created_on));
        let config_path = temp_dir.join(format!("ca_config_{}.cnf", self.created_on));

        // Write the private key to a temporary file in the appropriate format
        let key_pem = if self.private_key.rsa().is_ok() {
            // Use PKCS#1 format for RSA keys (traditional format expected by OpenSSL)
            self.private_key.rsa().unwrap().private_key_to_pem()?
        } else if self.private_key.ec_key().is_ok() {
            // Use PKCS#8 format for ECDSA keys
            self.private_key.private_key_to_pem_pkcs8()?
        } else {
            return Err(anyhow!("Unsupported key type for CA certificate"));
        };
        std::fs::write(&key_path, &key_pem)?;

        // Create the temporary configuration file with all settings from openssl_rootca.cnf
        // and update only the user-configured values
        let mut config_content = r#"[ ca ]
default_ca      = CA_default

[ CA_default ]
dir             = /root/ca
certs           = $dir/certs
crl_dir         = $dir/crl
new_certs_dir   = $dir/newcerts
database        = $dir/index.txt
serial          = $dir/serial
RANDFILE        = $dir/private/.rand
private_key     = $dir/private/ca.key.pem
certificate     = $dir/certs/ca.cert.pem
crlnumber       = $dir/crlnumber
crl             = $dir/crl/ca.crl.pem
crl_extensions  = crl_ext
default_crl_days= 30
default_md      = sha256
preserve        = no
policy          = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
distinguished_name = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                 = Country Name (2 letter code)
countryName_default         = "#.to_string();

        // Set default values and update with user-provided values
        let country_default = self.country.as_deref().unwrap_or("QA");
        let state_default = self.state.as_deref().unwrap_or("Doha");
        let locality_default = self.locality.as_deref().unwrap_or("Bin Omran");
        let organization_default = self.organization.as_deref().unwrap_or("ABC Inc.");
        let common_default = self.common_name.as_deref().unwrap_or("rootca.abc.io");
        let email_default = self.email.as_deref().unwrap_or("pki@abc.io");

        config_content.push_str(country_default);
        config_content.push_str(r#"
stateOrProvinceName         = State or Province Name
stateOrProvinceName_default = "#);
        config_content.push_str(state_default);
        config_content.push_str(r#"
localityName                = Locality Name
localityName_default        = "#);
        config_content.push_str(locality_default);
        config_content.push_str(r#"
0.organizationName          = Organization Name
0.organizationName_default  = "#);
        config_content.push_str(organization_default);
        config_content.push_str(r#"
commonName                  = Common Name
commonName_default          = "#);
        config_content.push_str(common_default);
        config_content.push_str(r#"
emailAddress                = Email Address
emailAddress_default        = "#);
        config_content.push_str(email_default);
        config_content.push_str(r#"

# Root CA extensions for self-signed cert
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
"#);

        // Add certificate policies if provided
        if let Some(oid) = &self.certificate_policies_oid {
            config_content.push_str(&format!("certificatePolicies = {oid}\n"));
        }

        // Add AIA and CDP extensions using the configured URLs (only if provided)
        if let Some(aia_url) = &self.authority_info_access {
            config_content.push_str("authorityInfoAccess = ");
            config_content.push_str(&format!("caIssuers;URI:{aia_url}\n"));
        }

        // Add CDP extension (only if provided)
        if let Some(cdp_url) = &self.crl_distribution_points {
            config_content.push_str(&format!("crlDistributionPoints = URI:{cdp_url}\n"));
        }

        config_content.push_str(r#"

[ v3_intermediate_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

# Extensions for CRL signed by this CA
[ crl_ext ]
authorityKeyIdentifier=keyid:always

# Extensions for intermediate CA certs issued
[ v3_aia_cdp ]
authorityInfoAccess = @aia_info
crlDistributionPoints = @crl_info

[ aia_info ]
caIssuers;URI.0 = http://pki.yawal.io/certs/ca.cert.pem

[ crl_info ]
URI.0 = http://pki.yawal.io/crl/ca.crl.pem
"#);

        // Write the config file
        std::fs::write(&config_path, &config_content)?;

        // Build the subject DN string for OpenSSL using the user-provided values
        // Ensure all fields are included to match the issuer for self-signed certificates
        let country = self.country.as_deref().unwrap_or("QA");
        let state = self.state.as_deref().unwrap_or("Doha");
        let locality = self.locality.as_deref().unwrap_or("Bin Omran");
        let organization = self.organization.as_deref().unwrap_or("ABC Inc.");
        let common_name = self.common_name.as_deref().unwrap_or(&name);
        let email = self.email.as_deref().unwrap_or("pki@abc.io");

        let subject = format!("/C={country}/ST={state}/L={locality}/O={organization}/CN={common_name}/emailAddress={email}");

        // Also include organizational unit if provided
        let subject = if let Some(org_unit) = &self.organizational_unit {
            subject.replace("/CN=", &format!("/OU={org_unit}/CN="))
        } else {
            subject
        };

        // Calculate validity days from the valid_until timestamp
        let validity_days = ((valid_until - self.created_on) / (1000 * 60 * 60 * 24)) as u32;
        let validity_days = validity_days.max(1); // Ensure at least 1 day

        // Build the OpenSSL command with the appropriate hash algorithm
        let mut openssl_args = vec![
            "req".to_string(),
            "-new".to_string(),
            "-x509".to_string(),
            "-key".to_string(),
            key_path.to_string_lossy().to_string(),
            "-out".to_string(),
            cert_path.to_string_lossy().to_string(),
            "-days".to_string(),
            validity_days.to_string(),
            "-subj".to_string(),
            subject,
            "-config".to_string(),
            config_path.to_string_lossy().to_string(),
            "-extensions".to_string(),
            "v3_ca".to_string(),
        ];

        // Add the hash algorithm flag
        if let Some(hash_alg) = &self.hash_algorithm {
            match hash_alg.as_str() {
                "sha256" => openssl_args.insert(2, "-sha256".to_string()),
                "sha512" => openssl_args.insert(2, "-sha512".to_string()),
                _ => openssl_args.insert(2, "-sha256".to_string()), // Default to SHA256
            }
        } else {
            openssl_args.insert(2, "-sha256".to_string()); // Default to SHA256
        }

        // Generate the certificate using OpenSSL command-line tool
        let output = Command::new("openssl")
            .args(&openssl_args)
            .output()
            .map_err(|e| anyhow!("Failed to execute openssl command: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("OpenSSL command failed: {stderr}"));
        }

        // Read the generated certificate
        let cert_pem = std::fs::read(&cert_path)?;
        let cert = X509::from_pem(&cert_pem)?;

        // Clean up temporary files
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&config_path);

        let cert_der = cert.to_der()?;
        Ok(CA{
            id: -1,
            created_on: self.created_on,
            valid_until,
            creation_source: 0, // 0 = self-signed
            can_create_subordinate_ca: false, // Will be set by the API caller
            cert: cert_der.clone(),
            cert_chain: vec![cert_der], // Self-signed CA has single certificate in chain
            key: self.private_key.private_key_to_der()?,
            aia_url: self.authority_info_access.clone(),
            cdp_url: self.crl_distribution_points.clone(),
        })
    }

    pub fn build_client(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .client_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common_with_extensions(Client, None, None)
    }

    pub fn build_server(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .server_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common_with_extensions(Server, None, None)
    }

    pub fn build_common_with_extensions(mut self, certificate_type: CertificateType, crl_url: Option<&str>, ocsp_url: Option<&str>) -> Result<Certificate, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("X509: user_id not set"))?;
        let common_name_field = self.common_name;

        // If we have CRL or OCSP URLs, we need to use OpenSSL CLI to generate the certificate
        // with proper extensions, since rust-openssl doesn't support these extensions
        if crl_url.is_some() || ocsp_url.is_some() {
            debug!("Certificate requires CRL/OCSP extensions, using OpenSSL CLI generation");

            use std::process::Command;

            // Collect fields that will be moved before using methods
            let ca = self.ca.as_ref().ok_or(anyhow!("X509: CA not set"))?;
            let common_name = common_name_field.as_deref().unwrap_or(&name);

            // Create subject name manually for OpenSSL CLI
            use openssl::x509::X509NameBuilder;
            let mut subject_builder = X509NameBuilder::new()?;
            if let Some(country) = &self.country {
                subject_builder.append_entry_by_text("C", country)?;
            }
            if let Some(state) = &self.state {
                subject_builder.append_entry_by_text("ST", state)?;
            }
            if let Some(locality) = &self.locality {
                subject_builder.append_entry_by_text("L", locality)?;
            }
            if let Some(organization) = &self.organization {
                subject_builder.append_entry_by_text("O", organization)?;
            }
            if let Some(org_unit) = &self.organizational_unit {
                subject_builder.append_entry_by_text("OU", org_unit)?;
            }
            subject_builder.append_entry_by_text("CN", common_name)?;
            if let Some(email) = &self.email {
                subject_builder.append_entry_by_text("emailAddress", email)?;
            }
            let subject_name = subject_builder.build();

            // Create temporary files for certificate generation with extensions
            let temp_dir = std::env::temp_dir();
            let ca_cert_path = temp_dir.join(format!("ca_cert_ext_{}.pem", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
            let ca_key_path = temp_dir.join(format!("ca_key_ext_{}.pem", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
            let cert_req_path = temp_dir.join(format!("cert_req_ext_{}.csr", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
            let cert_path = temp_dir.join(format!("cert_ext_{}.pem", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
            let config_path = temp_dir.join(format!("cert_ext_config_{}.cnf", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));

            let cleanup_temp_files = || {
                let _ = std::fs::remove_file(&ca_cert_path);
                let _ = std::fs::remove_file(&ca_key_path);
                let _ = std::fs::remove_file(&cert_req_path);
                let _ = std::fs::remove_file(&cert_path);
                let _ = std::fs::remove_file(&config_path);
            };

            let ca_cert = X509::from_der(&ca.cert)?;
            let ca_key = PKey::private_key_from_der(&ca.key)?;

            // Write CA certificate and key to temp files
            let ca_cert_pem = ca_cert.to_pem()
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to encode CA certificate to PEM: {e}")
                })?;
            std::fs::write(&ca_cert_path, &ca_cert_pem)
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to write CA certificate to temp file: {e}")
                })?;

            let ca_key_pem = ca_key.private_key_to_pem_pkcs8()
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to encode CA private key to PEM: {e}")
                })?;
            std::fs::write(&ca_key_path, &ca_key_pem)
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to write CA private key to temp file: {e}")
                })?;

            let mut req_builder = openssl::x509::X509ReqBuilder::new()?;
            req_builder.set_version(0)?;
            req_builder.set_subject_name(&subject_name)?;
            req_builder.set_pubkey(&self.private_key)?;
            req_builder.sign(&self.private_key, MessageDigest::sha256())?;
            let cert_req = req_builder.build();

            let cert_req_pem = cert_req.to_pem()
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to encode certificate request to PEM: {e}")
                })?;
            std::fs::write(&cert_req_path, &cert_req_pem)
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to write certificate request to temp file: {e}")
                })?;

            // Create OpenSSL configuration for certificate with extensions
            let mut config_content = r#"[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
string_mask = utf8only
default_md = sha256

[ req_distinguished_name ]
countryName = Country Name (2 letter code)
countryName_default = QA

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
"#.to_string();

            // Add extended key usage based on certificate type
            match certificate_type {
                CertificateType::Client => {
                    config_content.push_str("extendedKeyUsage = clientAuth\n");
                },
                CertificateType::Server => {
                    config_content.push_str("extendedKeyUsage = serverAuth\n");
                },
                _ => {}
            }

            // Add CRL Distribution Points extension if requested
            if let Some(crl_url) = crl_url {
                config_content.push_str(&format!("crlDistributionPoints = URI:{crl_url}\n"));
            }

            // Add Authority Information Access (OCSP) extension if requested
            if let Some(ocsp_url) = ocsp_url {
                config_content.push_str(&format!("authorityInfoAccess = OCSP;URI:{ocsp_url}\n"));
            }

            config_content.push_str(r#"

[ ca ]
default_ca = CA_default

[ CA_default ]
dir = /tmp/ca_temp
certs = $dir/certs
new_certs_dir = $dir/newcerts
database = $dir/index.txt
serial = $dir/serial.txt
default_md = sha256
policy = policy_anything
email_in_dn = no
unique_subject = no
copy_extensions = copy

[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = CA:FALSE
"#);

            // Add the same extensions to the CA section for signing
            if let Some(crl_url) = crl_url {
                config_content.push_str(&format!("crlDistributionPoints = URI:{crl_url}\n"));
            }
            if let Some(ocsp_url) = ocsp_url {
                config_content.push_str(&format!("authorityInfoAccess = OCSP;URI:{ocsp_url}\n"));
            }

            std::fs::write(&config_path, &config_content)
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to write OpenSSL config file: {e}")
                })?;

            // Sign the certificate with OpenSSL CLI to include extensions
            let validity_days = ((valid_until - self.created_on) / (1000 * 60 * 60 * 24)) as u32;
            let validity_days = validity_days.max(1);

            let output = Command::new("openssl")
                .args([
                    "x509",
                    "-req",
                    "-in", &cert_req_path.to_string_lossy(),
                    "-CA", &ca_cert_path.to_string_lossy(),
                    "-CAkey", &ca_key_path.to_string_lossy(),
                    "-CAcreateserial",
                    "-out", &cert_path.to_string_lossy(),
                    "-days", &validity_days.to_string(),
                    "-sha256",
                    "-extfile", &config_path.to_string_lossy(),
                    "-extensions", "v3_ca",
                ])
                .output()
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to execute openssl x509 command: {e}")
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                cleanup_temp_files();
                return Err(anyhow!("OpenSSL certificate signing failed: {stderr}"));
            }

            // Read and convert the signed certificate
            let cert_pem = std::fs::read(&cert_path)
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to read signed certificate: {e}")
                })?;
            let cert = X509::from_pem(&cert_pem)
                .map_err(|e| {
                    cleanup_temp_files();
                    anyhow!("Failed to parse signed certificate: {e}")
                })?;

            cleanup_temp_files();

            // Build the certificate chain
            let mut ca_stack = Stack::new()?;
            for chain_cert_der in &ca.cert_chain {
                let chain_cert = X509::from_der(chain_cert_der)?;
                ca_stack.push(chain_cert)?;
            }

            let pkcs12 = Pkcs12::builder()
                .name(&name)
                .ca(ca_stack)
                .cert(&cert)
                .pkey(&self.private_key)
                .build2(&self.pkcs12_password)?;

            Ok(Certificate{
                id: -1,
                name,
                created_on: self.created_on,
                valid_until,
                certificate_type,
                pkcs12: pkcs12.to_der()?,
                pkcs12_password: self.pkcs12_password,
                ca_id: ca.id,
                user_id,
                renew_method: self.renew_method,
                is_revoked: false,
                revoked_on: None,
                revoked_reason: None,
                revoked_by: None,
                custom_revocation_reason: None,
            })
        } else {
            // Use the original rust-openssl implementation when no extensions are needed
            let ca = self.ca.ok_or(anyhow!("X509: CA not set"))?;
            let ca_cert = X509::from_der(&ca.cert)?;
            let ca_key = PKey::private_key_from_der(&ca.key)?;

            let basic_constraints = BasicConstraints::new().build()?;
            self.x509.append_extension(basic_constraints)?;

            let key_usage = KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()?;
            self.x509.append_extension(key_usage)?;

            self.x509.set_issuer_name(ca_cert.subject_name())?;

            // Sign with the selected hash algorithm
            let digest = match self.hash_algorithm.as_deref() {
                Some("sha256") | Some("sha-256") | Some("SHA-256") | Some("SHA256") => MessageDigest::sha256(),
                Some("sha512") | Some("sha-512") | Some("SHA-512") | Some("SHA512") => MessageDigest::sha512(),
                _ => MessageDigest::sha256(), // Default to SHA256
            };

            self.x509.sign(&ca_key, digest)?;
            let cert = self.x509.build();

            // Build the certificate chain for the PKCS#12 including all intermediate certificates
            let mut ca_stack = Stack::new()?;
            for chain_cert_der in &ca.cert_chain {
                if chain_cert_der != &ca.cert {
                    let chain_cert = X509::from_der(chain_cert_der)?;
                    ca_stack.push(chain_cert)?;
                }
            }
            if ca_stack.is_empty() {
                ca_stack.push(ca_cert.clone())?;
            }

            let pkcs12 = Pkcs12::builder()
                .name(&name)
                .ca(ca_stack)
                .cert(&cert)
                .pkey(&self.private_key)
                .build2(&self.pkcs12_password)?;

            Ok(Certificate{
                id: -1,
                name,
                created_on: self.created_on,
                valid_until,
                certificate_type,
                pkcs12: pkcs12.to_der()?,
                pkcs12_password: self.pkcs12_password,
                ca_id: ca.id,
                user_id,
                renew_method: self.renew_method,
                is_revoked: false,
                revoked_on: None,
                revoked_reason: None,
                revoked_by: None,
                custom_revocation_reason: None,
            })
        }
    }

    pub fn build_subordinate_ca(mut self) -> Result<Certificate, anyhow::Error> {
        self.authority_info_access = self.authority_info_access.filter(|s| !s.is_empty());
        self.crl_distribution_points = self.crl_distribution_points.filter(|s| !s.is_empty());

        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("X509: user_id not set"))?;
        let ca = self.ca.ok_or(anyhow!("X509: CA not set"))?;

        // Collect fields that will be moved before using the certificate builder
        let common_name = self.common_name.as_deref().unwrap_or(&name);
        let aia_url = self.authority_info_access.clone();
        let cdp_url = self.crl_distribution_points.clone();

        // Use OpenSSL CLI to generate subordinate CA certificate with proper extensions
        // This ensures AIA and CDP URLs are properly included
        use std::process::Command;

        // Create temporary files for certificate generation
        let temp_dir = std::env::temp_dir();
        let ca_cert_path = temp_dir.join(format!("ca_cert_sub_{}.pem", self.created_on));
        let ca_key_path = temp_dir.join(format!("ca_key_sub_{}.pem", self.created_on));
        let cert_req_path = temp_dir.join(format!("cert_req_sub_{}.csr", self.created_on));
        let cert_path = temp_dir.join(format!("cert_sub_{}.pem", self.created_on));
        let config_path = temp_dir.join(format!("cert_sub_config_{}.cnf", self.created_on));

        let cleanup_temp_files = || {
            let _ = std::fs::remove_file(&ca_cert_path);
            let _ = std::fs::remove_file(&ca_key_path);
            let _ = std::fs::remove_file(&cert_req_path);
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&config_path);
        };

        let ca_cert = X509::from_der(&ca.cert)?;
        let ca_key = PKey::private_key_from_der(&ca.key)?;

        // Write CA certificate to PEM
        let ca_cert_pem = ca_cert.to_pem()
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to encode CA certificate to PEM: {e}")
            })?;
        std::fs::write(&ca_cert_path, &ca_cert_pem)
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to write CA certificate to temp file: {e}")
            })?;

        // Write CA private key to PEM
        let ca_key_pem = ca_key.private_key_to_pem_pkcs8()
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to encode CA private key to PEM: {e}")
            })?;
        std::fs::write(&ca_key_path, &ca_key_pem)
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to write CA private key to temp file: {e}")
            })?;

        // Create certificate signing request (CSR)
        let mut req_builder = openssl::x509::X509ReqBuilder::new()?;
        req_builder.set_version(0)?;

        // Build subject name
        let mut subject_builder = openssl::x509::X509NameBuilder::new()?;
        if let Some(country) = &self.country {
            subject_builder.append_entry_by_text("C", country)?;
        }
        if let Some(state) = &self.state {
            subject_builder.append_entry_by_text("ST", state)?;
        }
        if let Some(locality) = &self.locality {
            subject_builder.append_entry_by_text("L", locality)?;
        }
        if let Some(organization) = &self.organization {
            subject_builder.append_entry_by_text("O", organization)?;
        }
        if let Some(org_unit) = &self.organizational_unit {
            subject_builder.append_entry_by_text("OU", org_unit)?;
        }
        subject_builder.append_entry_by_text("CN", common_name)?;
        if let Some(email) = &self.email {
            subject_builder.append_entry_by_text("emailAddress", email)?;
        }
        let subject_name = subject_builder.build();

        req_builder.set_subject_name(&subject_name)?;
        req_builder.set_pubkey(&self.private_key)?;
        req_builder.sign(&self.private_key, MessageDigest::sha256())?;
        let cert_req = req_builder.build();

        let cert_req_pem = cert_req.to_pem()
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to encode certificate request to PEM: {e}")
            })?;
        std::fs::write(&cert_req_path, &cert_req_pem)
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to write certificate request to temp file: {e}")
            })?;

        // Create OpenSSL configuration for subordinate CA certificate
        let mut config_content = r#"[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
string_mask = utf8only
default_md = sha256

[ req_distinguished_name ]
countryName = Country Name (2 letter code)
countryName_default = QA

[ v3_req ]
basicConstraints = CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign

[ ca ]
default_ca = CA_default

[ CA_default ]
dir = /tmp/ca_temp
certs = $dir/certs
new_certs_dir = $dir/newcerts
database = $dir/index.txt
serial = $dir/serial.txt
default_md = sha256
policy = policy_anything
email_in_dn = no
unique_subject = no
copy_extensions = copy

[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
"#.to_string();

        // Add AIA extension if provided
        if let Some(ref aia) = aia_url {
            config_content.push_str(&format!("authorityInfoAccess = caIssuers;URI:{aia}\n"));
        }

        // Add CDP extension if provided
        if let Some(ref cdp) = cdp_url {
            config_content.push_str(&format!("crlDistributionPoints = URI:{cdp}\n"));
        }

        std::fs::write(&config_path, &config_content)
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to write OpenSSL config file: {e}")
            })?;

        // Sign the certificate with the parent CA using OpenSSL CLI
        let validity_days = ((valid_until - self.created_on) / (1000 * 60 * 60 * 24)) as u32;
        let validity_days = validity_days.max(1);

        debug!("Executing OpenSSL x509 command for subordinate CA with validity_days: {}, aia_url: {:?}, cdp_url: {:?}", validity_days, aia_url, cdp_url);

        let output = Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in", &cert_req_path.to_string_lossy(),
                "-CA", &ca_cert_path.to_string_lossy(),
                "-CAkey", &ca_key_path.to_string_lossy(),
                "-CAcreateserial",
                "-out", &cert_path.to_string_lossy(),
                "-days", &validity_days.to_string(),
                "-sha256",
                "-extfile", &config_path.to_string_lossy(),
                "-extensions", "v3_ca",
            ])
            .output()
            .map_err(|e| {
                error!("Failed to execute openssl x509 command: {e}");
                cleanup_temp_files();
                anyhow!("Failed to execute openssl x509 command: {e}")
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            error!("OpenSSL certificate signing failed. Exit code: {:?}", output.status.code());
            error!("OpenSSL stderr: {stderr}");
            error!("OpenSSL stdout: {stdout}");
            cleanup_temp_files();
            return Err(anyhow!("OpenSSL certificate signing failed: {stderr}\nStdout: {stdout}"));
        }

        debug!("OpenSSL certificate signing successful");

        // Read and convert the signed certificate
        let cert_pem = std::fs::read(&cert_path)
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to read signed certificate: {e}")
            })?;
        let cert = X509::from_pem(&cert_pem)
            .map_err(|e| {
                cleanup_temp_files();
                anyhow!("Failed to parse signed certificate: {e}")
            })?;

        cleanup_temp_files();

        // Build certificate chain: [parent CA cert, parent's parent if any, ...]
        let mut ca_stack = Stack::new()?;

        // Add all certificates from the parent CA's chain
        for chain_cert_der in &ca.cert_chain {
            let chain_cert = X509::from_der(chain_cert_der)?;
            ca_stack.push(chain_cert)?;
        }

        let pkcs12 = Pkcs12::builder()
            .name(&name)
            .ca(ca_stack)
            .cert(&cert)
            .pkey(&self.private_key)
            .build2(&self.pkcs12_password)?;

        Ok(Certificate{
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            certificate_type: CertificateType::SubordinateCA,
            pkcs12: pkcs12.to_der()?,
            pkcs12_password: self.pkcs12_password,
            ca_id: ca.id,
            user_id,
            renew_method: self.renew_method,
            is_revoked: false,
            revoked_on: None,
            revoked_reason: None,
            revoked_by: None,
            custom_revocation_reason: None,
        })
    }
}

/// Generates a new private key.
fn generate_ecdsa_private_key(nid: Nid) -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(nid)?;
    let ec_key = EcKey::generate(&group)?;
    let server_key = PKey::from_ec_key(ec_key)?;
    Ok(server_key)
}

fn generate_rsa_private_key() -> Result<PKey<Private>, ErrorStack> {
    generate_rsa_private_key_of_size(4096)
}

fn generate_rsa_private_key_of_size(bits: u32) -> Result<PKey<Private>, ErrorStack> {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(bits)?;
    let server_key = PKey::from_rsa(rsa)?;
    Ok(server_key)
}

fn create_cn(ca_name: &str) -> Result<X509Name, ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", ca_name)?;
    let name = name_builder.build();
    Ok(name)
}

/// Returns the password for the PKCS#12.
pub(crate) fn get_password(system_generated_password: bool, pkcs12_password: &Option<String>) -> String {
    if system_generated_password {
        // Create password for the PKCS#12
        let pg = PasswordGenerator {
            length: 20,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            spaces: false,
            exclude_similar_characters: false,
            strict: true,
        };
        pg.generate_one().unwrap()
    } else {
        match pkcs12_password {
            Some(p) => p.clone(),
            None => "".to_string(),
        }
    }
}

/// Generates a random serial number.
fn generate_serial_number() -> Result<Asn1Integer, ErrorStack> {
    let mut big_serial = BigNum::new()?;
    big_serial.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    let asn1_serial = big_serial.to_asn1_integer()?;
    Ok(asn1_serial)
}

/// Returns the current UNIX timestamp in milliseconds and an OpenSSL Asn1Time object.
fn get_timestamp(from_now_in_years: u64) -> Result<(i64, Asn1Time), ErrorStack> {
    let time = SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24 * 365 * from_now_in_years);
    let time_unix = time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
    let time_openssl = Asn1Time::days_from_now(365 * from_now_in_years as u32)?;

    Ok((time_unix, time_openssl))
}

/// For E2E testing generate a short lifetime certificate.
fn get_short_lifetime() -> Result<(i64, Asn1Time), ErrorStack> {
    let time = SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24);
    let time_unix = time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
    let time_openssl = Asn1Time::days_from_now(1)?;

    Ok((time_unix, time_openssl))
}

/// Convert a CA certificate chain to PEM format.
pub(crate) fn get_pem(ca: &CA) -> Result<Vec<u8>, ErrorStack> {
    let mut pem_chain = Vec::new();

    // Convert each certificate in the chain to PEM and concatenate
    for cert_der in &ca.cert_chain {
        let cert = X509::from_der(cert_der)?;
        let cert_pem = cert.to_pem()?;
        pem_chain.extend(cert_pem);

        // RFC 7468 specifies that PEM-encoded certificates should be separated by newlines
        // and that extra trailing whitespace is allowed, so we add a newline for readability
        if !pem_chain.is_empty() && *pem_chain.last().unwrap() != b'\n' {
            pem_chain.push(b'\n');
        }
    }

    Ok(pem_chain)
}

/// Saves the CA certificate to a file for filesystem access.
pub(crate) fn save_ca(ca: &CA) -> Result<(), ApiError> {
    let pem = get_pem(ca)?;
    fs::write(CA_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(())
}

pub(crate) fn get_dns_names(cert: &Certificate) -> Result<Vec<String>, anyhow::Error> {
    let encrypted_p12 = Pkcs12::from_der(&cert.pkcs12)?;
    let Some(cert) = encrypted_p12.parse2(&cert.pkcs12_password)?.cert else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    let Some(san) = cert.subject_alt_names() else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    Ok(san.iter().filter_map(|name| name.dnsname().map(|s| s.to_string())).collect())
}

/// Convert a user certificate from PKCS#12 to PEM format.
pub(crate) fn certificate_pkcs12_to_pem(cert: &Certificate) -> Result<Vec<u8>, ApiError> {
    let encrypted_p12 = Pkcs12::from_der(&cert.pkcs12)
        .map_err(|e| ApiError::Other(format!("Failed to parse PKCS#12: {e}")))?;

    let parsed = if cert.pkcs12_password.is_empty() {
        // Try without password first
        match encrypted_p12.parse2("") {
            Ok(parsed) => parsed,
            Err(e) => return Err(ApiError::Other(format!("Failed to decrypt PKCS#12 without password: {e}"))),
        }
    } else {
        // Try with provided password
        encrypted_p12.parse2(&cert.pkcs12_password)
            .map_err(|e| ApiError::Other(format!("Failed to decrypt PKCS#12 with password: {e}")))?
    };

    let x509_cert = parsed.cert
        .ok_or_else(|| ApiError::Other("No certificate found in PKCS#12".to_string()))?;

    x509_cert.to_pem()
        .map_err(|e| ApiError::Other(format!("Failed to convert certificate to PEM: {e}")))
}

/// Convert a user certificate's private key from PKCS#12 to PEM format.
pub(crate) fn certificate_pkcs12_to_key(cert: &Certificate) -> Result<Vec<u8>, ApiError> {
    let encrypted_p12 = Pkcs12::from_der(&cert.pkcs12)
        .map_err(|e| ApiError::Other(format!("Failed to parse PKCS#12: {e}")))?;

    let parsed = if cert.pkcs12_password.is_empty() {
        // Try without password first
        match encrypted_p12.parse2("") {
            Ok(parsed) => parsed,
            Err(e) => return Err(ApiError::Other(format!("Failed to decrypt PKCS#12 without password: {e}"))),
        }
    } else {
        // Try with provided password
        encrypted_p12.parse2(&cert.pkcs12_password)
            .map_err(|e| ApiError::Other(format!("Failed to decrypt PKCS#12 with password: {e}")))?
    };

    let private_key = parsed.pkey
        .ok_or_else(|| ApiError::Other("No private key found in PKCS#12".to_string()))?;

    private_key.private_key_to_pem_pkcs8()
        .map_err(|e| ApiError::Other(format!("Failed to convert private key to PEM: {e}")))
}

/// Convert a user certificate from PKCS#12 to DER format.
pub(crate) fn certificate_pkcs12_to_der(cert: &Certificate) -> Result<Vec<u8>, ApiError> {
    let encrypted_p12 = Pkcs12::from_der(&cert.pkcs12)
        .map_err(|e| ApiError::Other(format!("Failed to parse PKCS#12: {e}")))?;

    let parsed = if cert.pkcs12_password.is_empty() {
        // Try without password first
        match encrypted_p12.parse2("") {
            Ok(parsed) => parsed,
            Err(e) => return Err(ApiError::Other(format!("Failed to decrypt PKCS#12 without password: {e}"))),
        }
    } else {
        // Try with provided password
        encrypted_p12.parse2(&cert.pkcs12_password)
            .map_err(|e| ApiError::Other(format!("Failed to decrypt PKCS#12 with password: {e}")))?
    };

    let x509_cert = parsed.cert
        .ok_or_else(|| ApiError::Other("No certificate found in PKCS#12".to_string()))?;

    x509_cert.to_der()
        .map_err(|e| ApiError::Other(format!("Failed to convert certificate to DER: {e}")))
}

/// Convert a CA certificate to DER format.
// pub(crate) fn get_der(ca: &CA) -> Result<Vec<u8>, ErrorStack> {
//     Ok(ca.cert.clone())
// }

#[derive(Serialize, JsonSchema, Debug)]
pub struct CertificateDetails {
    pub id: i64,
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub serial_number: String,
    pub key_size: String,
    pub signature_algorithm: String,
    pub certificate_type: CertificateType,
    pub user_id: i64,
    pub renew_method: CertificateRenewMethod,
    pub certificate_pem: String,
}

/// Extract detailed information from a user certificate's PKCS#12 data
pub fn get_certificate_details(cert: &Certificate) -> Result<CertificateDetails, ApiError> {
    let encrypted_p12 = Pkcs12::from_der(&cert.pkcs12)
        .map_err(|e| ApiError::Other(format!("Failed to parse PKCS#12: {e}")))?;

    let parsed = if cert.pkcs12_password.is_empty() {
        // Try without password first
        match encrypted_p12.parse2("") {
            Ok(parsed) => parsed,
            Err(e) => return Err(ApiError::Other(format!("Failed to decrypt PKCS#12 without password: {e}"))),
        }
    } else {
        // Try with provided password
        encrypted_p12.parse2(&cert.pkcs12_password)
            .map_err(|e| ApiError::Other(format!("Failed to decrypt PKCS#12 with password: {e}")))?
    };

    let x509_cert = parsed.cert
        .ok_or_else(|| ApiError::Other("No certificate found in PKCS#12".to_string()))?;

    // Extract certificate details
    let subject_name = x509_cert.subject_name();
    let issuer_name = x509_cert.issuer_name();
    let serial = x509_cert.serial_number();

    // Get key information from the certificate's public key
    let public_key = x509_cert.public_key()
        .map_err(|e| ApiError::Other(format!("Failed to get public key: {e}")))?;

    let key_size = if public_key.rsa().is_ok() {
        format!("RSA {}", public_key.rsa().unwrap().size() * 8)
    } else if public_key.ec_key().is_ok() {
        "ECDSA P-256".to_string()
    } else {
        "Unknown".to_string()
    };

    // Get signature algorithm
    let sig_alg_obj = x509_cert.signature_algorithm().object();
    let sig_alg_str = sig_alg_obj.to_string();
    let signature_algorithm = match sig_alg_str.as_str() {
        "sha256WithRSAEncryption" => "RSA-SHA256",
        "sha512WithRSAEncryption" => "RSA-SHA512",
        "ecdsa-with-SHA256" => "ECDSA-SHA256",
        "ecdsa-with-SHA512" => "ECDSA-SHA512",
        _ => {
            // Debug: print the actual signature algorithm string
            debug!("Unknown signature algorithm: '{}' (NID: {})", sig_alg_str, sig_alg_obj.nid().as_raw());
            // Fallback to NID-based detection if string matching fails
            match sig_alg_obj.nid().as_raw() {
                668 => "RSA-SHA256",
                794 => "ECDSA-SHA256",
                913 => "RSA-SHA512",
                796 => "ECDSA-SHA512",
                _ => "Unknown",
            }
        }
    };

    // Convert certificate to PEM format
    let certificate_pem = String::from_utf8(
        x509_cert.to_pem()
            .map_err(|e| ApiError::Other(format!("Failed to convert certificate to PEM: {e}")))?
    ).map_err(|e| ApiError::Other(format!("Failed to convert certificate to string: {e}")))?;

    Ok(CertificateDetails {
        id: cert.id,
        name: cert.name.clone(),
        subject: format!("{subject_name:?}"),
        issuer: format!("{issuer_name:?}"),
        created_on: cert.created_on,
        valid_until: cert.valid_until,
        serial_number: serial.to_bn()
            .map_err(|e| ApiError::Other(format!("Failed to convert serial number: {e}")))?
            .to_hex_str()
            .map_err(|e| ApiError::Other(format!("Failed to format serial number: {e}")))?
            .to_string(),
        key_size,
        signature_algorithm: signature_algorithm.to_string(),
        certificate_type: cert.certificate_type,
        user_id: cert.user_id,
        renew_method: cert.renew_method,
        certificate_pem,
    })
}

/// Generate a Certificate Revocation List (CRL) for the given CA using external OpenSSL CLI
pub fn generate_crl(ca: &CA, revoked_certificates: &[CRLEntry]) -> Result<Vec<u8>, ApiError> {
    debug!("Generating CRL for CA using external OpenSSL CLI ({} revoked certificates)", revoked_certificates.len());

    use std::process::Command;

    // Create temporary files
    let temp_dir = std::env::temp_dir();
    let ca_cert_path = temp_dir.join(format!("ca_cert_{}.pem", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
    let ca_key_path = temp_dir.join(format!("ca_key_{}.pem", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
    let index_path = temp_dir.join(format!("index_{}.txt", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
    let serial_path = temp_dir.join(format!("serial_{}.txt", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
    let crl_path = temp_dir.join(format!("crl_{}.pem", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
    let config_path = temp_dir.join(format!("crl_config_{}.cnf", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));

    let cleanup_temp_files = || {
        let _ = std::fs::remove_file(&ca_cert_path);
        let _ = std::fs::remove_file(&ca_key_path);
        let _ = std::fs::remove_file(&index_path);
        let _ = std::fs::remove_file(&serial_path);
        let _ = std::fs::remove_file(&crl_path);
        let _ = std::fs::remove_file(&config_path);
    };

    // Load CA certificate and key
    let ca_cert = X509::from_der(&ca.cert)
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to load CA certificate: {e}"))
        })?;

    let ca_key = PKey::private_key_from_der(&ca.key)
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to load CA private key: {e}"))
        })?;

    // Write CA certificate to PEM
    let ca_cert_pem = ca_cert.to_pem()
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to encode CA certificate to PEM: {e}"))
        })?;
    std::fs::write(&ca_cert_path, &ca_cert_pem)
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to write CA certificate to temp file: {e}"))
        })?;

    // Write CA private key to PEM (PKCS#8 format for better compatibility)
    let ca_key_pem = ca_key.private_key_to_pem_pkcs8()
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to encode CA private key to PEM: {e}"))
        })?;
    std::fs::write(&ca_key_path, &ca_key_pem)
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to write CA private key to temp file: {e}"))
        })?;

    // Create OpenSSL index file with revoked certificates
    let mut index_content = String::new();

    // Format: Status|Expiration|RevocationDate|Serial|FileName|Subject
    // We use a far-future expiration date since we don't track individual certificate validity in this context
    let far_future = "20351231235959Z";

    for (i, entry) in revoked_certificates.iter().enumerate() {
        // Convert revocation date from milliseconds to OpenSSL UTCTime format
        let revocation_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(entry.revocation_date as u64);
        let revocation_datetime: chrono::DateTime<chrono::Utc> = revocation_time.into();
        let revocation_openssl = revocation_datetime.format("%y%m%d%H%M%SZ").to_string();

        // Convert serial number to hex string
        let serial_hex = hex::encode(&entry.serial_number).to_uppercase();

        // Create a unique filename for this entry
        let filename = format!("unknown_{}", i + 1);

        // Create subject (simplified - we don't have full subject info from CRLEntry)
        let subject = format!("/CN=RevokedCertificate{}", i + 1);

        // Add entry for revoked certificate
        index_content.push_str(&format!("R|{far_future}|{revocation_openssl}|{serial_hex}|{filename}|{subject}\n"            // Subject (simplified)
        ));
    }

    std::fs::write(&index_path, &index_content)
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to write CRL index file: {e}"))
        })?;

    // Create serial file for CRL numbering
    let crl_serial_big_num = generate_serial_number()
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to generate CRL serial number: {e}"))
        })?
        .to_bn()
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to convert ASN.1 integer to BigNum: {e}"))
        })?;
    let crl_serial = crl_serial_big_num.to_hex_str()
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to convert CRL serial to hex: {e}"))
        })?;
    std::fs::write(&serial_path, format!("{crl_serial}\n"))
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to write CRL serial file: {e}"))
        })?;

    // Create OpenSSL configuration for CRL generation
    let config_content = format!(r#"[ ca ]
default_ca = CA_default

[ CA_default ]
database = {}
serial = {}
crl_extensions = crl_ext
default_crl_days = 30
default_md = sha256

[ crl_ext ]
authorityKeyIdentifier=keyid:always
"#, index_path.to_string_lossy(), serial_path.to_string_lossy());

    std::fs::write(&config_path, &config_content)
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to write OpenSSL config file: {e}"))
        })?;

    // Run OpenSSL command to generate CRL
    let output = Command::new("openssl")
        .args([
            "ca",
            "-config", &config_path.to_string_lossy(),
            "-gencrl",
            "-keyfile", &ca_key_path.to_string_lossy(),
            "-cert", &ca_cert_path.to_string_lossy(),
            "-out", &crl_path.to_string_lossy(),
            "-batch",  // Don't prompt for anything
        ])
        .output()
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to execute openssl ca command: {e}"))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        cleanup_temp_files();
        return Err(ApiError::Other(format!("OpenSSL CRL generation failed: {stderr}")));
    }

    // The CRL is already generated in PEM format, now convert PEM to DER
    let crl_der_path = temp_dir.join(format!("crl_der_{}.der", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()));
    let cleanup_temp_files = || {
        let _ = std::fs::remove_file(&ca_cert_path);
        let _ = std::fs::remove_file(&ca_key_path);
        let _ = std::fs::remove_file(&index_path);
        let _ = std::fs::remove_file(&serial_path);
        let _ = std::fs::remove_file(&crl_path);
        let _ = std::fs::remove_file(&crl_der_path);
        let _ = std::fs::remove_file(&config_path);
    };

    let crl_der = Command::new("openssl")
        .args([
            "crl",
            "-inform", "PEM",
            "-outform", "DER",
            "-in", &crl_path.to_string_lossy(),
            "-out", &crl_der_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to convert CRL to DER: {e}"))
        })?;

    if !crl_der.status.success() {
        let stderr = String::from_utf8_lossy(&crl_der.stderr);
        cleanup_temp_files();
        return Err(ApiError::Other(format!("CRL DER conversion failed: {stderr}")));
    }

    // Read the DER encoded CRL
    let crl_der_data = std::fs::read(&crl_der_path)
        .map_err(|e| {
            cleanup_temp_files();
            ApiError::Other(format!("Failed to read DER CRL: {e}"))
        })?;

    cleanup_temp_files();

    debug!("Successfully generated CRL using OpenSSL CLI ({} bytes)", crl_der_data.len());
    Ok(crl_der_data)
}

/// Convert CRL to PEM format
pub fn crl_to_pem(crl_der: &[u8]) -> Result<Vec<u8>, ApiError> {
    debug!("Converting CRL from DER to PEM format ({} bytes)", crl_der.len());

    // For now, create a basic PEM structure
    // In a full implementation, this would use OpenSSL's PEM encoding functions
    // Since OpenSSL rust bindings don't support CRL PEM conversion directly,
    // we'll create a basic PEM structure

    let mut pem = Vec::new();

    // PEM header for CRL
    pem.extend_from_slice(b"-----BEGIN X509 CRL-----\n");

    // Base64 encode the DER data
    use base64::{Engine as _, engine::general_purpose};
    let base64_data = general_purpose::STANDARD.encode(crl_der);

    // Split into lines of 64 characters as per RFC 7468
    for chunk in base64_data.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }

    // PEM footer
    pem.extend_from_slice(b"-----END X509 CRL-----\n");

    debug!("Converted CRL to PEM format ({} bytes)", pem.len());
    Ok(pem)
}

/// Save CRL to file system with metadata
#[allow(dead_code)]
pub fn save_crl_to_file(crl_der: &[u8], ca_id: i64) -> Result<(), ApiError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    debug!("Saving CRL to file system for CA {}", ca_id);

    // Ensure CRL directory exists
    std::fs::create_dir_all(CRL_DIR_PATH).map_err(|e| {
        error!("Failed to create CRL directory: {}", e);
        ApiError::Other(format!("Failed to create CRL directory: {e}"))
    })?;

    // Convert to PEM format for storage
    let crl_pem = crl_to_pem(crl_der)?;

    // Save to current CRL file
    std::fs::write(CURRENT_CRL_FILE_PATH, &crl_pem).map_err(|e| {
        error!("Failed to write CRL file: {}", e);
        ApiError::Other(format!("Failed to write CRL file: {e}"))
    })?;

    // Create timestamped backup
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let backup_path = format!("{CRL_DIR_PATH}/ca_{ca_id}_{timestamp}.crl");
    std::fs::write(&backup_path, &crl_pem).map_err(|e| {
        error!("Failed to write CRL backup file: {}", e);
        ApiError::Other(format!("Failed to write CRL backup file: {e}"))
    })?;

    debug!("Successfully saved CRL to file system (main: {}, backup: {})",
           CURRENT_CRL_FILE_PATH, backup_path);
    Ok(())
}

/// Load CRL from file system
#[allow(dead_code)]
pub(crate) fn load_crl_from_file() -> Result<Vec<u8>, ApiError> {
    debug!("Loading CRL from file system");

    // Check if CRL file exists
    if !std::path::Path::new(CURRENT_CRL_FILE_PATH).exists() {
        debug!("CRL file does not exist: {}", CURRENT_CRL_FILE_PATH);
        return Err(ApiError::NotFound(Some("CRL file not found".to_string())));
    }

    // Read the PEM-encoded CRL
    let crl_pem = std::fs::read(CURRENT_CRL_FILE_PATH).map_err(|e| {
        error!("Failed to read CRL file: {}", e);
        ApiError::Other(format!("Failed to read CRL file: {e}"))
    })?;

    // Extract DER data from PEM
    let crl_pem_str = String::from_utf8_lossy(&crl_pem);
    let der_data = extract_der_from_pem(&crl_pem_str)?;

    debug!("Successfully loaded CRL from file system ({} bytes)", der_data.len());
    Ok(der_data)
}

/// Get CRL metadata from file system
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct CrlMetadata {
    pub ca_id: i64,
    pub file_size: u64,
    pub created_time: i64,
    pub modified_time: i64,
    pub backup_count: usize,
}

pub fn get_crl_metadata(ca_id: i64) -> Result<CrlMetadata, ApiError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    debug!("Getting CRL metadata for CA {}", ca_id);

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Check current CRL file
    let file_path = std::path::Path::new(CURRENT_CRL_FILE_PATH);
    if !file_path.exists() {
        return Err(ApiError::NotFound(Some("CRL file not found".to_string())));
    }

    let metadata = file_path.metadata().map_err(|e| {
        ApiError::Other(format!("Failed to get file metadata: {e}"))
    })?;

    // Count backup files for this CA
    let backup_count = match std::fs::read_dir(CRL_DIR_PATH) {
        Ok(entries) => {
            entries.filter_map(|entry_result| {
                entry_result.ok().and_then(|entry| {
                    entry.file_name().to_str().and_then(|name| {
                        // Look for files that start with ca_{ca_id}_
                        if name.starts_with(&format!("ca_{ca_id}_")) && name.ends_with(".crl") {
                            Some(())
                        } else {
                            None
                        }
                    })
                })
            }).count()
        },
        Err(_) => 0,
    };

    let crl_metadata = CrlMetadata {
        ca_id,
        file_size: metadata.len(),
        created_time: metadata.created().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64,
        modified_time: metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64,
        backup_count,
    };

    debug!("CRL metadata retrieved: {:?}", crl_metadata);
    Ok(crl_metadata)
}

/// List all stored CRL files with their metadata
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct CrlFileInfo {
    pub filename: String,
    pub ca_id: i64,
    pub created_time: i64,
    pub file_size: u64,
}

pub fn list_crl_files() -> Result<Vec<CrlFileInfo>, ApiError> {
    debug!("Listing all CRL files");

    use std::time::UNIX_EPOCH;

    let mut crl_files = Vec::new();

    // Create directory if it doesn't exist
    if !std::path::Path::new(CRL_DIR_PATH).exists() {
        std::fs::create_dir_all(CRL_DIR_PATH).map_err(|e| {
            ApiError::Other(format!("Failed to create CRL directory: {e}"))
        })?;
        return Ok(crl_files);
    }

    let entries = std::fs::read_dir(CRL_DIR_PATH).map_err(|e| {
        ApiError::Other(format!("Failed to read CRL directory: {e}"))
    })?;

    for entry_result in entries {
        let entry = entry_result.map_err(|e| {
            ApiError::Other(format!("Failed to read directory entry: {e}"))
        })?;

        let path = entry.path();
        if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
            if filename.ends_with(".crl") {
                // Parse CA ID and timestamp from filename ca_{ca_id}_{timestamp}.crl
                if let Some(ca_id) = parse_ca_id_from_filename(filename) {
                    if let Ok(metadata) = entry.metadata() {
                        let created_time = metadata.created().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                            .duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;

                        crl_files.push(CrlFileInfo {
                            filename: filename.to_string(),
                            ca_id,
                            created_time,
                            file_size: metadata.len(),
                        });
                    }
                }
            }
        }
    }

    // Sort by creation time (newest first)
    crl_files.sort_by(|a, b| b.created_time.cmp(&a.created_time));

    debug!("Found {} CRL files", crl_files.len());
    Ok(crl_files)
}

/// Parse CA ID from CRL filename (format: ca_{ca_id}_{timestamp}.crl)
fn parse_ca_id_from_filename(filename: &str) -> Option<i64> {
    // Remove .crl extension
    let name_without_ext = filename.strip_suffix(".crl")?;

    // Split by underscore and extract CA ID
    let parts: Vec<&str> = name_without_ext.split('_').collect();
    if parts.len() >= 2 && parts[0] == "ca" {
        parts[1].parse::<i64>().ok()
    } else {
        None
    }
}

/// Extract DER data from PEM format
fn extract_der_from_pem(pem_str: &str) -> Result<Vec<u8>, ApiError> {
    // Find the PEM content between BEGIN and END markers
    let begin_marker = "-----BEGIN X509 CRL-----";
    let end_marker = "-----END X509 CRL-----";

    let start_pos = pem_str.find(begin_marker)
        .ok_or_else(|| ApiError::Other("Invalid PEM format: BEGIN marker not found".to_string()))?;
    let end_pos = pem_str.find(end_marker)
        .ok_or_else(|| ApiError::Other("Invalid PEM format: END marker not found".to_string()))?;

    let pem_content = &pem_str[start_pos + begin_marker.len()..end_pos];

    // Remove whitespace and decode from base64
    let clean_content: String = pem_content.chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.decode(&clean_content)
        .map_err(|e| ApiError::Other(format!("Failed to decode base64 PEM content: {e}")))
}

/// Parse an OCSP request from DER-encoded bytes
/// NOTE: This is a simplified implementation. Full OCSP parsing would require
/// proper ASN.1 parsing of OCSP request structures.
pub(crate) fn parse_ocsp_request(_request_der: &[u8]) -> Result<OCSPRequest, ApiError> {
    debug!("OCSP request parsing requested ({} bytes)", _request_der.len());
    debug!("NOTE: Full OCSP request parsing not yet implemented");

    // TODO: Implement proper OCSP request parsing
    // For now, return a placeholder error
    Err(ApiError::Other("OCSP request parsing not yet implemented.".to_string()))
}

/// Generate an OCSP response for a given certificate status
pub(crate) async fn generate_ocsp_response(
    request: &OCSPRequest,
    _ca: &CA,
    db: &crate::db::VaulTLSDB,
) -> Result<Vec<u8>, ApiError> {
    debug!("Generating OCSP response for certificate ID: {:?}", request.certificate_id.serial_number);

    // Check if the certificate is revoked
    let cert_id = extract_certificate_id_from_ocsp_request(request)?;
    let is_revoked = db.is_certificate_revoked(cert_id).await
        .map_err(|e| ApiError::Other(format!("Database error checking revocation status: {e}")))?;

    // Get revocation details if revoked
    let revocation_info = if is_revoked {
        db.get_certificate_revocation(cert_id).await
            .map_err(|e| ApiError::Other(format!("Database error getting revocation details: {e}")))?
    } else {
        None
    };

    // Determine certificate status
    let cert_status = if is_revoked {
        if let Some(revocation) = revocation_info {
            OCSPCertStatus::Revoked {
                revocation_time: revocation.revocation_date,
                revocation_reason: Some(revocation.revocation_reason),
            }
        } else {
            OCSPCertStatus::Revoked {
                revocation_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64,
                revocation_reason: None,
            }
        }
    } else {
        OCSPCertStatus::Good
    };

    // Create single response
    let single_response = OCSPSingleResponse {
        cert_id: request.certificate_id.clone(),
        cert_status,
        this_update: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64,
        next_update: Some((SystemTime::now() + std::time::Duration::from_secs(3600)).duration_since(UNIX_EPOCH).unwrap().as_millis() as i64), // 1 hour validity
        extensions: Vec::new(),
    };

    // Create response
    let _response = OCSPResponse {
        version: 1,
        response_status: OCSPResponseStatus::Successful,
        response_bytes: Some(single_response),
        produced_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64,
        extensions: Vec::new(),
    };

    // TODO: Sign the response with CA certificate
    // For now, return a placeholder
    debug!("OCSP response generated (placeholder - signing not implemented)");
    Err(ApiError::Other("OCSP response generation not yet fully implemented. Requires proper ASN.1 encoding and signing.".to_string()))
}

/// Extract certificate ID from OCSP request
/// This is a simplified implementation
fn extract_certificate_id_from_ocsp_request(_request: &OCSPRequest) -> Result<i64, ApiError> {
    // TODO: Implement proper certificate ID extraction from OCSP_CERTID
    // For now, this is a placeholder
    Err(ApiError::Other("Certificate ID extraction from OCSP request not yet implemented.".to_string()))
}

/// Generate OcspCertid from certificate serial number and issuer
pub(crate) fn generate_ocsp_cert_id(
    serial_number: &[u8],
    issuer_cert: &X509,
    hash_algorithm: &str,
) -> Result<OcspCertid, ApiError> {
    use openssl::hash::hash;

    let digest = match hash_algorithm {
        "sha1" => MessageDigest::sha1(),
        "sha256" => MessageDigest::sha256(),
        _ => return Err(ApiError::Other(format!("Unsupported hash algorithm: {hash_algorithm}"))),
    };

    // Hash the issuer name
    let issuer_name_der = issuer_cert.subject_name().to_der()
        .map_err(|e| ApiError::Other(format!("Failed to encode issuer name: {e}")))?;
    let issuer_name_hash = hash(digest, &issuer_name_der)
        .map_err(|e| ApiError::Other(format!("Failed to hash issuer name: {e}")))?;

    // Hash the issuer public key
    let issuer_key_der = issuer_cert.public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|e| ApiError::Other(format!("Failed to get issuer public key: {e}")))?;
    let issuer_key_hash = hash(digest, &issuer_key_der)
        .map_err(|e| ApiError::Other(format!("Failed to hash issuer key: {e}")))?;

    Ok(OcspCertid {
        hash_algorithm: hash_algorithm.to_string(),
        issuer_name_hash: issuer_name_hash.to_vec(),
        issuer_key_hash: issuer_key_hash.to_vec(),
        serial_number: serial_number.to_vec(),
    })
}
