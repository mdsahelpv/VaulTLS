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
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::X509Builder;
use passwords::PasswordGenerator;
use rocket_okapi::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use crate::constants::CA_FILE_PATH;
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
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct CA {
    pub id: i64,
    pub created_on: i64,
    pub valid_until: i64,
    pub creation_source: i32, // 0: self-signed, 1: imported
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub key: Vec<u8>,
}

pub struct CertificateBuilder {
    x509: X509Builder,
    private_key: PKey<Private>,
    created_on: i64,
    valid_until: Option<i64>,
    name: Option<String>,
    pkcs12_password: String,
    ca: Option<(i64, X509, PKey<Private>)>,
    user_id: Option<i64>,
    renew_method: CertificateRenewMethod
}

impl CertificateBuilder {
    /// Create a CA from a PKCS#12 file containing a CA certificate
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
                anyhow!("Invalid PKCS#12 file format: {}", e)
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

        // Extract the private key
        let pkey = parsed.pkey
            .ok_or_else(|| {
                error!("No private key found in PKCS#12");
                anyhow!("No private key found in PKCS#12 file. The file may be missing the private key or be corrupted.")
            })?;

        debug!("Private key extracted from PKCS#12");

        // Basic validation: ensure we have both certificate and private key
        // For more detailed CA validation, we would need to check extensions
        // but the OpenSSL API has changed. This is a simplified validation.
        // In production, you might want to add more robust CA validation.

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
            anyhow!("Failed to process certificate: {}", e)
        })?;

        let ca_key_der = pkey.private_key_to_der().map_err(|e| {
            error!("Failed to encode private key to DER: {}", e);
            anyhow!("Failed to process private key: {}", e)
        })?;

        debug!("CA certificate and key processed successfully");

        Ok(CA {
            id: -1,
            created_on,
            valid_until,
            creation_source: 1, // 1 = imported
            cert: ca_cert_der,
            key: ca_key_der,
        })
    }
}
impl CertificateBuilder {
    pub fn new_with_ca(ca: Option<&CA>) -> Result<Self> {
        let private_key = match ca {
            Some(ca) => {
                // Detect CA key type
                let ca_key = PKey::private_key_from_der(&ca.key)?;
                if ca_key.rsa().is_ok() {
                    generate_rsa_private_key()?
                } else if ca_key.ec_key().is_ok() {
                    generate_ecdsa_private_key()?
                } else {
                    return Err(anyhow!("Unsupported CA key type"));
                }
            },
            None => generate_ecdsa_private_key()?
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
            renew_method: Default::default()
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

    Self::new_with_ca(None)?
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
        let ca_cert = X509::from_der(&ca.cert)?;
        let ca_key = PKey::private_key_from_der(&ca.key)?;
        self.ca = Some((ca.id, ca_cert, ca_key));
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

    pub fn build_ca(mut self) -> Result<CA, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;

        let cn = create_cn(&name)?;
        self.x509.set_issuer_name(&cn)?;

        let basic_constraints = BasicConstraints::new().ca().build()?;
        self.x509.append_extension(basic_constraints)?;

        let key_usage = KeyUsage::new()
            .key_cert_sign()
            .crl_sign()
            .build()?;
        self.x509.append_extension(key_usage)?;

        let subject_key_identifier = SubjectKeyIdentifier::new().build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(subject_key_identifier)?;
        let authority_key_identifier = AuthorityKeyIdentifier::new().keyid(true).build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(authority_key_identifier)?;

        self.x509.sign(&self.private_key, MessageDigest::sha256())?;
        let cert = self.x509.build();

        Ok(CA{
            id: -1,
            created_on: self.created_on,
            valid_until,
            creation_source: 0, // 0 = self-signed
            cert: cert.to_der()?,
            key: self.private_key.private_key_to_der()?,
        })
    }

    pub fn build_client(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .client_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common(Client)
    }

    pub fn build_server(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .server_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common(Server)
    }

    pub fn build_common(mut self, certificate_type: CertificateType) -> Result<Certificate, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("X509: user_id not set"))?;
        let (ca_id, ca_cert, ca_key) = self.ca.ok_or(anyhow!("X509: CA not set"))?;

        let basic_constraints = BasicConstraints::new().build()?;
        self.x509.append_extension(basic_constraints)?;

        let key_usage = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()?;
        self.x509.append_extension(key_usage)?;

        self.x509.set_issuer_name(ca_cert.subject_name())?;

        self.x509.sign(&ca_key, MessageDigest::sha256())?;
        let cert = self.x509.build();

        let mut ca_stack = Stack::new()?;
        ca_stack.push(ca_cert.clone())?;

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
            ca_id,
            user_id,
            renew_method: self.renew_method
        })
    }
}

/// Generates a new private key.
fn generate_ecdsa_private_key() -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let server_key = PKey::from_ec_key(ec_key)?;
    Ok(server_key)
}

fn generate_rsa_private_key() -> Result<PKey<Private>, ErrorStack> {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(4096)?;
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

/// Convert a CA certificate to PEM format.
pub(crate) fn get_pem(ca: &CA) -> Result<Vec<u8>, ErrorStack> {
    let cert = X509::from_der(&ca.cert)?;
    cert.to_pem()
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
