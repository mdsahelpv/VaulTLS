use crate::cert::{CertificateBuilder, get_pem};
use crate::data::error::ApiError;
use crate::data::objects::CertificateChainInfo;
use crate::api::{CADetails, CreateCASelfSignedRequest};
use crate::db::VaulTLSDB;
use crate::settings::Settings;
use openssl::x509::X509;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// CA service for handling Certificate Authority business logic
pub struct CAService {
    db: Arc<VaulTLSDB>,
    settings: Arc<Settings>,
}

impl CAService {
    /// Create a new CA service
    pub fn new(db: Arc<VaulTLSDB>, settings: Arc<Settings>) -> Self {
        Self { db, settings }
    }

    /// Create a self-signed CA
    pub async fn create_self_signed_ca(&self, request: CreateCASelfSignedRequest) -> Result<i64, ApiError> {
        debug!("Creating self-signed CA with name: {}", request.name);

        let mut builder = CertificateBuilder::new_with_ca_and_key_type_size(
            None,
            request.key_type.as_deref(),
            request.key_size.as_deref()
        )?
        .set_name(&request.name)?
        .set_valid_until(request.validity_in_years)?;

        // Set advanced PKI extensions if provided
        if let Some(oid) = &request.certificate_policies_oid {
            builder = builder.set_certificate_policies_oid(oid)?;
        }
        if let Some(cps_url) = &request.certificate_policies_cps_url {
            builder = builder.set_certificate_policies_cps_url(cps_url)?;
        }

        // Set DN fields if provided
        if let Some(country) = &request.country_name {
            builder = builder.set_country(country)?;
        }
        if let Some(state) = &request.state_or_province_name {
            builder = builder.set_state(state)?;
        }
        if let Some(locality) = &request.locality_name {
            builder = builder.set_locality(locality)?;
        }
        if let Some(org) = &request.organization_name {
            builder = builder.set_organization(org)?;
        }
        if let Some(org_unit) = &request.organizational_unit_name {
            builder = builder.set_organizational_unit(org_unit)?;
        }
        if let Some(common) = &request.common_name {
            builder = builder.set_common_name(common)?;
        }
        if let Some(email) = &request.email_address {
            builder = builder.set_email(email)?;
        }

        // Set URLs if provided
        if let Some(aia_url) = &request.aia_url {
            builder = builder.set_authority_info_access(aia_url)?;
        }
        if let Some(cdp_url) = &request.cdp_url {
            builder = builder.set_crl_distribution_points(cdp_url)?;
        }

        let mut ca = builder.build_ca()?;
        ca.can_create_subordinate_ca = request.can_create_subordinate_ca;

        let ca_id = ca.id;
        let ca = self.db.insert_ca(ca).await?;

        info!("Self-signed CA created: {} (ID: {})", request.name, ca_id);

        Ok(ca_id)
    }

    /// Import CA from PKCS#12 file
    pub async fn import_ca_from_file(&self, pfx_data: &[u8], password: Option<&str>, name: Option<&str>) -> Result<i64, ApiError> {
        debug!("Importing CA from PKCS#12 file");

        let ca = CertificateBuilder::from_pfx(pfx_data, password, name)?;
        let ca_id = ca.id;
        let ca = self.db.insert_ca(ca).await?;

        info!("CA imported from PKCS#12 file (ID: {})", ca_id);

        Ok(ca_id)
    }

    /// Get all CAs with detailed information
    pub async fn get_ca_list(&self) -> Result<Vec<CADetails>, ApiError> {
        let cas = self.db.get_all_ca().await?;
        let mut ca_details = Vec::new();

        for ca in cas {
            let cert = X509::from_der(&ca.cert)?;

            // Extract certificate details
            let subject_name = cert.subject_name();
            let issuer_name = cert.issuer_name();
            let serial = cert.serial_number();

            // Get key information
            let public_key = cert.public_key()?;
            let key_size = if let Ok(rsa) = public_key.rsa() {
                format!("RSA {}", rsa.size() * 8)
            } else if public_key.ec_key().is_ok() {
                "ECDSA P-256".to_string()
            } else {
                "Unknown".to_string()
            };

            // Get signature algorithm
            let sig_alg_obj = cert.signature_algorithm().object();
            let signature_algorithm = match sig_alg_obj.to_string().as_str() {
                "sha256WithRSAEncryption" => "RSA-SHA256",
                "sha512WithRSAEncryption" => "RSA-SHA512",
                "ecdsa-with-SHA256" => "ECDSA-SHA256",
                "ecdsa-with-SHA512" => "ECDSA-SHA512",
                _ => {
                    match sig_alg_obj.nid().as_raw() {
                        668 => "RSA-SHA256",
                        794 => "ECDSA-SHA256",
                        913 => "RSA-SHA512",
                        796 => "ECDSA-SHA512",
                        _ => "Unknown",
                    }
                }
            };

            // Use the creation_source field to determine if CA is self-signed or imported
            let is_self_signed = ca.creation_source == 0;

            // Get certificate name from subject
            let name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13)
                .and_then(|e| e.data().as_utf8().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            // Extract AIA and CDP URLs
            let (aia_url, cdp_url) = self.extract_aia_and_cdp_urls(&cert).unwrap_or((None, None));

            // Update database if URLs are missing
            if ca.aia_url.is_none() || ca.cdp_url.is_none() {
                debug!("Updating database URLs for CA {}: AIA='{}', CDP='{}'",
                       ca.id, aia_url.as_deref().unwrap_or(""), cdp_url.as_deref().unwrap_or(""));

                let db_clone = Arc::clone(&self.db);
                let ca_id = ca.id;
                let update_aia = aia_url.clone();
                let update_cdp = cdp_url.clone();
                tokio::spawn(async move {
                    if let Err(e) = db_clone.update_ca_urls(ca_id, update_aia, update_cdp).await {
                        warn!("Failed to update CA URLs in database: {}", e);
                    }
                });
            }

            // Get chain information
            let chain_length = ca.cert_chain.len();
            let mut chain_certificates = Vec::new();

            for (index, cert_der) in ca.cert_chain.iter().enumerate() {
                match X509::from_der(cert_der) {
                    Ok(chain_cert) => {
                        let chain_subject = chain_cert.subject_name();
                        let chain_issuer = chain_cert.issuer_name();
                        match chain_cert.serial_number().to_bn() {
                            Ok(serial_bn) => {
                                let serial_number = serial_bn.to_hex_str()
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|_| "Invalid".to_string());

                                let certificate_type = self.determine_certificate_type(&chain_cert, index, ca.cert_chain.len());
                                chain_certificates.push(CertificateChainInfo {
                                    subject: format!("{chain_subject:?}"),
                                    issuer: format!("{chain_issuer:?}"),
                                    serial_number,
                                    certificate_type,
                                    is_end_entity: index == 0,
                                });
                            }
                            Err(e) => {
                                warn!("Failed to get serial number for certificate {} in chain: {}", index + 1, e);
                                let certificate_type = self.determine_certificate_type(&chain_cert, index, ca.cert_chain.len());
                                chain_certificates.push(CertificateChainInfo {
                                    subject: format!("Certificate {}: Failed to parse - {:?}", index + 1, e),
                                    issuer: "Unknown".to_string(),
                                    serial_number: "Unknown".to_string(),
                                    certificate_type: "unknown".to_string(),
                                    is_end_entity: index == 0,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse certificate {} in chain: {}", index + 1, e);
                        chain_certificates.push(CertificateChainInfo {
                            subject: format!("Certificate {}: Failed to parse - {:?}", index + 1, e),
                            issuer: "Unknown".to_string(),
                            serial_number: "Unknown".to_string(),
                            certificate_type: "unknown".to_string(),
                            is_end_entity: index == 0,
                        });
                    }
                }
            }

            // Format subject and issuer
            let subject = self.format_subject_name(subject_name);
            let issuer = self.format_subject_name(issuer_name);

            let cert_pem_vec = get_pem(&ca)?;
            let certificate_pem = String::from_utf8(cert_pem_vec)
                .map_err(|e| ApiError::Other(format!("Failed to convert certificate PEM to string: {e}")))?;

            let ca_detail = CADetails {
                id: ca.id,
                name,
                subject,
                issuer,
                created_on: ca.created_on,
                valid_until: ca.valid_until,
                serial_number: serial.to_bn()?.to_hex_str()?.to_string(),
                key_size,
                signature_algorithm: signature_algorithm.to_string(),
                is_self_signed,
                certificate_pem,
                chain_length,
                chain_certificates,
                can_create_subordinate_ca: ca.can_create_subordinate_ca,
                aia_url,
                cdp_url,
            };

            ca_details.push(ca_detail);
        }

        Ok(ca_details)
    }

    /// Get CA details by ID
    pub async fn get_ca_details(&self, ca_id: i64) -> Result<CADetails, ApiError> {
        let ca = if ca_id == 0 {
            self.db.get_current_ca().await?
        } else {
            self.db.get_ca(ca_id).await?
        };

        let cert = X509::from_der(&ca.cert)?;

        let subject_name = cert.subject_name();
        let issuer_name = cert.issuer_name();
        let serial = cert.serial_number();

        let public_key = cert.public_key()?;
        let key_size = if let Ok(rsa) = public_key.rsa() {
            format!("RSA {}", rsa.size() * 8)
        } else if public_key.ec_key().is_ok() {
            "ECDSA P-256".to_string()
        } else {
            "Unknown".to_string()
        };

        let sig_alg_obj = cert.signature_algorithm().object();
        let sig_alg_str = sig_alg_obj.to_string();
        let signature_algorithm = match sig_alg_str.as_str() {
            "sha256WithRSAEncryption" => "RSA-SHA256",
            "sha512WithRSAEncryption" => "RSA-SHA512",
            "ecdsa-with-SHA256" => "ECDSA-SHA256",
            "ecdsa-with-SHA512" => "ECDSA-SHA512",
            _ => {
                match sig_alg_obj.nid().as_raw() {
                    668 => "RSA-SHA256",
                    794 => "ECDSA-SHA256",
                    913 => "RSA-SHA512",
                    796 => "ECDSA-SHA512",
                    _ => "Unknown",
                }
            }
        };

        let is_self_signed = ca.creation_source == 0;
        let name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13)
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let (aia_url, cdp_url) = if ca.aia_url.is_some() && ca.cdp_url.is_some() {
            (ca.aia_url.clone(), ca.cdp_url.clone())
        } else {
            self.extract_aia_and_cdp_urls(&cert).unwrap_or((None, None))
        };

        let chain_length = ca.cert_chain.len();
        let mut chain_certificates = Vec::new();

        for (index, cert_der) in ca.cert_chain.iter().enumerate() {
            match X509::from_der(cert_der) {
                Ok(chain_cert) => {
                    let chain_subject = chain_cert.subject_name();
                    let chain_issuer = chain_cert.issuer_name();
                    match chain_cert.serial_number().to_bn() {
                        Ok(serial_bn) => {
                            let serial_number = serial_bn.to_hex_str()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|_| "Invalid".to_string());
                            chain_certificates.push(CertificateChainInfo {
                                subject: format!("{chain_subject:?}"),
                                issuer: format!("{chain_issuer:?}"),
                                serial_number,
                                certificate_type: self.determine_certificate_type(&chain_cert, index, ca.cert_chain.len()),
                                is_end_entity: index == 0,
                            });
                        }
                        Err(e) => warn!("Failed to parse main CA certificate: {}", e),
                    }
                }
                Err(e) => warn!("Failed to parse chain certificate: {}", e),
            }
        }

        let cert_pem_vec = get_pem(&ca)?;
        let certificate_pem = String::from_utf8(cert_pem_vec)
            .map_err(|e| ApiError::Other(format!("Failed to convert certificate PEM to string: {e}")))?;

        let ca_details = CADetails {
            id: ca.id,
            name,
            subject: self.format_subject_name(subject_name),
            issuer: self.format_subject_name(issuer_name),
            created_on: ca.created_on,
            valid_until: ca.valid_until,
            serial_number: serial.to_bn()?.to_hex_str()?.to_string(),
            key_size,
            signature_algorithm: signature_algorithm.to_string(),
            is_self_signed,
            certificate_pem,
            chain_length,
            chain_certificates,
            can_create_subordinate_ca: ca.can_create_subordinate_ca,
            aia_url,
            cdp_url,
        };

        Ok(ca_details)
    }

    /// Delete a CA
    pub async fn delete_ca(&self, ca_id: i64) -> Result<(), ApiError> {
        // Get CA details before deletion for logging
        let ca_to_delete = self.db.get_ca(ca_id).await
            .map_err(|_| ApiError::NotFound(Some("CA not found".to_string())))?;

        self.db.delete_ca(ca_id).await?;

        info!("CA {} deleted", ca_id);

        Ok(())
    }

    /// Get CA certificate PEM
    pub async fn get_ca_certificate_pem(&self, ca_id: i64) -> Result<String, ApiError> {
        let ca = if ca_id == 0 {
            self.db.get_current_ca().await?
        } else {
            self.db.get_ca(ca_id).await?
        };

        let cert_pem_vec = get_pem(&ca)?;
        String::from_utf8(cert_pem_vec)
            .map_err(|e| ApiError::Other(format!("Failed to convert certificate PEM to string: {e}")))
    }

    /// Get CA certificate and private key pair
    pub async fn get_ca_key_pair(&self, ca_id: i64) -> Result<Vec<u8>, ApiError> {
        use openssl::pkey::PKey;

        let ca = if ca_id == 0 {
            self.db.get_current_ca().await?
        } else {
            self.db.get_ca(ca_id).await?
        };

        let cert_pem = get_pem(&ca)?;
        let private_key = PKey::private_key_from_der(&ca.key)
            .map_err(|e| ApiError::Other(format!("Failed to load CA private key: {e}")))?;
        let key_pem = private_key.private_key_to_pem_pkcs8()
            .map_err(|e| ApiError::Other(format!("Failed to convert private key to PEM: {e}")))?;

        let mut combined_pem = Vec::new();
        combined_pem.extend(cert_pem);
        combined_pem.extend(b"\n");
        combined_pem.extend(key_pem);

        Ok(combined_pem)
    }

    /// Extract AIA and CDP URLs from certificate
    fn extract_aia_and_cdp_urls(&self, cert: &X509) -> Result<(Option<String>, Option<String>), ApiError> {
        let pem = cert.to_pem()
            .map_err(|e| ApiError::Other(format!("Failed to convert certificate to PEM: {e}")))?;

        let pem_str = String::from_utf8(pem)
            .map_err(|e| ApiError::Other(format!("Failed to convert PEM to string: {e}")))?;

        let temp_cert_path = std::env::temp_dir().join(format!("cert_ext_{}.pem", std::process::id()));
        std::fs::write(&temp_cert_path, &pem_str)
            .map_err(|e| ApiError::Other(format!("Failed to write temp certificate: {e}")))?;

        let output = std::process::Command::new("openssl")
            .args([
                "x509",
                "-in", &temp_cert_path.to_string_lossy(),
                "-text",
                "-noout"
            ])
            .output()
            .map_err(|e| ApiError::Other(format!("Failed to run openssl command: {e}")))?;

        let _ = std::fs::remove_file(&temp_cert_path);

        if !output.status.success() {
            return Ok((None, None));
        }

        let text_output = String::from_utf8(output.stdout)
            .map_err(|e| ApiError::Other(format!("Failed to parse openssl output: {e}")))?;

        let mut aia_url: Option<String> = None;
        let mut cdp_url: Option<String> = None;

        for line in text_output.lines() {
            let line_trimmed = line.trim();

            if let Some(http_start) = line_trimmed.find("URI:") {
                if let Some(url_start_pos) = line_trimmed[http_start..].find("http") {
                    let actual_url_start = http_start + url_start_pos;
                    let url = &line_trimmed[actual_url_start..];

                    if url.contains("ca.cert") || line_trimmed.contains("Authority Information Access") {
                        if aia_url.is_none() {
                            aia_url = Some(url.to_string());
                        }
                    } else if url.contains("ca.crl") || line_trimmed.contains("CRL Distribution Points") {
                        if cdp_url.is_none() {
                            cdp_url = Some(url.to_string());
                        }
                    }
                }
            }

            if !line_trimmed.contains("URI:") && line_trimmed.contains("http") {
                if let Some(http_start) = line_trimmed.find("http") {
                    let url = &line_trimmed[http_start..];

                    if url.contains("ca.cert") {
                        if aia_url.is_none() {
                            aia_url = Some(url.to_string());
                        }
                    } else if url.contains("ca.crl") || cdp_url.is_none() {
                        if cdp_url.is_none() {
                            cdp_url = Some(url.to_string());
                        }
                    }
                }
            }
        }

        Ok((aia_url, cdp_url))
    }

    /// Determine certificate type in chain
    fn determine_certificate_type(&self, cert: &X509, index: usize, total_certs: usize) -> String {
        let is_ca = || -> bool {
            let pem_result = cert.to_pem();
            if let Ok(pem_data) = pem_result {
                if let Ok(pem_str) = String::from_utf8(pem_data) {
                    let temp_cert_path = std::env::temp_dir().join(format!("cert_ca_check_{}.pem", std::process::id()));
                    if std::fs::write(&temp_cert_path, &pem_str).is_ok() {
                        let openssl_result = std::process::Command::new("openssl")
                            .args([
                                "x509",
                                "-in", &temp_cert_path.to_string_lossy(),
                                "-text",
                                "-noout"
                            ])
                            .output();

                        let _ = std::fs::remove_file(&temp_cert_path);

                        if let Ok(output) = openssl_result {
                            if output.status.success() {
                                if let Ok(text_output) = String::from_utf8(output.stdout) {
                                    return text_output.contains("CA:TRUE");
                                }
                            }
                        }
                    }
                }
            }
            false
        };

        let is_self_signed = {
            let subject = cert.subject_name();
            let issuer = cert.issuer_name();
            if let (Ok(subject_der), Ok(issuer_der)) = (subject.to_der(), issuer.to_der()) {
                subject_der == issuer_der
            } else {
                false
            }
        };

        if is_ca() {
            if is_self_signed && index == total_certs - 1 {
                return "root_ca".to_string();
            } else if is_ca() {
                return "intermediate_ca".to_string();
            }
        }

        if index == 0 {
            return "end_entity".to_string();
        }

        "intermediate_ca".to_string()
    }

    /// Format X509Name as DN string
    fn format_subject_name(&self, name: &openssl::x509::X509NameRef) -> String {
        let mut dn_parts = Vec::new();

        for entry in name.entries() {
            if let Ok(data) = entry.data().as_utf8() {
                let rdn_type = match entry.object().nid().as_raw() {
                    13 => "CN".to_string(),
                    14 => "SN".to_string(),
                    3 => "CN".to_string(),
                    17 => "ST".to_string(),
                    18 => "L".to_string(),
                    19 => "STREET".to_string(),
                    6 => "O".to_string(),
                    7 => "OU".to_string(),
                    8 => "ST".to_string(),
                    10 => "O".to_string(),
                    11 => "OU".to_string(),
                    16 => "POSTALCODE".to_string(),
                    20 => "DC".to_string(),
                    41 => "NAME".to_string(),
                    43 => "INITIALS".to_string(),
                    44 => "GENERATION".to_string(),
                    46 => "DNQUALIFIER".to_string(),
                    48 => "emailAddress".to_string(),
                    49 => "emailAddress".to_string(),
                    _ => entry.object().to_string(),
                };

                dn_parts.push(format!("{}={}", rdn_type, data.as_ref() as &str));
            }
        }

        dn_parts.join(", ")
    }
}
