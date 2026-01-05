use crate::cert::{get_password, Certificate, CertificateBuilder, CertificateDetails};
use crate::data::api::{CreateUserCertificateRequest};
use crate::data::enums::CertificateType;
use crate::data::error::ApiError;
use crate::data::objects::User;
use crate::db::VaulTLSDB;
use crate::notification::mail::{MailMessage, Mailer};
use crate::settings::Settings;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, error};

/// Repository trait for certificate data access
#[async_trait::async_trait]
pub trait CertificateRepository {
    async fn insert_user_cert(&self, cert: Certificate) -> Result<Certificate, anyhow::Error>;
    async fn get_user_cert_by_id(&self, id: i64) -> Result<Certificate, anyhow::Error>;
    async fn get_user_cert(&self, id: i64) -> Result<(i64, String, i64, i64, Vec<u8>, String, crate::data::enums::CertificateType, crate::data::enums::CertificateRenewMethod, i64), anyhow::Error>;
    async fn get_user_cert_pkcs12(&self, id: i64) -> Result<(i64, String, Vec<u8>), anyhow::Error>;
    async fn get_user_cert_pkcs12_password(&self, id: i64) -> Result<(i64, String), anyhow::Error>;
    async fn get_all_user_cert(&self, user_id: Option<i64>) -> Result<Vec<Certificate>, anyhow::Error>;
    async fn delete_user_cert(&self, id: i64) -> Result<(), anyhow::Error>;
    async fn revoke_certificate(&self, id: i64, reason: crate::data::enums::CertificateRevocationReason, admin_id: Option<i64>, custom_reason: Option<String>) -> Result<i64, anyhow::Error>;
    async fn unrevoke_certificate(&self, id: i64) -> Result<(), anyhow::Error>;
    async fn is_certificate_revoked(&self, id: i64) -> Result<bool, anyhow::Error>;
    async fn get_certificate_revocation(&self, id: i64) -> Result<Option<crate::data::objects::CertificateRevocation>, anyhow::Error>;
    async fn get_all_revocation_records(&self) -> Result<Vec<crate::data::objects::CertificateRevocation>, anyhow::Error>;
}

/// Database-backed certificate repository implementation
pub struct DatabaseCertificateRepository {
    db: Arc<VaulTLSDB>,
}

impl DatabaseCertificateRepository {
    pub fn new(db: Arc<VaulTLSDB>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl CertificateRepository for DatabaseCertificateRepository {
    async fn insert_user_cert(&self, cert: Certificate) -> Result<Certificate, anyhow::Error> {
        self.db.insert_user_cert(cert).await
    }

    async fn get_user_cert_by_id(&self, id: i64) -> Result<Certificate, anyhow::Error> {
        self.db.get_user_cert_by_id(id).await
    }

    async fn get_user_cert(&self, id: i64) -> Result<(i64, String, i64, i64, Vec<u8>, String, crate::data::enums::CertificateType, crate::data::enums::CertificateRenewMethod, i64), anyhow::Error> {
        self.db.get_user_cert(id).await
    }

    async fn get_user_cert_pkcs12(&self, id: i64) -> Result<(i64, String, Vec<u8>), anyhow::Error> {
        self.db.get_user_cert_pkcs12(id).await
    }

    async fn get_user_cert_pkcs12_password(&self, id: i64) -> Result<(i64, String), anyhow::Error> {
        self.db.get_user_cert_pkcs12_password(id).await
    }

    async fn get_all_user_cert(&self, user_id: Option<i64>) -> Result<Vec<Certificate>, anyhow::Error> {
        self.db.get_all_user_cert(user_id).await
    }

    async fn delete_user_cert(&self, id: i64) -> Result<(), anyhow::Error> {
        self.db.delete_user_cert(id).await
    }

    async fn revoke_certificate(&self, id: i64, reason: crate::data::enums::CertificateRevocationReason, admin_id: Option<i64>, custom_reason: Option<String>) -> Result<i64, anyhow::Error> {
        self.db.revoke_certificate(id, reason, admin_id, custom_reason).await
    }

    async fn unrevoke_certificate(&self, id: i64) -> Result<(), anyhow::Error> {
        self.db.unrevoke_certificate(id).await
    }

    async fn is_certificate_revoked(&self, id: i64) -> Result<bool, anyhow::Error> {
        self.db.is_certificate_revoked(id).await
    }

    async fn get_certificate_revocation(&self, id: i64) -> Result<Option<crate::data::objects::CertificateRevocation>, anyhow::Error> {
        self.db.get_certificate_revocation(id).await
    }

    async fn get_all_revocation_records(&self) -> Result<Vec<crate::data::objects::CertificateRevocation>, anyhow::Error> {
        self.db.get_all_revocation_records().await
    }
}

/// Data structure for certificate preparation
struct CertificatePreparationData {
    ca: crate::cert::CA,
    pkcs12_password: String,
    crl_url: Option<String>,
    ocsp_url: Option<String>,
}

/// Certificate service for handling certificate business logic
pub struct CertificateService {
    repository: Arc<DatabaseCertificateRepository>,
    settings: Arc<Settings>,
    mailer: Arc<Mutex<Option<Mailer>>>,
}

impl CertificateService {
    /// Create a new certificate service
    pub fn new(repository: Arc<DatabaseCertificateRepository>, settings: Arc<Settings>, mailer: Arc<Mutex<Option<Mailer>>>) -> Self {
        Self { repository, settings, mailer }
    }

    /// Create a new certificate
    pub async fn create_certificate(
        &self,
        request: CreateUserCertificateRequest,
        admin_id: i64,
        db: &Arc<VaulTLSDB>,
    ) -> Result<Certificate, ApiError> {
        debug!("Creating certificate for user {}", request.user_id);

        // Step 1: Get and validate user
        let user = self.get_and_validate_user(&request, db).await?;

        // Step 2: Validate certificate parameters
        self.validate_certificate_request(&request)?;

        // Step 3: Prepare certificate data (CA, URLs, etc.)
        let cert_data = self.prepare_certificate_data(&request, db).await?;

        // Step 4: Build certificate based on type
        let certificate = self.build_certificate_based_on_type(&request, &user, &cert_data).await?;

        // Step 5: Finalize certificate creation (save and notify)
        self.finalize_certificate_creation(certificate, &user, request.notify_user.unwrap_or(false)).await
    }

    /// Get and validate user for certificate creation
    async fn get_and_validate_user(
        &self,
        request: &CreateUserCertificateRequest,
        db: &Arc<VaulTLSDB>,
    ) -> Result<crate::data::objects::User, ApiError> {
        db.get_user(request.user_id).await
            .map_err(|e| ApiError::Other(format!("Failed to get user {}: {}", request.user_id, e)))
    }

    /// Prepare certificate data (CA, URLs, password, etc.)
    async fn prepare_certificate_data(
        &self,
        request: &CreateUserCertificateRequest,
        db: &Arc<VaulTLSDB>,
    ) -> Result<CertificatePreparationData, ApiError> {
        // Get CA
        let ca_id = request.ca_id.unwrap_or(0);
        let ca = if ca_id > 0 {
            db.get_ca(ca_id).await?
        } else {
            db.get_current_ca().await?
        };

        // Generate password
        let pkcs12_password = get_password(
            request.system_generated_password,
            &request.pkcs12_password
        );

        // Get CRL and OCSP settings
        let crl_settings = self.settings.get_crl();
        let ocsp_settings = self.settings.get_ocsp();

        let crl_url = if crl_settings.enabled {
            crl_settings.distribution_url.as_deref()
        } else {
            None
        };

        let ocsp_url = if ocsp_settings.enabled {
            ocsp_settings.responder_url.as_deref()
        } else {
            None
        };

        // Check Root CA restrictions
        let is_root_ca = self.settings.get_is_root_ca();
        if is_root_ca && request.cert_type.unwrap_or_default() != CertificateType::SubordinateCA {
            return Err(ApiError::BadRequest("Root CA Server can only issue subordinate CA certificates".to_string()));
        }

        Ok(CertificatePreparationData {
            ca,
            pkcs12_password,
            crl_url: crl_url.map(|s| s.to_string()),
            ocsp_url: ocsp_url.map(|s| s.to_string()),
        })
    }

    /// Build certificate based on requested type
    async fn build_certificate_based_on_type(
        &self,
        request: &CreateUserCertificateRequest,
        user: &crate::data::objects::User,
        cert_data: &CertificatePreparationData,
    ) -> Result<Certificate, ApiError> {
        let mut cert_builder = CertificateBuilder::new_with_ca_and_key_type_size(
            Some(&cert_data.ca),
            request.key_type.as_deref(),
            request.key_size.as_deref()
        )?
        .set_name(&request.cert_name)?
        .set_valid_until(request.validity_in_years.unwrap_or(1))?
        .set_renew_method(request.renew_method.unwrap_or_default())?
        .set_pkcs12_password(&cert_data.pkcs12_password)?
        .set_ca(&cert_data.ca)?
        .set_user_id(request.user_id)?;

        // Apply user-selected hash algorithm if provided
        if let Some(hash_alg) = &request.hash_algorithm {
            cert_builder = cert_builder.set_hash_algorithm(hash_alg)?;
        }

        // Set URLs
        cert_builder = self.configure_certificate_urls(cert_builder, request, cert_data);

        // Build based on certificate type
        match request.cert_type.unwrap_or_default() {
            CertificateType::Client => self.build_client_certificate(cert_builder, user, cert_data).await,
            CertificateType::Server => self.build_server_certificate(cert_builder, request, cert_data).await,
            CertificateType::SubordinateCA => self.build_subordinate_ca_certificate(cert_builder).await,
        }
    }

    /// Configure certificate URLs (AIA, OCSP, CDP)
    fn configure_certificate_urls(
        &self,
        cert_builder: CertificateBuilder,
        request: &CreateUserCertificateRequest,
        _cert_data: &CertificatePreparationData,
    ) -> CertificateBuilder {
        // URL configuration is handled in individual build methods
        // This method is kept for future extensibility
        cert_builder
    }

    /// Build client certificate
    async fn build_client_certificate(
        &self,
        cert_builder: CertificateBuilder,
        user: &crate::data::objects::User,
        _cert_data: &CertificatePreparationData,
    ) -> Result<Certificate, ApiError> {
        Ok(cert_builder
            .set_email_san(&user.email)?
            .build_common_with_extensions(crate::data::enums::CertificateType::Client, None, None)?)
    }

    /// Build server certificate with SAN validation
    async fn build_server_certificate(
        &self,
        cert_builder: CertificateBuilder,
        request: &CreateUserCertificateRequest,
        cert_data: &CertificatePreparationData,
    ) -> Result<Certificate, ApiError> {
        // Filter out empty strings from DNS names and IP addresses
        let dns_names: Vec<String> = request.dns_names.clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.trim().is_empty())
            .collect();

        let ip_addresses: Vec<String> = request.ip_addresses.clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.trim().is_empty())
            .collect();

        // SAN validation: Server certificates MUST include Subject Alternative Name
        if dns_names.is_empty() && ip_addresses.is_empty() {
            return Err(ApiError::BadRequest("Server certificates must include at least one valid DNS name or IP address".to_string()));
        }

        // Use configured URLs for server certificates
        let final_crl_url = request.cdp_url.as_deref().or_else(|| cert_data.crl_url.as_deref());
        let final_ocsp_url = request.ocsp_url.as_deref()
            .or_else(|| request.aia_url.as_deref())
            .or_else(|| cert_data.ocsp_url.as_deref());

        Ok(cert_builder
            .set_san(&dns_names, &ip_addresses)?
            .build_common_with_extensions(crate::data::enums::CertificateType::Server, final_crl_url, final_ocsp_url)?)
    }

    /// Build subordinate CA certificate
    async fn build_subordinate_ca_certificate(
        &self,
        cert_builder: CertificateBuilder,
    ) -> Result<Certificate, ApiError> {
        Ok(cert_builder.build_subordinate_ca()?)
    }

    /// Finalize certificate creation (save to DB and send notifications)
    async fn finalize_certificate_creation(
        &self,
        certificate: Certificate,
        user: &crate::data::objects::User,
        notify_user: bool,
    ) -> Result<Certificate, ApiError> {
        let certificate = self.repository.insert_user_cert(certificate).await
            .map_err(|e| ApiError::Other(format!("Failed to insert certificate: {e}")))?;

        info!("New certificate created: {} (ID: {})", certificate.name, certificate.id);

        // Send notification email if requested
        if notify_user {
            self.send_certificate_notification(&certificate, user).await;
        }

        Ok(certificate)
    }

    /// Sign a certificate from CSR
    pub async fn sign_csr_certificate(
        &self,
        ca_id: i64,
        user_id: i64,
        certificate_type: Option<String>,
        validity_in_days: Option<i64>,
        cert_name: Option<String>,
        csr_data: &[u8],
        allow_weak_key: Option<bool>,
        notify_user: Option<bool>,
    ) -> Result<Certificate, ApiError> {
        debug!("Signing certificate from CSR for user {}", user_id);

        // Parse the CSR
        let (parsed_csr, _csr_pem) = match crate::cert::parse_csr_from_pem(csr_data) {
            Ok(p) => {
                let pem = String::from_utf8_lossy(csr_data).to_string();
                (p, pem)
            },
            Err(_) => {
                let p = crate::cert::parse_csr_from_der(csr_data).map_err(|e| {
                    error!("Failed to parse CSR (tried PEM and DER): {:?}", e);
                    ApiError::BadRequest("Failed to parse CSR. Please ensure it is a valid Certificate Signing Request in PEM or DER format.".to_string())
                })?;
                let pem = p.csr.to_pem().map_err(|e| ApiError::Other(format!("Failed to encode CSR to PEM: {e}")))?;
                let pem_str = String::from_utf8_lossy(&pem).to_string();
                (p, pem_str)
            }
        };

        // Validate CSR
        if !parsed_csr.signature_valid {
            return Err(ApiError::BadRequest("CSR signature verification failed. The CSR may be corrupted or was not signed correctly.".to_string()));
        }

        if parsed_csr.is_weak && !allow_weak_key.unwrap_or(false) {
            let warnings = parsed_csr.security_warnings.join(" ");
            return Err(ApiError::BadRequest(format!("Security Warning: The CSR uses a weak public key. {}. Please confirm you want to proceed by checking 'Allow weak keys'.", warnings)));
        }

        // Get CA and user
        let ca = self.repository.db.get_ca(ca_id).await?;
        let user = self.repository.db.get_user(user_id).await?;

        // Check Root CA restrictions
        let is_root_ca = self.settings.get_is_root_ca();
        let cert_type = certificate_type.as_deref().unwrap_or("server");
        if is_root_ca && cert_type != "subordinate_ca" {
            return Err(ApiError::BadRequest("Root CA Server can only issue subordinate CA certificates".to_string()));
        }

        // Convert string to enum
        let certificate_type_enum = match cert_type {
            "client" => CertificateType::Client,
            "server" => CertificateType::Server,
            "subordinate_ca" => CertificateType::SubordinateCA,
            _ => return Err(ApiError::BadRequest(format!("Invalid certificate type: {}", cert_type))),
        };

        // Generate certificate name
        let raw_cert_name = cert_name.unwrap_or_else(|| {
            parsed_csr.subject_name.entries().find(|e| e.object().nid().as_raw() == 13)
                .and_then(|e| e.data().as_utf8().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "CSR-Certificate".to_string())
        });

        // Sanitize name (reuse logic from api.rs)
        let cert_name = self.sanitize_certificate_name(&raw_cert_name)?;

        let validity_in_days = validity_in_days.unwrap_or(365);
        let pkcs12_password = get_password(false, &None);

        // Create certificate from CSR
        let builder = CertificateBuilder::from_csr(&parsed_csr, Some(&ca))?
            .set_name(&cert_name)?
            .set_certificate_type(certificate_type_enum)?
            .set_user_id(user.id)?
            .set_validity_days(validity_in_days as u64)?
            .set_pkcs12_password(&pkcs12_password)?;

        let certificate = builder.build_csr_certificate(certificate_type_enum)?;
        let certificate = self.repository.insert_user_cert(certificate).await
            .map_err(|e| ApiError::Other(format!("Failed to insert certificate: {e}")))?;

        info!("Certificate '{}' signed and created successfully (ID: {})", cert_name, certificate.id);

        // Send notification if requested
        if notify_user.unwrap_or(false) {
            self.send_certificate_notification(&certificate, &user).await;
        }

        Ok(certificate)
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(
        &self,
        cert_id: i64,
        reason: crate::data::enums::CertificateRevocationReason,
        admin_id: i64,
        custom_reason: Option<String>,
    ) -> Result<(), ApiError> {
        debug!("Revoking certificate {}", cert_id);

        // Check if certificate exists
        let _cert = self.repository.db.get_user_cert_by_id(cert_id).await?;

        // Check if already revoked
        if self.repository.db.is_certificate_revoked(cert_id).await? {
            return Err(ApiError::BadRequest("Certificate is already revoked".to_string()));
        }

        // Revoke the certificate
        self.repository.revoke_certificate(cert_id, reason, Some(admin_id), custom_reason).await
            .map_err(|e| ApiError::Other(format!("Failed to revoke certificate: {e}")))?;

        // Clear CRL cache
        // Note: This would need access to the CrlCache, which might need to be passed in or handled differently

        info!("Certificate {} revoked successfully", cert_id);

        Ok(())
    }

    /// Unrevoke a certificate
    pub async fn unrevoke_certificate(&self, cert_id: i64) -> Result<(), ApiError> {
        debug!("Unrevoking certificate {}", cert_id);

        // Check if certificate exists
        let _cert = self.repository.db.get_user_cert_by_id(cert_id).await?;

        // Check if actually revoked
        if !self.repository.db.is_certificate_revoked(cert_id).await? {
            return Err(ApiError::BadRequest("Certificate is not revoked".to_string()));
        }

        // Unrevoke the certificate
        self.repository.unrevoke_certificate(cert_id).await
            .map_err(|e| ApiError::Other(format!("Failed to unrevoke certificate: {e}")))?;

        info!("Certificate {} unrevoked successfully", cert_id);

        Ok(())
    }

    /// Get certificate details
    pub async fn get_certificate_details(&self, cert_id: i64, user_id: i64, is_admin: bool) -> Result<CertificateDetails, ApiError> {
        let mut cert = self.repository.db.get_user_cert_by_id(cert_id).await?;

        if cert.user_id != user_id && !is_admin {
            return Err(ApiError::Forbidden(None));
        }

        // Get revocation status
        if let Some(revocation) = self.repository.db.get_certificate_revocation(cert_id).await? {
            cert.is_revoked = true;
            cert.revoked_on = Some(revocation.revocation_date);
            cert.revoked_reason = Some(revocation.revocation_reason);
            cert.revoked_by = revocation.revoked_by_user_id;
            cert.custom_revocation_reason = revocation.custom_reason;
        }

        let details = crate::cert::get_certificate_details(&cert)?;
        Ok(details)
    }

    /// Validate certificate creation request
    fn validate_certificate_request(&self, request: &CreateUserCertificateRequest) -> Result<(), ApiError> {
        // Validate certificate name (assuming sanitize_certificate_name does validation)
        self.sanitize_certificate_name(&request.cert_name)?;

        // Validate DNS names
        if let Some(dns_names) = &request.dns_names {
            for dns_name in dns_names {
                if !dns_name.trim().is_empty() {
                    self.validate_dns_name(dns_name)?;
                }
            }
        }

        // Validate IP addresses
        if let Some(ip_addresses) = &request.ip_addresses {
            for ip_addr in ip_addresses {
                if !ip_addr.trim().is_empty() {
                    self.validate_ip_address(ip_addr)?;
                }
            }
        }

        // Validate parameters
        if let Some(validity_years) = request.validity_in_years {
            if validity_years < 1 || validity_years > 10 {
                return Err(ApiError::BadRequest("Certificate validity must be between 1 and 10 years".to_string()));
            }
        }

        // Validate key type and size
        self.validate_key_type_and_size(request.key_type.as_deref(), request.key_size.as_deref())?;

        // Validate hash algorithm
        self.validate_hash_algorithm(request.hash_algorithm.as_deref())?;

        // Validate certificate type
        if let Some(cert_type) = request.cert_type {
            match cert_type {
                CertificateType::Client | CertificateType::Server | CertificateType::SubordinateCA => {},
                _ => return Err(ApiError::BadRequest("Invalid certificate type".to_string())),
            }
        }

        Ok(())
    }

    /// Sanitize certificate name
    fn sanitize_certificate_name(&self, name: &str) -> Result<String, ApiError> {
        if name.len() > 255 {
            return Err(ApiError::BadRequest("Certificate name is too long (maximum 255 characters)".to_string()));
        }

        // Remove dangerous characters
        let mut sanitized = name.to_string();
        sanitized = sanitized.replace("../", "");
        sanitized = sanitized.replace("..\\", "");
        sanitized = sanitized.replace("./", "");
        sanitized = sanitized.replace(".\\", "");

        let dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '[', ']', '{', '}', '\'', '"', '\\', '\n', '\r', '\t'];
        for &ch in &dangerous_chars {
            sanitized = sanitized.replace(ch, "");
        }

        let sanitized = sanitized.trim();
        if sanitized.is_empty() {
            return Err(ApiError::BadRequest("Certificate name cannot be empty after sanitization".to_string()));
        }

        Ok(sanitized.to_string())
    }

    /// Validate DNS name
    fn validate_dns_name(&self, dns_name: &str) -> Result<(), ApiError> {
        if dns_name.len() > 253 {
            return Err(ApiError::BadRequest(format!("DNS name '{}' is too long", dns_name)));
        }

        if dns_name.contains("..") || dns_name.starts_with('.') || dns_name.ends_with('.') {
            return Err(ApiError::BadRequest(format!("Invalid DNS name format: '{}'", dns_name)));
        }

        if !dns_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.') {
            return Err(ApiError::BadRequest(format!("Invalid DNS name '{}'. Only alphanumeric characters, hyphens, and dots are allowed", dns_name)));
        }

        Ok(())
    }

    /// Validate IP address
    fn validate_ip_address(&self, ip: &str) -> Result<(), ApiError> {
        if ip.len() > 45 {
            return Err(ApiError::BadRequest(format!("IP address '{}' is too long", ip)));
        }
        Ok(())
    }

    /// Validate key type and size
    fn validate_key_type_and_size(&self, key_type: Option<&str>, key_size: Option<&str>) -> Result<(), ApiError> {
        let key_type = key_type.unwrap_or("rsa");
        let key_size = key_size.unwrap_or("4096");

        match key_type.to_lowercase().as_str() {
            "rsa" => match key_size {
                "2048" | "3072" | "4096" => Ok(()),
                _ => Err(ApiError::BadRequest(format!("Invalid RSA key size '{}'", key_size))),
            },
            "ecdsa" => match key_size {
                "256" | "384" => Ok(()),
                _ => Err(ApiError::BadRequest(format!("Invalid ECDSA key size '{}'", key_size))),
            },
            _ => Err(ApiError::BadRequest(format!("Invalid key type '{}'", key_type))),
        }
    }

    /// Validate hash algorithm
    fn validate_hash_algorithm(&self, hash_alg: Option<&str>) -> Result<(), ApiError> {
        let hash_alg = hash_alg.unwrap_or("sha256");
        match hash_alg.to_lowercase().as_str() {
            "sha256" | "sha384" | "sha512" => Ok(()),
            _ => Err(ApiError::BadRequest(format!("Invalid hash algorithm '{}'", hash_alg))),
        }
    }

    /// Send certificate notification email
    async fn send_certificate_notification(&self, certificate: &Certificate, user: &User) {
        let mail = MailMessage {
            to: format!("{} <{}>", user.name, user.email),
            username: user.name.clone(),
            certificate: certificate.clone(),
        };

        debug!("Sending certificate notification email");
        let mailer_clone = Arc::clone(&self.mailer);
        tokio::spawn(async move {
            if let Some(mailer) = &mut *mailer_clone.lock().await {
                let _ = mailer.notify_new_certificate(mail).await;
            }
        });
    }
}
