use rocket_okapi::openapi;
use rocket::{delete, get, post, put, State};
use rocket::form::Form;
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::FromForm;
use tokio::io::AsyncReadExt;
use tracing::{trace, debug, info, warn, error};
use openssl::x509::X509;
use openssl::pkey::PKey;
use serde::Serialize;
use schemars::JsonSchema;
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::auth::session_auth::{generate_token, Authenticated, AuthenticatedPrivileged};
use crate::cert::{certificate_pkcs12_to_der, certificate_pkcs12_to_key, certificate_pkcs12_to_pem, generate_crl, generate_ocsp_response, get_password, get_pem, parse_ocsp_request, save_ca, Certificate, CertificateBuilder, CertificateDetails, CRLEntry};
use crate::constants::VAULTLS_VERSION;
use crate::data::api::{CallbackQuery, ChangePasswordRequest, CreateUserCertificateRequest, CreateUserRequest, DownloadResponse, IsSetupResponse, LoginRequest, SetupRequest, SetupFormRequest};
use crate::data::enums::{CertificateFormat, CertificateType, CertificateType::{Client, Server}, PasswordRule, UserRole};
use crate::data::error::ApiError;
use crate::data::objects::{AppState, User, CrlCache, OcspCache};
use crate::notification::mail::{MailMessage, Mailer};
use crate::settings::{FrontendSettings, InnerSettings};


#[openapi(tag = "Setup")]
#[get("/server/version")]
/// Get the current version of the server.
pub(crate) fn version() -> &'static str {
    VAULTLS_VERSION
}

#[derive(Serialize, JsonSchema, Debug)]
pub struct CAModeResponse {
    pub is_root_ca: bool,
    pub mode: String,
    pub description: String,
}

#[openapi(tag = "Setup")]
#[get("/server/ca-mode")]
/// Get the current CA mode (Root CA or Regular CA).
pub(crate) fn get_ca_mode(state: &State<AppState>) -> Json<CAModeResponse> {
    let is_root_ca = state.settings.get_is_root_ca();
    let (mode, description) = if is_root_ca {
        ("root-ca", "Root CA Server: Can only issue subordinate CA certificates")
    } else {
        ("regular-ca", "Regular Certificate Authority: Can issue all certificate types")
    };

    Json(CAModeResponse {
        is_root_ca,
        mode: mode.to_string(),
        description: description.to_string(),
    })
}

#[openapi(tag = "Setup")]
#[get("/server/setup")]
/// Get server setup parameters.
pub(crate) async fn is_setup(
    state: &State<AppState>
) -> Result<Json<IsSetupResponse>, ApiError> {
    let is_setup = state.db.is_setup().await.is_ok();
    let has_password = state.settings.get_password_enabled();
    let oidc_url = state.settings.get_oidc().auth_url.clone();
    Ok(Json(IsSetupResponse {
        setup: is_setup,
        password: has_password,
        oidc: oidc_url
    }))
}

#[openapi(tag = "Setup")]
#[post("/server/setup", format = "json", data = "<setup_req>")]
/// Set up the application with self-signed CA. Only possible if DB is not setup.
pub(crate) async fn setup_json(
    state: &State<AppState>,
    setup_req: Json<SetupRequest>
) -> Result<(), ApiError> {
    setup_common(
        state,
        setup_req.name.clone(),
        setup_req.email.clone(),
        setup_req.ca_name.clone(),
        setup_req.ca_validity_in_years,
        setup_req.password.clone(),
        None,
        None,
        setup_req.key_type.clone(),
        setup_req.key_size.clone(),
        setup_req.hash_algorithm.clone(),
        setup_req.countryName.clone(),
        setup_req.stateOrProvinceName.clone(),
        setup_req.localityName.clone(),
        setup_req.organizationName.clone(),
        setup_req.organizationalUnitName.clone(),
        setup_req.commonName.clone(),
        setup_req.emailAddress.clone(),
        setup_req.is_root_ca,
    ).await
}

#[post("/server/setup/form", data = "<setup_req>")]
/// Set up the application with uploaded CA. Only possible if DB is not setup.
pub(crate) async fn setup_form(
    state: &State<AppState>,
    setup_req: Form<SetupFormRequest<'_>>
) -> Result<(), ApiError> {
    let mut pfx_data = Vec::new();
    let mut reader = setup_req.pfx_file.open().await.map_err(|e| ApiError::Other(format!("Failed to open PFX file: {}", e)))?;
    reader.read_to_end(&mut pfx_data).await.map_err(|e| ApiError::Other(format!("Failed to read PFX file: {}", e)))?;
    setup_common(state, setup_req.name.clone(), setup_req.email.clone(), setup_req.ca_name.clone(), setup_req.ca_validity_in_years, setup_req.password.clone(), Some(pfx_data), setup_req.pfx_password.clone(), setup_req.key_type.clone(), setup_req.key_size.clone(), None, None, None, None, None, None, None, None, setup_req.is_root_ca).await
}

async fn setup_common(
    state: &State<AppState>,
    name: String,
    email: String,
    ca_name: String,
    ca_validity_in_years: u64,
    password: Option<String>,
    pfx_data: Option<Vec<u8>>,
    pfx_password: Option<String>,
    key_type: Option<String>,
    key_size: Option<String>,
    hash_algorithm: Option<String>,
    // DN fields for self-signed CA
    country_name: Option<String>,
    state_or_province_name: Option<String>,
    locality_name: Option<String>,
    organization_name: Option<String>,
    organizational_unit_name: Option<String>,
    common_name: Option<String>,
    email_address: Option<String>,
    // Root CA mode
    is_root_ca: bool
) -> Result<(), ApiError> {
    debug!("Starting setup process for user: {}, email: {}", name, email);

    info!("key_type => {:?}", key_type);
    info!("key_size/curve => {:?}", key_size);
    info!("hash_algorithm => {:?}", hash_algorithm);

    if state.db.is_setup().await.is_ok() {
        warn!("Server is already setup.");
        return Err(ApiError::Other("Server is already set up".to_string()))
    }

    let has_oidc = !state.settings.get_oidc().auth_url.is_empty();
    debug!("OIDC configured: {}", has_oidc);

    if password.is_none() && !has_oidc {
        debug!("Password is required but not provided, and OIDC is not configured");
        return Err(ApiError::Other("Password is required for local login. Please provide a password or configure OIDC.".to_string()))
    }

    let trim_password = password.as_deref().unwrap_or("").trim();
    debug!("Password provided: {}", !trim_password.is_empty());

    let password = match trim_password {
        "" => None,
        _ => Some(trim_password)
    };

    let mut password_hash: Option<String> = None;
    if let Some(password) = password {
        debug!("Setting password authentication enabled");
        state.settings.set_password_enabled(true)?;
        password_hash = Some(Password::new_server_hash(password)?.to_string());
    }

    debug!("Creating user with name: {}, email: {}", name, email);
    let user = User{
        id: -1,
        name: name.clone(),
        email: email.clone(),
        password_hash,
        oidc_id: None,
        role: UserRole::Admin,
    };

    match state.db.insert_user(user).await {
        Ok(_) => debug!("User created successfully"),
        Err(e) => {
            error!("Failed to create user: {}", e);
            return Err(ApiError::Other(format!("Failed to create user: {}", e)))
        }
    }

    let ca = if let Some(pfx_data) = pfx_data {
        debug!("Importing CA from PFX file (size: {} bytes)", pfx_data.len());
        match CertificateBuilder::from_pfx(&pfx_data, pfx_password.as_deref(), Some(&ca_name)) {
            Ok(ca) => {
                debug!("CA imported successfully from PFX");
                ca
            },
            Err(e) => {
                error!("Failed to import CA from PFX: {}", e);
                return Err(ApiError::Other(format!("Failed to import CA from PFX file: {}. Please check that the file is valid and the password is correct.", e)))
            }
        }
    } else {
        debug!("Generating self-signed CA with name: {}", ca_name);
        let mut builder = CertificateBuilder::new_with_ca_and_key_type_size(None, key_type.as_deref(), key_size.as_deref())?
            .set_name(&ca_name)?
            .set_valid_until(ca_validity_in_years)?;

        // Set hash algorithm if provided
        if let Some(hash_alg) = &hash_algorithm {
            builder = builder.set_hash_algorithm(hash_alg)?;
        }

        // Set DN fields if provided
        if let Some(country) = country_name {
            builder = builder.set_country(&country)?;
        }
        if let Some(state) = state_or_province_name {
            builder = builder.set_state(&state)?;
        }
        if let Some(locality) = locality_name {
            builder = builder.set_locality(&locality)?;
        }
        if let Some(org) = organization_name {
            builder = builder.set_organization(&org)?;
        }
        if let Some(org_unit) = organizational_unit_name {
            builder = builder.set_organizational_unit(&org_unit)?;
        }
        if let Some(common) = common_name {
            builder = builder.set_common_name(&common)?;
        }
        if let Some(email) = email_address {
            builder = builder.set_email(&email)?;
        }

        match builder.build_ca() {
            Ok(ca) => {
                debug!("Self-signed CA generated successfully");
                ca
            },
            Err(e) => {
                error!("Failed to generate self-signed CA: {}", e);
                return Err(ApiError::Other(format!("Failed to generate self-signed CA: {}", e)))
            }
        }
    };

    debug!("Saving CA certificate");
    match save_ca(&ca) {
        Ok(_) => debug!("CA saved successfully"),
        Err(e) => {
            error!("Failed to save CA: {}", e);
            return Err(ApiError::Other(format!("Failed to save CA certificate: {}", e)))
        }
    }

    debug!("Inserting CA into database");
    match state.db.insert_ca(ca).await {
        Ok(_) => debug!("CA inserted into database successfully"),
        Err(e) => {
            error!("Failed to insert CA into database: {}", e);
            return Err(ApiError::Other(format!("Failed to save CA to database: {}", e)))
        }
    }

    // Set the Root CA mode in settings
    state.settings.set_is_root_ca(is_root_ca)?;

    if is_root_ca {
        info!("VaulTLS set up as Root CA Server - only subordinate CA certificates can be issued");
    } else {
        info!("VaulTLS set up as regular Certificate Authority - all certificate types available");
    }

    info!("VaulTLS was successfully set up for user: {}", name);
    Ok(())
}

#[openapi(tag = "Authentication")]
#[post("/auth/login", format = "json", data = "<login_req_opt>")]
/// Endpoint to login. Required for most endpoints.
pub(crate) async fn login(
    state: &State<AppState>,
    jar: &CookieJar<'_>,
    login_req_opt: Json<LoginRequest>
) -> Result<(), ApiError> {
    if !state.settings.get_password_enabled() {
        warn!("Password login is disabled.");
        return Err(ApiError::Unauthorized(Some("Password login is disabled".to_string())))
    }
    let user: User = state.db.get_user_by_email(login_req_opt.email.clone()).await.map_err(|_| {
        warn!(user=login_req_opt.email, "Invalid email");
        ApiError::Unauthorized(Some("Invalid credentials".to_string()))
    })?;
    if let Some(password_hash_str) = user.password_hash {
        let password_hash = Password::try_from(password_hash_str.as_str())?;
        if password_hash.verify(&login_req_opt.password) {
            let jwt_key = state.settings.get_jwt_key()?;
            let token = generate_token(&jwt_key, user.id, user.role)?;

            let cookie = Cookie::build(("auth_token", token.clone()))
                .http_only(true)
                .same_site(SameSite::Lax)
                .secure(false);
            jar.add_private(cookie);

            info!(user=user.name, "Successful password-based user login.");

            // Audit log successful login
            if let Err(e) = state.audit.log_authentication(
                Some(user.id),
                Some(user.name.clone()),
                None, // TODO: extract IP from request
                None, // TODO: extract User-Agent from request
                "login",
                true,
                None,
                None,
            ).await {
                warn!("Failed to log authentication audit event: {}", e);
            }

            if let Password::V1(_) = password_hash {
                info!(user=user.name, "Migrating a user' password to V2.");
                let migration_password = Password::new_double_hash(&login_req_opt.password)?;
                state.db.set_user_password(user.id, migration_password).await?;
            }

            return Ok(());
        } else if let Password::V1(hash_string) = password_hash {
            // User tried to supply a hashed password, but has not been migrated yet
            // Require user to supply plaintext password to log in
            return Err(ApiError::Conflict(hash_string.to_string()))
        }
    }
    warn!(user=user.name, "Invalid password");

    // Audit log failed login
    if let Err(e) = state.audit.log_authentication(
        Some(user.id),
        Some(user.name.clone()),
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        "login",
        false,
        Some("Invalid password".to_string()),
        None,
    ).await {
        warn!("Failed to log authentication audit event: {}", e);
    }

    Err(ApiError::Unauthorized(Some("Invalid credentials".to_string())))
}

#[openapi(tag = "Authentication")]
#[post("/auth/change_password", data = "<change_pass_req>")]
/// Endpoint to change password.
pub(crate) async fn change_password(
    state: &State<AppState>,
    change_pass_req: Json<ChangePasswordRequest>,
    authentication: Authenticated
) -> Result<(), ApiError> {
    let user_id = authentication.claims.id;
    let user = state.db.get_user(user_id).await?;
    let password_hash_str = user.password_hash;

    if let Some(password_hash_str) = password_hash_str {
        let password_hash = Password::try_from(password_hash_str.as_str())?;
        if let Some(ref old_password) = change_pass_req.old_password {
            if !password_hash.verify(old_password) {
                warn!(user=user.name, "Password Change: Old password is incorrect");
                return Err(ApiError::BadRequest("Old password is incorrect".to_string()))
            }
        } else {
            warn!(user=user.name, "Password Change: Old password is required");
            return Err(ApiError::BadRequest("Old password is required".to_string()))
        }
    }

    let password_hash = Password::new_server_hash(&change_pass_req.new_password)?;
    state.db.set_user_password(user_id, password_hash).await?;
    // todo unset

    info!(user=user.name, "Password Change: Success");

    Ok(())
}

#[openapi(tag = "Authentication")]
#[post("/auth/logout")]
/// Endpoint to logout.
pub(crate) async fn logout(
    jar: &CookieJar<'_>,
    authentication: Authenticated,
    state: &State<AppState>
) -> Result<(), ApiError> {
    jar.remove_private(Cookie::build(("name", "auth_token")));

    // Audit log user logout
    if let Err(e) = state.audit.log_authentication(
        Some(authentication.claims.id), // User logging out
        None, // TODO: get actual user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        "logout",
        true,
        None,
        Some(serde_json::json!({
            "logout_successful": true,
            "session_ended": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            "logout_timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        }).to_string()),
    ).await {
        warn!("Failed to log authentication logout audit event: {}", e);
    }

    Ok(())
}

#[openapi(tag = "Authentication")]
#[get("/auth/oidc/login")]
/// Endpoint to initiate OIDC login.
pub(crate) async fn oidc_login(
    state: &State<AppState>,
) -> Result<Redirect, ApiError> {
    let mut oidc_option = state.oidc.lock().await;

    match &mut *oidc_option {
        Some(oidc) => {
            let url = oidc.generate_oidc_url().await?;
            debug!(url=?url, "Redirecting to OIDC login URL");
            Ok(Redirect::to(url.to_string()))

        }
        None => {
            warn!("A user tried to login with OIDC, but OIDC is not configured.");
            Err(ApiError::BadRequest("OIDC not configured".to_string()))
        },
    }
}

#[openapi(tag = "Authentication")]
#[get("/auth/oidc/callback?<response..>")]
/// Endpoint to handle OIDC callback.
pub(crate) async fn oidc_callback(
    state: &State<AppState>,
    jar: &CookieJar<'_>,
    response: CallbackQuery
) -> Result<Redirect, ApiError> {
    let mut oidc_option = state.oidc.lock().await;

    match &mut *oidc_option {
        Some(oidc) => {
            trace!("Verifying OIDC authentication code.");
            let mut user = oidc.verify_auth_code(response.code.to_string(), response.state.to_string()).await?;

            user = state.db.register_oidc_user(user).await?;

            let jwt_key = state.settings.get_jwt_key()?;
            let token = generate_token(&jwt_key, user.id, user.role)?;

            let auth_cookie = Cookie::build(("auth_token", token))
                .http_only(true)
                .same_site(SameSite::None)
                .secure(false);
            jar.add_private(auth_cookie);

            info!(user=user.name, "Successful oidc-based user login");

            Ok(Redirect::to("/overview?oidc=success"))
        }
        None => { Err(ApiError::BadRequest("OIDC not configured".to_string())) },
    }
}

#[openapi(tag = "Authentication")]
#[get("/auth/me")]
/// Endpoint to get the current user. Used to know role of user.
pub(crate) async fn get_current_user(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<User>, ApiError> {
    let user = state.db.get_user(authentication.claims.id).await?;
    Ok(Json(user))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/cert")]
/// Get all certificates. If admin all certificates are returned, otherwise only certificates owned by the user. Requires authentication.
pub(crate) async fn get_certificates(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<Vec<Certificate>>, ApiError> {
    let user_id = match authentication.claims.role {
        UserRole::User => Some(authentication.claims.id),
        UserRole::Admin => None
    };
    let certificates = state.db.get_all_user_cert(user_id).await?;
    Ok(Json(certificates))
}

#[openapi(tag = "Certificates")]
#[post("/certificates/cert", format = "json", data = "<payload>")]
/// Create a new certificate. Requires admin role.
pub(crate) async fn create_user_certificate(
    state: &State<AppState>,
    payload: Json<CreateUserCertificateRequest>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Certificate>, ApiError> {
    debug!(cert_name=?payload.cert_name, "Creating certificate");

    let password_rule = state.settings.get_password_rule();
    let use_random_password = if password_rule == PasswordRule::System
        || (password_rule == PasswordRule::Required
            && payload.pkcs12_password.as_deref().unwrap_or("").trim().is_empty()) {
        debug!(cert_name=?payload.cert_name, "Using system-supplied password");
        true
    } else {
        debug!(cert_name=?payload.cert_name, "Using user-supplied password");
        payload.system_generated_password
    };

    // Use specified CA or default to current (first) CA
    let ca_id = payload.ca_id.unwrap_or(0);
    let ca = if ca_id > 0 {
        state.db.get_ca(ca_id).await?
    } else {
        state.db.get_current_ca().await?
    };

    let pkcs12_password = get_password(use_random_password, &payload.pkcs12_password);

    // Get CRL and OCSP settings
    let crl_settings = state.settings.get_crl();
    let ocsp_settings = state.settings.get_ocsp();

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

    // Check if we're in Root CA mode and restrict certificate types
    let is_root_ca = state.settings.get_is_root_ca();
    if is_root_ca && payload.cert_type.unwrap_or_default() != CertificateType::SubordinateCA {
        return Err(ApiError::BadRequest("Root CA Server can only issue subordinate CA certificates".to_string()));
    }

    let cert_builder = CertificateBuilder::new_with_ca(Some(&ca))?
        .set_name(&payload.cert_name)?
        .set_valid_until(payload.validity_in_years.unwrap_or(1))?
        .set_renew_method(payload.renew_method.unwrap_or_default())?
        .set_pkcs12_password(&pkcs12_password)?
        .set_ca(&ca)?
        .set_user_id(payload.user_id)?;
    let mut cert = match payload.cert_type.unwrap_or_default() {
        CertificateType::Client => {
            let user = state.db.get_user(payload.user_id).await?;
            cert_builder
                .set_email_san(&user.email)?
                .build_common_with_extensions(Client, crl_url, ocsp_url)?
        }
        CertificateType::Server => {
            let dns = payload.dns_names.clone().unwrap_or_default();
            cert_builder
                .set_dns_san(&dns)?
                .build_common_with_extensions(Server, crl_url, ocsp_url)?
        }
        CertificateType::SubordinateCA => {
            // For subordinate CA, we need to create a CA certificate signed by the parent CA
            cert_builder.build_subordinate_ca()?
        }
    };

    cert = state.db.insert_user_cert(cert).await?;

    info!(cert=cert.name, "New certificate created.");
    trace!("{:?}", cert);

    // Audit log certificate creation
    if let Err(e) = state.audit.log_certificate_operation(
        Some(_authentication._claims.id), // Admin ID doing the operation
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        cert.id,
        &cert.name,
        "create",
        true,
        None,
        Some(serde_json::json!({
            "certificate_type": payload.cert_type,
            "user_id": payload.user_id,
            "validity_in_years": payload.validity_in_years,
            "ca_id": ca_id
        })),
        None,
        None,
    ).await {
        warn!("Failed to log certificate creation audit event: {}", e);
    }

    if Some(true) == payload.notify_user {
        let user = state.db.get_user(payload.user_id).await?;
        let mail = MailMessage{
            to: format!("{} <{}>", user.name, user.email),
            username: user.name,
            certificate: cert.clone()
        };

        debug!(mail=?mail, "Sending mail notification");

        let mailer = state.mailer.clone();
        tokio::spawn(async move {
            if let Some(mailer) = &mut *mailer.lock().await {
                let _ = mailer.notify_new_certificate(mail).await;
            }
        });
    }

    Ok(Json(cert))
}

#[openapi(tag = "Certificates")]
#[post("/certificates/ca/new", format = "json", data = "<payload>")]
/// Create a new self-signed CA certificate. Requires admin role.
pub(crate) async fn create_self_signed_ca(
    state: &State<AppState>,
    payload: Json<CreateCASelfSignedRequest>,
    authentication: AuthenticatedPrivileged
) -> Result<Json<i64>, ApiError> {
    debug!(ca_name=?payload.name, validity_years=?payload.validity_in_years, "Creating self-signed CA");

    let mut builder = CertificateBuilder::new_with_ca_and_key_type_size(None, payload.key_type.as_deref(), payload.key_size.as_deref())?
        .set_name(&payload.name)?
        .set_valid_until(payload.validity_in_years)?;

    // Set advanced PKI extensions if provided
    if let Some(oid) = &payload.certificate_policies_oid {
        builder = builder.set_certificate_policies_oid(oid)?;
    }
    if let Some(cps_url) = &payload.certificate_policies_cps_url {
        builder = builder.set_certificate_policies_cps_url(cps_url)?;
    }

    // Set DN fields if provided
    if let Some(country) = &payload.country_name {
        builder = builder.set_country(country)?;
    }
    if let Some(state) = &payload.state_or_province_name {
        builder = builder.set_state(state)?;
    }
    if let Some(locality) = &payload.locality_name {
        builder = builder.set_locality(locality)?;
    }
    if let Some(org) = &payload.organization_name {
        builder = builder.set_organization(org)?;
    }
    if let Some(org_unit) = &payload.organizational_unit_name {
        builder = builder.set_organizational_unit(org_unit)?;
    }
    if let Some(common) = &payload.common_name {
        builder = builder.set_common_name(common)?;
    }
    if let Some(email) = &payload.email_address {
        builder = builder.set_email(email)?;
    }

    let mut ca = builder.build_ca()?;
    ca.can_create_subordinate_ca = payload.can_create_subordinate_ca;

    let ca_id = ca.id;
    // Extract CA name from certificate subject
    let ca_cert = X509::from_der(&ca.cert)?;
    let subject_name = ca_cert.subject_name();
    let ca_name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13) // CN
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let ca = state.db.insert_ca(ca).await?;
    info!(ca=?ca, "Self-signed CA created");

    // Audit log CA creation
    if let Err(e) = state.audit.log_ca_operation(
        Some(authentication._claims.id), // Admin doing the operation
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        ca,
        &ca_name,
        "create",
        true,
        None,
        None,
    ).await {
        warn!("Failed to log CA creation audit event: {}", e);
    }

    Ok(Json(ca_id))
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct CreateCASelfSignedRequest {
    pub name: String,
    pub validity_in_years: u64,
    #[serde(default)]
    pub key_type: Option<String>,
    #[serde(default)]
    pub key_size: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub country_name: Option<String>,
    #[serde(default)]
    pub state_or_province_name: Option<String>,
    #[serde(default)]
    pub locality_name: Option<String>,
    #[serde(default)]
    pub organization_name: Option<String>,
    #[serde(default)]
    pub organizational_unit_name: Option<String>,
    #[serde(default)]
    pub common_name: Option<String>,
    #[serde(default)]
    pub email_address: Option<String>,
    #[serde(default)]
    pub can_create_subordinate_ca: bool,
    #[serde(default)]
    pub certificate_policies_oid: Option<String>,
    #[serde(default)]
    pub certificate_policies_cps_url: Option<String>,
}


#[openapi(tag = "Certificates")]
#[post("/certificates/ca/import", data = "<upload>")]
/// Import a CA certificate from PKCS#12 file. Requires admin role.
pub(crate) async fn import_ca_from_file(
    state: &State<AppState>,
    upload: Form<ImportCARequest<'_>>,
    authentication: AuthenticatedPrivileged
) -> Result<Json<i64>, ApiError> {
    debug!("Importing CA from PKCS#12 file");

    let mut buffer = Vec::new();
    let file = upload.file.open().await.map_err(|e| ApiError::Other(format!("Failed to open file: {}", e)))?;
    let mut reader = tokio::io::BufReader::new(file);
    reader.read_to_end(&mut buffer).await.map_err(|e| ApiError::Other(format!("Failed to read file: {}", e)))?;

    let ca = CertificateBuilder::from_pfx(&buffer, upload.password.as_deref(), upload.name.as_deref())?;
    let ca_id = ca.id;
    // Extract CA name from certificate subject
    let ca_cert = X509::from_der(&ca.cert)?;
    let subject_name = ca_cert.subject_name();
    let ca_name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13) // CN
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let ca = state.db.insert_ca(ca).await?;

    info!(ca=?ca, "CA imported from PKCS#12 file");

    // Audit log CA import
    if let Err(e) = state.audit.log_ca_operation(
        Some(authentication._claims.id), // Admin doing the import
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        ca,
        &ca_name,
        "import",
        true,
        None,
        None,
    ).await {
        warn!("Failed to log CA import audit event: {}", e);
    }

    Ok(Json(ca_id))
}

#[derive(FromForm, JsonSchema, Debug)]
pub struct ImportCARequest<'r> {
    pub password: Option<String>,
    pub name: Option<String>,
    #[schemars(skip)]
    pub file: rocket::fs::TempFile<'r>,
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/download")]
/// Download the current CA certificate.
pub(crate) async fn download_ca(
    state: &State<AppState>
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_current_ca().await?;
    let pem = get_pem(&ca)?;
    Ok(DownloadResponse::new(pem, "ca_certificate.pem"))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/<id>/download")]
/// Download a specific CA certificate by ID.
pub(crate) async fn download_ca_by_id(
    state: &State<AppState>,
    id: i64,
    _authentication: Authenticated
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_ca(id).await?;
    let pem = get_pem(&ca)?;
    Ok(DownloadResponse::new(pem, &format!("ca_certificate_{}.pem", ca.id)))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/<id>/download_key")]
/// Download a specific CA certificate and private key pair by ID.
/// Requires admin role.
pub(crate) async fn download_ca_key_pair_by_id(
    state: &State<AppState>,
    id: i64,
    authentication: AuthenticatedPrivileged
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_ca(id).await?;

    // Get certificate PEM
    let cert_pem = get_pem(&ca)?;

    // Get private key PEM
    let private_key = PKey::private_key_from_der(&ca.key)
        .map_err(|e| ApiError::Other(format!("Failed to load CA private key: {}", e)))?;
    let key_pem = private_key.private_key_to_pem_pkcs8()
        .map_err(|e| ApiError::Other(format!("Failed to convert private key to PEM: {}", e)))?;

    // Combine certificate and private key
    let mut combined_pem = Vec::new();
    combined_pem.extend(cert_pem);
    combined_pem.extend(b"\n");
    combined_pem.extend(key_pem);

    // Extract CA name from certificate subject
    let ca_cert = X509::from_der(&ca.cert)?;
    let subject_name = ca_cert.subject_name();
    let ca_name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13) // CN
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Audit log CA private key download - HIGH SECURITY RISK
    if let Err(e) = state.audit.log_ca_operation(
        Some(authentication._claims.id), // Admin downloading the keys
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        ca.id,
        &ca_name,
        "download_private_key",
        true,
        Some(serde_json::json!({
            "security_risk": "HIGH",
            "operation": "CA private key exported",
            "exported_by": authentication._claims.id,
            "export_timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        }).to_string()),
        None,
    ).await {
        warn!("Failed to log CA private key download audit event: {}", e);
    }

    Ok(DownloadResponse::new(combined_pem, &format!("ca_certificate_and_key_{}.pem", ca.id)))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/download_key")]
/// Download the current CA certificate and private key pair in PEM format.
/// Requires admin role.
pub(crate) async fn download_ca_key_pair(
    state: &State<AppState>,
    authentication: AuthenticatedPrivileged
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_current_ca().await?;

    // Get certificate PEM
    let cert_pem = get_pem(&ca)?;

    // Get private key PEM
    let private_key = PKey::private_key_from_der(&ca.key)
        .map_err(|e| ApiError::Other(format!("Failed to load CA private key: {}", e)))?;
    let key_pem = private_key.private_key_to_pem_pkcs8()
        .map_err(|e| ApiError::Other(format!("Failed to convert private key to PEM: {}", e)))?;

    // Combine certificate and private key
    let mut combined_pem = Vec::new();
    combined_pem.extend(cert_pem);
    combined_pem.extend(b"\n");
    combined_pem.extend(key_pem);

    // Audit log CA private key download - HIGH SECURITY RISK
    if let Err(e) = state.audit.log_ca_operation(
        Some(authentication._claims.id), // Admin downloading the keys
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        ca.id,
        "Unknown", // TODO: Extract CA name from certificate
        "download_private_key",
        true,
        Some(serde_json::json!({
            "security_risk": "HIGH",
            "operation": "CA private key exported",
            "exported_by": authentication._claims.id,
            "export_timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        }).to_string()),
        None,
    ).await {
        warn!("Failed to log CA private key download audit event: {}", e);
    }

    Ok(DownloadResponse::new(combined_pem, "ca_certificate_and_key.pem"))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/list")]
/// Get all CA certificates. Requires authentication.
pub(crate) async fn get_ca_list(
    state: &State<AppState>,
    _authentication: Authenticated
) -> Result<Json<Vec<CADetails>>, ApiError> {
    let cas = state.db.get_all_ca().await?;
    let mut ca_details = Vec::new();

    for ca in cas {
        let cert = X509::from_der(&ca.cert)?;

        // Extract certificate details
        let subject_name = cert.subject_name();
        let issuer_name = cert.issuer_name();
        let serial = cert.serial_number();

        // Get key information
        let public_key = cert.public_key()?;
        let key_size = if public_key.rsa().is_ok() {
            format!("RSA {}", public_key.rsa().unwrap().size() * 8)
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

        // Use the creation_source field to determine if CA is self-signed or imported
        // 0 = self-signed (system generated), 1 = imported (user uploaded)
        let is_self_signed = ca.creation_source == 0;

        // Get certificate name from subject
        let name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13) // CN
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        // Convert to PEM
        let pem = get_pem(&ca)?;
        let certificate_pem = String::from_utf8(pem)
            .map_err(|e| ApiError::Other(format!("Failed to convert certificate to string: {}", e)))?;

        // Extract chain information
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
                                subject: format!("{:?}", chain_subject),
                                issuer: format!("{:?}", chain_issuer),
                                serial_number,
                                is_end_entity: index == 0, // First certificate in chain is end-entity
                            });
                        }
                        Err(e) => {
                            warn!("Failed to get serial number for certificate {} in chain: {}", index + 1, e);
                            // Add entry with invalid serial
                            chain_certificates.push(CertificateChainInfo {
                                subject: format!("{:?}", chain_subject),
                                issuer: format!("{:?}", chain_issuer),
                                serial_number: "Invalid".to_string(),
                                is_end_entity: index == 0,
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse certificate {} in chain: {}", index + 1, e);
                    // Add placeholder entry for failed certificate
                    chain_certificates.push(CertificateChainInfo {
                        subject: format!("Certificate {}: Failed to parse - {:?}", index + 1, e),
                        issuer: "Unknown".to_string(),
                        serial_number: "Unknown".to_string(),
                        is_end_entity: index == 0,
                    });
                }
            }
        }

        // If no certificates were successfully parsed, but we have a raw cert, add the main CA info as fallback
        if chain_certificates.is_empty() && chain_length > 0 {
            warn!("All certificates failed to parse, adding fallback info for main CA certificate");
            // Try to parse the main certificate
            if let Ok(main_cert) = X509::from_der(&ca.cert) {
                let main_subject = main_cert.subject_name();
                let main_issuer = main_cert.issuer_name();
                match main_cert.serial_number().to_bn() {
                    Ok(serial_bn) => {
                        let serial_number = serial_bn.to_hex_str()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|_| "Invalid".to_string());
                        chain_certificates.push(CertificateChainInfo {
                            subject: format!("{:?}", main_subject),
                            issuer: format!("{:?}", main_issuer),
                            serial_number,
                            is_end_entity: true,
                        });
                    }
                    Err(e) => warn!("Failed to parse main CA certificate: {}", e),
                }
            }
        }

        // Format subject and issuer as proper DN strings
        let subject = format_subject_name(subject_name);
        let issuer = format_subject_name(issuer_name);

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
        };

        ca_details.push(ca_detail);
    }

    Ok(Json(ca_details))
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/ca/<id>")]
/// Delete a CA certificate. Requires admin role.
pub(crate) async fn delete_ca(
    state: &State<AppState>,
    id: i64,
    authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    // Get CA details before deletion for audit logging
    let ca_to_delete = state.db.get_ca(id).await.map_err(|_| ApiError::NotFound(Some("CA not found".to_string())))?;

    // Check if this CA is being used by any certificates
    // Note: This is a simplified check; in production you might want more comprehensive validation

    // TODO: Add logic to check if CA is referenced by any user certificates
    // For now, we'll allow deletion but this could break existing certificates

    state.db.delete_ca(id).await?;
    info!(ca_id=id, "CA deleted");

    // Extract CA name from certificate subject for audit logging
    let ca_cert = X509::from_der(&ca_to_delete.cert)?;
    let subject_name = ca_cert.subject_name();
    let ca_name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13) // CN
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Audit log CA deletion
    if let Err(e) = state.audit.log_ca_operation(
        Some(authentication._claims.id), // Admin doing the deletion
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        id,
        &ca_name,
        "delete",
        true,
        Some(serde_json::json!({
            "creation_source": ca_to_delete.creation_source,
            "created_on": ca_to_delete.created_on,
            "valid_until": ca_to_delete.valid_until
        }).to_string()),
        None,
    ).await {
        warn!("Failed to log CA deletion audit event: {}", e);
    }

    Ok(())
}

#[derive(Serialize, JsonSchema, Debug)]
pub struct CertificateChainInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub is_end_entity: bool,
}

#[derive(Serialize, JsonSchema, Debug)]
pub struct CADetails {
    pub id: i64,
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub serial_number: String,
    pub key_size: String,
    pub signature_algorithm: String,
    pub is_self_signed: bool,
    pub certificate_pem: String,
    pub chain_length: usize,
    pub chain_certificates: Vec<CertificateChainInfo>,
    pub can_create_subordinate_ca: bool,
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/details")]
/// Get detailed information about the current CA certificate.
pub(crate) async fn get_ca_details(
    state: &State<AppState>
) -> Result<Json<CADetails>, ApiError> {
    let ca = state.db.get_current_ca().await?;
    let cert = X509::from_der(&ca.cert)?;

    // Extract certificate details
    let subject_name = cert.subject_name();
    let issuer_name = cert.issuer_name();
    let serial = cert.serial_number();

    // Get key information
    let public_key = cert.public_key()?;
    let key_size = if public_key.rsa().is_ok() {
        format!("RSA {}", public_key.rsa().unwrap().size() * 8)
    } else if public_key.ec_key().is_ok() {
        "ECDSA P-256".to_string()
    } else {
        "Unknown".to_string()
    };

    // Get signature algorithm
    let sig_alg_obj = cert.signature_algorithm().object();
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

    // Use the creation_source field to determine if CA is self-signed or imported
    // 0 = self-signed (system generated), 1 = imported (user uploaded)
    let is_self_signed = ca.creation_source == 0;

    // Get certificate name from subject
    let name = subject_name.entries().find(|e| e.object().nid().as_raw() == 13) // CN
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Convert to PEM
    let pem = get_pem(&ca)?;
    let certificate_pem = String::from_utf8(pem)
        .map_err(|e| ApiError::Other(format!("Failed to convert certificate to string: {}", e)))?;

        // Extract chain information
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
                                subject: format!("{:?}", chain_subject),
                                issuer: format!("{:?}", chain_issuer),
                                serial_number,
                                is_end_entity: index == 0, // First certificate in chain is end-entity
                            });
                        }
                        Err(e) => {
                            warn!("Failed to get serial number for certificate {} in chain: {}", index + 1, e);
                            // Add entry with invalid serial
                            chain_certificates.push(CertificateChainInfo {
                                subject: format!("{:?}", chain_subject),
                                issuer: format!("{:?}", chain_issuer),
                                serial_number: "Invalid".to_string(),
                                is_end_entity: index == 0,
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse certificate {} in chain: {}", index + 1, e);
                    // Add placeholder entry for failed certificate
                    chain_certificates.push(CertificateChainInfo {
                        subject: format!("Certificate {}: Failed to parse - {:?}", index + 1, e),
                        issuer: "Unknown".to_string(),
                        serial_number: "Unknown".to_string(),
                        is_end_entity: index == 0,
                    });
                }
            }
        }

    let ca_details = CADetails {
        id: ca.id,
        name,
        subject: format_subject_name(subject_name),
        issuer: format_subject_name(issuer_name),
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
    };

    Ok(Json(ca_details))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/cert/<id>/download?<format>")]
/// Download a user-owned certificate. Requires authentication.
/// Query parameters:
/// * format: Certificate format (pkcs12, pem, der, pem_key). Default: pkcs12
pub(crate) async fn download_certificate(
    state: &State<AppState>,
    id: i64,
    format: Option<&str>,
    authentication: Authenticated
) -> Result<DownloadResponse, ApiError> {
    let (user_id, name, pkcs12) = state.db.get_user_cert_pkcs12(id).await?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }

    let cert_format = match format {
        Some(fmt) => CertificateFormat::from_str(fmt).map_err(|_| ApiError::BadRequest("Invalid format parameter. Supported formats: pkcs12, pem, der, pem_key".to_string()))?,
        None => CertificateFormat::PKCS12,
    };

    let (content, filename) = match cert_format {
        CertificateFormat::PKCS12 => (pkcs12, format!("{}.{}", name, cert_format.extension())),
        CertificateFormat::PEM => {
            let cert = state.db.get_user_cert_by_id(id).await?;
            let pem = certificate_pkcs12_to_pem(&cert)?;
            (pem, format!("{}.{}", name, cert_format.extension()))
        },
        CertificateFormat::DER => {
            let cert = state.db.get_user_cert_by_id(id).await?;
            let der = certificate_pkcs12_to_der(&cert)?;
            (der, format!("{}.{}", name, cert_format.extension()))
        },
        CertificateFormat::PemKey => {
            let cert = state.db.get_user_cert_by_id(id).await?;
            let cert_pem = certificate_pkcs12_to_pem(&cert)?;
            let cert_key = certificate_pkcs12_to_key(&cert)?;

            // Create ZIP file containing both certificate and key
            use std::io::Write;
            let mut zip_buffer = Vec::new();
            {
                let mut zip_writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buffer));

                // Add certificate file
                zip_writer.start_file::<_, ()>(format!("{}.pem", name), Default::default())?;
                zip_writer.write_all(&cert_pem)?;

                // Add private key file
                zip_writer.start_file::<_, ()>(format!("{}.key", name), Default::default())?;
                zip_writer.write_all(&cert_key)?;
            }

            (zip_buffer, format!("{}.{}", name, cert_format.extension()))
        },
    };

    Ok(DownloadResponse::new(content, &filename))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/cert/<id>/password")]
/// Fetch the password for a user-owned certificate. Requires authentication.
pub(crate) async fn fetch_certificate_password(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<Json<String>, ApiError> {
    let (user_id, pkcs12_password) = state.db.get_user_cert_pkcs12_password(id).await?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    Ok(Json(pkcs12_password))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/cert/<id>/details")]
/// Get detailed information about a user certificate. Requires authentication.
pub(crate) async fn get_certificate_details(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<Json<CertificateDetails>, ApiError> {
    let (user_id, name, created_on, valid_until, pkcs12, pkcs12_password, certificate_type, renew_method, ca_id) = state.db.get_user_cert(id).await?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin {
        return Err(ApiError::Forbidden(None));
    }

    let cert = Certificate {
        id,
        name,
        created_on,
        valid_until,
        certificate_type,
        user_id,
        renew_method,
        pkcs12,
        pkcs12_password,
        ca_id,
        is_revoked: false, // This will be determined by the database query
        revoked_on: None,
        revoked_reason: None,
        revoked_by: None,
    };

    let details = crate::cert::get_certificate_details(&cert)?;
    Ok(Json(details))
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/cert/<id>")]
/// Delete a user-owned certificate. Requires admin role.
pub(crate) async fn delete_user_cert(
    state: &State<AppState>,
    id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    state.db.delete_user_cert(id).await?;
    Ok(())
}

#[openapi(tag = "Settings")]
#[get("/settings")]
/// Fetch application settings. Requires admin role.
pub(crate) async fn fetch_settings(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<FrontendSettings>, ApiError> {
    let frontend_settings = FrontendSettings(state.settings.clone());
    Ok(Json(frontend_settings))
}

#[openapi(tag = "Settings")]
#[put("/settings", format = "json", data = "<payload>")]
/// Update application settings. Requires admin role.
pub(crate) async fn update_settings(
    state: &State<AppState>,
    payload: Json<InnerSettings>,
    authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    let mut oidc = state.oidc.lock().await;

    // Capture settings before changes for audit logging
    let old_frontend_settings = FrontendSettings(state.settings.clone());

    state.settings.set_settings(&payload)?;

    let oidc_settings = state.settings.get_oidc();
    if oidc_settings.is_valid() {
        *oidc = OidcAuth::new(&oidc_settings).await.ok()
    } else {
        *oidc = None;
    }

    match oidc.is_some() {
        true => info!("OIDC is active."),
        false => info!("OIDC is inactive.")
    }

    let mut mailer = state.mailer.lock().await;
    let mail_settings = state.settings.get_mail();
    if mail_settings.is_valid() {
        *mailer = Mailer::new(&mail_settings, &state.settings.get_vaultls_url()).await.ok()
    } else {
        *mailer = None;
    }

    match mailer.is_some() {
        true => info!("Mail notifications are active."),
        false => info!("Mail notifications are inactive.")
    }

    info!("Settings updated.");

    // Audit log settings change with before/after comparison
    if let Err(e) = state.audit.log_settings_change(
        Some(authentication._claims.id), // Admin making the change
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        "update_settings", // Action
        true, // Success
        Some(serde_json::json!({
            "old_settings": old_frontend_settings,
            "new_settings": FrontendSettings(state.settings.clone()),
            "modified_by": authentication._claims.id,
            "change_timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        })),
        Some(serde_json::json!({
            "settings_updated": "Application configuration modified",
            "admin_id": authentication._claims.id
        })),
        None, // session_id
        None, // additional_details
    ).await {
        warn!("Failed to log settings change audit event: {}", e);
    }

    Ok(())
}

#[openapi(tag = "Users")]
#[get("/users")]
/// Returns a list of all users. Requires admin role.
pub(crate) async fn get_users(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Vec<User>>, ApiError> {
    let users = state.db.get_all_user().await?;
    Ok(Json(users))
}

#[openapi(tag = "Users")]
#[post("/users", format = "json", data = "<payload>")]
/// Create a new user. Requires admin role.
pub(crate) async fn create_user(
    state: &State<AppState>,
    payload: Json<CreateUserRequest>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<i64>, ApiError> {
    let trim_password = payload.password.as_deref().unwrap_or("").trim();

    let password = match trim_password {
        "" => None,
        _ => Some(trim_password)
    };

    let password_hash: Option<String> = match password {
        Some(p) => Some(Password::new_server_hash(p)?.to_string()),
        None => None,
    };

    let mut user = User{
        id: -1,
        name: payload.user_name.to_string(),
        email: payload.user_email.to_string(),
        password_hash,
        oidc_id: None,
        role: payload.role
    };

    let user_id = user.id;
    let user_name = user.name.clone();
    user = state.db.insert_user(user).await?;

    info!(user=?user, "User created.");
    trace!("{:?}", user);

    // Audit log user creation
    if let Err(e) = state.audit.log_user_operation(
        Some(user_id), // user_id will be -1 for the creator, but we can pass None or actual admin ID
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        user.id,
        &user.name,
        "create",
        true,
        None,
        Some(serde_json::json!({
            "role": payload.role,
            "email": payload.user_email
        })),
        None,
        None,
    ).await {
        warn!("Failed to log user creation audit event: {}", e);
    }

    Ok(Json(user.id))
}

#[openapi(tag = "Users")]
#[put("/users/<id>", format = "json", data = "<payload>")]
/// Update a user. Requires admin role.
pub(crate) async fn update_user(
    state: &State<AppState>,
    id: i64,
    payload: Json<User>,
    authentication: Authenticated
) -> Result<(), ApiError> {
    if authentication.claims.id != id && authentication.claims.role != UserRole::Admin {
        return Err(ApiError::Forbidden(None))
    }
    if authentication.claims.role == UserRole::User
        && payload.role == UserRole::Admin {
        return Err(ApiError::Forbidden(None))
    }

    // Get current user for before/after comparison
    let old_user = state.db.get_user(id).await?;

    let user = User {
        id,
        ..payload.into_inner()
    };
    state.db.update_user(user.clone()).await?;

    info!(user=?user, "User updated.");
    trace!("{:?}", user);

    // Audit log user profile update with role change detection
    let role_changed = old_user.role != user.role;
    if let Err(e) = state.audit.log_user_operation(
        Some(authentication.claims.id), // Admin or user doing the update
        None, // TODO: get actual user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        id,
        &user.name,
        "update",
        true,
        Some(serde_json::json!({
            "old_profile": {
                "name": old_user.name,
                "email": old_user.email,
                "role": old_user.role
            }
        })),
        Some(serde_json::json!({
            "new_profile": {
                "name": user.name,
                "email": user.email,
                "role": user.role
            },
            "changes_detected": {
                "role_changed": role_changed,
                "name_changed": old_user.name != user.name,
                "email_changed": old_user.email != user.email,
                "updated_by": authentication.claims.id
            }
        })),
        None,
        Some(if role_changed {
            serde_json::json!({
                "security_event": "Role change detected",
                "old_role": old_user.role,
                "new_role": user.role,
                "changed_by": authentication.claims.id,
                "change_timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            }).to_string()
        } else {
            serde_json::json!({
                "profile_update": "User profile modified",
                "updated_by": authentication.claims.id,
                "update_timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            }).to_string()
        }),
    ).await {
        warn!("Failed to log user profile update audit event: {}", e);
    }

    Ok(())
}

#[openapi(tag = "Users")]
#[delete("/users/<id>")]
/// Delete a user. Requires admin role.
pub(crate) async fn delete_user(
    state: &State<AppState>,
    id: i64,
    authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    // Get user details before deletion for audit logging
    let user_to_delete = state.db.get_user(id).await.map_err(|_| ApiError::NotFound(Some("User not found".to_string())))?;

    state.db.delete_user(id).await?;

    info!(user=?id, "User deleted.");

    // Audit log user deletion
    if let Err(e) = state.audit.log_user_operation(
        Some(authentication._claims.id), // Admin doing the deletion
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        id,
        &user_to_delete.name,
        "delete",
        true,
        Some(serde_json::json!({
            "role": user_to_delete.role,
            "email": user_to_delete.email
        })),
        None,
        None,
        None,
    ).await {
        warn!("Failed to log user deletion audit event: {}", e);
    }

    Ok(())
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct RevokeCertificateRequest {
    pub reason: crate::data::enums::CertificateRevocationReason,
    pub notify_user: Option<bool>,
}

#[derive(Serialize, JsonSchema, Debug)]
pub struct RevocationHistoryEntry {
    pub id: i64,
    pub certificate_id: i64,
    pub certificate_name: String,
    pub revocation_date: i64,
    pub revocation_reason: crate::data::enums::CertificateRevocationReason,
    pub revoked_by_user_id: Option<i64>,
}

#[openapi(tag = "Certificates")]
#[post("/certificates/cert/<id>/revoke", format = "json", data = "<payload>")]
/// Revoke a certificate. Requires admin role.
/// This will mark the certificate as revoked in the database and update the CRL.
/// The certificate will be included in future CRL downloads and OCSP responses will show it as revoked.
///
/// Example request:
/// ```json
/// {
///   "reason": 1,
///   "notify_user": true
/// }
/// ```
///
/// Revocation reasons:
/// - 0: Unspecified
/// - 1: Key Compromise
/// - 2: CA Compromise
/// - 3: Affiliation Changed
/// - 4: Superseded
/// - 5: Cessation of Operation
/// - 6: Certificate Hold
/// - 8: Remove from CRL
/// - 9: Privilege Withdrawn
/// - 10: AA Compromise
pub(crate) async fn revoke_certificate(
    state: &State<AppState>,
    id: i64,
    payload: Json<RevokeCertificateRequest>,
    authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    debug!(cert_id=id, reason=?payload.reason, "Revoking certificate");

    // Check if certificate exists and get its details
    let cert = state.db.get_user_cert_by_id(id).await
        .map_err(|_| ApiError::NotFound(Some("Certificate not found".to_string())))?;

    // Check if certificate is already revoked
    if state.db.is_certificate_revoked(id).await? {
        return Err(ApiError::BadRequest("Certificate is already revoked".to_string()));
    }

    // Revoke the certificate
    state.db.revoke_certificate(id, payload.reason, Some(authentication._claims.id)).await?;

    // Clear CRL cache since revocation list has changed
    let mut cache = state.crl_cache.lock().await;
    *cache = None;
    debug!("CRL cache cleared due to certificate revocation");

    info!(cert_id=id, cert_name=?cert.name, admin_id=?authentication._claims.id, "Certificate revoked successfully");

    // Audit log certificate revocation
    if let Err(e) = state.audit.log_certificate_operation(
        Some(authentication._claims.id), // Admin ID doing the revocation
        None, // TODO: get actual admin user name
        None, // TODO: extract IP from request
        None, // TODO: extract User-Agent from request
        id,
        &cert.name,
        "revoke",
        true,
        Some(serde_json::json!({
            "old_status": "active",
            "revocation_reason": format!("{:?}", payload.reason),
            "notify_user": payload.notify_user
        })),
        Some(serde_json::json!({
            "new_status": "revoked",
            "revoked_by": authentication._claims.id,
            "revocation_date": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        })),
        None,
        None,
    ).await {
        warn!("Failed to log certificate revocation audit event: {}", e);
    }

    // Optionally notify the user
    if payload.notify_user.unwrap_or(false) {
        let user = state.db.get_user(cert.user_id).await?;
        // TODO: Implement revocation notification
        debug!(cert_id=id, user_email=?user.email, "Revocation notification requested but not yet implemented");
    }

    Ok(())
}

#[openapi(tag = "Certificates")]
#[get("/certificates/cert/<id>/revocation-status")]
/// Get revocation status of a certificate. Requires authentication.
/// Returns detailed revocation information if the certificate is revoked, or null if not revoked.
///
/// Response format:
/// ```json
/// {
///   "certificate_id": 123,
///   "revocation_date": 1640995200000,
///   "revocation_reason": 1,
///   "revoked_by_user_id": 1
/// }
/// ```
///
/// Revocation reasons:
/// - 0: Unspecified
/// - 1: Key Compromise
/// - 2: CA Compromise
/// - 3: Affiliation Changed
/// - 4: Superseded
/// - 5: Cessation of Operation
/// - 6: Certificate Hold
/// - 8: Remove from CRL
/// - 9: Privilege Withdrawn
/// - 10: AA Compromise
pub(crate) async fn get_revocation_status(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<Json<Option<crate::data::objects::CertificateRevocation>>, ApiError> {
    // Check if user owns the certificate or is admin
    let (user_id, _, _, _, _, _, _, _, _) = state.db.get_user_cert(id).await
        .map_err(|_| ApiError::NotFound(Some("Certificate not found".to_string())))?;

    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin {
        return Err(ApiError::Forbidden(None));
    }

    let revocation = state.db.get_certificate_revocation(id).await?;
    Ok(Json(revocation))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/revocation-history")]
/// Get all certificate revocation history. Requires admin role.
pub(crate) async fn get_revocation_history(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Vec<RevocationHistoryEntry>>, ApiError> {
    let revocation_records = state.db.get_all_revocation_records().await?;

    let mut history_entries = Vec::new();
    for record in revocation_records {
        // Try to get the certificate name, but handle the case where the certificate might have been deleted
        let certificate_name = match state.db.get_user_cert_by_id(record.certificate_id).await {
            Ok(cert) => cert.name,
            Err(_) => format!("Certificate {}", record.certificate_id), // Certificate was deleted
        };

        history_entries.push(RevocationHistoryEntry {
            id: record.id,
            certificate_id: record.certificate_id,
            certificate_name,
            revocation_date: record.revocation_date,
            revocation_reason: record.revocation_reason,
            revoked_by_user_id: record.revoked_by_user_id,
        });
    }

    Ok(Json(history_entries))
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/revocation-history")]
/// Clear all certificate revocation history. Requires admin role.
/// This permanently deletes all revocation records from the database.
/// Use with caution as this action cannot be undone.
pub(crate) async fn clear_revocation_history(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    debug!("Clearing all certificate revocation history");

    state.db.clear_all_revocation_records().await?;

    // Clear CRL cache since revocation list has changed
    let mut cache = state.crl_cache.lock().await;
    *cache = None;
    debug!("CRL cache cleared due to revocation history clearance");

    info!("All certificate revocation history cleared successfully");

    Ok(())
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/cert/<id>/revoke")]
/// Unrevoke a certificate (remove from revocation list). Requires admin role.
pub(crate) async fn unrevoke_certificate(
    state: &State<AppState>,
    id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    debug!(cert_id=id, "Unrevoking certificate");

    // Check if certificate exists
    let _cert = state.db.get_user_cert_by_id(id).await
        .map_err(|_| ApiError::NotFound(Some("Certificate not found".to_string())))?;

    // Check if certificate is actually revoked
    if !state.db.is_certificate_revoked(id).await? {
        return Err(ApiError::BadRequest("Certificate is not revoked".to_string()));
    }

    // Unrevoke the certificate
    state.db.unrevoke_certificate(id).await?;

    // Clear CRL cache since revocation list has changed
    let mut cache = state.crl_cache.lock().await;
    *cache = None;
    debug!("CRL cache cleared due to certificate unrevocation");

    info!(cert_id=id, "Certificate unrevoked successfully");

    Ok(())
}

#[openapi(tag = "Certificates")]
#[get("/certificates/crl")]
/// Download the current Certificate Revocation List (CRL). Requires authentication.
/// Returns a PEM-encoded CRL containing all revoked certificates.
/// The CRL is cached for 5 minutes and automatically regenerated when certificates are revoked/unrevoked.
///
/// Usage in applications:
/// ```bash
/// curl -H "Authorization: Bearer <token>" \
///      http://localhost:8000/api/certificates/crl > certificate.crl
/// ```
///
/// Configure CRL distribution in certificate extensions:
/// - Authority Information Access (AIA) extension with OCSP URL
/// - CRL Distribution Points extension with CRL URL
pub(crate) async fn download_crl(
    state: &State<AppState>,
    _authentication: Authenticated
) -> Result<DownloadResponse, ApiError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    debug!("CRL download requested");

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Check if we have a valid cached CRL
    let mut cache = state.crl_cache.lock().await;
    if let Some(cached_crl) = &*cache {
        // Check if cache is still valid (within 5 minutes)
        if current_time < cached_crl.valid_until {
            debug!("Returning cached CRL (valid until {})", cached_crl.valid_until);
            return Ok(DownloadResponse::new(cached_crl.data.clone(), "certificate_revocation_list.crl"));
        } else {
            debug!("Cached CRL expired, regenerating");
        }
    }

    // Generate new CRL
    let ca = state.db.get_current_ca().await?;
    let revoked_records = state.db.get_all_revocation_records().await?;

    // Convert to CRLEntry format with proper serial numbers
    let mut revoked_entries = Vec::new();
    for record in revoked_records {
        // Get certificate details to extract serial number
        let cert = state.db.get_user_cert_by_id(record.certificate_id).await?;

        // Extract serial number from certificate
        let serial_number = if let Ok(details) = crate::cert::get_certificate_details(&cert) {
            // Parse the hex serial number back to bytes
            hex::decode(&details.serial_number.trim_start_matches("0x").trim_start_matches("0X"))
                .unwrap_or_else(|_| Vec::new())
        } else {
            Vec::new()
        };

        revoked_entries.push(CRLEntry {
            serial_number,
            revocation_date: record.revocation_date,
            reason: record.revocation_reason,
        });
    }

    // Generate CRL
    let crl_der = generate_crl(&ca, &revoked_entries)?;
    let crl_pem = crate::cert::crl_to_pem(&crl_der)?;

    // Save CRL to file system for persistence
    if let Err(e) = crate::cert::save_crl_to_file(&crl_der, ca.id) {
        warn!("Failed to save CRL to file system: {}", e);
        // Continue anyway - the CRL will still work from cache
    }

    // Get CRL cache timeout from settings (refresh_interval_hours converted to milliseconds)
    let crl_settings = state.settings.get_crl();
    let cache_timeout_ms = (crl_settings.refresh_interval_hours as i64) * 60 * 60 * 1000; // hours to milliseconds

    // Cache the CRL for the configured interval
    let valid_until = current_time + cache_timeout_ms;
    *cache = Some(CrlCache {
        data: crl_pem.clone(),
        last_updated: current_time,
        valid_until,
    });

    debug!("Generated, saved to file system, and cached new CRL (valid until {}, cache timeout: {} hours)",
           valid_until, crl_settings.refresh_interval_hours);

    Ok(DownloadResponse::new(crl_pem, "certificate_revocation_list.crl"))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/crl/metadata")]
/// Get CRL metadata information. Requires authentication.
/// Returns information about the current CRL including file size, creation time, and backup count.
///
/// Response format:
/// ```json
/// {
///   "ca_id": 1,
///   "file_size": 1024,
///   "created_time": 1640995200000,
///   "modified_time": 1640995200000,
///   "backup_count": 5
/// }
/// ```
pub(crate) async fn get_crl_metadata_endpoint(
    state: &State<AppState>,
    _authentication: Authenticated
) -> Result<Json<crate::cert::CrlMetadata>, ApiError> {
    let ca = state.db.get_current_ca().await?;
    let metadata = crate::cert::get_crl_metadata(ca.id)?;
    Ok(Json(metadata))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/crl/files")]
/// List all CRL files and their metadata. Requires admin role.
/// Returns a list of all CRL backup files with their creation times and sizes.
///
/// Response format:
/// ```json
/// [
///   {
///     "filename": "ca_1_1640995200000.crl",
///     "ca_id": 1,
///     "created_time": 1640995200000,
///     "file_size": 1024
///   }
/// ]
/// ```
pub(crate) async fn list_crl_files_endpoint(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Vec<crate::cert::CrlFileInfo>>, ApiError> {
    let files = crate::cert::list_crl_files()?;
    Ok(Json(files))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/crl/backup/<filename>")]
/// Download a specific CRL backup file. Requires admin role.
/// Allows downloading of specific CRL backup files by filename.
///
/// Usage:
/// ```bash
/// curl -H "Authorization: Bearer <token>" \
///      http://localhost:8000/api/certificates/crl/backup/ca_1_1640995200000.crl
/// ```
pub(crate) async fn download_crl_backup(
    _state: &State<AppState>,
    filename: &str,
    _authentication: AuthenticatedPrivileged
) -> Result<DownloadResponse, ApiError> {
    use std::path::Path;
    use crate::constants::CRL_DIR_PATH;

    // Security check: ensure the filename doesn't contain path traversal
    if filename.contains("..") || filename.contains("/") || filename.contains("\\") {
        return Err(ApiError::BadRequest("Invalid filename".to_string()));
    }

    if !filename.ends_with(".crl") {
        return Err(ApiError::BadRequest("Invalid file extension".to_string()));
    }

    let file_path = Path::new(CRL_DIR_PATH).join(filename);

    if !file_path.exists() {
        return Err(ApiError::NotFound(Some("CRL backup file not found".to_string())));
    }

    // Read the file
    let file_data = std::fs::read(&file_path).map_err(|e| {
        error!("Failed to read CRL backup file: {}", e);
        ApiError::Other("Failed to read CRL backup file".to_string())
    })?;

    Ok(DownloadResponse::new(file_data, filename))
}

// #[get("/ocsp?<request>")]
// /// OCSP responder endpoint for real-time certificate status checking.
// /// Accepts base64-encoded OCSP requests via GET and returns DER-encoded OCSP responses.
// /// Requires authentication.
// ///
// /// Usage with OpenSSL:
// /// ```bash
// /// openssl ocsp -issuer ca.pem -cert cert.pem \
// ///              -url http://localhost:8000/api/ocsp \
// ///              -header "Authorization: Bearer <token>"
// /// ```
// ///
// /// Response status codes:
// /// - Successful: Certificate status returned
// /// - MalformedRequest: Invalid OCSP request format
// /// - InternalError: Server error processing request
// /// - TryLater: Temporary server unavailability
// /// - SigRequired: Request must be signed
// /// - Unauthorized: Authentication required
// ///
// /// Certificate status values:
// /// - Good: Certificate is valid and not revoked
// /// - Revoked: Certificate has been revoked
// /// - Unknown: Certificate status cannot be determined
// pub(crate) async fn ocsp_responder_get(
//     state: &State<AppState>,
//     request: &str,
//     _authentication: Authenticated
// ) -> Result<Vec<u8>, ApiError> {
//     debug!("OCSP GET request received (base64 length: {})", request.len());
//
//     // Decode base64 request
//     let request_data = base64::decode(request)
//         .map_err(|e| ApiError::BadRequest(format!("Invalid base64 encoding in OCSP request: {}", e)))?;
//
//     debug!("Decoded OCSP request ({} bytes)", request_data.len());
//
//     // Process the request
//     process_ocsp_request(state, &request_data).await
// }
//
// #[post("/ocsp", data = "<request_data>")]
// /// OCSP responder endpoint for real-time certificate status checking.
// /// Accepts DER-encoded OCSP requests and returns DER-encoded OCSP responses.
// /// Requires authentication.
// pub(crate) async fn ocsp_responder_post(
//     state: &State<AppState>,
//     request_data: Vec<u8>,
//     _authentication: Authenticated
// ) -> Result<Vec<u8>, ApiError> {
//     debug!("OCSP POST request received ({} bytes)", request_data.len());
//
//     // Process the request
//     process_ocsp_request(state, &request_data).await
// }

/// Format an X509Name as a proper DN string (RFC 4514 format)
fn format_subject_name(name: &openssl::x509::X509NameRef) -> String {
    let mut dn_parts = Vec::new();

    for entry in name.entries() {
        if let Ok(data) = entry.data().as_utf8() {
            // Map common OIDs to their short names
            let rdn_type = match entry.object().nid().as_raw() {
                13 => "CN".to_string(),      // commonName
                14 => "SN".to_string(),      // surname
                3 => "CN".to_string(),       // commonName (alternative)
                17 => "ST".to_string(),      // stateOrProvinceName
                18 => "L".to_string(),       // localityName
                19 => "STREET".to_string(),  // streetAddress
                6 => "O".to_string(),        // organizationName
                7 => "OU".to_string(),       // organizationalUnitName
                8 => "ST".to_string(),       // stateOrProvinceName (alternative)
                10 => "O".to_string(),       // organizationName (alternative)
                11 => "OU".to_string(),      // organizationalUnitName (alternative)
                16 => "POSTALCODE".to_string(), // postalCode
                20 => "DC".to_string(),      // domainComponent
                41 => "NAME".to_string(),    // name
                43 => "INITIALS".to_string(), // initials
                44 => "GENERATION".to_string(), // generationQualifier
                46 => "DNQUALIFIER".to_string(), // dnQualifier
                48 => "emailAddress".to_string(), // emailAddress (PKCS#9)
                49 => "emailAddress".to_string(), // emailAddress (alternative)
                _ => {
                    // Use the full OID if not recognized
                    entry.object().to_string()
                }
            };

            dn_parts.push(format!("{}={}", rdn_type, data.as_ref() as &str));
        }
    }

    dn_parts.join(", ")
}

async fn process_ocsp_request(
    state: &State<AppState>,
    request_data: &[u8]
) -> Result<Vec<u8>, ApiError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Parse the OCSP request
    let ocsp_request = parse_ocsp_request(request_data)?;

    // Create cache key from certificate ID
    let cert_id_hash = format!("{:x}", md5::compute(&ocsp_request.certificate_id.serial_number));

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Check cache first
    let mut cache = state.ocsp_cache.lock().await;
    if let Some(cached_response) = &*cache {
        if cached_response.cert_id_hash == cert_id_hash && current_time < cached_response.valid_until {
            debug!("Returning cached OCSP response for cert ID hash: {}", cert_id_hash);
            return Ok(cached_response.data.clone());
        }
    }

    // Generate new OCSP response
    let ca = state.db.get_current_ca().await?;
    let response_der = generate_ocsp_response(&ocsp_request, &ca, &state.db).await?;

    // Cache the response for 1 hour (OCSP responses are typically valid for 1 hour)
    let valid_until = current_time + (60 * 60 * 1000); // 1 hour in milliseconds
    *cache = Some(OcspCache {
        data: response_der.clone(),
        cert_id_hash: cert_id_hash.clone(),
        last_updated: current_time,
        valid_until,
    });

    debug!("Generated and cached OCSP response for cert ID hash: {} (valid until {})", cert_id_hash, valid_until);

    Ok(response_der)
}

// AUDIT LOGGING API ENDPOINTS
use crate::data::objects::{AuditEventType, AuditEventCategory, AuditLogQuery, AuditLogStats, AuditCleanupResult};
use crate::settings::AuditSettings;
use serde_json::{json, Value};

// Simple audit logging function - logs to console for now
async fn log_audit_event_simple(
    event_category: AuditEventCategory,
    user_id: Option<i64>,
    user_name: Option<&str>,
    action: &str,
    success: bool,
    details: Option<&str>,
    error_message: Option<&str>,
) {
    if success {
        info!(
            "AUDIT SUCCESS: [{}] {} by user '{}' - {}",
            format!("{:?}", event_category),
            action,
            user_name.unwrap_or("unknown"),
            details.unwrap_or("")
        );
    } else {
        warn!(
            "AUDIT FAILED: [{}] {} by user '{}' - {} - Error: {}",
            format!("{:?}", event_category),
            action,
            user_name.unwrap_or("unknown"),
            details.unwrap_or(""),
            error_message.unwrap_or("unknown error")
        );
    }
}

#[openapi(tag = "Audit")]
#[get("/audit/logs?<query..>")]
pub async fn get_audit_logs(
    state: &State<AppState>,
    query: AuditLogQuery,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<Value>, ApiError> {
    let (logs, total) = state.audit.query_logs(&query).await.map_err(|e| {
        error!("Failed to query audit logs: {}", e);
        ApiError::Other("Failed to query audit logs".to_string())
    })?;

    Ok(Json(json!({
        "logs": logs,
        "total": total,
        "page": query.page.unwrap_or(1),
        "limit": query.limit.unwrap_or(50)
    })))
}

#[get("/audit/stats")]
pub async fn get_audit_stats(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<AuditLogStats>, ApiError> {
    let stats = state.audit.get_stats().await.map_err(|e| {
        error!("Failed to get audit stats: {}", e);
        ApiError::Other("Failed to get audit statistics".to_string())
    })?;

    Ok(Json(stats))
}

#[post("/audit/cleanup")]
pub async fn cleanup_audit_logs(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<AuditCleanupResult>, ApiError> {
    let result = state.audit.cleanup_old_logs().await.map_err(|e| {
        error!("Failed to cleanup audit logs: {}", e);
        ApiError::Other("Failed to cleanup audit logs".to_string())
    })?;

    Ok(Json(result))
}

#[get("/audit/settings")]
pub async fn get_audit_settings(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<serde_json::Value>, ApiError> {
    let settings = state.audit.get_settings();
    Ok(Json(json!({
        "enabled": settings.enabled,
        "retention_days": settings.retention_days,
        "log_authentication": settings.log_authentication,
        "log_certificate_operations": settings.log_certificate_operations,
        "log_ca_operations": settings.log_ca_operations,
        "log_user_operations": settings.log_user_operations,
        "log_settings_changes": settings.log_settings_changes,
        "log_system_events": settings.log_system_events,
        "max_log_size_mb": settings.max_log_size_mb
    })))
}

#[put("/audit/settings", data = "<settings>")]
pub async fn update_audit_settings(
    state: &State<AppState>,
    settings: Json<serde_json::Value>,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<serde_json::Value>, ApiError> {
    let new_settings = AuditSettings {
        enabled: settings.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
        retention_days: settings.get("retention_days").and_then(|v| v.as_i64()).unwrap_or(365) as i32,
        log_authentication: settings.get("log_authentication").and_then(|v| v.as_bool()).unwrap_or(true),
        log_certificate_operations: settings.get("log_certificate_operations").and_then(|v| v.as_bool()).unwrap_or(true),
        log_ca_operations: settings.get("log_ca_operations").and_then(|v| v.as_bool()).unwrap_or(true),
        log_user_operations: settings.get("log_user_operations").and_then(|v| v.as_bool()).unwrap_or(true),
        log_settings_changes: settings.get("log_settings_changes").and_then(|v| v.as_bool()).unwrap_or(true),
        log_system_events: settings.get("log_system_events").and_then(|v| v.as_bool()).unwrap_or(true),
        max_log_size_mb: settings.get("max_log_size_mb").and_then(|v| v.as_i64()).unwrap_or(100) as i32,
        last_cleanup: None, // Will be set when cleanup occurs
    };

    // TODO: Implement audit settings update when audit service supports mutable borrowing
    warn!("Audit settings update not yet implemented - service needs mutable borrowing");

    Ok(settings)
}
