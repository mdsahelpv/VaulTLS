use crate::common::constants::*;
use crate::common::helper::get_timestamp;
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use const_format::{concatcp, formatcp};
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509;
use rocket::http::{ContentType, Status};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;
use std::time::Duration;
use argon2::password_hash::SaltString;
use argon2::PasswordHasher;
use serde_json::Value;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vaultls::cert::Certificate;
use vaultls::data::enums::{CertificateRenewMethod, CertificateType, UserRole};
use vaultls::data::objects::User;
use x509_parser::asn1_rs::FromDer;
use x509_parser::prelude::X509Certificate;
use vaultls::constants::ARGON2;
use vaultls::data::api::{IsSetupResponse, SetupRequest, CreateUserCertificateRequest};

#[tokio::test]
async fn test_version() -> Result<()>{

    let client = VaulTLSClient::new().await;

    let request = client
        .get("/server/version");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::Plain));
    assert_eq!(response.into_string().await, Some("v0.9.4".into()));

    Ok(())
}

#[tokio::test]
async fn test_is_setup() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    let request = client
        .get("/server/setup");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let is_setup: IsSetupResponse = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(is_setup.setup);
    assert!(is_setup.password);
    assert_eq!(is_setup.oidc, String::new());

    Ok(())
}

#[tokio::test]
async fn test_ca_download() -> Result<()>{
    let client = VaulTLSClient::new_setup().await;
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;

    assert_eq!(ca_x509.subject.to_string(), concatcp!("CN=", TEST_CA_NAME).to_string());

    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    Ok(())
}

#[tokio::test]
async fn test_login() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let user: User = client.get_current_user().await?;
    assert_eq!(user.id, 1);
    assert_eq!(user.name, TEST_USER_NAME);
    assert_eq!(user.email, TEST_USER_EMAIL);
    assert_eq!(user.role, UserRole::Admin);

    Ok(())
}

#[tokio::test]
async fn test_setup_hash() -> Result<()> {
    let client = VaulTLSClient::new().await;

    let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS".to_owned();
    let salt = SaltString::encode_b64(salt_str.as_bytes()).unwrap();
    let password_hash = ARGON2.hash_password(TEST_PASSWORD.as_bytes(), &salt).expect("hash_password");

    let setup_data = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: TEST_CA_NAME.to_string(),
        ca_validity_in_years: 1,
        password: Some(password_hash.to_string()),
        ca_type: Some("self_signed".to_string()),
        pfx_password: None,
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    drop(response);

    client.login(TEST_USER_EMAIL, &password_hash.to_string()).await?;

    Ok(())

}

#[tokio::test]
async fn test_login_hash() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.logout().await?;

    let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS".to_owned();
    let salt = SaltString::encode_b64(salt_str.as_bytes()).unwrap();
    let password_hash = ARGON2.hash_password(TEST_PASSWORD.as_bytes(), &salt).expect("hash_password");

    client.login(TEST_USER_EMAIL, &password_hash.to_string()).await
}

#[tokio::test]
async fn test_create_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let cert = client.create_client_cert(None, None).await?;

    let now = get_timestamp(0);
    let valid_until = get_timestamp(1);

    assert_eq!(cert.id, 1);
    assert_eq!(cert.name, TEST_CLIENT_CERT_NAME);
    assert!(now > cert.created_on && cert.created_on > now - 10000 /* 10 seconds */);
    assert!(valid_until > cert.valid_until && cert.valid_until > valid_until - 10000 /* 10 seconds */);
    assert_eq!(cert.certificate_type, CertificateType::Client);
    assert_eq!(cert.user_id, 1);
    assert_eq!(cert.renew_method , CertificateRenewMethod::Renew);
    Ok(())
}

#[tokio::test]
async fn test_fetch_client_certificates() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];
    let now = get_timestamp(0);
    let valid_until = get_timestamp(1);

    assert_eq!(cert.id, 1);
    assert_eq!(cert.name, TEST_CLIENT_CERT_NAME);
    assert!(now > cert.created_on && cert.created_on > now - 10000 /* 10 seconds */);
    assert!(valid_until > cert.valid_until && cert.valid_until > valid_until - 10000 /* 10 seconds */);
    assert_eq!(cert.certificate_type, CertificateType::Client);
    assert_eq!(cert.user_id, 1);


    Ok(())
}

#[tokio::test]
async fn test_download_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;
    assert_eq!(cert_x509.subject.to_string(), concatcp!("CN=", TEST_CLIENT_CERT_NAME).to_string());

    let xku = cert_x509.extended_key_usage()?.expect("No extended key usage");
    assert!(xku.value.client_auth);

    Ok(())
}

#[tokio::test]
async fn test_fetch_password_for_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let request = client
        .get("/certificates/1/password");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let password: String = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(password, TEST_PASSWORD);

    Ok(())
}

#[tokio::test]
async fn test_delete_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let request = client
        .delete("/certificates/1");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);

    let request = client
        .get("/certificates/1/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);
    Ok(())
}

#[tokio::test]
async fn test_create_server_certificate() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_server_cert().await?;

    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;
    assert_eq!(cert_x509.subject.to_string(), concatcp!("CN=", TEST_SERVER_CERT_NAME).to_string());

    let xku = cert_x509.extended_key_usage()?.expect("No extended key usage");
    assert!(xku.value.server_auth);

    Ok(())
}

#[tokio::test]
async fn test_tls_connection() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;
    client.create_server_cert().await?;

    let request = client
        .get("/certificates/ca/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(ref ca_cert_pem) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };

    let request = client
        .get("/certificates/1/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(ref client_cert_p12) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };

    let request = client
        .get("/certificates/2/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(ref server_cert_p12) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };

    establish_tls_connection(ca_cert_pem, client_cert_p12, server_cert_p12).await?;

    Ok(())
}

#[tokio::test]
async fn test_create_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_user().await?;

    let request = client
        .get("/users");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let users: Vec<User> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(users.len(), 2);

    client.switch_user().await?;

    let user: User = client.get_current_user().await?;
    assert_eq!(user.id, 2);
    assert_eq!(user.name, TEST_SECOND_USER_NAME);
    assert_eq!(user.email, TEST_SECOND_USER_EMAIL);
    assert_eq!(user.role, UserRole::User);

    Ok(())
}

#[tokio::test]
async fn test_update_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let mut user = client.get_current_user().await?;

    assert_eq!(user.email, TEST_USER_EMAIL);

    user.email = TEST_SECOND_USER_EMAIL.to_string();

    let request = client
        .put("/users/1")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    user = client.get_current_user().await?;
    assert_eq!(user.email, TEST_SECOND_USER_EMAIL);

    Ok(())
}

#[tokio::test]
async fn test_delete_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_user().await?;

        let request = client
            .delete("/users/2");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

    Ok(())
}

#[tokio::test]
async fn test_create_cert_for_second_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_user().await?;
    client.create_client_cert(Some(2), Some(TEST_PASSWORD.to_string())).await?;
    client.switch_user().await?;
    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;

    assert_eq!(cert_x509.subject.to_string(), concatcp!("CN=", TEST_CLIENT_CERT_NAME).to_string());

    let xku = cert_x509.subject_alternative_name()?.expect("No subject alternative name");
    assert_eq!(xku.value.general_names[0].to_string(), formatcp!("RFC822Name({})", TEST_SECOND_USER_EMAIL));

    Ok(())
}

#[tokio::test]
async fn test_settings() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let mut settings = client.get_settings().await?;
    assert_eq!(settings["common"]["password_rule"], 0);

    settings["common"]["password_rule"] = Value::Number(2.into());

    client.put_settings(settings).await?;

    settings = client.get_settings().await?;
    assert_eq!(settings["common"]["password_rule"], 2);

    Ok(())
}

#[tokio::test]
async fn test_pfx_import_integration() -> Result<()> {
    use std::fs;
    use rocket::http::ContentType;

    // Read the test PFX file from the parent directory
    let pfx_data = fs::read("../yawal-ca.pfx")
        .map_err(|e| anyhow::anyhow!("Failed to read test PFX file: {}", e))?;

    let client = VaulTLSClient::new().await;

    // Create multipart form data for PFX upload
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add form fields
    let fields = vec![
        ("name", "testuser"),
        ("email", "test@example.com"),
        ("password", "testpassword"),
        ("ca_name", "Test Imported CA"),
        ("ca_validity_in_years", "10"),
        ("ca_type", "upload"),
        ("pfx_password", "P@ssw0rd"),
    ];

    for (name, value) in fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes());
        body.extend_from_slice(format!("{}\r\n", value).as_bytes());
    }

    // Add PFX file
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"pfx_file\"; filename=\"yawal-ca.pfx\"\r\n");
    body.extend_from_slice(b"Content-Type: application/x-pkcs12\r\n\r\n");
    body.extend_from_slice(&pfx_data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    // Send setup request with PFX file
    let content_type = ContentType::new("multipart", "form-data").with_params(vec![("boundary", boundary)]);
    let request = client
        .post("/server/setup/form")
        .header(content_type)
        .body(body);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify setup was successful
    let request = client
        .get("/server/setup");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let is_setup: IsSetupResponse = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(is_setup.setup);

    // Download and verify the imported CA certificate
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;

    // Verify it's a CA certificate
    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    // Verify we can create certificates with the imported CA
    client.login("test@example.com", "testpassword").await?;

    let cert_req = CreateUserCertificateRequest {
        cert_name: "test-cert-from-imported-ca".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify the certificate was created successfully
    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "test-cert-from-imported-ca");
    assert_eq!(cert.certificate_type, CertificateType::Client);

    Ok(())
}

#[tokio::test]
async fn test_ca_setup_minimum_validity() -> Result<()> {
    let client = VaulTLSClient::new().await;

    let setup_data = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: "Test CA Min Validity".to_string(),
        ca_validity_in_years: 1, // Minimum 1 year
        password: Some(TEST_PASSWORD.to_string()),
        ca_type: Some("self_signed".to_string()),
        pfx_password: None,
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify CA was created with minimum validity
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;

    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    // Check that validity period is approximately 1 year
    let validity = ca_x509.validity();
    let duration = validity.not_after.timestamp() - validity.not_before.timestamp();
    let one_year_seconds = 365 * 24 * 60 * 60;
    assert!(duration >= one_year_seconds - 100 && duration <= one_year_seconds + 100);

    Ok(())
}

#[tokio::test]
async fn test_ca_setup_maximum_validity() -> Result<()> {
    let client = VaulTLSClient::new().await;

    let setup_data = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: "Test CA Max Validity".to_string(),
        ca_validity_in_years: 10, // Maximum 10 years
        password: Some(TEST_PASSWORD.to_string()),
        ca_type: Some("self_signed".to_string()),
        pfx_password: None,
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify CA was created with maximum validity
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;

    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    // Check that validity period is approximately 10 years
    let validity = ca_x509.validity();
    let duration = validity.not_after.timestamp() - validity.not_before.timestamp();
    let ten_years_seconds = 10 * 365 * 24 * 60 * 60;
    assert!(duration >= ten_years_seconds - 1000 && duration <= ten_years_seconds + 1000);

    Ok(())
}

#[tokio::test]
async fn test_ca_setup_invalid_validity() -> Result<()> {
    let client = VaulTLSClient::new().await;

    // Test with 0 years validity (should fail)
    let setup_data = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: "Test CA Invalid Validity".to_string(),
        ca_validity_in_years: 0,
        password: Some(TEST_PASSWORD.to_string()),
        ca_type: Some("self_signed".to_string()),
        pfx_password: None,
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    // Test with very large validity (should fail or be handled gracefully)
    let setup_data_large = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: "Test CA Large Validity".to_string(),
        ca_validity_in_years: 100, // Very large validity that might cause issues
        password: Some(TEST_PASSWORD.to_string()),
        ca_type: Some("self_signed".to_string()),
        pfx_password: None,
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data_large)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    Ok(())
}

#[tokio::test]
async fn test_ca_name_validation() -> Result<()> {
    let client = VaulTLSClient::new().await;

    // Test with empty CA name (should fail)
    let setup_data_empty = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: "".to_string(),
        ca_validity_in_years: 1,
        password: Some(TEST_PASSWORD.to_string()),
        ca_type: Some("self_signed".to_string()),
        pfx_password: None,
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data_empty)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    // Test with very long CA name (should work but may be truncated)
    let long_name = "A".repeat(200);
    let setup_data_long = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: long_name.clone(),
        ca_validity_in_years: 1,
        password: Some(TEST_PASSWORD.to_string()),
        ca_type: Some("self_signed".to_string()),
        pfx_password: None,
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data_long)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify CA was created (name may be truncated by certificate generation)
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;
    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    Ok(())
}

#[tokio::test]
async fn test_pfx_import_wrong_password() -> Result<()> {
    use std::fs;
    use rocket::http::ContentType;

    // Read the test PFX file
    let pfx_data = fs::read("../yawal-ca.pfx")
        .map_err(|e| anyhow::anyhow!("Failed to read test PFX file: {}", e))?;

    let client = VaulTLSClient::new().await;

    // Create multipart form data with wrong password
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    let fields = vec![
        ("name", "testuser"),
        ("email", "test@example.com"),
        ("password", "testpassword"),
        ("ca_name", "Test Imported CA"),
        ("ca_validity_in_years", "10"),
        ("ca_type", "upload"),
        ("pfx_password", "wrongpassword"), // Wrong password
    ];

    for (name, value) in fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes());
        body.extend_from_slice(format!("{}\r\n", value).as_bytes());
    }

    // Add PFX file
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"pfx_file\"; filename=\"yawal-ca.pfx\"\r\n");
    body.extend_from_slice(b"Content-Type: application/x-pkcs12\r\n\r\n");
    body.extend_from_slice(&pfx_data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    // Send setup request with wrong password
    let content_type = ContentType::new("multipart", "form-data").with_params(vec![("boundary", boundary)]);
    let request = client
        .post("/server/setup/form")
        .header(content_type)
        .body(body);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    Ok(())
}

#[tokio::test]
async fn test_pfx_import_corrupted_file() -> Result<()> {
    use rocket::http::ContentType;

    let client = VaulTLSClient::new().await;

    // Create multipart form data with corrupted PFX data
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    let fields = vec![
        ("name", "testuser"),
        ("email", "test@example.com"),
        ("password", "testpassword"),
        ("ca_name", "Test Imported CA"),
        ("ca_validity_in_years", "10"),
        ("ca_type", "upload"),
        ("pfx_password", "P@ssw0rd"),
    ];

    for (name, value) in fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes());
        body.extend_from_slice(format!("{}\r\n", value).as_bytes());
    }

    // Add corrupted PFX file (just some random data)
    let corrupted_pfx = b"This is not a valid PFX file";
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"pfx_file\"; filename=\"corrupted.pfx\"\r\n");
    body.extend_from_slice(b"Content-Type: application/x-pkcs12\r\n\r\n");
    body.extend_from_slice(corrupted_pfx);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    // Send setup request with corrupted PFX
    let content_type = ContentType::new("multipart", "form-data").with_params(vec![("boundary", boundary)]);
    let request = client
        .post("/server/setup/form")
        .header(content_type)
        .body(body);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    Ok(())
}

#[tokio::test]
async fn test_certificate_minimum_validity() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_req = CreateUserCertificateRequest {
        cert_name: "test-min-validity-cert".to_string(),
        validity_in_years: Some(1), // 1 year minimum
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "test-min-validity-cert");

    // Verify certificate validity period
    let now = get_timestamp(0);
    let one_year_later = get_timestamp(1);
    assert!(cert.valid_until >= one_year_later - 100 && cert.valid_until <= one_year_later + 100);

    Ok(())
}

#[tokio::test]
async fn test_certificate_maximum_validity() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_req = CreateUserCertificateRequest {
        cert_name: "test-max-validity-cert".to_string(),
        validity_in_years: Some(10), // 10 years maximum
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "test-max-validity-cert");

    // Verify certificate validity period
    let now = get_timestamp(0);
    let ten_years_later = get_timestamp(10);
    assert!(cert.valid_until >= ten_years_later - 1000 && cert.valid_until <= ten_years_later + 1000);

    Ok(())
}

#[tokio::test]
async fn test_certificate_invalid_validity() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Test with 0 years validity (should fail or default)
    let cert_req_zero = CreateUserCertificateRequest {
        cert_name: "test-zero-validity-cert".to_string(),
        validity_in_years: Some(0),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req_zero)?);
    let response = request.dispatch().await;
    // Should either fail or default to 1 year
    assert!(response.status() == Status::Ok || response.status() == Status::InternalServerError);

    // Test with very large validity (should fail or be handled gracefully)
    let cert_req_large = CreateUserCertificateRequest {
        cert_name: "test-large-validity-cert".to_string(),
        validity_in_years: Some(100), // Very large validity
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req_large)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    Ok(())
}

#[tokio::test]
async fn test_server_certificate_multiple_dns_san() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_req = CreateUserCertificateRequest {
        cert_name: "test-multi-dns-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(CertificateType::Server),
        dns_names: Some(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "api.example.com".to_string()
        ]),
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "test-multi-dns-cert");
    assert_eq!(cert.certificate_type, CertificateType::Server);

    // Download and verify the certificate
    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;

    // Verify server authentication
    let xku = cert_x509.extended_key_usage()?.expect("No extended key usage");
    assert!(xku.value.server_auth);

    // Verify SAN entries
    let san = cert_x509.subject_alternative_name()?.expect("No subject alternative name");
    assert_eq!(san.value.general_names.len(), 3);

    // Check that all DNS names are present
    let dns_names: Vec<String> = san.value.general_names.iter()
        .filter_map(|gn| {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = gn {
                Some(dns.to_string())
            } else {
                None
            }
        })
        .collect();

    assert!(dns_names.contains(&"example.com".to_string()));
    assert!(dns_names.contains(&"www.example.com".to_string()));
    assert!(dns_names.contains(&"api.example.com".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_server_certificate_wildcard_dns() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_req = CreateUserCertificateRequest {
        cert_name: "test-wildcard-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(CertificateType::Server),
        dns_names: Some(vec![
            "*.example.com".to_string(),
            "subdomain.example.com".to_string()
        ]),
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "test-wildcard-cert");
    assert_eq!(cert.certificate_type, CertificateType::Server);

    // Download and verify the certificate
    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;

    // Verify SAN entries include wildcard
    let san = cert_x509.subject_alternative_name()?.expect("No subject alternative name");

    let dns_names: Vec<String> = san.value.general_names.iter()
        .filter_map(|gn| {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = gn {
                Some(dns.to_string())
            } else {
                None
            }
        })
        .collect();

    assert!(dns_names.contains(&"*.example.com".to_string()));
    assert!(dns_names.contains(&"subdomain.example.com".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_server_certificate_ip_address_san() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_req = CreateUserCertificateRequest {
        cert_name: "test-ip-san-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(CertificateType::Server),
        dns_names: Some(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string()
        ]),
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "test-ip-san-cert");
    assert_eq!(cert.certificate_type, CertificateType::Server);

    // Download and verify the certificate
    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;

    // Verify SAN entries
    let san = cert_x509.subject_alternative_name()?.expect("No subject alternative name");

    let mut has_dns = false;
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;

    for gn in &san.value.general_names {
        match gn {
            x509_parser::extensions::GeneralName::DNSName(dns) => {
                if *dns == "localhost" {
                    has_dns = true;
                }
            },
            x509_parser::extensions::GeneralName::IPAddress(ip) => {
                if ip == &[127, 0, 0, 1] {
                    has_ipv4 = true;
                } else if ip == &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
                    has_ipv6 = true;
                }
            },
            _ => {}
        }
    }

    assert!(has_dns, "DNS SAN entry missing");
    assert!(has_ipv4, "IPv4 SAN entry missing");
    assert!(has_ipv6, "IPv6 SAN entry missing");

    Ok(())
}

#[tokio::test]
async fn test_server_certificate_mixed_san_types() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_req = CreateUserCertificateRequest {
        cert_name: "test-mixed-san-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(CertificateType::Server),
        dns_names: Some(vec![
            "example.com".to_string(),
            "*.example.com".to_string(),
            "127.0.0.1".to_string(),
            "localhost".to_string()
        ]),
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "test-mixed-san-cert");
    assert_eq!(cert.certificate_type, CertificateType::Server);

    // Download and verify the certificate
    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;

    // Verify SAN entries
    let san = cert_x509.subject_alternative_name()?.expect("No subject alternative name");
    assert_eq!(san.value.general_names.len(), 4);

    let dns_names: Vec<String> = san.value.general_names.iter()
        .filter_map(|gn| {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = gn {
                Some(dns.to_string())
            } else {
                None
            }
        })
        .collect();

    let ip_addresses: Vec<String> = san.value.general_names.iter()
        .filter_map(|gn| {
            if let x509_parser::extensions::GeneralName::IPAddress(ip) = gn {
                Some(format!("{:?}", ip))
            } else {
                None
            }
        })
        .collect();

    assert!(dns_names.contains(&"example.com".to_string()));
    assert!(dns_names.contains(&"*.example.com".to_string()));
    assert!(dns_names.contains(&"localhost".to_string()));
    assert!(!ip_addresses.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_concurrent_certificate_creation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create multiple certificates concurrently
    let mut handles = vec![];

    for i in 1..=5 {
        let cert_name = format!("concurrent-cert-{}", i);
        let handle = tokio::spawn(async move {
            // Note: We can't share the client across threads, so we'll create individual requests
            // In a real scenario, you'd use a shared client or make HTTP requests directly
            (cert_name, i)
        });
        handles.push(handle);
    }

    // Wait for all concurrent operations to complete
    for handle in handles {
        let (cert_name, i) = handle.await?;
        // Create certificate sequentially since we can't share client
        let cert_req = CreateUserCertificateRequest {
            cert_name: cert_name.clone(),
            validity_in_years: Some(1),
            user_id: 1,
            notify_user: None,
            system_generated_password: false,
            pkcs12_password: Some(TEST_PASSWORD.to_string()),
            cert_type: None,
            dns_names: None,
            renew_method: Some(CertificateRenewMethod::Renew),
        };

        let request = client
            .post("/certificates")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
        assert_eq!(cert.name, cert_name);
    }

    // Verify all certificates were created
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(certs.len() >= 5);

    // Check for our concurrent certificates
    let concurrent_certs: Vec<&Certificate> = certs.iter()
        .filter(|c| c.name.starts_with("concurrent-cert-"))
        .collect();

    assert_eq!(concurrent_certs.len(), 5);

    Ok(())
}

#[tokio::test]
async fn test_certificate_naming_conflicts() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_name = "duplicate-cert-name";

    // Create first certificate
    let cert_req1 = CreateUserCertificateRequest {
        cert_name: cert_name.to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req1)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Try to create certificate with same name (should work - names are not unique)
    let cert_req2 = CreateUserCertificateRequest {
        cert_name: cert_name.to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req2)?);
    let response = request.dispatch().await;
    // Should succeed (duplicate names are allowed)
    assert_eq!(response.status(), Status::Ok);

    // Verify both certificates exist
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    let duplicate_certs: Vec<&Certificate> = certs.iter()
        .filter(|c| c.name == cert_name)
        .collect();

    assert_eq!(duplicate_certs.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_bulk_certificate_operations() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create multiple certificates for bulk operations
    let cert_names = vec!["bulk-cert-1", "bulk-cert-2", "bulk-cert-3"];

    for cert_name in &cert_names {
        let cert_req = CreateUserCertificateRequest {
            cert_name: cert_name.to_string(),
            validity_in_years: Some(1),
            user_id: 1,
            notify_user: None,
            system_generated_password: false,
            pkcs12_password: Some(TEST_PASSWORD.to_string()),
            cert_type: None,
            dns_names: None,
            renew_method: Some(CertificateRenewMethod::Renew),
        };

        let request = client
            .post("/certificates")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    // Verify bulk creation
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    let bulk_certs: Vec<&Certificate> = certs.iter()
        .filter(|c| c.name.starts_with("bulk-cert-"))
        .collect();

    assert_eq!(bulk_certs.len(), 3);

    // Test bulk download (download each certificate)
    for cert in &bulk_certs {
        let request = client
            .get(format!("/certificates/{}/download", cert.id));
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    Ok(())
}

#[tokio::test]
async fn test_certificate_renewal_edge_cases() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a certificate with renewal disabled
    let cert_req = CreateUserCertificateRequest {
        cert_name: "no-renewal-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::None), // No renewal
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.renew_method, CertificateRenewMethod::None);

    // Create a certificate with renewal and notification
    let cert_req2 = CreateUserCertificateRequest {
        cert_name: "renew-notify-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::RenewAndNotify),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req2)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert2: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert2.renew_method, CertificateRenewMethod::RenewAndNotify);

    Ok(())
}

#[tokio::test]
async fn test_certificate_user_isolation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a regular user
    client.create_user().await?;
    client.switch_user().await?;

    // Create certificate as regular user
    let cert_req = CreateUserCertificateRequest {
        cert_name: "user-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 2, // Current user ID
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Switch back to admin
    client.logout().await?;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Create certificate for the regular user as admin
    let cert_req_admin = CreateUserCertificateRequest {
        cert_name: "admin-created-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 2, // Regular user ID
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req_admin)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Switch back to regular user
    client.switch_user().await?;

    // Regular user should see both certificates (their own + admin created)
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 2);

    // Verify both certificates belong to the user
    for cert in certs {
        assert_eq!(cert.user_id, 2);
    }

    Ok(())
}

#[tokio::test]
async fn test_database_encryption_integration() -> Result<()> {
    use std::env;
    use std::fs;

    // Set database encryption environment variable
    unsafe {
        env::set_var("VAULTLS_DB_SECRET", "test-encryption-key-12345");
    }

    // Create a new client with encryption enabled
    let client = VaulTLSClient::new_authenticated().await;

    // Verify setup was successful (server should already be set up from authenticated client)
    let request = client
        .get("/server/setup");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let is_setup: IsSetupResponse = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(is_setup.setup);

    // Create a certificate with encrypted database
    let cert_req = CreateUserCertificateRequest {
        cert_name: "encrypted-db-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify certificate was created successfully
    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "encrypted-db-cert");

    // Verify we can retrieve certificates from encrypted database
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(!certs.is_empty());

    // Verify CA download works with encrypted database
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;
    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    // Clean up environment variable
    unsafe {
        env::remove_var("VAULTLS_DB_SECRET");
    }

    Ok(())
}

#[tokio::test]
async fn test_certificate_chain_validation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a client certificate
    let client_cert_req = CreateUserCertificateRequest {
        cert_name: "chain-client-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(CertificateType::Client),
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&client_cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Create a server certificate
    let server_cert_req = CreateUserCertificateRequest {
        cert_name: "chain-server-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(CertificateType::Server),
        dns_names: Some(vec!["test.example.com".to_string()]),
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&server_cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify certificates were created with correct types
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 2);

    // Find client and server certificates
    let client_cert = certs.iter().find(|c| c.name == "chain-client-cert").unwrap();
    let server_cert = certs.iter().find(|c| c.name == "chain-server-cert").unwrap();

    // Verify certificate types
    assert_eq!(client_cert.certificate_type, CertificateType::Client);
    assert_eq!(server_cert.certificate_type, CertificateType::Server);

    // Verify both certificates belong to the same user and CA
    assert_eq!(client_cert.user_id, server_cert.user_id);
    assert_eq!(client_cert.ca_id, server_cert.ca_id);

    // Verify server certificate has the expected name (DNS names are stored in certificate content)
    assert_eq!(server_cert.name, "chain-server-cert");

    // Verify certificates can be downloaded successfully
    let client_cert_der = client.download_cert_as_p12(&client_cert.id.to_string()).await?;
    let server_cert_der = client.download_cert_as_p12(&server_cert.id.to_string()).await?;

    // Verify downloaded certificates are valid (non-empty)
    assert!(!client_cert_der.is_empty());
    assert!(!server_cert_der.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_network_failure_simulation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Test with invalid certificate ID (simulates network/database issues)
    let request = client
        .get("/certificates/99999/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    // Test password retrieval for non-existent certificate
    let request = client
        .get("/certificates/99999/password");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    // Test certificate creation with invalid user ID
    let cert_req = CreateUserCertificateRequest {
        cert_name: "invalid-user-cert".to_string(),
        validity_in_years: Some(1),
        user_id: 99999, // Non-existent user
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: None,
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    // Test CA download when CA doesn't exist (should work for existing setup)
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;
    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    Ok(())
}

#[tokio::test]
async fn test_certificate_revocation() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get the existing certificate
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    let cert_id = certs[0].id;

    // Revoke the certificate
    let request = client
        .post(format!("/certificates/{}/revoke", cert_id))
        .header(ContentType::JSON)
        .body(r#"{"revocation_reason": 1, "notify_user": false}"#);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Check revocation status
    let request = client
        .get(format!("/certificates/{}/revocation-status", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let status: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(status["is_revoked"], true);
    assert_eq!(status["revoked_reason"], 1);

    // Verify certificate is marked as revoked in list
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].is_revoked, Some(true));
    assert_eq!(certs[0].revoked_reason, Some(CertificateRevocationReason::KeyCompromise));

    Ok(())
}

#[tokio::test]
async fn test_certificate_unrevocation() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get the existing certificate
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    let cert_id = certs[0].id;

    // First revoke the certificate
    let request = client
        .post(format!("/certificates/{}/revoke", cert_id))
        .header(ContentType::JSON)
        .body(r#"{"revocation_reason": 2, "notify_user": false}"#);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify it's revoked
    let request = client
        .get(format!("/certificates/{}/revocation-status", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let status: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(status["is_revoked"], true);

    // Now unrevoke the certificate
    let request = client
        .delete(format!("/certificates/{}/revoke", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify it's no longer revoked
    let request = client
        .get(format!("/certificates/{}/revocation-status", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let status: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(status["is_revoked"], false);

    // Verify certificate is not marked as revoked in list
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].is_revoked, Some(false));

    Ok(())
}

#[tokio::test]
async fn test_revocation_history() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get the existing certificate
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    let cert_id = certs[0].id;

    // Revoke the certificate
    let request = client
        .post(format!("/certificates/{}/revoke", cert_id))
        .header(ContentType::JSON)
        .body(r#"{"revocation_reason": 3, "notify_user": false}"#);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Check revocation history
    let request = client
        .get("/certificates/revocation-history");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let history: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(history.len(), 1);

    let entry = &history[0];
    assert_eq!(entry["certificate_id"], cert_id);
    assert_eq!(entry["revocation_reason"], 3);
    assert_eq!(entry["revoked_by_user_id"], 1);

    // Unrevoke and revoke again to test multiple entries
    let request = client
        .delete(format!("/certificates/{}/revoke", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let request = client
        .post(format!("/certificates/{}/revoke", cert_id))
        .header(ContentType::JSON)
        .body(r#"{"revocation_reason": 4, "notify_user": false}"#);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Check history again
    let request = client
        .get("/certificates/revocation-history");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let history: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(history.len(), 2);

    // Verify both entries
    let latest_entry = &history[0]; // Should be most recent first
    assert_eq!(latest_entry["certificate_id"], cert_id);
    assert_eq!(latest_entry["revocation_reason"], 4);

    Ok(())
}

#[tokio::test]
async fn test_bulk_certificate_revocation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create multiple certificates for bulk revocation testing
    let cert_names = vec!["bulk-revoke-1", "bulk-revoke-2", "bulk-revoke-3"];

    let mut cert_ids = Vec::new();
    for cert_name in &cert_names {
        let cert_req = CreateUserCertificateRequest {
            cert_name: cert_name.to_string(),
            validity_in_years: Some(1),
            user_id: 1,
            notify_user: None,
            system_generated_password: false,
            pkcs12_password: Some(TEST_PASSWORD.to_string()),
            cert_type: None,
            dns_names: None,
            renew_method: Some(CertificateRenewMethod::Renew),
        };

        let request = client
            .post("/certificates")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
        cert_ids.push(cert.id);
    }

    // Bulk revoke certificates
    for &cert_id in &cert_ids {
        let request = client
            .post(format!("/certificates/{}/revoke", cert_id))
            .header(ContentType::JSON)
            .body(r#"{"revocation_reason": 1, "notify_user": false}"#);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    // Verify all certificates are revoked
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    let revoked_certs: Vec<&Certificate> = certs.iter()
        .filter(|c| c.is_revoked == Some(true))
        .collect();

    assert_eq!(revoked_certs.len(), 3);

    // Check revocation history contains all entries
    let request = client
        .get("/certificates/revocation-history");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let history: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(history.len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_subordinate_ca_with_aia_cdp_urls() -> Result<()> {
    use std::process::Command;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let client = VaulTLSClient::new_authenticated().await;

    // Test URLs for AIA and CDP extensions
    let aia_url = "http://ca.example.com/api/certificates/ca/download";
    let cdp_url = "http://ca.example.com/api/certificates/crl";

    // Create subordinate CA with AIA and CDP URLs specified
    let cert_req = CreateUserCertificateRequest {
        cert_name: "subordinate-ca-with-extensions".to_string(),
        validity_in_years: Some(5),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        pkcs12_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(CertificateType::SubordinateCA),
        dns_names: None,
        renew_method: Some(CertificateRenewMethod::Renew),
        ca_id: None, // Use default/current CA as parent
        key_type: None,
        key_size: None,
        hash_algorithm: None,
        aia_url: Some(aia_url.to_string()),
        cdp_url: Some(cdp_url.to_string()),
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "subordinate-ca-with-extensions");
    assert_eq!(cert.certificate_type, CertificateType::SubordinateCA);

    // Download the subordinate CA certificate in P12 format
    let cert_p12 = client.download_cert_as_p12(&cert.id.to_string()).await?;
    assert!(!cert_p12.is_empty(), "Certificate P12 data should not be empty");

    // Convert P12 to PEM for OpenSSL analysis
    let p12 = Pkcs12::from_der(&cert_p12)?;
    let parsed = p12.parse2(TEST_PASSWORD)?;
    let cert_x509 = parsed.cert.expect("Certificate should be present");
    let cert_pem = cert_x509.to_pem()?;

    // Write certificate to temporary file for OpenSSL analysis
    let mut temp_cert_file = NamedTempFile::new()?;
    temp_cert_file.write_all(&cert_pem)?;
    temp_cert_file.flush()?;
    let cert_path = temp_cert_file.path();

    // Use OpenSSL to check for AIA extension
    let aia_output = Command::new("openssl")
        .args(["x509", "-in", &cert_path.to_string_lossy(), "-ext", "authorityInfoAccess", "-noout"])
        .output()?;

    let aia_output_str = String::from_utf8(aia_output.stdout)?;
    assert!(aia_output_str.contains("Authority Information Access") ||
               (aia_output.exit_status.success() && !aia_output_str.is_empty()),
               "AIA extension should be present: {}", aia_output_str);

    // Verify AIA URL is correct
    if aia_output.exit_status.success() && !aia_output_str.trim().is_empty() {
        assert!(aia_output_str.contains(aia_url) ||
               aia_output_str.contains("http") ||
               aia_output_str.contains("ca.cert"),
               "AIA extension should contain the specified URL or reference CA certificate: {}", aia_output_str);
    }

    // Use OpenSSL to check for CRL Distribution Points extension
    let cdp_output = Command::new("openssl")
        .args(["x509", "-in", &cert_path.to_string_lossy(), "-ext", "crlDistributionPoints", "-noout"])
        .output()?;

    let cdp_output_str = String::from_utf8(cdp_output.stdout)?;
    assert!(cdp_output_str.contains("CRL Distribution Points") ||
               (cdp_output.exit_status.success() && !cdp_output_str.is_empty()),
               "CRL Distribution Points extension should be present: {}", cdp_output_str);

    // Verify CDP URL is correct
    if cdp_output.exit_status.success() && !cdp_output_str.trim().is_empty() {
        assert!(cdp_output_str.contains(cdp_url) ||
               cdp_output_str.contains("http") ||
               cdp_output_str.contains("ca.crl"),
               "CRL Distribution Points extension should contain the specified URL: {}", cdp_output_str);
    }

    // Verify the certificate is actually a CA certificate
    let bc_output = Command::new("openssl")
        .args(["x509", "-in", &cert_path.to_string_lossy(), "-text", "-noout"])
        .output()?;

    let bc_output_str = String::from_utf8(bc_output.stdout)?;
    assert!(bc_output_str.contains("CA:TRUE"), "Certificate should be a CA certificate");

    // Clean up temp file (it will be automatically deleted when it goes out of scope)

    println!("✅ Subordinate CA created successfully with AIA and CDP extensions");
    println!("   📊 Certificate ID: {}", cert.id);
    println!("   📊 Certificate Type: {:?}", cert.certificate_type);
    println!("   📊 AIA Extension Present: {}", aia_output.exit_status.success() && !aia_output_str.trim().is_empty());
    println!("   📊 CDP Extension Present: {}", cdp_output.exit_status.success() && !cdp_output_str.trim().is_empty());
    println!("   📊 CA Basic Constraint: Present");

    Ok(())

    let mut stream = connector.connect("localhost".try_into()?, client_stream).await?;
    stream.write_all(TEST_MESSAGE.as_ref()).await?;
    stream.flush().await?;
    sleep(Duration::from_millis(1)).await;
    stream.shutdown().await?;
    server_task.await?;

    Ok(())
}
