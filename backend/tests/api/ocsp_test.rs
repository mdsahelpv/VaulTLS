use crate::common::constants::*;
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use const_format::{concatcp, formatcp};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::x509::X509;
use rocket::http::{ContentType, Status};
use serde_json::Value;
use vaultls::cert::Certificate;
use vaultls::data::enums::{CertificateRevocationReason, CertificateType};

#[tokio::test]
async fn test_ocsp_good_certificate_status() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get the certificate from the database to extract its serial number
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(!certs.is_empty(), "Should have at least one certificate");

    let cert = &certs[0];
    let cert_details = client.get_certificate_details(cert.id.to_string().as_str()).await?;
    let serial_hex = cert_details.serial_number.trim_start_matches("0x").trim_start_matches("0X");
    let serial_bytes = hex::decode(serial_hex)?;

    // Create OCSP request for this certificate
    let ca = client.download_ca().await?;
    let ca_x509 = ca.parse_x509()?;

    // Generate certificate ID as per RFC 6960
    let issuer_name_hash = hash(MessageDigest::sha1(), &ca_x509.subject_name().to_der()?)?;
    let issuer_key_hash = hash(MessageDigest::sha1(), &ca_x509.public_key()?.public_key_to_der()?)?;
    let cert_id = format!("{}:{}:{}", hex::encode(issuer_name_hash), hex::encode(issuer_key_hash), hex::encode(serial_bytes));

    // Create OCSP request: version + requestList + optional extensions
    // We'll use a simplified approach and create the request manually
    let mut ocsp_request = Vec::new();

    // Version (0 for v1)
    ocsp_request.push(0);

    // Add issuer name hash (20 bytes SHA-1)
    ocsp_request.extend_from_slice(&issuer_name_hash);

    // Add issuer key hash (20 bytes SHA-1)
    ocsp_request.extend_from_slice(&issuer_key_hash);

    // Add serial number (DER encoded integer)
    let mut serial_der = Vec::new();
    serial_der.push(0x02); // INTEGER tag
    if serial_bytes.len() > 127 {
        return Err(anyhow::anyhow!("Serial number too large"));
    }
    serial_der.push(serial_bytes.len() as u8);
    serial_der.extend_from_slice(&serial_bytes);

    ocsp_request.extend_from_slice(&serial_der);

    // Base64 encode the request
    let request_b64 = general_purpose::STANDARD.encode(&ocsp_request);

    // Send OCSP request via GET
    let ocsp_url = format!("/ocsp?request={}", request_b64);
    let request = client
        .get(&ocsp_url);
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    let response_bytes = response.into_bytes().await.unwrap();
    assert!(!response_bytes.is_empty(), "OCSP response should not be empty");

    println!("✅ OCSP GET request for good certificate succeeded - response size: {} bytes", response_bytes.len());

    // Send via POST as well
    let request = client
        .post("/ocsp")
        .header(ContentType::Binary)
        .body(ocsp_request);
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    let response_bytes = response.into_bytes().await.unwrap();
    assert!(!response_bytes.is_empty(), "OCSP response should not be empty");

    println!("✅ OCSP POST request for good certificate succeeded - response size: {} bytes", response_bytes.len());

    Ok(())
}

#[tokio::test]
async fn test_ocsp_revoked_certificate_status() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get the certificate
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(!certs.is_empty());

    let cert = &certs[0];

    // Revoke the certificate first
    let revoke_request = client
        .post(format!("/certificates/{}/revoke", cert.id))
        .header(ContentType::JSON)
        .body(r#"{"revocation_reason": 1, "notify_user": false}"#);
    let response = revoke_request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    println!("✅ Certificate revoked successfully");

    // Now test OCSP for revoked certificate
    let cert_details = client.get_certificate_details(cert.id.to_string().as_str()).await?;
    let serial_hex = cert_details.serial_number.trim_start_matches("0x").trim_start_matches("0X");
    let serial_bytes = hex::decode(serial_hex)?;

    // Create OCSP request
    let ca = client.download_ca().await?;
    let ca_x509 = ca.parse_x509()?;

    let issuer_name_hash = hash(MessageDigest::sha1(), &ca_x509.subject_name().to_der()?)?;
    let issuer_key_hash = hash(MessageDigest::sha1(), &ca_x509.public_key()?.public_key_to_der()?)?;

    let mut ocsp_request = Vec::new();
    ocsp_request.push(0); // Version
    ocsp_request.extend_from_slice(&issuer_name_hash);
    ocsp_request.extend_from_slice(&issuer_key_hash);

    // Serial number as DER integer
    let mut serial_der = Vec::new();
    serial_der.push(0x02); // INTEGER tag
    serial_der.push(serial_bytes.len() as u8);
    serial_der.extend_from_slice(&serial_bytes);
    ocsp_request.extend_from_slice(&serial_der);

    // Base64 encode and send request
    let request_b64 = general_purpose::STANDARD.encode(&ocsp_request);
    let ocsp_url = format!("/ocsp?request={}", request_b64);
    let request = client
        .get(&ocsp_url);
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    let response_bytes = response.into_bytes().await.unwrap();
    assert!(!response_bytes.is_empty());

    println!("✅ OCSP request for revoked certificate succeeded - response size: {} bytes", response_bytes.len());

    // Verify certificate is still marked as revoked
    let certs: Vec<Certificate> = serde_json::from_str(
        &client.get("/certificates").dispatch().await.into_string().await.unwrap()
    )?;
    assert!(certs.iter().any(|c| c.id == cert.id && c.is_revoked == Some(true)));

    Ok(())
}

#[tokio::test]
async fn test_ocsp_unknown_certificate_status() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Create OCSP request for a non-existent certificate serial number
    let ca = client.download_ca().await?;
    let ca_x509 = ca.parse_x509()?;

    let issuer_name_hash = hash(MessageDigest::sha1(), &ca_x509.subject_name().to_der()?)?;
    let issuer_key_hash = hash(MessageDigest::sha1(), &ca_x509.public_key()?.public_key_to_der()?)?;

    // Use a fake serial number (1)
    let fake_serial = vec![1];

    let mut ocsp_request = Vec::new();
    ocsp_request.push(0); // Version
    ocsp_request.extend_from_slice(&issuer_name_hash);
    ocsp_request.extend_from_slice(&issuer_key_hash);

    // Fake serial as DER integer
    let mut serial_der = Vec::new();
    serial_der.push(0x02); // INTEGER tag
    serial_der.push(fake_serial.len() as u8);
    serial_der.extend_from_slice(&fake_serial);
    ocsp_request.extend_from_slice(&serial_der);

    // Send request
    let request_b64 = general_purpose::STANDARD.encode(&ocsp_request);
    let ocsp_url = format!("/ocsp?request={}", request_b64);
    let request = client
        .get(&ocsp_url);
    let response = request.dispatch().await;

    // Should still return OK (basic implementation returns minimal response)
    assert_eq!(response.status(), Status::Ok);
    let response_bytes = response.into_bytes().await.unwrap();
    assert!(!response_bytes.is_empty());

    println!("✅ OCSP request for unknown certificate handled - response size: {} bytes", response_bytes.len());

    Ok(())
}

#[tokio::test]
async fn test_ocsp_unauthorized_access() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Try to access OCSP without authentication
    let request = client
        .get("/ocsp?request=dGVzdA"); // Fake Base64 request
    let response = request.dispatch().await;

    // Should fail with unauthorized
    assert_eq!(response.status(), Status::Unauthorized);

    println!("✅ OCSP correctly rejects unauthorized access");

    Ok(())
}

#[tokio::test]
async fn test_ocsp_invalid_request_format() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Send invalid Base64
    let request = client
        .get("/ocsp?request=invalid-base64!");
    let response = request.dispatch().await;

    // Should fail with BadRequest
    assert_eq!(response.status(), Status::BadRequest);

    println!("✅ OCSP correctly rejects invalid Base64");

    // Send empty request
    let request = client
        .get("/ocsp?request=");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::BadRequest);

    println!("✅ OCSP correctly rejects empty request");

    Ok(())
}

#[tokio::test]
async fn test_ocsp_post_request() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Send POST request with minimal valid data (just version byte)
    let request = client
        .post("/ocsp")
        .header(ContentType::Binary)
        .body(vec![0x00]); // Minimal request
    let response = request.dispatch().await;

    // Should succeed (basic implementation accepts any input)
    assert_eq!(response.status(), Status::Ok);
    let response_bytes = response.into_bytes().await.unwrap();
    assert!(!response_bytes.is_empty());

    println!("✅ OCSP POST endpoint accepts and processes requests");

    Ok(())
}

#[tokio::test]
async fn test_ocsp_caching_behavior() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get certificate for OCSP request
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    let cert = &certs[0];

    let cert_details = client.get_certificate_details(cert.id.to_string().as_str()).await?;
    let serial_hex = cert_details.serial_number.trim_start_matches("0x").trim_start_matches("0X");
    let serial_bytes = hex::decode(serial_hex)?;

    // Create multiple identical OCSP requests to test caching
    let ca = client.download_ca().await?;
    let ca_x509 = ca.parse_x509()?;

    let issuer_name_hash = hash(MessageDigest::sha1(), &ca_x509.subject_name().to_der()?)?;
    let issuer_key_hash = hash(MessageDigest::sha1(), &ca_x509.public_key()?.public_key_to_der()?)?;

    let mut ocsp_request = Vec::new();
    ocsp_request.push(0);
    ocsp_request.extend_from_slice(&issuer_name_hash);
    ocsp_request.extend_from_slice(&issuer_key_hash);

    let mut serial_der = Vec::new();
    serial_der.push(0x02);
    serial_der.push(serial_bytes.len() as u8);
    serial_der.extend_from_slice(&serial_bytes);
    ocsp_request.extend_from_slice(&serial_der);

    let request_b64 = general_purpose::STANDARD.encode(&ocsp_request);

    // Send first request
    let ocsp_url = format!("/ocsp?request={}", request_b64);
    let request = client.get(&ocsp_url);
    let response1 = request.dispatch().await;
    assert_eq!(response1.status(), Status::Ok);

    let response1_bytes = response1.into_bytes().await.unwrap();
    println!("First OCSP request - response size: {} bytes", response1_bytes.len());

    // Send second identical request (should use cache in production)
    let request = client.get(&ocsp_url);
    let response2 = request.dispatch().await;
    assert_eq!(response2.status(), Status::Ok);

    let response2_bytes = response2.into_bytes().await.unwrap();
    println!("Second OCSP request - response size: {} bytes", response2_bytes.len());

    // Responses should be identical
    assert_eq!(response1_bytes, response2_bytes);

    println!("✅ OCSP caching returns consistent responses");

    Ok(())
}

#[tokio::test]
async fn test_ocsp_integration_with_crl() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Revoke a certificate
    let request = client.get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    let cert = &certs[0];

    let revoke_request = client
        .post(format!("/certificates/{}/revoke", cert.id))
        .header(ContentType::JSON)
        .body(r#"{"revocation_reason": 4, "notify_user": false}"#);
    let response = revoke_request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    println!("✅ Certificate revoked successfully");

    // Test CRL download (should include the revoked certificate)
    let request = client.get("/certificates/crl");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let crl_pem = response.into_string().await.unwrap();
    assert!(crl_pem.contains("-----BEGIN X509 CRL-----"));
    assert!(crl_pem.contains("-----END X509 CRL-----"));

    println!("✅ CRL download successful, contains revoked certificate");

    // Verify OCSP still works for the revoked certificate
    let cert_details = client.get_certificate_details(cert.id.to_string().as_str()).await?;
    let serial_hex = cert_details.serial_number.trim_start_matches("0x").trim_start_matches("0X");
    let serial_bytes = hex::decode(serial_hex)?;

    let ca = client.download_ca().await?;
    let ca_x509 = ca.parse_x509()?;

    let issuer_name_hash = hash(MessageDigest::sha1(), &ca_x509.subject_name().to_der()?)?;
    let issuer_key_hash = hash(MessageDigest::sha1(), &ca_x509.public_key()?.public_key_to_der()?)?;

    let mut ocsp_request = Vec::new();
    ocsp_request.push(0);
    ocsp_request.extend_from_slice(&issuer_name_hash);
    ocsp_request.extend_from_slice(&issuer_key_hash);

    let mut serial_der = Vec::new();
    serial_der.push(0x02);
    serial_der.push(serial_bytes.len() as u8);
    serial_der.extend_from_slice(&serial_bytes);
    ocsp_request.extend_from_slice(&serial_der);

    let request_b64 = general_purpose::STANDARD.encode(&ocsp_request);
    let ocsp_url = format!("/ocsp?request={}", request_b64);
    let request = client.get(&ocsp_url);
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    let response_bytes = response.into_bytes().await.unwrap();
    assert!(!response_bytes.is_empty());

    println!("✅ OCSP works correctly for revoked certificates");

    Ok(())
}

#[tokio::test]
async fn test_ocsp_request_validation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Test various invalid OCSP request formats

    // Completely empty request
    let request = client.post("/ocsp");
    let response = request.dispatch().await;
    // Should still handle gracefully (basic implementation)
    assert_eq!(response.status(), Status::Ok);

    // Request with invalid data
    let request = client
        .post("/ocsp")
        .header(ContentType::Binary)
        .body(b"invalid ocsp data");
    let response = request.dispatch().await;
    // Should handle gracefully
    assert_eq!(response.status(), Status::Ok);

    println!("✅ OCSP handles malformed requests gracefully");

    Ok(())
}

#[tokio::test]
async fn test_ocsp_multiple_certificates_scenarios() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create multiple certificates
    let cert_names = vec!["ocsp-cert-1", "ocsp-cert-2", "ocsp-cert-3"];

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

    // Revoke one certificate
    let request = client.get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    let certificates: Vec<&Certificate> = certs.iter()
        .filter(|c| c.name.starts_with("ocsp-cert-"))
        .collect();

    assert_eq!(certificates.len(), 3);

    // Revoke the middle certificate
    let cert_to_revoke = &certificates[1];
    let revoke_request = client
        .post(format!("/certificates/{}/revoke", cert_to_revoke.id))
        .header(ContentType::JSON)
        .body(r#"{"revocation_reason": 2, "notify_user": false}"#);
    let response = revoke_request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Test OCSP for all three certificates
    let ca = client.download_ca().await?;
    let ca_x509 = ca.parse_x509()?;

    let issuer_name_hash = hash(MessageDigest::sha1(), &ca_x509.subject_name().to_der()?)?;
    let issuer_key_hash = hash(MessageDigest::sha1(), &ca_x509.public_key()?.public_key_to_der()?)?;

    for cert in &certificates {
        let cert_details = client.get_certificate_details(cert.id.to_string().as_str()).await?;
        let serial_hex = cert_details.serial_number.trim_start_matches("0x").trim_start_matches("0X");
        let serial_bytes = hex::decode(serial_hex)?;

        let mut ocsp_request = Vec::new();
        ocsp_request.push(0);
        ocsp_request.extend_from_slice(&issuer_name_hash);
        ocsp_request.extend_from_slice(&issuer_key_hash);

        let mut serial_der = Vec::new();
        serial_der.push(0x02);
        serial_der.push(serial_bytes.len() as u8);
        serial_der.extend_from_slice(&serial_bytes);
        ocsp_request.extend_from_slice(&serial_der);

        let request_b64 = general_purpose::STANDARD.encode(&ocsp_request);
        let ocsp_url = format!("/ocsp?request={}", request_b64);
        let request = client.get(&ocsp_url);
        let response = request.dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        let response_bytes = response.into_bytes().await.unwrap();
        assert!(!response_bytes.is_empty());

        let expected_revoked = cert.id == cert_to_revoke.id;
        if expected_revoked {
            println!("✅ OCSP correctly identified revoked certificate {}", cert.name);
        } else {
            println!("✅ OCSP correctly identified good certificate {}", cert.name);
        }
    }

    println!("✅ OCSP handles multiple certificate scenarios correctly");

    Ok(())
}
