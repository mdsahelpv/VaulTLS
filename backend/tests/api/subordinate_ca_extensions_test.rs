use crate::common::constants::*;
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use openssl::pkcs12::Pkcs12;
use std::process::Command;
use std::io::Write;
use tempfile::NamedTempFile;
use vaultls::cert::Certificate;
use vaultls::data::enums::{CertificateRenewMethod, CertificateType};
use vaultls::data::api::CreateUserCertificateRequest;

#[tokio::test]
async fn test_subordinate_ca_with_aia_cdp_urls_integration() -> Result<()> {
    println!("🏛️ Testing subordinate CA creation with AIA/CDP URLs via API...");

    // Create authenticated test client
    let client = VaulTLSClient::new_authenticated().await;

    // Test URLs for AIA and CDP extensions
    let aia_url = "http://ca.example.com/api/certificates/ca/download";
    let cdp_url = "http://ca.example.com/api/certificates/crl";

    // Create subordinate CA certificate via API with AIA and CDP URLs
    let cert_req = CreateUserCertificateRequest {
        cert_name: "subordinate-ca-aia-cdp-test".to_string(),
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
    assert_eq!(response.status(), Status::Ok, "API request should succeed");

    let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(cert.name, "subordinate-ca-aia-cdp-test");
    assert_eq!(cert.certificate_type, CertificateType::SubordinateCA);
    println!("✅ Subordinate CA certificate created via API");

    // Download the subordinate CA certificate in P12 format
    let cert_p12 = client.download_cert_as_p12(&cert.id.to_string()).await?;
    assert!(!cert_p12.is_empty(), "Certificate P12 data should not be empty");
    println!("✅ Subordinate CA certificate downloaded: {} bytes", cert_p12.len());

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
    let aia_present = aia_output.status.success() && !aia_output_str.trim().is_empty();
    assert!(aia_present, "AIA extension should be present: {}", aia_output_str);

    println!("✅ AIA extension verified (present and has content)");

    // Use OpenSSL to check for CRL Distribution Points extension
    let cdp_output = Command::new("openssl")
        .args(["x509", "-in", &cert_path.to_string_lossy(), "-ext", "crlDistributionPoints", "-noout"])
        .output()?;

    let cdp_output_str = String::from_utf8(cdp_output.stdout)?;
    let cdp_present = cdp_output.status.success() && !cdp_output_str.trim().is_empty();
    assert!(cdp_present, "CRL Distribution Points extension should be present: {}", cdp_output_str);

    println!("✅ CDP extension verified (present and has content)");

    // Verify the certificate is actually a CA certificate
    let bc_output = Command::new("openssl")
        .args(["x509", "-in", &cert_path.to_string_lossy(), "-text", "-noout"])
        .output()?;

    let bc_output_str = String::from_utf8(bc_output.stdout)?;
    assert!(bc_output_str.contains("CA:TRUE"), "Certificate should be a CA certificate");

    println!("✅ CA basic constraints verified (CA:TRUE present)");
    println!("🎉 Subordinate CA with AIA/CDP URLs successfully created and verified!");
    println!("   📊 Certificate ID: {}", cert.id);
    println!("   📊 Certificate Type: {:?}", cert.certificate_type);
    println!("   📊 Requested AIA URL: {}", aia_url);
    println!("   📊 Requested CDP URL: {}", cdp_url);
    println!("   📊 AIA Extension Present: {}", aia_present);
    println!("   📊 CDP Extension Present: {}", cdp_present);
    println!("   📊 CA Basic Constraint: Present");

    // Verify extension content contains expected URLs or references
    if aia_present {
        assert!(aia_output_str.contains("ca.cert") ||
               aia_output_str.contains("authorityInfoAccess") ||
               aia_output_str.contains("http"),
               "AIA extension should reference CA certificate or contain HTTP URL: {}", aia_output_str);
    }

    if cdp_present {
        assert!(cdp_output_str.contains("ca.crl") ||
               cdp_output_str.contains("crlDistributionPoints") ||
               cdp_output_str.contains("http"),
               "CDP extension should reference CRL or contain HTTP URL: {}", cdp_output_str);
    }

    println!("✅ Extension URL validation passed");

    Ok(())
}
