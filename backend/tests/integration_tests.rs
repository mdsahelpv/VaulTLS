use std::fs;
use std::path::Path;
use vaultls::data::enums::CertificateType;
use vaultls::cert::CertificateBuilder;
use vaultls::create_test_rocket;
use rocket::local::asynchronous::Client;

/// Test CA setup using yawal-ca.pfx and certificate issuance
#[cfg(test)]
mod ca_setup_and_certificate_tests {
    use super::*;

    /// Test CA setup from PFX file
    #[tokio::test]
    async fn test_ca_setup_from_pfx() {
        // Create test rocket instance
        let rocket = create_test_rocket().await;
        let _client = Client::tracked(rocket).await.expect("Failed to create test client");

        // Check if yawal-ca.pfx exists (from backend directory, need to go up one level)
        let pfx_path = Path::new("../yawal-ca.pfx");
        assert!(pfx_path.exists(), "yawal-ca.pfx file not found in root directory");

        // Read the PFX file
        let pfx_data = fs::read(pfx_path)
            .expect("Failed to read yawal-ca.pfx file");

        // Setup CA from PFX using the correct password
        let ca = CertificateBuilder::from_pfx(&pfx_data, Some("P@ssw0rd"), Some("Test CA from PFX"))
            .expect("Failed to create CA from PFX with correct password");

        // Verify CA structure
        assert!(ca.cert.len() > 0);
        assert!(ca.key.len() > 0);
        assert_eq!(ca.id, -1); // New CA hasn't been saved yet

        println!("✅ CA setup from PFX successful - Cert size: {} bytes, Key size: {} bytes",
                 ca.cert.len(), ca.key.len());
    }

    /// Test creating a self-signed CA certificate
    #[tokio::test]
    async fn test_create_self_signed_ca() {
        // Create a self-signed CA certificate
        let ca = CertificateBuilder::new_with_ca(None)
            .unwrap()
            .set_name("Test Self-Signed CA")
            .unwrap()
            .set_valid_until(5) // 5 years validity
            .unwrap()
            .build_ca()
            .unwrap();

        // Verify CA structure
        assert_eq!(ca.id, -1); // New CA
        assert!(ca.cert.len() > 0);
        assert!(ca.key.len() > 0);
        assert!(ca.created_on > 0);
        assert!(ca.valid_until > ca.created_on);

        println!("✅ Self-signed CA created successfully - Cert size: {} bytes", ca.cert.len());
    }

    /// Test issuing client certificates from CA
    #[tokio::test]
    async fn test_issue_client_certificates_from_ca() {
        // First create a CA
        let ca = CertificateBuilder::new_with_ca(None)
            .unwrap()
            .set_name("Test CA for Client Certs")
            .unwrap()
            .set_valid_until(2)
            .unwrap()
            .build_ca()
            .unwrap();

        // Issue 5 client certificates
        for i in 1..=5 {
            let cert_name = format!("Test Client Certificate {}", i);

            let certificate = CertificateBuilder::new_with_ca(Some(&ca))
                .unwrap()
                .set_ca(&ca)
                .unwrap()
                .set_name(&cert_name)
                .unwrap()
                .set_valid_until(1) // 1 year validity
                .unwrap()
                .set_pkcs12_password("testpassword123")
                .unwrap()
                .set_user_id(1)
                .unwrap()
                .build_client()
                .unwrap();

            // Verify certificate structure
            assert_eq!(certificate.name, cert_name);
            assert_eq!(certificate.certificate_type, CertificateType::Client);
            assert_eq!(certificate.user_id, 1);
            assert!(certificate.pkcs12.len() > 0);
            assert_eq!(certificate.pkcs12_password, "testpassword123");
            assert_eq!(certificate.ca_id, ca.id);

            println!("✅ Client Certificate {} created - PKCS12 size: {} bytes",
                     i, certificate.pkcs12.len());
        }

        println!("✅ All 5 client certificates issued successfully!");
    }

    /// Test issuing server certificates with SAN entries
    #[tokio::test]
    async fn test_issue_server_certificates_with_san() {
        // First create a CA
        let ca = CertificateBuilder::new_with_ca(None)
            .unwrap()
            .set_name("Test CA for Server Certs")
            .unwrap()
            .set_valid_until(2)
            .unwrap()
            .build_ca()
            .unwrap();

        // Issue 5 server certificates with different SAN configurations
        let san_configs = vec![
            vec!["example.com".to_string()],
            vec!["test.example.com".to_string(), "www.test.example.com".to_string()],
            vec!["api.example.com".to_string(), "*.example.com".to_string()],
            vec!["localhost".to_string()],
            vec!["vaultls.local".to_string(), "*.local".to_string()],
        ];

        for (i, sans) in san_configs.iter().enumerate() {
            let cert_name = format!("Test Server Certificate {}", i + 1);

            let certificate = CertificateBuilder::new_with_ca(Some(&ca))
                .unwrap()
                .set_ca(&ca)
                .unwrap()
                .set_name(&cert_name)
                .unwrap()
                .set_valid_until(1)
                .unwrap()
                .set_pkcs12_password("serverpassword123")
                .unwrap()
                .set_user_id(1)
                .unwrap()
                .set_dns_san(sans)
                .unwrap()
                .build_server()
                .unwrap();

            // Verify certificate structure
            assert_eq!(certificate.name, cert_name);
            assert_eq!(certificate.certificate_type, CertificateType::Server);
            assert_eq!(certificate.user_id, 1);
            assert!(certificate.pkcs12.len() > 0);
            assert_eq!(certificate.pkcs12_password, "serverpassword123");

            println!("✅ Server Certificate {} created - SAN: {:?}, PKCS12 size: {} bytes",
                     i + 1, sans, certificate.pkcs12.len());
        }

        println!("✅ All 5 server certificates with SAN issued successfully!");
    }

    /// Test CA setup from PFX file and certificate creation
    #[tokio::test]
    async fn test_pfx_import_and_certificate_creation() {
        // Check if yawal-ca.pfx exists (from backend directory, need to go up one level)
        let pfx_path = Path::new("../yawal-ca.pfx");
        assert!(pfx_path.exists(), "yawal-ca.pfx file not found in root directory");

        // Read the PFX file
        let pfx_data = fs::read(pfx_path)
            .expect("Failed to read yawal-ca.pfx file");

        println!("📋 Read PFX file: {} bytes", pfx_data.len());

        // Import CA from PFX using the correct password
        let imported_ca = CertificateBuilder::from_pfx(&pfx_data, Some("P@ssw0rd"), Some("Imported Test CA"))
            .expect("Failed to import CA from PFX with correct password");

        println!("✅ CA imported from PFX - Cert: {} bytes, Key: {} bytes",
                 imported_ca.cert.len(), imported_ca.key.len());

        // Create certificates using the imported CA
        for i in 1..=3 {
            let cert_name = format!("Certificate from Imported CA {}", i);

            let certificate = CertificateBuilder::new_with_ca(Some(&imported_ca))
                .unwrap()
                .set_ca(&imported_ca)
                .unwrap()
                .set_name(&cert_name)
                .unwrap()
                .set_valid_until(1)
                .unwrap()
                .set_pkcs12_password(&format!("importpass{}", i))
                .unwrap()
                .set_user_id(1)
                .unwrap()
                .build_client()
                .unwrap();

            assert!(certificate.pkcs12.len() > 0);
            println!("✅ Certificate {} created from imported CA - PKCS12: {} bytes",
                     i, certificate.pkcs12.len());
        }

        println!("✅ PFX import and certificate creation test completed!");
    }

    /// Test comprehensive certificate workflow
    #[tokio::test]
    async fn test_comprehensive_certificate_workflow() {
        println!("🚀 Starting comprehensive certificate workflow test...");

        // Step 1: Create self-signed CA
        println!("📋 Step 1: Creating self-signed CA...");
        let ca = CertificateBuilder::new_with_ca(None)
            .unwrap()
            .set_name("Comprehensive Test CA")
            .unwrap()
            .set_valid_until(10)
            .unwrap()
            .build_ca()
            .unwrap();
        println!("✅ CA created: {} bytes certificate", ca.cert.len());

        // Step 2: Issue 5 client certificates
        println!("📋 Step 2: Issuing 5 client certificates...");
        let mut client_certs = Vec::new();
        for i in 1..=5 {
            let cert_name = format!("Comprehensive Client {}", i);
            let certificate = CertificateBuilder::new_with_ca(Some(&ca))
                .unwrap()
                .set_ca(&ca)
                .unwrap()
                .set_name(&cert_name)
                .unwrap()
                .set_valid_until(1)
                .unwrap()
                .set_pkcs12_password(&format!("clientpass{}", i))
                .unwrap()
                .set_user_id(1)
                .unwrap()
                .build_client()
                .unwrap();

            let pkcs12_size = certificate.pkcs12.len();
            client_certs.push(certificate);
            println!("  ✅ Client {}: {} bytes PKCS12", i, pkcs12_size);
        }

        // Step 3: Issue 5 server certificates with SAN
        println!("📋 Step 3: Issuing 5 server certificates with SAN...");
        let server_sans = vec![
            vec!["app.example.com".to_string()],
            vec!["api.example.com".to_string(), "*.example.com".to_string()],
            vec!["test.local".to_string()],
            vec!["vaultls.internal".to_string(), "ca.internal".to_string()],
            vec!["demo.vaultls.com".to_string()],
        ];

        let mut server_certs = Vec::new();
        for (i, sans) in server_sans.iter().enumerate() {
            let cert_name = format!("Comprehensive Server {}", i + 1);
            let certificate = CertificateBuilder::new_with_ca(Some(&ca))
                .unwrap()
                .set_ca(&ca)
                .unwrap()
                .set_name(&cert_name)
                .unwrap()
                .set_valid_until(1)
                .unwrap()
                .set_pkcs12_password(&format!("serverpass{}", i + 1))
                .unwrap()
                .set_user_id(1)
                .unwrap()
                .set_dns_san(sans)
                .unwrap()
                .build_server()
                .unwrap();

            let pkcs12_size = certificate.pkcs12.len();
            server_certs.push(certificate);
            println!("  ✅ Server {}: {} SAN entries, {} bytes PKCS12",
                     i + 1, sans.len(), pkcs12_size);
        }

        // Step 4: Verify all certificates
        println!("📋 Step 4: Verifying certificate creation...");
        assert_eq!(client_certs.len(), 5, "Expected 5 client certificates");
        assert_eq!(server_certs.len(), 5, "Expected 5 server certificates");

        // Verify all certificates have valid PKCS12 data
        for (i, cert) in client_certs.iter().enumerate() {
            assert!(cert.pkcs12.len() > 100, "Client cert {} has invalid PKCS12", i + 1);
            assert!(cert.pkcs12_password.starts_with("clientpass"));
        }

        for (i, cert) in server_certs.iter().enumerate() {
            assert!(cert.pkcs12.len() > 100, "Server cert {} has invalid PKCS12", i + 1);
            assert!(cert.pkcs12_password.starts_with("serverpass"));
        }

        // Step 5: Summary
        let total_pkcs12_size: usize = client_certs.iter().map(|c| c.pkcs12.len()).sum::<usize>() +
                                       server_certs.iter().map(|c| c.pkcs12.len()).sum::<usize>();

        println!("🎉 Comprehensive test completed successfully!");
        println!("   📊 CA: 1 created ({} bytes cert)", ca.cert.len());
        println!("   📊 Client Certificates: 5 issued");
        println!("   📊 Server Certificates: 5 issued (with SAN)");
        println!("   📊 Total Certificates: 10");
        println!("   📊 Total PKCS12 Size: {} bytes", total_pkcs12_size);
        println!("   📊 Average PKCS12 Size: {} bytes", total_pkcs12_size / 10);
    }
}
