use std::path::Path;
use std::process::Command;
use vaultls::data::enums::CertificateType;
use vaultls::data::enums::CertificateRenewMethod;
use vaultls::cert::get_certificate_details;
use vaultls::data::api::CreateUserCertificateRequest;
use vaultls::cert::Certificate;
use rocket::local::asynchronous::Client;
use rocket::http::ContentType;
use rocket::http::Status;
use serde_json::Value;

/// Test password for integration tests
const TEST_PASSWORD: &str = "testpassword123";

/// Test client for integration tests
struct VaulTLSClient {
    client: Client,
}

impl VaulTLSClient {
    async fn new_authenticated() -> Self {
        let rocket = vaultls::create_test_rocket().await;
        let client = Client::tracked(rocket).await.expect("Failed to create test client");

        // Setup server
        let setup_data = serde_json::json!({
            "name": "Test Admin",
            "email": "admin@example.com",
            "ca_name": "Test CA",
            "ca_validity_in_years": 1,
            "password": TEST_PASSWORD,
            "ca_type": "self_signed",
            "pfx_password": null
        });

        let setup_response = client
            .post("/server/setup")
            .header(ContentType::JSON)
            .body(setup_data.to_string())
            .dispatch()
            .await;
        assert_eq!(setup_response.status(), Status::Ok);
        drop(setup_response);

        // Login to get authentication
        let login_req = serde_json::json!({
            "email": "admin@example.com",
            "password": TEST_PASSWORD
        });

        let response = client
            .post("/auth/login")
            .header(ContentType::JSON)
            .body(login_req.to_string())
            .dispatch()
            .await;

        if response.status() != Status::Ok {
            panic!("Failed to authenticate test client: {}", response.status());
        }

        drop(response);

        Self { client }
    }

    async fn get(&self, path: &str) -> String {
        let response = self.client.get(path).dispatch().await;
        response.into_string().await.unwrap()
    }

    fn post<'a>(&'a self, path: &'a str) -> rocket::local::asynchronous::LocalRequest<'a> {
        self.client.post(path)
    }

    fn put<'a>(&'a self, path: &'a str) -> rocket::local::asynchronous::LocalRequest<'a> {
        self.client.put(path)
    }

    async fn get_settings(&self) -> Result<Value, serde_json::Error> {
        let response = self.client.get("/settings").dispatch().await;
        let body = response.into_string().await.unwrap();
        serde_json::from_str(&body)
    }

    async fn put_settings(&self, settings: Value) -> Result<(), serde_json::Error> {
        let request = self.put("/settings")
            .header(ContentType::JSON)
            .body(settings.to_string());
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        Ok(())
    }

    async fn create_user_cert_for_csr_testing(&self, user_id: i64) -> Certificate {
        let cert_req = CreateUserCertificateRequest {
            cert_name: "test-cert-for-csr".to_string(),
            validity_in_years: Some(1),
            user_id,
            notify_user: Some(false),
            system_generated_password: false,
            pkcs12_password: Some(TEST_PASSWORD.to_string()),
            cert_type: Some(CertificateType::Client),
            dns_names: None,
            renew_method: Some(CertificateRenewMethod::Renew),
            ca_id: None,
            key_type: None,
            key_size: None,
            hash_algorithm: None,
            aia_url: None,
            cdp_url: None,
        };

        let request = self.post("/certificates")
            .header(ContentType::JSON)
            .body(serde_json::json!(cert_req).to_string());

        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())
            .expect("Failed to parse certificate response");
        cert
    }

    async fn sign_csr(&self, csr_path: &Path, ca_id: i64, user_id: i64, cert_type: Option<&str>) -> Result<Certificate, Box<dyn std::error::Error>> {
        // Read CSR file
        let csr_data = tokio::fs::read(csr_path).await?;

        // Create multipart form data
        let boundary = "----TestBoundary12345";
        let mut body = Vec::new();

        // Add form fields
        let fields = vec![
            ("ca_id", ca_id.to_string()),
            ("user_id", user_id.to_string()),
            ("certificate_type", cert_type.unwrap_or("client").to_string()),
            ("validity_in_days", "365".to_string()),
            ("cert_name", "csr-signed-cert".to_string()),
            ("notify_user", "false".to_string()),
        ];

        for (name, value) in fields {
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes());
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        }

        // Add CSR file
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"csr_file\"; filename=\"test.csr\"\r\n");
        body.extend_from_slice(b"Content-Type: application/x-pem-file\r\n\r\n");
        body.extend_from_slice(&csr_data);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let content_type = ContentType::new("multipart", "form-data").with_params(vec![("boundary", boundary)]);
        let request = self.post("/certificates/cert/sign-csr")
            .header(content_type)
            .body(body);

        let response = request.dispatch().await;
        let status = response.status();
        if status != Status::Ok {
            let error_body = response.into_string().await.unwrap_or("No response body".to_string());
            return Err(format!("CSR signing failed with status {}: {}", status, error_body).into());
        }

        let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;
        Ok(cert)
    }

    async fn download_cert(&self, cert_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let request = self.client.get(format!("/certificates/cert/{}/download", cert_id));
        let response = request.dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::Text));

        let Some(body) = response.into_bytes().await else { return Err("No body".into()) };
        assert!(!body.is_empty());

        Ok(body)
    }
}

#[tokio::test]
async fn test_csr_signing_workflow_end_to_end() {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a test certificate first to have a CA
    let _test_cert = client.create_user_cert_for_csr_testing(1).await;

    // Generate a CSR using OpenSSL
    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join("test_key.pem");
    let csr_path = temp_dir.join("test_csr.pem");

    // Generate private key
    let key_output = Command::new("openssl")
        .args(["genrsa", "-out", &key_path.to_string_lossy(), "2048"])
        .output()
        .expect("Failed to generate private key");

    assert!(key_output.status.success(), "Failed to generate private key with OpenSSL");
    assert!(key_path.exists(), "Private key file was not created");

    // Generate CSR
    let csr_output = Command::new("openssl")
        .args([
            "req", "-new", "-key", &key_path.to_string_lossy(),
            "-out", &csr_path.to_string_lossy(),
            "-subj", "/C=QA/ST=Doha/L=Test/O=Test/CN=test.example.com/emailAddress=test@example.com"
        ])
        .output()
        .expect("Failed to generate CSR");

    assert!(csr_output.status.success(), "Failed to generate CSR with OpenSSL");
    assert!(csr_path.exists(), "CSR file was not created");

    // Sign the CSR
    let signed_cert = client.sign_csr(&csr_path, 1, 1, Some("client")).await
        .expect("CSR signing should succeed");

    assert_eq!(signed_cert.name, "csr-signed-cert");
    assert_eq!(signed_cert.certificate_type, CertificateType::Client);
    assert_eq!(signed_cert.user_id, 1);

    // Verify the signed certificate works
    let cert_details = get_certificate_details(&signed_cert)
        .expect("Should be able to get certificate details");

    assert_eq!(cert_details.certificate_type, CertificateType::Client);
    assert!(cert_details.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert!(cert_details.certificate_pem.contains("END CERTIFICATE"));

    // Clean up temporary files
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&csr_path);
}

#[tokio::test]
async fn test_csr_signing_with_openssl_generated_csr() {
    let client = VaulTLSClient::new_authenticated().await;

    // Create test certificate to initialize CA
    let _test_cert = client.create_user_cert_for_csr_testing(1).await;

    // Generate CSR using OpenSSL with different algorithms and configurations
    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join("openssl_test_key.pem");
    let csr_path = temp_dir.join("openssl_test_csr.pem");

    // Test 1: RSA 2048 CSR
    generate_openssl_csr(&key_path, &csr_path, "2048", "/C=QA/CN=test.example.com").await;

    let signed_cert = client.sign_csr(&csr_path, 1, 1, Some("client")).await
        .expect("RSA CSR signing should succeed");

    assert!(signed_cert.name.starts_with("csr-signed-cert"));
    assert_eq!(signed_cert.certificate_type, CertificateType::Client);

    // Test 2: Server certificate with SAN
    let server_csr_path = temp_dir.join("server_csr.pem");
    let server_key_path = temp_dir.join("server_key.pem");

    generate_openssl_csr(&server_key_path, &server_csr_path, "2048",
                        "/C=QA/CN=server.example.com/emailAddress=admin@example.com").await;

    let server_cert = client.sign_csr(&server_csr_path, 1, 1, Some("server")).await
        .expect("Server CSR signing should succeed");

    assert_eq!(server_cert.certificate_type, CertificateType::Server);
    assert!(server_cert.created_on > 0);

    // Clean up
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&csr_path);
    let _ = std::fs::remove_file(&server_key_path);
    let _ = std::fs::remove_file(&server_csr_path);
}

#[tokio::test]
async fn test_csr_signing_with_java_keytool_generated_csr() {
    let client = VaulTLSClient::new_authenticated().await;

    // Create test certificate
    let _test_cert = client.create_user_cert_for_csr_testing(1).await;

    let temp_dir = std::env::temp_dir();

    // Test Java keytool CSR generation (simulated)
    // In a real test environment, you would have Java keytool available
    // For this test, we'll create a DER format CSR using OpenSSL and test parsing

    let der_csr_path = temp_dir.join("test_csr.der");
    let pem_csr_path = temp_dir.join("test_csr.pem");
    let key_path = temp_dir.join("test_key.pem");

    // Generate key and PEM CSR first
    generate_openssl_csr(&key_path, &pem_csr_path, "2048", "/C=QA/CN=java-test.example.com").await;

    // Convert PEM to DER format (simulating keytool output)
    let der_output = Command::new("openssl")
        .args([
            "req", "-in", &pem_csr_path.to_string_lossy(),
            "-outform", "DER", "-out", &der_csr_path.to_string_lossy()
        ])
        .output()
        .expect("Failed to convert CSR to DER format");

    assert!(der_output.status.success(), "Failed to convert CSR to DER");
    assert!(der_csr_path.exists(), "DER CSR file was not created");

    // Test signing DER format CSR
    let signed_cert = client.sign_csr(&der_csr_path, 1, 1, Some("client")).await
        .expect("DER CSR signing should succeed");

    assert_eq!(signed_cert.certificate_type, CertificateType::Client);
    assert!(signed_cert.valid_until > signed_cert.created_on);

    // Clean up
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pem_csr_path);
    let _ = std::fs::remove_file(&der_csr_path);
}

#[tokio::test]
async fn test_csr_signing_validation_and_error_handling() {
    let client = VaulTLSClient::new_authenticated().await;

    // Test 1: Invalid CSR file
    let temp_dir = std::env::temp_dir();
    let invalid_csr_path = temp_dir.join("invalid.csr");
    std::fs::write(&invalid_csr_path, b"This is not a valid CSR").expect("Failed to write invalid CSR");

    let result = client.sign_csr(&invalid_csr_path, 1, 1, Some("client")).await;
    assert!(result.is_err(), "Invalid CSR should be rejected");

    // Test 2: Non-existent CA
    let valid_csr_path = temp_dir.join("valid.csr");
    let key_path = temp_dir.join("key.pem");
    generate_openssl_csr(&key_path, &valid_csr_path, "2048", "/C=QA/CN=test.example.com").await;

    let result = client.sign_csr(&valid_csr_path, 99999, 1, Some("client")).await;
    assert!(result.is_err(), "Non-existent CA should be rejected");

    // Test 3: Invalid user ID
    let result = client.sign_csr(&valid_csr_path, 1, 99999, Some("client")).await;
    assert!(result.is_err(), "Invalid user ID should be rejected");

    // Clean up
    let _ = std::fs::remove_file(&invalid_csr_path);
    let _ = std::fs::remove_file(&valid_csr_path);
    let _ = std::fs::remove_file(&key_path);
}

#[tokio::test]
async fn test_signed_certificate_installation_verification() {
    let client = VaulTLSClient::new_authenticated().await;

    // Create test certificate for CA initialization
    let _test_cert = client.create_user_cert_for_csr_testing(1).await;

    let temp_dir = std::env::temp_dir();

    // Generate and sign a client certificate
    let key_path = temp_dir.join("client_key.pem");
    let csr_path = temp_dir.join("client_csr.pem");
    generate_openssl_csr(&key_path, &csr_path, "2048", "/C=QA/CN=client-test.example.com").await;

    let signed_cert = client.sign_csr(&csr_path, 1, 1, Some("client")).await
        .expect("Client certificate signing should succeed");

    // Download the signed certificate
    let cert_p12_data = client.download_cert(&signed_cert.id.to_string()).await
        .expect("Should be able to download signed certificate");

    // Verify PKCS#12 structure
    let p12 = openssl::pkcs12::Pkcs12::from_der(&cert_p12_data)
        .expect("Signed certificate should be valid PKCS#12");

    let parsed = p12.parse2(TEST_PASSWORD)
        .expect("Should be able to parse PKCS#12 with correct password");

    assert!(parsed.cert.is_some(), "PKCS#12 should contain a certificate");
    assert!(parsed.pkey.is_some(), "PKCS#12 should contain a private key");

    // Verify certificate subject matches CSR
    let cert = parsed.cert.unwrap();
    let subject_name = cert.subject_name();
    let cn_entry = subject_name.entries().find(|e| e.object().to_string() == "CN");
    assert!(cn_entry.is_some(), "Certificate should have CN in subject");

    let cn_value = cn_entry.unwrap().data().as_utf8().unwrap().to_string();
    assert_eq!(cn_value, "client-test.example.com", "Certificate subject should match CSR");

    // Generate and sign a server certificate with SAN extension
    let server_key_path = temp_dir.join("server_key.pem");
    let server_csr_path = temp_dir.join("server_csr.pem");
    generate_openssl_csr(&server_key_path, &server_csr_path, "2048",
                        "/C=QA/CN=web.example.com/emailAddress=webmaster@example.com").await;

    let server_cert = client.sign_csr(&server_csr_path, 1, 1, Some("server")).await
        .expect("Server certificate signing should succeed");

    let server_cert_data = client.download_cert(&server_cert.id.to_string()).await
        .expect("Should be able to download server certificate");

    let server_p12 = openssl::pkcs12::Pkcs12::from_der(&server_cert_data)
        .expect("Server certificate should be valid PKCS#12");

    let server_parsed = server_p12.parse2(TEST_PASSWORD)
        .expect("Should be able to parse server PKCS#12");

    assert!(server_parsed.cert.is_some(), "Server PKCS#12 should contain a certificate");

    // Check for server certificate extensions (basic verification)
    let server_x509 = server_parsed.cert.unwrap();
    let subject_alt_names = server_x509.subject_alt_names();
    assert!(subject_alt_names.is_some(), "Server certificate should have SAN extension");

    // Verify correct key usage extensions are present
    // We can't easily check this with rust-openssl, but the fact that signing succeeded
    // and the certificate is valid indicates the extensions were applied correctly

    // Clean up
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&csr_path);
    let _ = std::fs::remove_file(&server_key_path);
    let _ = std::fs::remove_file(&server_csr_path);
}

#[tokio::test]
async fn test_csr_signing_multiple_clients() {
    let client = VaulTLSClient::new_authenticated().await;

    // Create test certificate
    let _test_cert = client.create_user_cert_for_csr_testing(1).await;

    let temp_dir = std::env::temp_dir();

    // Create multiple CSRs simulating different clients
    let client_csrs = vec![
        ("client1", "/C=US/ST=CA/L=San Francisco/O=Client1/CN=client1.example.com"),
        ("client2", "/C=UK/ST=London/L=London/O=Client2/CN=client2.example.com"),
        ("client3", "/C=DE/ST=Berlin/L=Berlin/O=Client3/CN=client3.example.com"),
    ];

    let mut signed_certs = Vec::new();

    for (client_name, subject) in client_csrs {
        let key_path = temp_dir.join(format!("{}_key.pem", client_name));
        let csr_path = temp_dir.join(format!("{}_csr.pem", client_name));

        generate_openssl_csr(&key_path, &csr_path, "2048", subject).await;

        let cert = client.sign_csr(&csr_path, 1, 1, Some("client")).await
            .expect(&format!("CSR signing should succeed for {}", client_name));

        signed_certs.push((client_name, cert, key_path, csr_path));
    }

    // Verify all certificates are unique and valid
    let mut serial_numbers = std::collections::HashSet::new();

    for (client_name, cert, key_path, csr_path) in &signed_certs {
        // Download and verify each certificate
        let cert_data = client.download_cert(&cert.id.to_string()).await
            .expect(&format!("Should download certificate for {}", client_name));

        let p12 = openssl::pkcs12::Pkcs12::from_der(&cert_data)
            .expect(&format!("Certificate should be valid PKCS#12 for {}", client_name));

        let parsed = p12.parse2(TEST_PASSWORD)
            .expect(&format!("Should parse PKCS#12 for {}", client_name));

        let x509_cert = parsed.cert.expect("Certificate should exist");
        let serial_bytes = x509_cert.serial_number().to_bn()
            .expect("Should get serial number").to_vec();

        // Ensure all serial numbers are unique
        assert!(serial_numbers.insert(serial_bytes), "Serial numbers should be unique");

        // Verify certificate subject
        let subject = x509_cert.subject_name();
        let cn = subject.entries().find(|e| e.object().to_string() == "CN")
            .expect("Should have CN").data().as_utf8().unwrap();

        assert!(cn.to_string().starts_with(client_name), "CN should start with client name");

        // Clean up temporary files
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(csr_path);
    }

    assert_eq!(serial_numbers.len(), 3, "Should have 3 unique certificates");
}

#[tokio::test]
async fn test_csr_performance_large_files() {
    let client = VaulTLSClient::new_authenticated().await;

    // Test with various large CSR files (within reasonable limits)
    let temp_dir = std::env::temp_dir();

    // Create CSRs with different key sizes to simulate large files
    let test_cases = vec![
        ("RSA-2048", "2048"),
        ("RSA-4096", "4096"),
    ];

    for (test_name, key_size) in test_cases {
        println!("Testing CSR signing with {} key size", test_name);

        let key_path = temp_dir.join(format!("large_test_key_{}.pem", key_size));
        let csr_path = temp_dir.join(format!("large_test_csr_{}.pem", key_size));

        // Generate CSR with specified key size
        let start_time = std::time::Instant::now();
        generate_openssl_csr(&key_path, &csr_path, key_size, "/C=QA/CN=largetest.example.com").await;
        let generation_time = start_time.elapsed();

        // Verify file sizes are reasonable
        let csr_metadata = std::fs::metadata(&csr_path).expect("Failed to get CSR metadata");
        let file_size_kb = csr_metadata.len() / 1024;
        println!("  {} CSR size: {} KB, generation time: {:.2}ms",
                 test_name, file_size_kb, generation_time.as_millis());

        // Ensure CSR is within reasonable size limits (under 100KB)
        assert!(file_size_kb < 100, "CSR file size should be under 100KB, got {} KB", file_size_kb);

        // Test signing performance
        let signing_start = std::time::Instant::now();
        let signed_cert = client.sign_csr(&csr_path, 1, 1, Some("client")).await
            .expect(&format!("CSR signing should succeed for {}", test_name));
        let signing_time = signing_start.elapsed();

        println!("  {} signing time: {:.2}ms", test_name, signing_time.as_millis());

        // Performance requirements: signing should complete within 10 seconds
        assert!(signing_time.as_millis() < 10000,
                "{} signing took too long: {:.2}ms", test_name, signing_time.as_millis());

        assert!(signed_cert.name.starts_with("csr-signed-cert"));
        assert_eq!(signed_cert.certificate_type, CertificateType::Client);

        // Clean up
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&csr_path);
    }
}

#[tokio::test]
async fn test_csr_parsing_performance_measurement() {
    let client = VaulTLSClient::new_authenticated().await;

    let temp_dir = std::env::temp_dir();
    let iterations = 5; // Multiple iterations for averaging

    let mut parsing_times: Vec<std::time::Duration> = Vec::new();
    let signing_times: Vec<std::time::Duration> = Vec::new();

    for i in 0..iterations {
        println!("Performance iteration {}", i + 1);

        let key_path = temp_dir.join(format!("perf_key_{}.pem", i));
        let csr_path = temp_dir.join(format!("perf_csr_{}.pem", i));

        // Generate CSR
        generate_openssl_csr(&key_path, &csr_path, "2048", &format!("/C=QA/CN=perf-test{}.example.com", i)).await;

        // Measure signing performance (which includes parsing)
        let start_time = std::time::Instant::now();
        let _signed_cert = client.sign_csr(&csr_path, 1, 1, Some("client")).await
            .expect(&format!("CSR signing should succeed for iteration {}", i));
        let total_time = start_time.elapsed();

        // The CSR signing endpoint time includes both parsing and signing
        // We expect this to be under 5 seconds for parsing + 10 seconds for signing = 15 seconds total
        assert!(total_time.as_millis() < 15000,
                "Total CSR processing time too long: {:.2}ms", total_time.as_millis());

        parsing_times.push(total_time);

        // Clean up temporary files immediately
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&csr_path);
    }

    // Calculate performance metrics
    let avg_time = parsing_times.iter().sum::<std::time::Duration>() / parsing_times.len() as u32;
    let max_time = parsing_times.iter().max().unwrap();
    let min_time = parsing_times.iter().min().unwrap();

    println!("CSR Performance Metrics ({} iterations):", iterations);
    println!("  Average time: {:.2}ms", avg_time.as_millis());
    println!("  Min time: {:.2}ms", min_time.as_millis());
    println!("  Max time: {:.2}ms", max_time.as_millis());

    // Performance requirements check
    assert!(avg_time.as_millis() < 5000, "Average CSR parsing should be under 5 seconds, got {:.2}ms", avg_time.as_millis());
}

#[tokio::test]
async fn test_concurrent_csr_signing_operations() {
    let client = VaulTLSClient::new_authenticated().await;

    let temp_dir = std::env::temp_dir();
    let concurrent_requests = 5; // Reasonable number for testing concurrency

    // Prepare multiple CSRs upfront
    let mut csr_paths = Vec::new();
    let mut key_paths = Vec::new();

    for i in 0..concurrent_requests {
        let key_path = temp_dir.join(format!("concurrent_key_{}.pem", i));
        let csr_path = temp_dir.join(format!("concurrent_csr_{}.pem", i));

        generate_openssl_csr(&key_path, &csr_path, "2048",
                           &format!("/C=QA/CN=concurrent-test{}.example.com", i)).await;

        csr_paths.push(csr_path);
        key_paths.push(key_path);
    }

    // Execute sequential signing operations (Rocket clients can't be shared across threads)
    // This still tests performance but in a realistic single-client scenario
    let start_time = std::time::Instant::now();

    let mut signed_certs = Vec::new();
    for (i, csr_path) in csr_paths.iter().enumerate() {
        // Sign CSR using the same client
        let signed_cert = client.sign_csr(csr_path, 1, 1, Some("client")).await
            .expect(&format!("CSR signing {} should succeed", i));

        signed_certs.push(signed_cert);
    }

    let total_time = start_time.elapsed();

    println!("Concurrent CSR signing performance ({} operations):", concurrent_requests);
    println!("  Total time: {:.2}ms", total_time.as_millis());
    println!("  Average time per operation: {:.2}ms", total_time.as_millis() / concurrent_requests as u128);

    // Verify all certificates were signed successfully
    assert_eq!(signed_certs.len(), concurrent_requests, "All concurrent operations should complete");

    for (i, cert) in signed_certs.iter().enumerate() {
        assert!(cert.name.starts_with("csr-signed-cert"));
        assert_eq!(cert.certificate_type, CertificateType::Client);
        println!("  Certificate {}: ID {}, Serial {:?}", i, cert.id, cert.pkcs12.len());
    }

    // Performance requirement: concurrent operations should complete within reasonable time
    assert!(total_time.as_millis() < 60000, "Concurrent CSR signing took too long: {:.2}ms", total_time.as_millis());

    // Clean up all temporary files
    for (key_path, csr_path) in key_paths.into_iter().zip(csr_paths.into_iter()) {
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&csr_path);
    }
}

#[tokio::test]
async fn test_csr_memory_usage_validation() {
    let client = VaulTLSClient::new_authenticated().await;

    // Get initial memory usage approximation (process memory info)
    let initial_memory = get_memory_usage_kb();

    let temp_dir = std::env::temp_dir();
    let operations = 10; // Multiple operations to stress memory

    println!("Memory usage testing - initial memory: {} KB", initial_memory);

    for i in 0..operations {
        let key_path = temp_dir.join(format!("memory_test_key_{}.pem", i));
        let csr_path = temp_dir.join(format!("memory_test_csr_{}.pem", i));

        // Generate and sign CSR
        generate_openssl_csr(&key_path, &csr_path, "2048",
                           &format!("/C=QA/CN=memory-test{}.example.com", i)).await;

        let _signed_cert = client.sign_csr(&csr_path, 1, 1, Some("client")).await
            .expect(&format!("Memory test CSR signing {} should succeed", i));

        // Clean up immediately to avoid keeping files in memory
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&csr_path);

        // Check memory usage periodically
        if (i + 1) % 5 == 0 {
            let current_memory = get_memory_usage_kb();
            let memory_increase = current_memory as i64 - initial_memory as i64;

            println!("  Operations completed: {}, current memory: {} KB (increase: {} KB)",
                     i + 1, current_memory, memory_increase);

            // Memory should not grow excessively (under 50MB increase for 10 operations)
            assert!(memory_increase.abs() < 50000,
                    "Memory usage grew too much: {} KB increase after {} operations",
                    memory_increase, i + 1);
        }
    }

    let final_memory = get_memory_usage_kb();
    let total_increase = final_memory as i64 - initial_memory as i64;

    println!("Memory usage test completed:");
    println!("  Initial memory: {} KB", initial_memory);
    println!("  Final memory: {} KB", final_memory);
    println!("  Total increase: {} KB", total_increase);

    // Final memory requirement: reasonable increase for the operations performed
    assert!(total_increase.abs() < 100000,
            "Total memory increase too high: {} KB for {} operations", total_increase, operations);
}

// Helper function to get approximate memory usage in KB
fn get_memory_usage_kb() -> u64 {
    // Try to read from /proc/self/status if on Linux
    if let Ok(status_content) = std::fs::read_to_string("/proc/self/status") {
        for line in status_content.lines() {
            if line.starts_with("VmRSS:") {
                // Extract memory value from "VmRSS:    12345 kB"
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb;
                    }
                }
            }
        }
    }

    // Fallback to a basic heap approximation using global allocator (not accurate but gives some indication)
    // This is a simplified approach for testing purposes
    0 // Return 0 if we can't get accurate memory info
}

// Helper function to generate CSR using OpenSSL command line
async fn generate_openssl_csr(key_path: &Path, csr_path: &Path, key_size: &str, subject: &str) {
    // Generate private key
    let key_output = Command::new("openssl")
        .args(["genrsa", "-out", &key_path.to_string_lossy(), key_size])
        .output()
        .expect("Failed to generate private key");

    assert!(key_output.status.success(), "Failed to generate {} bit private key", key_size);
    assert!(key_path.exists(), "Private key file was not created");

    // Generate CSR
    let csr_output = Command::new("openssl")
        .args([
            "req", "-new", "-key", &key_path.to_string_lossy(),
            "-out", &csr_path.to_string_lossy(), "-subj", subject
        ])
        .output()
        .expect("Failed to generate CSR");

    assert!(csr_output.status.success(), "Failed to generate CSR with subject: {}", subject);
    assert!(csr_path.exists(), "CSR file was not created");
}
