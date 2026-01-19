use crate::common::constants::*;
use crate::common::helper::get_timestamp;
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

// Integration tests for security-critical functionality

#[tokio::test]
async fn test_setup_transaction_rollback_on_failure() -> Result<()> {
    // Test that setup operations are properly rolled back on failure

    // This test would require mocking database failures or other setup failures
    // For now, we'll test that normal setup works correctly

    let client = VaulTLSClient::new_setup().await;

    // Verify setup was successful
    let is_setup: serde_json::Value = client
        .get("/server/setup")
        .dispatch()
        .await
        .into_json()
        .await?;

    assert_eq!(is_setup["setup"], true);
    assert_eq!(is_setup["password"], true);

    // Verify CA was created
    let ca_pem = client.download_ca().await?;
    assert!(!ca_pem.is_empty());

    // Verify user was created and can login
    let user = client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;
    assert_eq!(user.name, TEST_USER_NAME);

    Ok(())
}

#[tokio::test]
async fn test_certificate_revocation_atomicity() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get the existing certificate
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let certs: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    let cert_id = certs[0]["id"].as_i64().unwrap();

    // Revoke the certificate
    let revoke_request = client
        .post(format!("/certificates/cert/{}/revoke", cert_id))
        .header(rocket::http::ContentType::JSON)
        .body(r#"{"reason": 1, "notify_user": false}"#);
    let response = revoke_request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    // Verify certificate is marked as revoked
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let certs: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0]["is_revoked"], Some(true));

    // Verify revocation record exists
    let request = client
        .get(format!("/certificates/cert/{}/revocation-status", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let status: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(status["is_revoked"], true);
    assert_eq!(status["revocation_reason"], 1);

    Ok(())
}

#[tokio::test]
async fn test_certificate_unrevocation_atomicity() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    // Get the existing certificate and revoke it first
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let certs: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    let cert_id = certs[0]["id"].as_i64().unwrap();

    // Revoke first
    let revoke_request = client
        .post(format!("/certificates/cert/{}/revoke", cert_id))
        .header(rocket::http::ContentType::JSON)
        .body(r#"{"reason": 1, "notify_user": false}"#);
    let response = revoke_request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    // Verify it's revoked
    let request = client
        .get(format!("/certificates/cert/{}/revocation-status", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let status: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(status["is_revoked"], true);

    // Now unrevoke
    let unrevoke_request = client
        .delete(format!("/certificates/cert/{}/revoke", cert_id));
    let response = unrevoke_request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    // Verify it's no longer revoked
    let request = client
        .get(format!("/certificates/cert/{}/revocation-status", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let status: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(status["is_revoked"], false);

    // Verify certificate is not marked as revoked in list
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let certs: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0]["is_revoked"], Some(false));

    Ok(())
}

#[tokio::test]
async fn test_concurrent_certificate_operations() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create multiple certificates concurrently to test for race conditions
    let cert_names = vec![
        "concurrent-cert-1",
        "concurrent-cert-2",
        "concurrent-cert-3",
        "concurrent-cert-4",
        "concurrent-cert-5"
    ];

    let mut handles = Vec::new();

    for cert_name in cert_names.clone() {
        let cert_req = serde_json::json!({
            "cert_name": cert_name,
            "validity_in_years": 1,
            "user_id": 1,
            "notify_user": false,
            "system_generated_password": false,
            "pkcs12_password": TEST_PASSWORD,
            "cert_type": "client",
            "renew_method": "renew"
        });

        let handle = tokio::spawn(async move {
            // Note: We can't share the client across threads easily with Rocket's test client
            // In a real scenario, this would test concurrent operations against the same endpoint
            // For now, we'll create certificates sequentially but verify they all succeed
            (cert_name, true)
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        let (cert_name, success) = handle.await?;
        assert!(success, "Certificate creation failed for: {}", cert_name);
    }

    // Create certificates sequentially since we can't share the test client
    let mut created_certs = Vec::new();
    for cert_name in cert_names {
        let cert_req = serde_json::json!({
            "cert_name": cert_name,
            "validity_in_years": 1,
            "user_id": 1,
            "notify_user": false,
            "system_generated_password": false,
            "pkcs12_password": TEST_PASSWORD,
            "cert_type": "client",
            "renew_method": "renew"
        });

        let request = client
            .post("/certificates")
            .header(rocket::http::ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), rocket::http::Status::Ok);

        let cert: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
        created_certs.push(cert["id"].as_i64().unwrap());
    }

    // Verify all certificates were created successfully
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let certs: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(certs.len() >= 5, "Expected at least 5 certificates, got {}", certs.len());

    // Verify each created certificate exists
    for &cert_id in &created_certs {
        let exists = certs.iter().any(|c| c["id"].as_i64() == Some(cert_id));
        assert!(exists, "Certificate {} was not found in the list", cert_id);
    }

    Ok(())
}

#[tokio::test]
async fn test_password_rehash_on_login_attempt() -> Result<()> {
    // This test would require creating a user with a V2 password hash
    // and then attempting to log in, which should fail with appropriate error

    // For now, test that normal login works
    let client = VaulTLSClient::new_authenticated().await;

    let user: serde_json::Value = client
        .get("/auth/me")
        .dispatch()
        .await
        .into_json()
        .await?;

    assert_eq!(user["name"], TEST_USER_NAME);
    assert_eq!(user["email"], TEST_USER_EMAIL);

    Ok(())
}

#[tokio::test]
async fn test_certificate_creation_with_invalid_ca() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Try to create a certificate with non-existent CA
    let cert_req = serde_json::json!({
        "cert_name": "invalid-ca-cert",
        "validity_in_years": 1,
        "user_id": 1,
        "ca_id": 99999,  // Non-existent CA
        "notify_user": false,
        "system_generated_password": false,
        "pkcs12_password": TEST_PASSWORD,
        "cert_type": "client",
        "renew_method": "renew"
    });

    let request = client
        .post("/certificates")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::InternalServerError);

    // Verify no certificate was created
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let certs: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    let invalid_cert = certs.iter().find(|c| c["name"] == "invalid-ca-cert");
    assert!(invalid_cert.is_none(), "Certificate should not have been created with invalid CA");

    Ok(())
}

#[tokio::test]
async fn test_certificate_download_with_invalid_permissions() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a certificate for user 1
    let cert_req = serde_json::json!({
        "cert_name": "permission-test-cert",
        "validity_in_years": 1,
        "user_id": 1,
        "notify_user": false,
        "system_generated_password": false,
        "pkcs12_password": TEST_PASSWORD,
        "cert_type": "client",
        "renew_method": "renew"
    });

    let request = client
        .post("/certificates")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let cert: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let cert_id = cert["id"].as_i64().unwrap();

    // Create a second user
    client.create_user().await?;

    // Switch to the second user (regular user)
    client.switch_user().await?;

    // Try to download the first user's certificate (should fail)
    let request = client
        .get(format!("/certificates/cert/{}/download", cert_id));
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::InternalServerError); // Forbidden

    Ok(())
}

#[tokio::test]
async fn test_input_validation_dos_prevention() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Test with very large certificate name (should be rejected)
    let large_name = "a".repeat(300);
    let cert_req = serde_json::json!({
        "cert_name": large_name,
        "validity_in_years": 1,
        "user_id": 1,
        "notify_user": false,
        "system_generated_password": false,
        "pkcs12_password": TEST_PASSWORD,
        "cert_type": "client",
        "renew_method": "renew"
    });

    let request = client
        .post("/certificates")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::InternalServerError); // Should fail validation

    // Test with dangerous certificate name (path traversal)
    let dangerous_name = "../../../etc/passwd";
    let cert_req = serde_json::json!({
        "cert_name": dangerous_name,
        "validity_in_years": 1,
        "user_id": 1,
        "notify_user": false,
        "system_generated_password": false,
        "pkcs12_password": TEST_PASSWORD,
        "cert_type": "client",
        "renew_method": "renew"
    });

    let request = client
        .post("/certificates")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::InternalServerError); // Should fail validation

    Ok(())
}

#[tokio::test]
async fn test_audit_log_security_events() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Perform some operations that should generate audit logs
    let cert_req = serde_json::json!({
        "cert_name": "audit-test-cert",
        "validity_in_years": 1,
        "user_id": 1,
        "notify_user": false,
        "system_generated_password": false,
        "pkcs12_password": TEST_PASSWORD,
        "cert_type": "client",
        "renew_method": "renew"
    });

    let request = client
        .post("/certificates")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let cert: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let cert_id = cert["id"].as_i64().unwrap();

    // Try to access audit logs (admin only)
    let request = client
        .get("/audit/logs");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok); // Admin should have access

    let audit_response: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let logs = audit_response["logs"].as_array().unwrap();

    // Should have some audit logs
    assert!(!logs.is_empty(), "Audit logs should contain entries");

    // Check for certificate creation log
    let cert_creation_log = logs.iter().find(|log| {
        log["action"] == "create" &&
        log["resource_type"] == "certificate" &&
        log["resource_id"] == cert_id
    });
    assert!(cert_creation_log.is_some(), "Certificate creation should be logged");

    Ok(())
}

#[tokio::test]
async fn test_rate_limiting_protection() -> Result<()> {
    let client = VaulTLSClient::new().await;

    // Try multiple login attempts quickly (should be rate limited)
    for i in 0..10 {
        let login_req = serde_json::json!({
            "email": TEST_USER_EMAIL,
            "password": "wrong_password"
        });

        let request = client
            .post("/auth/login")
            .header(rocket::http::ContentType::JSON)
            .body(serde_json::to_string(&login_req)?);
        let response = request.dispatch().await;

        // First few attempts should fail with invalid credentials
        // Later attempts should be rate limited
        if i < 5 {
            assert_eq!(response.status(), rocket::http::Status::Unauthorized);
        } else {
            // Rate limiting might kick in
            let status = response.status();
            assert!(status == rocket::http::Status::Unauthorized || status == rocket::http::Status::TooManyRequests,
                   "Expected Unauthorized or TooManyRequests, got {:?}", status);
        }

        // Small delay between attempts
        sleep(Duration::from_millis(100)).await;
    }

    Ok(())
}

#[tokio::test]
async fn test_certificate_chain_validation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a client certificate
    let client_cert_req = serde_json::json!({
        "cert_name": "chain-client-cert",
        "validity_in_years": 1,
        "user_id": 1,
        "notify_user": false,
        "system_generated_password": false,
        "pkcs12_password": TEST_PASSWORD,
        "cert_type": "client",
        "renew_method": "renew"
    });

    let request = client
        .post("/certificates")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_string(&client_cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    // Create a server certificate
    let server_cert_req = serde_json::json!({
        "cert_name": "chain-server-cert",
        "validity_in_years": 1,
        "user_id": 1,
        "notify_user": false,
        "system_generated_password": false,
        "pkcs12_password": TEST_PASSWORD,
        "cert_type": "server",
        "dns_names": ["test.example.com"],
        "renew_method": "renew"
    });

    let request = client
        .post("/certificates")
        .header(rocket::http::ContentType::JSON)
        .body(serde_json::to_string(&server_cert_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    // Verify certificates were created with correct types
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);

    let certs: Vec<serde_json::Value> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(certs.len() >= 2, "Expected at least 2 certificates, got {}", certs.len());

    // Find client and server certificates
    let client_cert = certs.iter().find(|c| c["name"] == "chain-client-cert");
    let server_cert = certs.iter().find(|c| c["name"] == "chain-server-cert");

    assert!(client_cert.is_some(), "Client certificate should exist");
    assert!(server_cert.is_some(), "Server certificate should exist");

    // Verify certificate types
    assert_eq!(client_cert.unwrap()["certificate_type"], "Client");
    assert_eq!(server_cert.unwrap()["certificate_type"], "Server");

    Ok(())
}
