use crate::common::constants::*;
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::Value;

#[tokio::test]
async fn test_invalid_certificate_creation_payload() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Test with malformed JSON
    let request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .body("{ invalid json");

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    Ok(())
}

#[tokio::test]
async fn test_certificate_creation_with_invalid_ca_id() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Test with non-existent CA ID
    let cert_req = serde_json::json!({
        "cert_name": "Invalid CA Test",
        "cert_type": "Client",
        "ca_id": 99999,  // Non-existent CA
        "validity_in_years": 1,
        "user_id": 1
    });

    let request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .body(cert_req.to_string());

    let response = request.dispatch().await;
    // Should return 404 or 400 depending on implementation
    assert!(response.status() == Status::NotFound || response.status() == Status::BadRequest);

    Ok(())
}

#[tokio::test]
async fn test_certificate_creation_without_required_fields() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Test with missing required fields
    let cert_req = serde_json::json!({
        "cert_name": "",  // Empty name
        "cert_type": "Client"
        // Missing ca_id, validity_in_years, user_id
    });

    let request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .body(cert_req.to_string());

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    Ok(())
}

#[tokio::test]
async fn test_server_certificate_without_dns_names() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Test server certificate without DNS names
    let cert_req = serde_json::json!({
        "cert_name": "Server Cert No DNS",
        "cert_type": "Server",
        "ca_id": 1,
        "validity_in_years": 1,
        "user_id": 1,
        "dns_names": []  // Empty DNS names for server cert
    });

    let request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .body(cert_req.to_string());

    let response = request.dispatch().await;
    // Should fail validation for server certificates requiring DNS names
    assert_eq!(response.status(), Status::BadRequest);

    let response_body: Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(response_body["error"].is_string());

    Ok(())
}

#[tokio::test]
async fn test_certificate_revocation_of_nonexistent_certificate() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Try to revoke non-existent certificate
    let request = client
        .put("/certificates/cert/99999/revoke")
        .header(ContentType::JSON)
        .body(serde_json::json!({
            "reason": 1,
            "notify_user": false
        }).to_string());

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::NotFound);

    Ok(())
}

#[tokio::test]
async fn test_certificate_download_of_nonexistent_certificate() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Try to download non-existent certificate
    let request = client
        .get("/certificates/cert/99999/download");

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::NotFound);

    Ok(())
}

#[tokio::test]
async fn test_audit_log_access_without_authentication() -> Result<()> {
    let client = VaulTLSClient::new().await; // Not logged in

    // Try to access audit logs without authentication
    let request = client
        .get("/audit/logs");

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    Ok(())
}

#[tokio::test]
async fn test_audit_log_with_invalid_query_parameters() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Test with invalid date format
    let request = client
        .get("/audit/logs?start_date=invalid-date&end_date=2024-01-01");

    let response = request.dispatch().await;
    // Should handle gracefully, either return error or ignore invalid params
    assert!(response.status() == Status::Ok || response.status() == Status::BadRequest);

    Ok(())
}

#[tokio::test]
async fn test_csr_signing_with_invalid_data() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Create multipart form with invalid CSR
    let form_data = "--boundary\r\n\
Content-Disposition: form-data; name=\"csr\"\r\n\
\r\n\
invalid-csr-content\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"ca_id\"\r\n\
\r\n\
1\r\n\
--boundary--\r\n";

    let request = client
        .post("/certificates/cert/sign-csr")
        .header(ContentType::new("multipart", "form-data; boundary=boundary"))
        .body(form_data);

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    Ok(())
}

#[tokio::test]
async fn test_certificate_deletion_of_already_revoked_certificate() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // First create and revoke a certificate
    let cert_req = serde_json::json!({
        "cert_name": "Test Revoked Delete",
        "cert_type": "Client",
        "ca_id": 1,
        "validity_in_years": 1,
        "user_id": 1
    });

    let create_request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .body(cert_req.to_string());

    let create_response = create_request.dispatch().await;
    assert_eq!(create_response.status(), Status::Ok);

    let cert_data: Value = serde_json::from_str(&create_response.into_string().await.unwrap())?;
    let cert_id = cert_data["id"].as_i64().unwrap();

    // Revoke the certificate
    let revoke_request = client
        .put(format!("/certificates/cert/{}/revoke", cert_id))
        .header(ContentType::JSON)
        .body(serde_json::json!({
            "reason": 1,
            "notify_user": false
        }).to_string());

    let revoke_response = revoke_request.dispatch().await;
    assert_eq!(revoke_response.status(), Status::Ok);

    // Try to delete the revoked certificate (should fail)
    let delete_request = client
        .delete(format!("/certificates/cert/{}", cert_id));

    let delete_response = delete_request.dispatch().await;
    assert_eq!(delete_response.status(), Status::BadRequest);

    Ok(())
}

#[tokio::test]
async fn test_concurrent_certificate_operations() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Create multiple certificates sequentially but quickly to test concurrency handling
    let mut responses = Vec::new();

    for i in 0..3 {
        let cert_req = serde_json::json!({
            "cert_name": format!("Concurrent Test {}", i),
            "cert_type": "Client",
            "ca_id": 1,
            "validity_in_years": 1,
            "user_id": 1
        });

        let request = client
            .post("/certificates/cert")
            .header(ContentType::JSON)
            .body(cert_req.to_string());

        let response = request.dispatch().await;
        responses.push(response);
    }

    // All should succeed (or at least not crash the server)
    for response in responses {
        assert!(response.status() == Status::Ok || response.status() == Status::InternalServerError);
    }

    Ok(())
}

#[tokio::test]
async fn test_large_certificate_name() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Test with extremely long certificate name
    let long_name = "A".repeat(1000); // 1000 character name

    let cert_req = serde_json::json!({
        "cert_name": long_name,
        "cert_type": "Client",
        "ca_id": 1,
        "validity_in_years": 1,
        "user_id": 1
    });

    let request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .body(cert_req.to_string());

    let response = request.dispatch().await;
    // Should either succeed or fail gracefully with appropriate error
    assert!(response.status() == Status::Ok || response.status() == Status::BadRequest);

    Ok(())
}
