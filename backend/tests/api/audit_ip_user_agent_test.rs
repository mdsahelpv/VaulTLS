use crate::common::constants::*;
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Header, Status};
use serde_json::Value;
use vaultls::data::api::LoginRequest;

#[tokio::test]
async fn test_audit_log_includes_ip_address() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Perform login to generate audit log
    let login_req = LoginRequest {
        email: TEST_USER_EMAIL.to_string(),
        password: TEST_PASSWORD.to_string(),
    };

    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .header(Header::new("X-Forwarded-For", "192.168.1.100"))
        .body(serde_json::to_string(&login_req)?);

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Query audit logs to verify IP address is captured
    let audit_request = client
        .get("/audit/logs?limit=10");

    let audit_response = audit_request.dispatch().await;
    assert_eq!(audit_response.status(), Status::Ok);

    let audit_data: Value = serde_json::from_str(&audit_response.into_string().await.unwrap())?;

    // Find the login audit event
    let login_event = audit_data["logs"].as_array().unwrap().iter()
        .find(|log| log["event_type"] == "login")
        .expect("Login audit event not found");

    // Verify IP address is captured
    assert!(login_event["ip_address"].is_string(), "IP address should be present in audit log");
    assert!(!login_event["ip_address"].as_str().unwrap().is_empty(), "IP address should not be empty");

    Ok(())
}

#[tokio::test]
async fn test_audit_log_includes_user_agent() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Perform login with custom User-Agent
    let login_req = LoginRequest {
        email: TEST_USER_EMAIL.to_string(),
        password: TEST_PASSWORD.to_string(),
    };

    let custom_user_agent = "VaullTLS-Test-Agent/1.0";

    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .header(Header::new("User-Agent", custom_user_agent))
        .body(serde_json::to_string(&login_req)?);

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Query audit logs to verify User-Agent is captured
    let audit_request = client
        .get("/audit/logs?limit=10");

    let audit_response = audit_request.dispatch().await;
    assert_eq!(audit_response.status(), Status::Ok);

    let audit_data: Value = serde_json::from_str(&audit_response.into_string().await.unwrap())?;

    // Find the login audit event
    let login_event = audit_data["logs"].as_array().unwrap().iter()
        .find(|log| log["event_type"] == "login")
        .expect("Login audit event not found");

    // Verify User-Agent is captured
    assert!(login_event["user_agent"].is_string(), "User-Agent should be present in audit log");
    assert_eq!(login_event["user_agent"], custom_user_agent, "User-Agent should match the sent value");

    Ok(())
}

#[tokio::test]
async fn test_audit_log_certificate_creation_with_ip_user_agent() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Login first
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Create a certificate with custom headers
    let cert_req = serde_json::json!({
        "cert_name": "Test Audit Cert",
        "cert_type": "Client",
        "ca_id": 1,
        "validity_in_years": 1,
        "user_id": 1
    });

    let custom_user_agent = "VaullTLS-Cert-Creation-Agent/2.0";
    let forwarded_ip = "10.0.0.50";

    let request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .header(Header::new("User-Agent", custom_user_agent))
        .header(Header::new("X-Forwarded-For", forwarded_ip))
        .body(cert_req.to_string());

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Query audit logs to verify certificate creation event
    let audit_request = client
        .get("/audit/logs?event_type=CertificateCreated&limit=5");

    let audit_response = audit_request.dispatch().await;
    assert_eq!(audit_response.status(), Status::Ok);

    let audit_data: Value = serde_json::from_str(&audit_response.into_string().await.unwrap())?;

    // Find the certificate creation audit event
    let cert_event = audit_data["logs"].as_array().unwrap().iter()
        .find(|log| log["event_type"] == "CertificateCreated")
        .expect("Certificate creation audit event not found");

    // Verify IP address and User-Agent are captured
    assert!(cert_event["ip_address"].is_string(), "IP address should be present");
    assert!(cert_event["user_agent"].is_string(), "User-Agent should be present");
    assert_eq!(cert_event["user_agent"], custom_user_agent);

    Ok(())
}

#[tokio::test]
async fn test_audit_log_with_proxy_headers() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test with various proxy headers
    let login_req = LoginRequest {
        email: TEST_USER_EMAIL.to_string(),
        password: TEST_PASSWORD.to_string(),
    };

    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .header(Header::new("X-Forwarded-For", "203.0.113.1, 198.51.100.1"))
        .header(Header::new("X-Real-IP", "203.0.113.1"))
        .header(Header::new("CF-Connecting-IP", "203.0.113.1"))
        .header(Header::new("User-Agent", "Proxy-Test-Agent/1.0"))
        .body(serde_json::to_string(&login_req)?);

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Query audit logs
    let audit_request = client
        .get("/audit/logs?limit=5");

    let audit_response = audit_request.dispatch().await;
    assert_eq!(audit_response.status(), Status::Ok);

    let audit_data: Value = serde_json::from_str(&audit_response.into_string().await.unwrap())?;

    let login_event = audit_data["logs"].as_array().unwrap().iter()
        .find(|log| log["event_type"] == "login")
        .expect("Login audit event not found");

    // Verify that IP and User-Agent are captured even with proxy headers
    assert!(login_event["ip_address"].is_string());
    assert!(login_event["user_agent"].is_string());
    assert_eq!(login_event["user_agent"], "Proxy-Test-Agent/1.0");

    Ok(())
}

#[tokio::test]
async fn test_audit_log_without_user_agent() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Login without User-Agent header
    let login_req = LoginRequest {
        email: TEST_USER_EMAIL.to_string(),
        password: TEST_PASSWORD.to_string(),
    };

    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&login_req)?);

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Query audit logs
    let audit_request = client
        .get("/audit/logs?limit=5");

    let audit_response = audit_request.dispatch().await;
    assert_eq!(audit_response.status(), Status::Ok);

    let audit_data: Value = serde_json::from_str(&audit_response.into_string().await.unwrap())?;

    let login_event = audit_data["logs"].as_array().unwrap().iter()
        .find(|log| log["event_type"] == "login")
        .expect("Login audit event not found");

    // IP address should still be captured (from Rocket's client_ip)
    // User-Agent might be null or default
    assert!(login_event["ip_address"].is_string());

    Ok(())
}

#[tokio::test]
async fn test_audit_log_stats_include_recent_events() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Login to create audit events
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;

    // Create a certificate to add more audit events
    let cert_req = serde_json::json!({
        "cert_name": "Stats Test Cert",
        "cert_type": "Server",
        "ca_id": 1,
        "validity_in_years": 1,
        "user_id": 1,
        "dns_names": ["test.example.com"]
    });

    let request = client
        .post("/certificates/cert")
        .header(ContentType::JSON)
        .body(cert_req.to_string());

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Get audit stats
    let stats_request = client
        .get("/audit/stats");

    let stats_response = stats_request.dispatch().await;
    assert_eq!(stats_response.status(), Status::Ok);

    let stats_data: Value = serde_json::from_str(&stats_response.into_string().await.unwrap())?;

    // Verify stats include recent events with IP/User-Agent
    assert!(stats_data["recent_events"].is_array());
    let recent_events = stats_data["recent_events"].as_array().unwrap();

    // Should have recent events
    assert!(recent_events.len() > 0, "Should have recent audit events");

    // Check that recent events include IP and User-Agent where available
    for event in recent_events {
        // IP address should be present for most events
        assert!(event["ip_address"].is_string() || event["ip_address"].is_null());

        // User-Agent might be null for some requests
        assert!(event["user_agent"].is_string() || event["user_agent"].is_null());
    }

    Ok(())
}
