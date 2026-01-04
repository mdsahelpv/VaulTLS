use crate::common::constants::{TEST_PASSWORD, TEST_USER_EMAIL};
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Cookie, Status};
use serde_json::Value;
use vaultls::data::api::{CreateUserRequest, LoginRequest};
use vaultls::data::enums::UserRole;

#[tokio::test]
async fn test_invalid_authentication() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test with missing cookie
    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    // Test with invalid cookie
    let request = client
        .get("/users")
        .cookie(Cookie::new("auth_token", "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJZCI6IjEiLCJleHAiOjE5MTAyNDkzMjR9.UMq0kSdrh4tpHRKfG3Fpy5YwCvNutdG34cfHAj4Vb40"));
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    Ok(())
}

#[tokio::test]
async fn test_sql_injection_prevention() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test SQL injection in login
    let malicious_login = LoginRequest{
        email: "mal@example.com'; DROP TABLE users; --".to_string(),
        password: "password".to_string(),
    };
    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&malicious_login)?);

    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;


    Ok(())
}

#[tokio::test]
async fn test_privilege_escalation() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await;

    let user_req = CreateUserRequest{
        user_name: "test3".to_string(),
        user_email: "test3@example.com".to_string(),
        password: Some("password".to_string()),
        role: UserRole::Admin,
    };

    // Attempt to create admin user
    let request = client
        .post("/users")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);

    let mut user = client.get_current_user().await?;
    user.role = UserRole::Admin;
    let request = client
        .put(format!("/users/{}", user.id))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn test_cert_private_key_protection() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_client_cert(None, None).await?;
    client.create_user().await?;
    client.switch_user().await?;
    let request = client
        .get("/certificates/1/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);

    Ok(())
}

#[tokio::test]
async fn test_protect_server_settings() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await;
    let request = client
        .get("/settings");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);

    let settings = r#"{"common":{"password_rule":0}}"#;
    let request = client
        .put("/settings")
        .header(ContentType::JSON)
        .body(settings);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);

    Ok(())
}

#[tokio::test]
async fn test_enforce_random_cert_password() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let mut settings = client.get_settings().await?;
    settings["common"]["password_rule"] = Value::Number(2.into());
    client.put_settings(settings).await?;

    client.create_client_cert(None, Some(TEST_PASSWORD.to_string())).await?;

    let request = client
        .get("/certificates/1/password");
    let response = request.dispatch().await;
    let password: String = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_ne!(password, TEST_PASSWORD);
    assert!(!password.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_enforce_cert_password() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let mut settings = client.get_settings().await?;
    settings["common"]["password_rule"] = Value::Number(1.into());
    client.put_settings(settings).await?;

    client.create_client_cert(None, Some("  ".to_string())).await?;

    let request = client
        .get("/certificates/1/password");
    let response = request.dispatch().await;
    let password: String = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_ne!(password, "  ");
    assert!(!password.is_empty());

    Ok(())
}

#[tokio::test]
async fn access_deleted_users_certs() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_user().await?;
    client.create_client_cert(Some(2), None).await?;
    client.delete("/users/2").dispatch().await;

    let request = client
        .get("/certificates/1/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);

    client.create_user().await?;
    client.switch_user().await?;

    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().await.unwrap(), "[]");

    Ok(())
}

#[tokio::test]
async fn password_disabled_login() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let mut settings = client.get_settings().await?;

    settings["common"]["password_enabled"] = Value::Bool(false);

    client.put_settings(settings).await?;

    client.logout().await?;

    let login_data = LoginRequest{
        email: TEST_USER_EMAIL.to_string(),
        password: TEST_PASSWORD.to_string()
    };

    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&login_data)?);
    let response = request.dispatch().await;
    assert_ne!(response.status(), Status::Ok);

    Ok(())
}

#[tokio::test]
async fn test_password_hash_not_leaked_in_user_creation_conflict() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a user first
    let user_req = CreateUserRequest{
        user_name: "testuser".to_string(),
        user_email: "duplicate@example.com".to_string(),
        password: Some("testpassword123".to_string()),
        role: UserRole::User,
    };

    let request = client
        .post("/users")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Try to create another user with the same email
    let duplicate_user_req = CreateUserRequest{
        user_name: "differentuser".to_string(),
        user_email: "duplicate@example.com".to_string(),
        password: Some("differentpassword456".to_string()),
        role: UserRole::User,
    };

    let request = client
        .post("/users")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&duplicate_user_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Conflict);

    // Verify the error response doesn't contain password hash
    let response_body: Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let error_message = response_body["error"].as_str().unwrap();
    assert!(!error_message.contains("password"));
    assert!(!error_message.contains("hash"));
    assert!(error_message.contains("already exists"));

    Ok(())
}

#[tokio::test]
async fn test_user_debug_not_leaked() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // Create a user
    let user_req = CreateUserRequest{
        user_name: "debugtest".to_string(),
        user_email: "debug@example.com".to_string(),
        password: Some("debugpassword".to_string()),
        role: UserRole::User,
    };

    let request = client
        .post("/users")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_req)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Get the current user (which should include the User struct in the response)
    let user_response = client.get_current_user().await?;
    let user_json = serde_json::to_string(&user_response)?;

    // Verify password hash is not in the JSON response
    assert!(!user_json.contains("password_hash"));
    assert!(!user_json.contains("debugpassword"));

    Ok(())
}

#[tokio::test]
async fn test_error_responses_dont_contain_sensitive_data() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test invalid login doesn't leak user existence differently
    let invalid_login = LoginRequest{
        email: "nonexistent@example.com".to_string(),
        password: "wrongpassword".to_string(),
    };

    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&invalid_login)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    let response_body: Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let error_message = response_body["error"].as_str().unwrap();

    // Test with existing user but wrong password
    let wrong_password_login = LoginRequest{
        email: TEST_USER_EMAIL.to_string(),
        password: "wrongpassword".to_string(),
    };

    let request = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&wrong_password_login)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    let response_body: Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let error_message2 = response_body["error"].as_str().unwrap();

    // Both should give the same generic error message
    assert_eq!(error_message, error_message2);
    assert_eq!(error_message, "Invalid credentials");

    Ok(())
}
