use rocket::local::asynchronous::Client;
use rocket::http::Status;

#[rocket::async_test]
async fn test_rate_limiting_login() {
    // Setup - Create a test instance of Rocket
    // We need to use valid rocket instance which has ratelimit state
    // but our `create_test_rocket` in lib.rs might not have it if it doesn't use the real main launch flow.
    // However, since we used Guards, they should self-register if the Quota is defined.
    // Let's verify if `create_test_rocket` includes the necessary configuration.
    
    use vaultls::create_test_rocket;
    let rocket = create_test_rocket().await;
    let client = Client::tracked(rocket).await.expect("valid rocket instance");

    // Login endpoint limit is 5 per minute
    let uri = "/auth/login";
    
    // We don't need valid credentials to trigger rate limit, just hits to the endpoint
    // But request format needs to be correct to reach the guard? 
    // Actually guards run before handler. 
    // But if guard is in arguments, it runs before handler logic.
    
    use std::net::SocketAddr;
    let remote_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    for _ in 0..5 {
        let req = client.post(uri)
            .remote(remote_addr)
            .header(rocket::http::ContentType::JSON)
            .body(r#"{"email": "admin@example.com", "password": "wrong"}"#);
        let response = req.dispatch().await;
        // Should be 401 Unauthorized or 200 (if we used correct creds), but definitely NOT 429 yet
        // Wait, if I send garbage creds, api might return 401. 
        // 401 != 429.
        assert_ne!(response.status(), Status::TooManyRequests);
    }

    // The 6th request should fail with 429
    let req = client.post(uri)
        .remote(remote_addr)
        .header(rocket::http::ContentType::JSON)
        .body(r#"{"email": "admin@example.com", "password": "wrong"}"#);
    let response = req.dispatch().await;
    
    assert_eq!(response.status(), Status::TooManyRequests);
}
