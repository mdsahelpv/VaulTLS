use std::fs;
use std::path::Path;
use vaultls::data::enums::CertificateType;
use vaultls::data::enums::CertificateRenewMethod;
// use vaultls::data::enums::CertificateRevocationReason;
use vaultls::cert::CertificateBuilder;
use vaultls::cert::get_certificate_details;
use vaultls::create_test_rocket;
use vaultls::data::api::CreateUserCertificateRequest;
use vaultls::cert::Certificate;
use rocket::local::asynchronous::Client;
use rocket::http::ContentType;
use rocket::http::Status;
use serde_json::Value;
// use once_cell::sync::Lazy;

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

        // Login to get authentication
        let login_req = serde_json::json!({
            "email": "admin@example.com",
            "password": "adminpassword"
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

        // release the response (and any borrow on `client`) before moving `client`
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
}
