use crate::common::constants::*;
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use rocket::http::{ContentType, Status};
use rocket::local::asynchronous::Client;
use std::ops::{Deref, DerefMut};
use serde_json::Value;
use vaultls::cert::Certificate;
use vaultls::create_test_rocket;
use vaultls::data::api::{CreateUserCertificateRequest, CreateUserRequest, LoginRequest, SetupRequest, ValidatedCertificateDetails};
use vaultls::data::enums::{CertificateRenewMethod, CertificateType, UserRole};
use x509_parser::pem::Pem;
use vaultls::data::objects::User;
use std::path::Path;

pub(crate) struct VaulTLSClient(Client);

impl Deref for VaulTLSClient {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for VaulTLSClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl VaulTLSClient {
    pub(crate) async fn new() -> Self {
        let rocket_build = create_test_rocket().await;
        let rocket = rocket_build.ignite().await.unwrap();
        VaulTLSClient(Client::tracked(rocket)
            .await
            .unwrap()
        )
    }

    pub(crate) async fn new_setup() -> Self {
        let client = Self::new().await;

        let setup_data = SetupRequest{
            name: TEST_USER_NAME.to_string(),
            email: TEST_USER_EMAIL.to_string(),
            ca_name: TEST_CA_NAME.to_string(),
            ca_validity_in_years: 1,
            password: Some(TEST_PASSWORD.to_string()),
            ca_type: Some("self_signed".to_string()),
            pfx_password: None,
            key_type: None,
            key_size: None,
            hash_algorithm: None,
            countryName: None,
            stateOrProvinceName: None,
            localityName: None,
            organizationName: None,
            organizationalUnitName: None,
            commonName: None,
            emailAddress: None,
            aia_url: None,
            cdp_url: None,
            crl_validity_days: None,
            path_length: None,
            is_root_ca: false,
        };

        let request = client
            .post("/server/setup")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&setup_data).unwrap());
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        drop(response);

        client
    }

    pub(crate) async fn new_authenticated() -> Self {
        let client = Self::new_setup().await;
        client.login(TEST_USER_EMAIL, TEST_PASSWORD).await.unwrap();
        client
    }

    pub(crate) async fn new_with_cert() -> Self {
        let client = Self::new_authenticated().await;
        client.create_client_cert(None, Some(TEST_PASSWORD.to_string())).await.unwrap();
        client
    }

    pub(crate) async fn new_authenticated_unprivileged() -> Self {
        let client = Self::new_authenticated().await;
        client.create_user().await.unwrap();
        client.switch_user().await.unwrap();
        client
    }

    pub(crate) async fn create_client_cert(&self, user_id: Option<i64>, password: Option<String>) -> Result<Certificate> {
        let cert_req = CreateUserCertificateRequest {
            cert_name: TEST_CLIENT_CERT_NAME.to_string(),
            validity_in_years: Some(1),
            user_id: user_id.unwrap_or(1),
            notify_user: None,
            system_generated_password: false,
            pkcs12_password: password,
            cert_type: None,
            dns_names: None,
            ip_addresses: None,
            renew_method: Some(CertificateRenewMethod::Renew),
            ca_id: None,
            key_type: None,
            key_size: None,
            hash_algorithm: None,
            aia_url: None,
            cdp_url: None,
        };

        let request = self
            .post("/certificates/cert")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn create_server_cert(&self) -> Result<()> {
        let cert_req = CreateUserCertificateRequest {
            cert_name: TEST_SERVER_CERT_NAME.to_string(),
            validity_in_years: Some(1),
            user_id: 1,
            notify_user: None,
            system_generated_password: false,
            pkcs12_password: Some(TEST_PASSWORD.to_string()),
            cert_type: Some(CertificateType::Server),
            dns_names: Some(vec![TEST_SERVER_CERT_DNS_NAME.to_string()]),
            ip_addresses: None,
            renew_method: None,
            ca_id: None,
            key_type: None,
            key_size: None,
            hash_algorithm: None,
            aia_url: None,
            cdp_url: None,
        };

        let request = self
            .post("/certificates/cert")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;

        assert_eq!(cert.certificate_type, CertificateType::Server);
        Ok(())
    }

    pub(crate) async fn create_user(&self) -> Result<()> {
        let user_req = CreateUserRequest {
            user_name: TEST_SECOND_USER_NAME.to_string(),
            user_email: TEST_SECOND_USER_EMAIL.to_string(),
            password: Some(TEST_PASSWORD.to_string()),
            role: UserRole::User,
        };

        let request = self
            .post("/users")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&user_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }

    pub(crate) async fn get_current_user(&self) -> Result<User> {
        let request = self
            .get("/auth/me");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn switch_user(&self) -> Result<()> {
        self.logout().await?;
        self.login(TEST_SECOND_USER_EMAIL, TEST_PASSWORD).await?;

        Ok(())
    }

    pub(crate) async fn login(&self, user_email: &str, user_password: &str) -> Result<()> {
        let login_data = LoginRequest{
            email: user_email.to_string(),
            password: user_password.to_string()
        };

        let request = self
            .post("/auth/login")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&login_data)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }
    
    pub(crate) async fn logout(&self) -> Result<()> {
        let request = self
            .post("/auth/logout");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }

    pub(crate) async fn download_cert(&self, cert_id: &str) -> Result<Vec<u8>> {
        let request = self
            .get(format!("/certificates/cert/{}/download", cert_id));
        let response = request.dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::Text));

        let Some(body) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };
        assert!(!body.is_empty());

        Ok(body)
    }

    pub(crate) async fn download_cert_pem(&self, cert_id: &str) -> Result<String> {
        let request = self
            .get(format!("/certificates/cert/{}/download?format=pem", cert_id));
        let response = request.dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::Text));

        let Some(body) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };
        assert!(!body.is_empty());

        Ok(String::from_utf8(body)?)
    }

    pub(crate) async fn download_cert_as_p12(&self, cert_id: &str) -> Result<Vec<u8>> {
        let p12_der = self.download_cert(cert_id).await?;
        let p12 = Pkcs12::from_der(&p12_der)?;
        let parsed_p12 = p12.parse2(TEST_PASSWORD)?;
        let cert = parsed_p12.cert.expect("No certificate found");
        Ok(cert.to_der()?)
    }

    pub(crate) async fn download_ca(&self) -> Result<Pem> {
        let request = self.get("/certificates/ca/download");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let x509_pem = response.into_bytes().await.unwrap();

        Ok(Pem::iter_from_buffer(&x509_pem)
            .nth(0)
            .expect("No PEM block found")?)
    }

    pub(crate) async fn get_settings(&self) -> Result<Value> {
        let request = self
            .get("/settings");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn put_settings(&self, settings: Value) -> Result<()> {
        let request = self
            .put("/settings")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&settings)?);
        let response = request.dispatch().await;

        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }
    pub(crate) async fn create_cert_for_csr(&self, user_id: i64) -> Result<Certificate> {
        let cert_req = CreateUserCertificateRequest {
            cert_name: "test-cert-for-csr".to_string(),
            validity_in_years: Some(1),
            user_id,
            notify_user: Some(false),
            system_generated_password: false,
            pkcs12_password: Some(TEST_PASSWORD.to_string()),
            cert_type: Some(CertificateType::Client),
            dns_names: None,
            ip_addresses: None,
            renew_method: Some(CertificateRenewMethod::Renew),
            ca_id: None,
            key_type: None,
            key_size: None,
            hash_algorithm: None,
            aia_url: None,
            cdp_url: None,
        };

        let request = self
            .post("/certificates/cert")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn sign_csr(&self, csr_path: &Path, ca_id: i64, user_id: i64, cert_type: Option<&str>) -> Result<Certificate> {
        let csr_data = tokio::fs::read(csr_path).await?;
        let boundary = "----TestBoundary12345";
        let mut body = Vec::new();

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
        if response.status() != Status::Ok {
             let error_msg = response.into_string().await.unwrap_or_else(|| "Unknown error".to_string());
             return Err(anyhow::anyhow!("CSR signing failed: {}", error_msg));
        }
        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn get_certificate_details(&self, cert_id: &str) -> Result<Value> {
        let response = self.get(format!("/certificates/cert/{}/details", cert_id)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }
}
