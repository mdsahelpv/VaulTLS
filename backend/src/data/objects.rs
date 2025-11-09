use crate::helper;
use std::sync::Arc;
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use tokio::sync::Mutex;
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::data::enums::{UserRole, CertificateRevocationReason};
use crate::db::VaulTLSDB;
use crate::notification::mail::Mailer;
use crate::settings::Settings;

#[derive(Clone, Debug)]
pub(crate) struct CRLCache {
    pub(crate) data: Vec<u8>,
    pub(crate) last_updated: i64,
    pub(crate) valid_until: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct OCSPResponseCache {
    pub(crate) data: Vec<u8>,
    pub(crate) cert_id_hash: String, // Hash of certificate ID for cache key
    pub(crate) last_updated: i64,
    pub(crate) valid_until: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub(crate) db: VaulTLSDB,
    pub(crate) settings: Settings,
    pub(crate) oidc: Arc<Mutex<Option<OidcAuth>>>,
    pub(crate) mailer: Arc<Mutex<Option<Mailer>>>,
    pub(crate) crl_cache: Arc<Mutex<Option<CRLCache>>>,
    pub(crate) ocsp_cache: Arc<Mutex<Option<OCSPResponseCache>>>,
}

#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub email: String,
    #[serde(rename = "has_password", serialize_with = "helper::serialize_password_hash", skip_deserializing)]
    #[schemars(skip)]
    pub password_hash: Option<Password>,
    #[serde(skip)]
    pub oidc_id: Option<String>,
    pub role: UserRole
}

#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct CertificateRevocation {
    pub id: i64,
    pub certificate_id: i64,
    pub revocation_date: i64,
    pub revocation_reason: CertificateRevocationReason,
    pub revoked_by_user_id: Option<i64>,
}
