use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use rocket::form::FromForm;
use crate::data::enums::CertificateRevocationReason;

/// Audit log event types - what kind of action was performed
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    UserAction,
    SystemEvent,
    SecurityEvent,
}

/// Audit event categories - logical grouping of events
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventCategory {
    Authentication,
    Authorization,
    Certificates,
    CertificateAuthority,
    Users,
    Settings,
    System,
    Security,
    API,
}

/// Represents a user in the system
#[derive(Serialize, Deserialize, JsonSchema, Clone)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub oidc_id: Option<String>,
    pub role: crate::data::enums::UserRole,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("email", &self.email)
            .field("password_hash", &"[REDACTED]") // Never log password hashes
            .field("oidc_id", &self.oidc_id)
            .field("role", &self.role)
            .finish()
    }
}

/// Represents an X.509 certificate in the system
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub(crate) struct Certificate {
    pub id: i64,
    pub name: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub pkcs12: Vec<u8>,
    pub pkcs12_password: String,
    pub user_id: i64,
    pub certificate_type: crate::data::enums::CertificateType,
    pub renew_method: crate::data::enums::CertificateRenewMethod,
    pub ca_id: i64,
    pub is_revoked: bool,
    pub revoked_on: Option<i64>,
    pub revoked_reason: Option<CertificateRevocationReason>,
    pub revoked_by: Option<i64>,
}

/// Represents a Certificate Authority in the system
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub(crate) struct CA {
    pub id: i64,
    pub created_on: i64,
    pub valid_until: i64,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub creation_source: i32,
    pub cert_chain: Vec<Vec<u8>>,
    pub can_create_subordinate_ca: bool,
}

/// Application state that holds all shared components
use crate::audit::AuditService;
use crate::db::VaulTLSDB;
use crate::settings::Settings;
use crate::auth::oidc_auth::OidcAuth;
use crate::notification::mail::Mailer;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Main application state containing all shared services
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<VaulTLSDB>,
    pub settings: Settings,
    pub oidc: Arc<Mutex<Option<OidcAuth>>>,
    pub mailer: Arc<Mutex<Option<Mailer>>>,
    pub audit: Arc<AuditService>,
    pub crl_cache: Arc<Mutex<Option<CrlCache>>>,
    pub ocsp_cache: Arc<Mutex<Option<OcspCache>>>,
}

/// Cache for Certificate Revocation List data
#[derive(Clone, Debug)]
pub struct CrlCache {
    pub data: Vec<u8>,
    pub last_updated: i64,
    pub valid_until: i64,
    pub ca_id: i64,
}

/// Cache for OCSP response data
#[derive(Clone, Debug)]
pub struct OcspCache {
    pub data: Vec<u8>,
    pub cert_id_hash: String,
    pub last_updated: i64,
    pub valid_until: i64,
}



/// Certificate Chain information for CA details
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub(crate) struct CertificateChainInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub certificate_type: String,
    pub is_end_entity: bool,
}

/// Certificate Revocation details
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub(crate) struct CertificateRevocation {
    pub id: i64,
    pub certificate_id: i64,
    pub revocation_date: i64,
    pub revocation_reason: CertificateRevocationReason,
    pub revoked_by_user_id: Option<i64>,
    pub custom_reason: Option<String>,
}



/// Comprehensive Audit Log Entry
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub(crate) struct AuditLogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub event_type: AuditEventType,
    pub event_category: AuditEventCategory,
    pub user_id: Option<i64>,
    pub user_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<i64>,
    pub resource_name: Option<String>,
    pub action: String,
    pub success: bool,
    pub details: Option<String>,
    pub old_values: Option<serde_json::Value>,
    pub new_values: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub session_id: Option<String>,
    pub source: String,
}

// Audit log query/search parameters
#[derive(Deserialize, JsonSchema, Debug, FromForm)]
pub(crate) struct AuditLogQuery {
    pub page: Option<i32>,
    pub limit: Option<i32>,
    pub user_id: Option<i64>,
    pub event_category: Option<String>,
    pub event_type: Option<String>,
    pub resource_type: Option<String>,
    pub action: Option<String>,
    pub success: Option<bool>,
    pub start_date: Option<i64>,
    pub end_date: Option<i64>,
    pub search_term: Option<String>,
}

// Audit log summary/statistics
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub(crate) struct AuditLogStats {
    pub total_events: i64,
    pub events_today: i64,
    pub failed_operations: i64,
    pub top_actions: Vec<ActionCount>,
    pub top_users: Vec<UserActivity>,
    pub recent_events: Vec<AuditLogEntry>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub(crate) struct ActionCount {
    pub action: String,
    pub count: i64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub(crate) struct UserActivity {
    pub user_id: i64,
    pub user_name: String,
    pub event_count: i64,
    pub last_activity: i64,
}

// Audit log retention cleanup statistics
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub(crate) struct AuditCleanupResult {
    pub deleted_count: i64,
    pub cutoff_date: i64,
    pub execution_time_ms: i64,
}
