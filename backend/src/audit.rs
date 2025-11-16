use crate::data::objects::{AuditLogEntry, AuditEventType, AuditEventCategory, AuditLogQuery, AuditLogStats, AuditCleanupResult, ActionCount, UserActivity};
use crate::settings::AuditSettings;
use crate::db::VaulTLSDB;
use std::sync::Arc;
use tracing::{debug, warn, info};

/// Audit service for logging and managing audit events
pub struct AuditService {
    db: Arc<VaulTLSDB>,
    settings: AuditSettings,
}

impl AuditService {
    /// Create a new audit service
    pub fn new(db: Arc<VaulTLSDB>, settings: AuditSettings) -> Self {
        Self { db, settings }
    }

    /// Update audit settings
    pub async fn update_settings(&mut self, new_settings: AuditSettings) -> Result<(), Box<dyn std::error::Error>> {
        self.settings = new_settings.clone();
        self.db.set_audit_settings(&new_settings).await?;
        Ok(())
    }

    /// Get current audit settings
    pub fn get_settings(&self) -> &AuditSettings {
        &self.settings
    }

    /// Check if audit logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.settings.enabled
    }

    /// Check if a specific event category should be logged
    pub fn should_log_category(&self, category: &AuditEventCategory) -> bool {
        if !self.is_enabled() {
            return false;
        }

        match category {
            AuditEventCategory::Authentication => self.settings.log_authentication,
            AuditEventCategory::Certificates => self.settings.log_certificate_operations,
            AuditEventCategory::CertificateAuthority => self.settings.log_ca_operations,
            AuditEventCategory::Users => self.settings.log_user_operations,
            AuditEventCategory::Settings => self.settings.log_settings_changes,
            AuditEventCategory::System => self.settings.log_system_events,
            _ => false, // API and other categories default to false for now
        }
    }

    /// Log an audit event (convenient method that fills in common fields)
    pub async fn log_event(
        &self,
        event_type: AuditEventType,
        event_category: AuditEventCategory,
        user_id: Option<i64>,
        user_name: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        resource_type: Option<String>,
        resource_id: Option<i64>,
        resource_name: Option<String>,
        action: String,
        success: bool,
        details: Option<String>,
        old_values: Option<serde_json::Value>,
        new_values: Option<serde_json::Value>,
        error_message: Option<String>,
        session_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check if this event category should be logged
        if !self.should_log_category(&event_category) {
            return Ok(()); // Silently skip logging
        }

        let entry = AuditLogEntry {
            id: 0, // Will be set by database
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
            event_type,
            event_category,
            user_id,
            user_name,
            ip_address,
            user_agent,
            resource_type,
            resource_id,
            resource_name,
            action,
            success,
            details,
            old_values,
            new_values,
            error_message,
            session_id,
            source: "api".to_string(),
        };

        let result = self.db.log_audit_event(&entry).await;
        match result {
            Ok(_) => {
                debug!(
                    "Audit event logged: {:?} {} by {:?}",
                    entry.event_category, entry.action, entry.user_name
                );
                Ok(())
            }
            Err(e) => {
                warn!("Failed to log audit event: {}", e);
                // We don't want audit failures to break the main operation
                // but we do want to log it
                Ok(())
            }
        }
    }

    /// Log a user authentication event
    pub async fn log_authentication(
        &self,
        user_id: Option<i64>,
        user_name: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        action: &str,
        success: bool,
        error_message: Option<String>,
        session_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.log_event(
            AuditEventType::UserAction,
            AuditEventCategory::Authentication,
            user_id,
            user_name,
            ip_address,
            user_agent,
            Some("user".to_string()),
            user_id,
            Some("authentication".to_string()),
            action.to_string(),
            success,
            Some(format!("User {} {}", action, if success { "successful" } else { "failed" })),
            None,
            None,
            error_message,
            session_id,
        ).await
    }

    /// Log a certificate operation
    pub async fn log_certificate_operation(
        &self,
        user_id: Option<i64>,
        user_name: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        certificate_id: i64,
        certificate_name: &str,
        action: &str,
        success: bool,
        old_values: Option<serde_json::Value>,
        new_values: Option<serde_json::Value>,
        error_message: Option<String>,
        session_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.log_event(
            AuditEventType::UserAction,
            AuditEventCategory::Certificates,
            user_id,
            user_name,
            ip_address,
            user_agent,
            Some("certificate".to_string()),
            Some(certificate_id),
            Some(certificate_name.to_string()),
            action.to_string(),
            success,
            Some(format!("Certificate '{}': {}", certificate_name, action)),
            old_values,
            new_values,
            error_message,
            session_id,
        ).await
    }

    /// Log a CA operation
    pub async fn log_ca_operation(
        &self,
        user_id: Option<i64>,
        user_name: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ca_id: i64,
        ca_name: &str,
        action: &str,
        success: bool,
        error_message: Option<String>,
        session_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.log_event(
            AuditEventType::UserAction,
            AuditEventCategory::CertificateAuthority,
            user_id,
            user_name,
            ip_address,
            user_agent,
            Some("ca".to_string()),
            Some(ca_id),
            Some(ca_name.to_string()),
            action.to_string(),
            success,
            Some(format!("CA '{}': {}", ca_name, action)),
            None,
            None,
            error_message,
            session_id,
        ).await
    }

    /// Log a user management operation
    pub async fn log_user_operation(
        &self,
        user_id: Option<i64>,
        user_name: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        target_user_id: i64,
        target_user_name: &str,
        action: &str,
        success: bool,
        old_values: Option<serde_json::Value>,
        new_values: Option<serde_json::Value>,
        error_message: Option<String>,
        session_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.log_event(
            AuditEventType::UserAction,
            AuditEventCategory::Users,
            user_id,
            user_name,
            ip_address,
            user_agent,
            Some("user".to_string()),
            Some(target_user_id),
            Some(target_user_name.to_string()),
            action.to_string(),
            success,
            Some(format!("User '{}': {}", target_user_name, action)),
            old_values,
            new_values,
            error_message,
            session_id,
        ).await
    }

    /// Log a settings change
    pub async fn log_settings_change(
        &self,
        user_id: Option<i64>,
        user_name: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        action: &str,
        success: bool,
        old_values: Option<serde_json::Value>,
        new_values: Option<serde_json::Value>,
        error_message: Option<String>,
        session_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.log_event(
            AuditEventType::UserAction,
            AuditEventCategory::Settings,
            user_id,
            user_name,
            ip_address,
            user_agent,
            Some("settings".to_string()),
            None,
            Some("application_settings".to_string()),
            action.to_string(),
            success,
            Some(format!("Settings: {}", action)),
            old_values,
            new_values,
            error_message,
            session_id,
        ).await
    }

    /// Log a system event
    pub async fn log_system_event(
        &self,
        event_type: AuditEventType,
        action: &str,
        success: bool,
        details: Option<String>,
        error_message: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.log_event(
            event_type,
            AuditEventCategory::System,
            None,
            Some("system".to_string()),
            None,
            None,
            Some("system".to_string()),
            None,
            Some("application".to_string()),
            action.to_string(),
            success,
            details,
            None,
            None,
            error_message,
            None,
        ).await
    }

    /// Query audit logs
    pub async fn query_logs(&self, query: &AuditLogQuery) -> Result<(Vec<AuditLogEntry>, i64), Box<dyn std::error::Error>> {
        let result = self.db.query_audit_logs(query).await?;
        Ok(result)
    }

    /// Get audit statistics
    pub async fn get_stats(&self) -> Result<AuditLogStats, Box<dyn std::error::Error>> {
        let stats = self.db.get_audit_stats().await?;
        Ok(stats)
    }

    /// Clean up old audit logs based on retention policy
    pub async fn cleanup_old_logs(&self) -> Result<AuditCleanupResult, Box<dyn std::error::Error>> {
        let result = self.db.cleanup_audit_logs(self.settings.retention_days).await?;
        info!(
            "Audit log cleanup completed: {} records deleted (retention: {} days)",
            result.deleted_count, self.settings.retention_days
        );
        Ok(result)
    }

    /// Get audit settings from database
    pub async fn load_settings(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let settings = self.db.get_audit_settings().await?;
        self.settings = settings;
        Ok(())
    }
}

/// Utility function to extract user info from request context
pub fn extract_user_from_request(req: &rocket::Request<'_>) -> (Option<i64>, Option<String>, Option<String>, Option<String>) {
    // Extract user ID from JWT claims (this would need to be implemented based on your auth system)
    // For now, return None - this should be filled in by your authentication middleware
    (None, None, None, None)
}

/// Utility function to create a new audit service instance
pub async fn create_audit_service(db: Arc<VaulTLSDB>) -> Result<Arc<AuditService>, Box<dyn std::error::Error>> {
    let settings = db.get_audit_settings().await?;
    Ok(Arc::new(AuditService::new(db, settings)))
}
