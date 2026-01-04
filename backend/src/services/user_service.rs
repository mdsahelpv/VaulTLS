use crate::auth::password_auth::Password;
use crate::data::api::{ChangePasswordRequest, CreateUserRequest};
use crate::data::error::ApiError;
use crate::data::objects::User;
use crate::db::VaulTLSDB;
use crate::settings::Settings;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// User service for handling user management business logic
pub struct UserService {
    db: Arc<VaulTLSDB>,
    settings: Arc<Settings>,
}

impl UserService {
    /// Create a new user service
    pub fn new(db: Arc<VaulTLSDB>, settings: Arc<Settings>) -> Self {
        Self { db, settings }
    }

    /// Create a new user
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<i64, ApiError> {
        debug!("Creating user: {}", request.user_name);

        // Validate user name and email
        self.validate_user_name(&request.user_name)?;
        self.validate_email(&request.user_email)?;

        // Check if user already exists
        if let Ok(_) = self.db.get_user_by_email(request.user_email.clone()).await {
            return Err(ApiError::Conflict("A user with this email address already exists".to_string()));
        }

        let password_hash = if let Some(password) = &request.password {
            Some(Password::new_server_hash(password)?.to_string())
        } else {
            None
        };

        let user = User {
            id: -1,
            name: request.user_name.clone(),
            email: request.user_email.clone(),
            password_hash,
            oidc_id: None,
            role: request.role,
        };

        let user_id = user.id;
        let user = self.db.insert_user(user).await?;

        info!("User created: {} (ID: {})", request.user_name, user.id);

        Ok(user.id)
    }

    /// Get all users
    pub async fn get_all_users(&self) -> Result<Vec<User>, ApiError> {
        self.db.get_all_user().await.map_err(|e| ApiError::Other(format!("Failed to get all users: {e}")))
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: i64) -> Result<User, ApiError> {
        self.db.get_user(user_id).await.map_err(|e| ApiError::Other(format!("Failed to get user {user_id}: {e}")))
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: String) -> Result<User, ApiError> {
        self.db.get_user_by_email(email).await.map_err(|e| ApiError::Other(format!("Failed to get user by email: {e}")))
    }

    /// Get current user (authenticated)
    pub async fn get_current_user(&self, user_id: i64) -> Result<User, ApiError> {
        self.db.get_user(user_id).await.map_err(|e| ApiError::Other(format!("Failed to get current user {user_id}: {e}")))
    }

    /// Update user
    pub async fn update_user(&self, user_id: i64, updated_user: User, current_user_id: i64, is_admin: bool) -> Result<(), ApiError> {
        if current_user_id != user_id && !is_admin {
            return Err(ApiError::Forbidden(None));
        }

        if !is_admin && updated_user.role != crate::data::enums::UserRole::User {
            return Err(ApiError::Forbidden(None));
        }

        let old_user = self.db.get_user(user_id).await?;
        let user = User {
            id: user_id,
            ..updated_user
        };

        self.db.update_user(user.clone()).await?;

        info!("User updated: {} (ID: {})", user.name, user.id);

        Ok(())
    }

    /// Delete user
    pub async fn delete_user(&self, user_id: i64) -> Result<(), ApiError> {
        let user_to_delete = self.db.get_user(user_id).await
            .map_err(|_| ApiError::NotFound(Some("User not found".to_string())))?;

        self.db.delete_user(user_id).await?;

        info!("User deleted: {} (ID: {})", user_to_delete.name, user_id);

        Ok(())
    }

    /// Register OIDC user
    pub async fn register_oidc_user(&self, mut user: User) -> Result<User, ApiError> {
        user = self.db.register_oidc_user(user).await?;
        debug!("OIDC user registered: {}", user.name);
        Ok(user)
    }

    /// Authenticate user with password
    pub async fn authenticate_password(&self, email: String, password: String) -> Result<User, ApiError> {
        if !self.settings.get_password_enabled() {
            return Err(ApiError::Unauthorized(Some("Password login is disabled".to_string())));
        }

        let user = self.db.get_user_by_email(email.clone()).await
            .map_err(|_| ApiError::Unauthorized(Some("Invalid credentials".to_string())))?;

        if let Some(password_hash_str) = user.password_hash.clone() {
            let password_hash = Password::try_from(password_hash_str.as_str())?;
            if password_hash.verify(&password) {
                debug!("Password authentication successful for user: {}", user.name);
                Ok(user)
            } else {
                warn!("Invalid password for user: {}", user.name);
                Err(ApiError::Unauthorized(Some("Invalid credentials".to_string())))
            }
        } else {
            warn!("No password hash found for user: {}", user.name);
            Err(ApiError::Unauthorized(Some("Invalid credentials".to_string())))
        }
    }

    /// Change user password
    pub async fn change_password(&self, user_id: i64, request: ChangePasswordRequest) -> Result<(), ApiError> {
        let user = self.db.get_user(user_id).await?;

        // Verify old password if provided
        if let Some(ref old_password) = request.old_password {
            if let Some(password_hash_str) = user.password_hash {
                let password_hash = Password::try_from(password_hash_str.as_str())?;
                if !password_hash.verify(old_password) {
                    warn!("Password change failed: old password incorrect for user {}", user.name);
                    return Err(ApiError::BadRequest("Old password is incorrect".to_string()));
                }
            }
        }

        // Hash new password
        let password_hash = Password::new_server_hash(&request.new_password)?;
        self.db.set_user_password(user_id, password_hash).await?;

        info!("Password changed for user: {}", user.name);

        Ok(())
    }

    /// Set user password (admin operation)
    pub async fn set_user_password(&self, user_id: i64, password: String) -> Result<(), ApiError> {
        let password_hash = Password::new_server_hash(&password)?;
        self.db.set_user_password(user_id, password_hash).await?;
        Ok(())
    }

    /// Validate user name
    fn validate_user_name(&self, name: &str) -> Result<(), ApiError> {
        if name.len() > 255 {
            return Err(ApiError::BadRequest("User name is too long (maximum 255 characters)".to_string()));
        }

        if name.trim().is_empty() {
            return Err(ApiError::BadRequest("User name cannot be empty".to_string()));
        }

        Ok(())
    }

    /// Validate email address
    fn validate_email(&self, email: &str) -> Result<(), ApiError> {
        use email_address::EmailAddress;

        if email.len() > 254 {
            return Err(ApiError::BadRequest("Email address is too long (maximum 254 characters)".to_string()));
        }

        if !EmailAddress::is_valid(email) {
            return Err(ApiError::BadRequest("Invalid email address format".to_string()));
        }

        Ok(())
    }
}
