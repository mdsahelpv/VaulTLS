use crate::cert::{Certificate, CA};
use crate::constants::{DB_FILE_PATH, TEMP_DB_FILE_PATH};
use crate::data::enums::{CertificateRenewMethod, CertificateType, UserRole, CertificateRevocationReason};
use crate::data::objects::{User, CertificateRevocation, AuditLogEntry, AuditEventType, AuditEventCategory, AuditLogQuery, AuditLogStats, AuditCleanupResult, ActionCount, UserActivity};
use crate::settings::AuditSettings;
use crate::helper::get_secret;
use anyhow::anyhow;
use anyhow::Result;
use include_dir::{include_dir, Dir};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{params, Connection};
use rusqlite_migration::Migrations;
use std::fs;
use std::path::Path;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tracing::{debug, info, trace, warn};
use crate::auth::password_auth::Password;

static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/migrations");

macro_rules! db_do {
    ($pool:expr, $operation:expr) => {
        {
            let pool = $pool.clone();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get().map_err(|e| {
                    anyhow!("DB pool error: {}", e)
                })?;
                $operation(&conn)
            }).await?
        }
    };
}


#[derive(Debug, Clone)]
pub(crate) struct VaulTLSDB {
    pool: Pool<SqliteConnectionManager>,
}

impl VaulTLSDB {
    pub(crate) fn new(db_encrypted: bool, mem: bool) -> Result<Self> {
        // The next two lines are for backward compatability and should be removed in a future release
        let db_initialized = if !mem {
            let db_path = Path::new(DB_FILE_PATH);
            db_path.exists()
        } else {
            false
        };

        let mut manager = if !mem {
            SqliteConnectionManager::file(DB_FILE_PATH)
        } else {
            debug!("Opening in-memory database");
            SqliteConnectionManager::memory()
        };

        let db_secret_result = get_secret("VAULTLS_DB_SECRET");
        manager = if db_encrypted {
            debug!("Using encrypted database");
            if let Ok(ref db_secret_result) = db_secret_result {
                let db_secret = db_secret_result.clone();
                manager.with_init(move |conn| {
                    conn.pragma_update(None, "key", db_secret.clone())?;
                    conn.pragma_update(None, "foreign_keys", "ON")?;
                    Ok(())
                })
            } else {
                return Err(anyhow!("VAULTLS_DB_SECRET missing".to_string()));
            }
        } else {
            manager.with_init(|connection| {
                connection.pragma_update(None, "foreign_keys", "ON")?;
                Ok(())
            })
        };

        let pool = Pool::builder()
            .max_size(1)
            .build(manager)?;
        let mut connection = pool.get()?;

        // This if statement can be removed in a future version
        if db_initialized {
            debug!("Correcting user_version of database");
            let user_version: i32 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .expect("Failed to get PRAGMA user_version");
            // Database already initialized, update user_version to 1
            if user_version == 0 {
                connection.pragma_update(None, "user_version", "1")?;
            }
        }

        Self::migrate_database(&mut connection)?;

        // ToDo fix when to migrate
        if !db_encrypted {
            if let Ok(ref db_secret_result) = db_secret_result {
                let db_secret = db_secret_result.clone();
                Self::create_encrypt_db(&connection, &db_secret)?;
                drop(connection);
                Self::migrate_to_encrypted_db()?;
                info!("Migrated to encrypted database");
                let manager = SqliteConnectionManager::file(DB_FILE_PATH)
                    .with_init(move |conn| {
                        conn.pragma_update(None, "key", db_secret.clone())?;
                        conn.pragma_update(None, "foreign_keys", "ON")?;
                        Ok(())
                    });

                let pool = Pool::builder()
                    .max_size(1)
                    .build(manager)?;

                return Ok(Self { pool });
            }
        }

        Ok(Self { pool })
    }

    /// Create a new encrypted database with cloned data
    fn create_encrypt_db(conn: &Connection, new_db_secret: &str) -> Result<()> {
        let encrypted_path = TEMP_DB_FILE_PATH;
        conn.execute(
            "ATTACH DATABASE ?1 AS encrypted KEY ?2",
            params![encrypted_path, new_db_secret],
        )?;

        // Migrate data
        conn.query_row("SELECT sqlcipher_export('encrypted');", [], |_row| Ok(()))?;
        // Copy user_version for migrations
        let user_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        conn.pragma_update(Some("encrypted"), "user_version", user_version.to_string())?;

        conn.execute("DETACH DATABASE encrypted;", [])?;
        Ok(())
    }

    /// Migrate the unencrypted database to an encrypted database
    fn migrate_to_encrypted_db() -> Result<()> {
        fs::remove_file(DB_FILE_PATH)?;
        fs::rename(TEMP_DB_FILE_PATH, DB_FILE_PATH)?;
        Ok(())
    }

    fn migrate_database(conn: &mut Connection) -> Result<()> {
        let migrations = Migrations::from_directory(&MIGRATIONS_DIR).expect("Failed to load migrations");
        migrations.to_latest(conn).expect("Failed to migrate database");
        debug!("Database migrated to latest version");

        Ok(())
    }

    pub(crate) async fn fix_password(&self) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, name, password_hash FROM users WHERE password_hash IS NOT NULL")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?
                ))
            })?;

            for row_result in rows {
                let (user_id, user_name, password_hash_str) = row_result?;
                if let Ok(password) = Password::try_from(password_hash_str.as_str()) {
                    if password.verify("") {
                        // Password stored is empty
                        info!("Password for user {} is empty, disabling password", user_name);
                        conn.execute("UPDATE users SET password_hash = NULL WHERE id = ?", [&user_id])?;
                    }
                }
            }

            Ok(())
        })
    }

    /// Insert a new CA certificate into the database
    /// Adds id to the Certificate struct
    pub(crate) async fn insert_ca(
        &self,
        ca: CA
    ) -> Result<i64> {
        db_do!(self.pool, |conn: &Connection| {
            // Serialize certificate chain as JSON (base64 encoded DER certificates)
            let cert_chain_json = serde_json::to_string(&ca.cert_chain)?;

            conn.execute(
                "INSERT INTO ca_certificates (created_on, valid_until, certificate, key, creation_source, cert_chain, can_create_subordinate_ca, aia_url, cdp_url) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![ca.created_on, ca.valid_until, ca.cert, ca.key, ca.creation_source, cert_chain_json, ca.can_create_subordinate_ca, ca.aia_url, ca.cdp_url],
            )?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Retrieve the most recent CA entry from the database
    pub(crate) async fn get_current_ca(&self) -> Result<CA> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, created_on, valid_until, certificate, key, creation_source, cert_chain, can_create_subordinate_ca, aia_url, cdp_url FROM ca_certificates ORDER BY id DESC LIMIT 1")?;

            stmt.query_row([], |row| {
                let cert_chain: Option<String> = row.get(6)?;
                let cert_chain = if let Some(chain_json) = cert_chain {
                    serde_json::from_str(&chain_json).unwrap_or_else(|_| vec![])
                } else {
                    // Backward compatibility: if cert_chain is null, use single cert
                    vec![row.get::<_, Vec<u8>>(3)?]
                };

                Ok(CA{
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    creation_source: row.get(5)?,
                    cert_chain,
                    can_create_subordinate_ca: row.get(7).unwrap_or(false), // Default for existing records
                    aia_url: row.get(8)?, // From database
                    cdp_url: row.get(9)?, // From database
                })
            }).map_err(|_| anyhow!("VaulTLS has not been set-up yet"))
        })
    }

    /// Update AIA and CDP URLs for an existing CA
    pub(crate) async fn update_ca_urls(&self, ca_id: i64, aia_url: Option<String>, cdp_url: Option<String>) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE ca_certificates SET aia_url = ?1, cdp_url = ?2 WHERE id = ?3",
                params![aia_url, cdp_url, ca_id],
            )?;
            Ok(())
        })
    }

    /// Retrieve all CA certificates from the database
    pub(crate) async fn get_all_ca(&self) -> Result<Vec<CA>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, created_on, valid_until, certificate, key, creation_source, cert_chain, can_create_subordinate_ca, aia_url, cdp_url FROM ca_certificates ORDER BY id DESC")?;
            let rows = stmt.query([])?;
            Ok(rows.map(|row| {
                let cert_chain: Option<String> = row.get(6)?;
                let cert_chain = if let Some(chain_json) = cert_chain {
                    serde_json::from_str(&chain_json).unwrap_or_else(|_| vec![])
                } else {
                    // Backward compatibility: if cert_chain is null, use single cert
                    vec![row.get::<_, Vec<u8>>(3)?]
                };

                Ok(CA {
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    creation_source: row.get(5)?,
                    cert_chain,
                    can_create_subordinate_ca: row.get(7).unwrap_or(false), // Default for existing records
                    aia_url: row.get(8)?, // From database
                    cdp_url: row.get(9)?, // From database
                })
            })
            .collect()?)
        })

    }

    /// Retrieve a specific CA by ID from the database
    #[allow(dead_code)]
    pub(crate) async fn get_ca(&self, id: i64) -> Result<CA> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, created_on, valid_until, certificate, key, creation_source, cert_chain, can_create_subordinate_ca, aia_url, cdp_url FROM ca_certificates WHERE id = ?1")?;

            stmt.query_row(params![id], |row| {
                let cert_chain: Option<String> = row.get(6)?;
                let cert_chain = if let Some(chain_json) = cert_chain {
                    serde_json::from_str(&chain_json).unwrap_or_else(|_| vec![])
                } else {
                    // Backward compatibility: if cert_chain is null, use single cert
                    vec![row.get::<_, Vec<u8>>(3)?]
                };

                Ok(CA{
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    creation_source: row.get(5)?,
                    cert_chain,
                    can_create_subordinate_ca: row.get(7).unwrap_or(false), // Default for existing records
                    aia_url: row.get(8)?, // From database
                    cdp_url: row.get(9)?, // From database
                })
            }).map_err(|e| anyhow!("CA with id {id} not found: {e}"))
        })
    }

    /// Delete a CA from the database
    pub(crate) async fn delete_ca(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM ca_certificates WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    /// Retrieve all user certificates from the database
    /// If user_id is Some, only certificates for that user are returned
    /// If user_id is None, all certificates are returned
    /// Certificates are marked as revoked based on the is_revoked column
    pub(crate) async fn get_all_user_cert(&self, user_id: Option<i64>) -> Result<Vec<Certificate>> {
        db_do!(self.pool, |conn: &Connection| {
            let query = match user_id {
                Some(_) => "SELECT uc.id, uc.name, uc.created_on, uc.valid_until, uc.pkcs12, uc.pkcs12_password, uc.user_id, uc.type, uc.renew_method, uc.ca_id, uc.is_revoked, cr.revocation_date, cr.revocation_reason, cr.revoked_by_user_id, cr.custom_reason FROM user_certificates uc LEFT JOIN certificate_revocation cr ON uc.id = cr.certificate_id WHERE uc.user_id = ?1",
                None => "SELECT uc.id, uc.name, uc.created_on, uc.valid_until, uc.pkcs12, uc.pkcs12_password, uc.user_id, uc.type, uc.renew_method, uc.ca_id, uc.is_revoked, cr.revocation_date, cr.revocation_reason, cr.revoked_by_user_id, cr.custom_reason FROM user_certificates uc LEFT JOIN certificate_revocation cr ON uc.id = cr.certificate_id"
            };
            let mut stmt = conn.prepare(query)?;
            let rows = match user_id {
                Some(id) => stmt.query(params![id])?,
                None => stmt.query([])?,
            };
            Ok(rows.map(|row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    pkcs12: row.get(4)?,
                    pkcs12_password: row.get(5).unwrap_or_default(),
                    user_id: row.get(6)?,
                    certificate_type: row.get(7)?,
                    renew_method: row.get(8)?,
                    ca_id: row.get(9)?,
                    is_revoked: row.get(10)?,
                    revoked_on: row.get(11).ok(),
                    revoked_reason: row.get(12).ok().map(|r: u8| CertificateRevocationReason::try_from(r).unwrap_or(CertificateRevocationReason::Unspecified)),
                    revoked_by: row.get(13).ok(),
                    custom_revocation_reason: row.get(14).ok(),
                })
            })
            .collect()?)
        })

    }

    /// Retrieve the certificate's PKCS12  data with id from the database
    /// Returns the id of the user the certificate belongs to and the PKCS12 data
    pub(crate) async fn get_user_cert_pkcs12(&self, id: i64) -> Result<(i64, String, Vec<u8>)> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT user_id, name, pkcs12 FROM user_certificates WHERE id = ?1")?;

            Ok(stmt.query_row(
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?)
        })
    }

    /// Retrieve a single user certificate with all its data
    /// Returns (user_id, name, created_on, valid_until, pkcs12, pkcs12_password, certificate_type, renew_method, ca_id)
    pub(crate) async fn get_user_cert(&self, id: i64) -> Result<(i64, String, i64, i64, Vec<u8>, String, CertificateType, CertificateRenewMethod, i64)> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT user_id, name, created_on, valid_until, pkcs12, pkcs12_password, type, renew_method, ca_id FROM user_certificates WHERE id = ?1")?;

            Ok(stmt.query_row(
                params![id],
                |row| Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5).unwrap_or_default(),
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?
                )),
            )?)
        })
    }

    /// Retrieve a single user certificate as a Certificate struct
    pub(crate) async fn get_user_cert_by_id(&self, id: i64) -> Result<Certificate> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT uc.id, uc.name, uc.created_on, uc.valid_until, uc.pkcs12, uc.pkcs12_password, uc.user_id, uc.type, uc.renew_method, uc.ca_id, uc.is_revoked, cr.revocation_date, cr.revocation_reason, cr.revoked_by_user_id, cr.custom_reason FROM user_certificates uc LEFT JOIN certificate_revocation cr ON uc.id = cr.certificate_id WHERE uc.id = ?1")?;

            stmt.query_row(params![id], |row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    pkcs12: row.get(4)?,
                    pkcs12_password: row.get(5).unwrap_or_default(),
                    user_id: row.get(6)?,
                    certificate_type: row.get(7)?,
                    renew_method: row.get(8)?,
                    ca_id: row.get(9)?,
                    is_revoked: row.get(10)?,
                    revoked_on: row.get(11).ok(),
                    revoked_reason: row.get(12).ok().map(|r: u8| CertificateRevocationReason::try_from(r).unwrap_or(CertificateRevocationReason::Unspecified)),
                    revoked_by: row.get(13).ok(),
                    custom_revocation_reason: row.get(14).ok(),
                })
            }).map_err(|e| anyhow!("Certificate with id {id} not found: {e}"))
        })
    }

    /// Retrieve the certificate's PKCS12 data with id from the database
    /// Returns the id of the user the certificate belongs to and the PKCS12 password
    pub(crate) async fn get_user_cert_pkcs12_password(&self, id: i64) -> Result<(i64, String)> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT user_id, pkcs12_password FROM user_certificates WHERE id = ?1")?;

            Ok(stmt.query_row(
                params![id],
                |row| Ok((row.get(0)?, row.get(1).unwrap_or_default())),
            )?)
        })
    }

    /// Insert a new certificate into the database
    /// Adds id to Certificate struct
    pub(crate) async fn insert_user_cert(&self, mut cert: Certificate) -> Result<Certificate> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO user_certificates (name, created_on, valid_until, pkcs12, pkcs12_password, type, renew_method, ca_id, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![cert.name, cert.created_on, cert.valid_until, cert.pkcs12, cert.pkcs12_password, cert.certificate_type as u8, cert.renew_method as u8, cert.ca_id, cert.user_id],
            )?;

            cert.id = conn.last_insert_rowid();

            Ok(cert)
        })
    }

    /// Delete a certificate from the database
    pub(crate) async fn delete_user_cert(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM user_certificates WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    pub(crate) async fn update_cert_renew_method(&self, id: i64, renew_method: CertificateRenewMethod) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET renew_method = ?1 WHERE id=?2",
                params![renew_method as u8, id]
            ).map(|_| ())?)
        })
    }

    /// Add a new user to the database
    pub(crate) async fn insert_user(&self, mut user: User) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO users (name, email, password_hash, oidc_id, role) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![user.name, user.email, user.password_hash.clone().map(|hash| hash.to_string()), user.oidc_id, user.role as u8],
            )?;

            user.id = conn.last_insert_rowid();

            Ok(user)
        })
    }

    /// Delete a user from the database
    pub(crate) async fn delete_user(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM users WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    /// Update a user in the database
    pub(crate) async fn update_user(&self, user: User) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE users SET name = ?1, email =?2 WHERE id=?3",
                params![user.name, user.email, user.id]
            ).map(|_| ())?)
        })
    }

    /// Return a user entry by id from the database
    pub(crate) async fn get_user(&self, id: i64) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE id=?1",
                params![id],
                |row| {
                    let role_number: u8 = row.get(5)?;
                    Ok(User {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: row.get(3).ok(),
                        oidc_id: row.get(4).ok(),
                        role: UserRole::try_from(role_number).unwrap(),
                    })
                }
            )?)
        })
    }

    /// Return a user entry by email from the database
    pub(crate) async fn get_user_by_email(&self, email: String) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE email=?1",
                params![email],
                |row| {
                    let role_number: u8 = row.get(5)?;
                    Ok(User {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: row.get(3).ok(),
                        oidc_id: row.get(4).ok(),
                        role: UserRole::try_from(role_number).map_err(|_| rusqlite::Error::QueryReturnedNoRows)?,
                    })
                }
            )?)
        })
    }

    /// Return all users from the database
    pub(crate) async fn get_all_user(&self) -> Result<Vec<User>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, name, email, role FROM users")?;
            let query = stmt.query([])?;
            Ok(query.map(|row| {
                    Ok(User {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: None,
                        oidc_id: None,
                        role: row.get(3)?
                    })
                })
                .collect()?)
        })
    }

    /// Set a new password for a user
    /// The password needs to be hashed already
    pub(crate) async fn set_user_password(&self, id: i64, password_hash: Password) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE users SET password_hash = ?1 WHERE id=?2",
                params![password_hash.to_string(), id]
            ).map(|_| ())?)
        })
    }

    pub(crate) async fn unset_user_password(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE users SET password_hash = NULL WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    /// Register a user with an OIDC ID:
    /// If the user does not exist, a new user is created.
    /// If the user already exists and has matching OIDC ID, nothing is done.
    /// If the user already exists but has no OIDC ID, the OIDC ID is added.
    /// If the user already exists but has a different OIDC ID, an error is returned.
    /// The function adds the user id and role to the User struct
    pub(crate) async fn register_oidc_user(&self, mut user: User) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            let existing_oidc_user_option: Option<(i64, UserRole)> = conn.query_row(
                "SELECT id, role FROM users WHERE oidc_id=?1",
                params![user.oidc_id],
                |row| Ok((row.get(0)?, row.get(1)?))
            ).ok();

            if let Some(existing_oidc_user) = existing_oidc_user_option {
                trace!("User with OIDC_ID {:?} already exists", user.oidc_id);
                user.id = existing_oidc_user.0;
                user.role = existing_oidc_user.1;
                Ok(user)
            } else {
                debug!("User with OIDC_ID {:?} does not exists", user.oidc_id);
                let existing_local_user_option = conn.query_row(
                    "SELECT id, oidc_id, role FROM users WHERE email=?1",
                    params![user.email],
                    |row| {
                        let id = row.get(0)?;
                        let oidc_id: Option<String> = row.get(1)?;
                        let role = row.get(2)?;
                        Ok((id, oidc_id, role))
                    }
                ).ok();
                if let Some(existing_local_user_option) = existing_local_user_option {
                    debug!("OIDC user matched with local account {:?}", existing_local_user_option.0);
                    if existing_local_user_option.1.is_some() {
                        warn!("OIDC user matched with local account but has different OIDC ID already");
                        Err(anyhow!("OIDC Subject ID mismatch"))
                    } else {
                        debug!("Adding OIDC_ID {:?} to local account {:?}", user.oidc_id, existing_local_user_option.0);
                        conn.execute(
                            "UPDATE users SET oidc_id = ?1 WHERE id=?2",
                            params![user.oidc_id, existing_local_user_option.0]
                        )?;
                        user.id = existing_local_user_option.0;
                        user.role = existing_local_user_option.2;
                        Ok(user)
                    }
                } else {
                    debug!("New local account is created for OIDC user");
                    conn.execute(
                        "INSERT INTO users (name, email, password_hash, oidc_id, role) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![user.name, user.email, user.password_hash.clone().map(|hash| hash.to_string()), user.oidc_id, user.role as u8],
                    )?;
                    user.id = conn.last_insert_rowid();
                    Ok(user)
                }
            }
        })
    }

    /// Check if the database is setup
    /// Returns true if the database contains at least one user
    /// Returns false if the database is empty
    pub(crate) async fn is_setup(&self) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id FROM users",
                [],
                |_| Ok(())
            )?)
        })
    }

    /// Revoke a certificate by adding it to the revocation table and updating the is_revoked flag
    pub(crate) async fn revoke_certificate(&self, certificate_id: i64, revocation_reason: CertificateRevocationReason, revoked_by_user_id: Option<i64>, custom_reason: Option<String>) -> Result<i64> {
        db_do!(self.pool, |conn: &Connection| {
            let revocation_date = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            // First, update the is_revoked flag in user_certificates
            conn.execute(
                "UPDATE user_certificates SET is_revoked = 1 WHERE id = ?1",
                params![certificate_id],
            )?;

            // Then add the revocation record for audit purposes
            conn.execute(
                "INSERT INTO certificate_revocation (certificate_id, revocation_date, revocation_reason, revoked_by_user_id, custom_reason) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![certificate_id, revocation_date, revocation_reason as u8, revoked_by_user_id, custom_reason],
            )?;

            let revocation_id = conn.last_insert_rowid();

            info!("Certificate {} revoked by user {:?} with reason {:?}, custom: {:?}", certificate_id, revoked_by_user_id, revocation_reason, custom_reason);

            Ok(revocation_id)
        })
    }

    /// Check if a certificate is revoked
    pub(crate) async fn is_certificate_revoked(&self, certificate_id: i64) -> Result<bool> {
        db_do!(self.pool, |conn: &Connection| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM certificate_revocation WHERE certificate_id = ?1",
                params![certificate_id],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
    }

    /// Get revocation details for a certificate
    pub(crate) async fn get_certificate_revocation(&self, certificate_id: i64) -> Result<Option<CertificateRevocation>> {
        db_do!(self.pool, |conn: &Connection| {
            let result = conn.query_row(
                "SELECT id, certificate_id, revocation_date, revocation_reason, revoked_by_user_id, custom_reason FROM certificate_revocation WHERE certificate_id = ?1",
                params![certificate_id],
                |row| {
                    let reason_value: u8 = row.get(3)?;
                    Ok(CertificateRevocation {
                        id: row.get(0)?,
                        certificate_id: row.get(1)?,
                        revocation_date: row.get(2)?,
                        revocation_reason: CertificateRevocationReason::try_from(reason_value).unwrap_or(CertificateRevocationReason::Unspecified),
                        revoked_by_user_id: row.get(4)?,
                        custom_reason: row.get(5)?,
                    })
                }
            );

            match result {
                Ok(revocation) => Ok(Some(revocation)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(anyhow!("Database error: {e}")),
            }
        })
    }

    /// Get all revocation records (for audit purposes)
    pub(crate) async fn get_all_revocation_records(&self) -> Result<Vec<CertificateRevocation>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, certificate_id, revocation_date, revocation_reason, revoked_by_user_id, custom_reason FROM certificate_revocation ORDER BY revocation_date DESC")?;
            let rows = stmt.query([])?;
            Ok(rows.map(|row| {
                let reason_value: u8 = row.get(3)?;
                let custom_reason: Option<String> = row.get(5)?;
                let (revocation_reason, final_custom_reason) = CertificateRevocationReason::from_u8_with_rfc5280_support(reason_value, custom_reason);
                Ok(CertificateRevocation {
                    id: row.get(0)?,
                    certificate_id: row.get(1)?,
                    revocation_date: row.get(2)?,
                    revocation_reason,
                    revoked_by_user_id: row.get(4)?,
                    custom_reason: final_custom_reason,
                })
            })
            .collect()?)
        })
    }

    /// Unrevoke a certificate (remove from revocation table and update is_revoked flag)
    pub(crate) async fn unrevoke_certificate(&self, certificate_id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            // First, update the is_revoked flag in user_certificates
            conn.execute(
                "UPDATE user_certificates SET is_revoked = 0 WHERE id = ?1",
                params![certificate_id],
            )?;

            // Then remove the revocation record
            conn.execute(
                "DELETE FROM certificate_revocation WHERE certificate_id = ?1",
                params![certificate_id],
            )?;
            Ok(())
        })
    }

    /// Clear all revocation records (for administrative purposes)
    pub(crate) async fn clear_all_revocation_records(&self) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute("DELETE FROM certificate_revocation", [])?;
            Ok(())
        })
    }

    // ================= AUDIT LOGGING METHODS =================

    /// Log an audit event
    pub(crate) async fn log_audit_event(&self, entry: &AuditLogEntry) -> Result<i64> {
        let entry = entry.clone();
        db_do!(self.pool, move |conn: &Connection| {
            let old_values_json = entry.old_values.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default());
            let new_values_json = entry.new_values.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default());

            conn.execute(
                "INSERT INTO audit_logs (timestamp, event_type, event_category, user_id, user_name, ip_address, user_agent, resource_type, resource_id, resource_name, action, success, details, old_values, new_values, error_message, session_id, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    entry.timestamp,
                    serde_json::to_string(&entry.event_type)?,
                    serde_json::to_string(&entry.event_category)?,
                    entry.user_id,
                    entry.user_name,
                    entry.ip_address,
                    entry.user_agent,
                    entry.resource_type,
                    entry.resource_id,
                    entry.resource_name,
                    entry.action,
                    entry.success,
                    entry.details,
                    old_values_json,
                    new_values_json,
                    entry.error_message,
                    entry.session_id,
                    entry.source
                ],
            )?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Query audit logs with advanced filtering
    pub(crate) async fn query_audit_logs(&self, query: &AuditLogQuery) -> Result<(Vec<AuditLogEntry>, i64)> {
        // Convert all the borrowed values to owned strings first
        let user_id_filter = query.user_id.map(|id| id.to_string());
        let event_category_filter = query.event_category.clone();
        let event_type_filter = query.event_type.clone();
        let resource_type_filter = query.resource_type.clone();
        let action_filter = query.action.clone();
        let success_filter = query.success;
        let start_date_filter = query.start_date.map(|d| d.to_string());
        let end_date_filter = query.end_date.map(|d| d.to_string());
        let search_term_filter = query.search_term.clone();
        let page_val = query.page.unwrap_or(1).max(1) as i64;
        let limit_val = query.limit.unwrap_or(50).min(1000) as i64; // Cap at 1000

        db_do!(self.pool, move |conn: &Connection| {
            let mut conditions = Vec::new();
            let mut params = Vec::new();

            // Build WHERE conditions dynamically - now using owned values
            if let Some(ref user_id) = user_id_filter {
                conditions.push("user_id = ?");
                params.push(user_id.clone());
            }

            if let Some(ref event_category) = event_category_filter {
                conditions.push("event_category = ?");
                params.push(serde_json::to_string(event_category)?);
            }

            if let Some(ref event_type) = event_type_filter {
                conditions.push("event_type = ?");
                params.push(serde_json::to_string(event_type)?);
            }

            if let Some(ref resource_type) = resource_type_filter {
                conditions.push("resource_type = ?");
                params.push(resource_type.clone());
            }

            if let Some(ref action) = action_filter {
                conditions.push("action = ?");
                params.push(action.clone());
            }

            if let Some(success) = success_filter {
                conditions.push("success = ?");
                params.push(format!("{}", if success { 1 } else { 0 }));
            }

            if let Some(ref start_date) = start_date_filter {
                conditions.push("timestamp >= ?");
                params.push(start_date.clone());
            }

            if let Some(ref end_date) = end_date_filter {
                conditions.push("timestamp <= ?");
                params.push(end_date.clone());
            }

            if let Some(ref search_term) = search_term_filter {
                conditions.push("(details LIKE ? OR resource_name LIKE ? OR user_name LIKE ? OR error_message LIKE ?)");
                let search_pattern = format!("%{search_term}%");
                params.extend(vec![search_pattern.clone(), search_pattern.clone(), search_pattern.clone(), search_pattern]);
            }

            let where_clause = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };

            // Get total count
            let count_query = format!("SELECT COUNT(*) FROM audit_logs {where_clause}");
            let total_count: i64 = {
                let mut stmt = conn.prepare(&count_query)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                stmt.query_row(&param_refs[..], |row| row.get(0))?
            };

            // Get paginated results
            let offset = (page_val - 1) * limit_val;

            let data_query = format!(
                "SELECT id, timestamp, event_type, event_category, user_id, user_name, ip_address, user_agent, resource_type, resource_id, resource_name, action, success, details, old_values, new_values, error_message, session_id, source FROM audit_logs {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            );

            params.push(limit_val.to_string());
            params.push(offset.to_string());

            let mut stmt = conn.prepare(&data_query)?;
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

            let rows = stmt.query_map(&param_refs[..], |row| {
                let event_type_str: String = row.get(2)?;
                let event_category_str: String = row.get(3)?;

                let old_values: Option<String> = row.get(14)?;
                let new_values: Option<String> = row.get(15)?;

                Ok(AuditLogEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: serde_json::from_str(&event_type_str).unwrap_or(AuditEventType::UserAction),
                    event_category: serde_json::from_str(&event_category_str).unwrap_or(AuditEventCategory::System),
                    user_id: row.get(4)?,
                    user_name: row.get(5)?,
                    ip_address: row.get(6)?,
                    user_agent: row.get(7)?,
                    resource_type: row.get(8)?,
                    resource_id: row.get(9)?,
                    resource_name: row.get(10)?,
                    action: row.get(11)?,
                    success: row.get::<_, i64>(12)? != 0,
                    details: row.get(13)?,
                    old_values: old_values.and_then(|s| serde_json::from_str(&s).ok()),
                    new_values: new_values.and_then(|s| serde_json::from_str(&s).ok()),
                    error_message: row.get(16)?,
                    session_id: row.get(17)?,
                    source: row.get(18)?,
                })
            })?;

            let entries = rows.collect::<Result<Vec<_>, _>>()?;
            Ok((entries, total_count))
        })
    }

    /// Get audit log statistics
    pub(crate) async fn get_audit_stats(&self) -> Result<AuditLogStats> {
        db_do!(self.pool, |conn: &Connection| {
            // Total events
            let total_events: i64 = conn.query_row("SELECT COUNT(*) FROM audit_logs", [], |row| row.get(0))?;

            // Events in last 24 hours
            let yesterday = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64 - (24 * 60 * 60 * 1000);
            let events_today: i64 = conn.query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?",
                params![yesterday],
                |row| row.get(0),
            )?;

            // Failed operations
            let failed_operations: i64 = conn.query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE success = 0",
                [],
                |row| row.get(0),
            )?;

            // Top actions (last 30 days)
            let thirty_days_ago = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64 - (30 * 24 * 60 * 60 * 1000);

            let mut top_actions_stmt = conn.prepare(
                "SELECT action, COUNT(*) as count FROM audit_logs WHERE timestamp >= ? GROUP BY action ORDER BY count DESC LIMIT 10"
            )?;
            let top_actions_rows = top_actions_stmt.query_map(params![thirty_days_ago], |row| {
                Ok(ActionCount {
                    action: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            let top_actions = top_actions_rows.collect::<Result<Vec<_>, _>>()?;

            // Top users (last 30 days)
            let mut top_users_stmt = conn.prepare(
                "SELECT user_id, user_name, COUNT(*) as count, MAX(timestamp) as last_activity FROM audit_logs WHERE timestamp >= ? AND user_id IS NOT NULL GROUP BY user_id, user_name ORDER BY count DESC LIMIT 10"
            )?;
            let top_users_rows = top_users_stmt.query_map(params![thirty_days_ago], |row| {
                Ok(UserActivity {
                    user_id: row.get(0)?,
                    user_name: row.get(1)?,
                    event_count: row.get(2)?,
                    last_activity: row.get(3)?,
                })
            })?;
            let top_users = top_users_rows.collect::<Result<Vec<_>, _>>()?;

            // Recent events (last 24 hours)
            let mut recent_stmt = conn.prepare(
                "SELECT id, timestamp, event_type, event_category, user_id, user_name, ip_address, user_agent, resource_type, resource_id, resource_name, action, success, details, old_values, new_values, error_message, session_id, source FROM audit_logs ORDER BY timestamp DESC LIMIT 50"
            )?;
            let recent_rows = recent_stmt.query_map([], |row| {
                let event_type_str: String = row.get(2)?;
                let event_category_str: String = row.get(3)?;

                let old_values: Option<String> = row.get(14)?;
                let new_values: Option<String> = row.get(15)?;

                Ok(AuditLogEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: serde_json::from_str(&event_type_str).unwrap_or(AuditEventType::UserAction),
                    event_category: serde_json::from_str(&event_category_str).unwrap_or(AuditEventCategory::System),
                    user_id: row.get(4)?,
                    user_name: row.get(5)?,
                    ip_address: row.get(6)?,
                    user_agent: row.get(7)?,
                    resource_type: row.get(8)?,
                    resource_id: row.get(9)?,
                    resource_name: row.get(10)?,
                    action: row.get(11)?,
                    success: row.get::<_, i64>(12)? != 0,
                    details: row.get(13)?,
                    old_values: old_values.and_then(|s| serde_json::from_str(&s).ok()),
                    new_values: new_values.and_then(|s| serde_json::from_str(&s).ok()),
                    error_message: row.get(16)?,
                    session_id: row.get(17)?,
                    source: row.get(18)?,
                })
            })?;
            let recent_events = recent_rows.collect::<Result<Vec<_>, _>>()?;

            Ok(AuditLogStats {
                total_events,
                events_today,
                failed_operations,
                top_actions,
                top_users,
                recent_events,
            })
        })
    }

    /// Clean up old audit logs based on retention policy
    pub(crate) async fn cleanup_audit_logs(&self, retention_days: i32) -> Result<AuditCleanupResult> {
        let start_time = std::time::SystemTime::now();

        db_do!(self.pool, |conn: &Connection| {
            let cutoff_date = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64 - ((retention_days as i64) * 24 * 60 * 60 * 1000);

            // Get count before deletion
            let count_before: i64 = conn.query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp < ?",
                params![cutoff_date],
                |row| row.get(0),
            )?;

            // Delete old records
            conn.execute(
                "DELETE FROM audit_logs WHERE timestamp < ?",
                params![cutoff_date],
            )?;

            // Update cleanup timestamp in settings if settings table exists
            let _ = conn.execute(
                "UPDATE audit_settings SET last_cleanup = ? WHERE id = 1",
                params![std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64],
            );

            let execution_time = std::time::SystemTime::now()
                .duration_since(start_time)
                .unwrap()
                .as_millis() as i64;

            Ok(AuditCleanupResult {
                deleted_count: count_before,
                cutoff_date,
                execution_time_ms: execution_time,
            })
        })
    }

    /// Set audit settings
    pub(crate) async fn set_audit_settings(&self, settings: &AuditSettings) -> Result<()> {
        let settings = settings.clone();
        db_do!(self.pool, move |conn: &Connection| {
            conn.execute(
                "INSERT OR REPLACE INTO audit_settings (id, enabled, retention_days, log_authentication, log_certificate_operations, log_ca_operations, log_user_operations, log_settings_changes, log_system_events, max_log_size_mb, last_cleanup) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    settings.enabled,
                    settings.retention_days,
                    settings.log_authentication,
                    settings.log_certificate_operations,
                    settings.log_ca_operations,
                    settings.log_user_operations,
                    settings.log_settings_changes,
                    settings.log_system_events,
                    settings.max_log_size_mb,
                    settings.last_cleanup,
                ],
            )?;
            Ok(())
        })
    }

    /// Get audit settings
    pub(crate) async fn get_audit_settings(&self) -> Result<AuditSettings> {
        db_do!(self.pool, |conn: &Connection| {
            let result = conn.query_row(
                "SELECT enabled, retention_days, log_authentication, log_certificate_operations, log_ca_operations, log_user_operations, log_settings_changes, log_system_events, max_log_size_mb, last_cleanup FROM audit_settings WHERE id = 1",
                [],
                |row| {
                    Ok(AuditSettings {
                        enabled: row.get::<_, i64>(0)? != 0,
                        retention_days: row.get(1)?,
                        log_authentication: row.get::<_, i64>(2)? != 0,
                        log_certificate_operations: row.get::<_, i64>(3)? != 0,
                        log_ca_operations: row.get::<_, i64>(4)? != 0,
                        log_user_operations: row.get::<_, i64>(5)? != 0,
                        log_settings_changes: row.get::<_, i64>(6)? != 0,
                        log_system_events: row.get::<_, i64>(7)? != 0,
                        max_log_size_mb: row.get(8)?,
                        last_cleanup: row.get(9).ok(),
                    })
                }
            );

            match result {
                Ok(settings) => Ok(settings),
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    // Create default settings if none exist
                    Ok(AuditSettings::default())
                }
                Err(e) => Err(anyhow!("Database error: {e}")),
            }
        })
    }
}
