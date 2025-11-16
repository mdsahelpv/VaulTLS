-- Create audit logs table for comprehensive event logging
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,                    -- Unix timestamp in milliseconds
    event_type VARCHAR(50) NOT NULL,              -- Type of event (user_action, system_event, etc.)
    event_category VARCHAR(50) NOT NULL,          -- Category (authentication, certificates, ca, settings, etc.)
    user_id INTEGER,                              -- User who performed the action (NULL for system events)
    user_name VARCHAR(255),                       -- User name for easier queries
    ip_address VARCHAR(45),                       -- IP address of the requester
    user_agent TEXT,                              -- User agent string
    resource_type VARCHAR(50),                    -- Type of resource affected (certificate, ca, user, etc.)
    resource_id BIGINT,                           -- ID of the affected resource
    resource_name VARCHAR(255),                   -- Name of the affected resource
    action VARCHAR(50) NOT NULL,                  -- Action performed (create, update, delete, etc.)
    success BOOLEAN NOT NULL DEFAULT 1,          -- Whether the action was successful
    details TEXT,                                 -- Detailed information about the event
    old_values TEXT,                              -- Previous values (for updates)
    new_values TEXT,                              -- New values (for creates/updates)
    error_message TEXT,                           -- Error message if the action failed
    session_id VARCHAR(255),                      -- Session identifier for tracking
    source VARCHAR(50) DEFAULT 'api'             -- Source of the event (api, web, cli, system)
);

-- Create indexes for efficient querying
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_event_category ON audit_logs(event_category);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX idx_audit_logs_success ON audit_logs(success);
CREATE INDEX idx_audit_logs_session_id ON audit_logs(session_id);

-- Settings table for audit configuration
CREATE TABLE audit_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),      -- Only one settings row
    enabled BOOLEAN NOT NULL DEFAULT 1,
    retention_days INTEGER NOT NULL DEFAULT 365,
    log_authentication BOOLEAN NOT NULL DEFAULT 1,
    log_certificate_operations BOOLEAN NOT NULL DEFAULT 1,
    log_ca_operations BOOLEAN NOT NULL DEFAULT 1,
    log_user_operations BOOLEAN NOT NULL DEFAULT 1,
    log_settings_changes BOOLEAN NOT NULL DEFAULT 1,
    log_system_events BOOLEAN NOT NULL DEFAULT 1,
    max_log_size_mb INTEGER NOT NULL DEFAULT 100,
    last_cleanup INTEGER                              -- Timestamp of last cleanup
);
