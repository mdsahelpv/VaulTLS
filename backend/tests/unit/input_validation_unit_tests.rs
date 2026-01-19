use crate::api::{validate_user_name, validate_email, validate_certificate_name, sanitize_certificate_name, validate_dns_name, validate_ip_address, validate_custom_revocation_reason};
use crate::ApiError;

// Unit tests for input validation and sanitization

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_name_validation() {
        // Valid names
        assert!(validate_user_name("john_doe").is_ok());
        assert!(validate_user_name("user123").is_ok());
        assert!(validate_user_name("test-user").is_ok());
        assert!(validate_user_name("a").is_ok()); // minimum length

        // Exactly maximum length
        let max_name = "a".repeat(255);
        assert!(validate_user_name(&max_name).is_ok());

        // Invalid names
        assert!(validate_user_name("").is_err()); // empty
        let too_long_name = "a".repeat(256);
        assert!(validate_user_name(&too_long_name).is_err()); // too long
    }

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.email+tag@domain.co.uk").is_ok());
        assert!(validate_email("user@localhost").is_ok());

        // Invalid emails
        assert!(validate_email("").is_err()); // empty
        assert!(validate_email("invalid").is_err()); // no @
        assert!(validate_email("@domain.com").is_err()); // no local part
        assert!(validate_email("user@").is_err()); // no domain
        assert!(validate_email("user@domain").is_err()); // no TLD
        assert!(validate_email("user domain.com").is_err()); // space

        // Too long emails
        let long_local = "a".repeat(250) + "@example.com";
        assert!(validate_email(&long_local).is_err()); // local part too long
    }

    #[test]
    fn test_certificate_name_validation() {
        // Valid certificate names
        assert!(validate_certificate_name("my-cert").is_ok());
        assert!(validate_certificate_name("cert_123").is_ok());
        assert!(validate_certificate_name("test.cert.domain").is_ok());

        // Exactly maximum length
        let max_name = "a".repeat(255);
        assert!(validate_certificate_name(&max_name).is_ok());

        // Invalid names
        assert!(validate_certificate_name("").is_err()); // empty
        let too_long_name = "a".repeat(256);
        assert!(validate_certificate_name(&too_long_name).is_err()); // too long
    }

    #[test]
    fn test_certificate_name_sanitization() {
        // Safe names should pass through unchanged
        assert_eq!(sanitize_certificate_name("my-cert"), Ok("my-cert".to_string()));
        assert_eq!(sanitize_certificate_name("cert_123"), Ok("cert_123".to_string()));
        assert_eq!(sanitize_certificate_name("test.cert"), Ok("test.cert".to_string()));

        // Dangerous characters should be removed
        assert_eq!(sanitize_certificate_name("cert;name"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert&name"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert|name"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert`name"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert$name"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert(name)"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert<name>"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert[name]"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert{name}"), Ok("certname".to_string()));

        // Path traversal attempts should be blocked
        assert_eq!(sanitize_certificate_name("../etc/passwd"), Ok("".to_string()));
        assert_eq!(sanitize_certificate_name("../../../etc/passwd"), Ok("".to_string()));
        assert_eq!(sanitize_certificate_name("./config"), Ok("config".to_string()));
        assert_eq!(sanitize_certificate_name(".\\config"), Ok("config".to_string()));

        // Control characters should be removed
        assert_eq!(sanitize_certificate_name("cert\x00name"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert\nname"), Ok("certname".to_string()));
        assert_eq!(sanitize_certificate_name("cert\tname"), Ok("certname".to_string()));

        // Empty result after sanitization should be rejected
        assert!(sanitize_certificate_name("../").is_err()); // becomes empty
        assert!(sanitize_certificate_name("...").is_err()); // becomes empty after removing dots
        assert!(sanitize_certificate_name(";;;").is_err()); // becomes empty

        // Whitespace handling
        assert_eq!(sanitize_certificate_name("  cert  "), Ok("cert".to_string()));
        assert_eq!(sanitize_certificate_name("\tcert\n"), Ok("cert".to_string()));

        // Complex attack vectors
        assert_eq!(sanitize_certificate_name("../../etc$(command)"), Ok("etcommand".to_string()));
        assert_eq!(sanitize_certificate_name("cert/../../../file"), Ok("certfile".to_string()));
    }

    #[test]
    fn test_dns_name_validation() {
        // Valid DNS names
        assert!(validate_dns_name("example.com").is_ok());
        assert!(validate_dns_name("sub.example.com").is_ok());
        assert!(validate_dns_name("test-server").is_ok());
        assert!(validate_dns_name("a").is_ok()); // minimum length

        // Exactly maximum length
        let max_dns = "a".repeat(253);
        assert!(validate_dns_name(&max_dns).is_ok());

        // Invalid DNS names
        assert!(validate_dns_name("").is_err()); // empty
        let too_long_dns = "a".repeat(254);
        assert!(validate_dns_name(&too_long_dns).is_err()); // too long

        // Invalid characters
        assert!(validate_dns_name("test space").is_err()); // space
        assert!(validate_dns_name("test@domain").is_err()); // @
        assert!(validate_dns_name("test#domain").is_err()); // #
        assert!(validate_dns_name("test$domain").is_err()); // $
        assert!(validate_dns_name("test%domain").is_err()); // %

        // Invalid formats
        assert!(validate_dns_name("..example.com").is_err()); // leading dots
        assert!(validate_dns_name("example.com.").is_err()); // trailing dot
        assert!(validate_dns_name(".example.com").is_err()); // leading dot
        assert!(validate_dns_name("example..com").is_err()); // consecutive dots
    }

    #[test]
    fn test_ip_address_validation() {
        // Valid IPv4 addresses
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("10.0.0.1").is_ok());
        assert!(validate_ip_address("127.0.0.1").is_ok());
        assert!(validate_ip_address("0.0.0.0").is_ok());
        assert!(validate_ip_address("255.255.255.255").is_ok());

        // Valid IPv6 addresses
        assert!(validate_ip_address("::1").is_ok());
        assert!(validate_ip_address("2001:db8::1").is_ok());
        assert!(validate_ip_address("fe80::1%eth0").is_ok()); // with zone identifier

        // Invalid IP addresses
        assert!(validate_ip_address("").is_err()); // empty
        assert!(validate_ip_address("192.168.1").is_err()); // incomplete IPv4
        assert!(validate_ip_address("192.168.1.1.1").is_err()); // too many octets
        assert!(validate_ip_address("256.1.1.1").is_err()); // invalid octet
        assert!(validate_ip_address("192.168.1.1.1").is_err()); // too many dots
        assert!(validate_ip_address("192.168.1.1 ").is_err()); // trailing space
        assert!(validate_ip_address(" 192.168.1.1").is_err()); // leading space
        assert!(validate_ip_address("192.168.1.1a").is_err()); // non-numeric
        assert!(validate_ip_address("not.an.ip").is_err()); // not IP format
        assert!(validate_ip_address("192.168.1.1/24").is_err()); // CIDR notation not supported
    }

    #[test]
    fn test_custom_revocation_reason_validation() {
        // Valid reasons
        assert!(validate_custom_revocation_reason("Certificate compromised").is_ok());
        assert!(validate_custom_revocation_reason("Key no longer trusted").is_ok());
        assert!(validate_custom_revocation_reason("A").is_ok()); // minimum length

        // Exactly maximum length
        let max_reason = "a".repeat(500);
        assert!(validate_custom_revocation_reason(&max_reason).is_ok());

        // Invalid reasons
        assert!(validate_custom_revocation_reason("").is_err()); // empty
        let too_long_reason = "a".repeat(501);
        assert!(validate_custom_revocation_reason(&too_long_reason).is_err()); // too long
    }

    #[test]
    fn test_certificate_name_injection_prevention() {
        // Path traversal attacks
        let dangerous_names = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config",
            "/etc/passwd",
            "C:\\Windows\\System32\\config",
            "../../../../../../etc/shadow",
        ];

        for dangerous_name in dangerous_names {
            let result = sanitize_certificate_name(dangerous_name);
            match result {
                Ok(sanitized) => {
                    // Should either be empty or not contain dangerous patterns
                    assert!(!sanitized.contains("../"), "Path traversal not fully sanitized: {} -> {}", dangerous_name, sanitized);
                    assert!(!sanitized.contains("..\\"), "Windows path traversal not fully sanitized: {} -> {}", dangerous_name, sanitized);
                    assert!(!sanitized.contains("/"), "Directory separator not removed: {} -> {}", dangerous_name, sanitized);
                    assert!(!sanitized.contains("\\"), "Backslash not removed: {} -> {}", dangerous_name, sanitized);
                }
                Err(_) => {
                    // It's acceptable for dangerous names to be rejected entirely
                }
            }
        }
    }

    #[test]
    fn test_command_injection_prevention() {
        // Command injection attempts
        let injection_attempts = vec![
            "cert$(rm -rf /)",
            "cert`rm -rf /`",
            "cert; rm -rf /",
            "cert && rm -rf /",
            "cert || rm -rf /",
            "cert | rm -rf /",
            "cert > /dev/null",
            "cert < /etc/passwd",
        ];

        for injection_attempt in injection_attempts {
            let result = sanitize_certificate_name(injection_attempt);
            assert!(result.is_ok(), "Sanitization should succeed: {}", injection_attempt);

            let sanitized = result.unwrap();
            // All dangerous shell metacharacters should be removed
            assert!(!sanitized.contains("$"), "Dollar sign not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains("`"), "Backtick not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains(";"), "Semicolon not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains("&"), "Ampersand not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains("|"), "Pipe not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains(">"), "Greater than not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains("<"), "Less than not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains("("), "Left parenthesis not removed: {} -> {}", injection_attempt, sanitized);
            assert!(!sanitized.contains(")"), "Right parenthesis not removed: {} -> {}", injection_attempt, sanitized);
        }
    }

    #[test]
    fn test_control_character_removal() {
        // Control characters that should be removed
        let control_chars = vec![
            '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', // C0 control codes
            '\x08', '\x09', '\x0A', '\x0B', '\x0C', '\x0D', '\x0E', '\x0F',
            '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17',
            '\x18', '\x19', '\x1A', '\x1B', '\x1C', '\x1D', '\x1E', '\x1F',
            '\x7F', // DEL
            '\u{0080}', '\u{0081}', '\u{0082}', // C1 control codes
        ];

        for &control_char in &control_chars {
            let test_name = format!("cert{}name", control_char);
            let result = sanitize_certificate_name(&test_name);
            assert!(result.is_ok(), "Sanitization should succeed for control char: {:?}", control_char);

            let sanitized = result.unwrap();
            assert!(!sanitized.chars().any(|c| c.is_control()), "Control character not removed: {:?} -> {}", control_char, sanitized);
        }
    }

    #[test]
    fn test_large_input_dos_prevention() {
        // Test with very large inputs that could cause DoS

        // Large certificate name (should be rejected by validation)
        let large_cert_name = "a".repeat(1000);
        assert!(validate_certificate_name(&large_cert_name).is_err());

        // Large email (should be rejected by validation)
        let large_email = "a".repeat(250) + "@example.com";
        assert!(validate_email(&large_email).is_err());

        // Large DNS name (should be rejected by validation)
        let large_dns = "a".repeat(300);
        assert!(validate_dns_name(&large_dns).is_err());

        // Large revocation reason (should be rejected by validation)
        let large_reason = "a".repeat(600);
        assert!(validate_custom_revocation_reason(&large_reason).is_err());

        // Test sanitization with large input containing dangerous chars
        let large_dangerous = "../".repeat(100) + "$(rm -rf /)".repeat(50);
        let result = sanitize_certificate_name(&large_dangerous);
        // Should either succeed (with dangerous chars removed) or fail gracefully
        match result {
            Ok(sanitized) => {
                assert!(sanitized.len() < large_dangerous.len(), "Sanitized output should be shorter than dangerous input");
                assert!(!sanitized.contains("$"), "Dangerous chars should be removed");
                assert!(!sanitized.contains("("), "Dangerous chars should be removed");
            }
            Err(_) => {
                // Acceptable to reject extremely large dangerous inputs
            }
        }
    }

    #[test]
    fn test_edge_case_validation() {
        // Edge cases that should be handled gracefully

        // Null bytes
        assert!(sanitize_certificate_name("cert\x00name").is_ok());
        assert_eq!(sanitize_certificate_name("cert\x00name").unwrap(), "certname");

        // Unicode control characters
        assert!(sanitize_certificate_name("cert\u{0000}name").is_ok());
        assert_eq!(sanitize_certificate_name("cert\u{0000}name").unwrap(), "certname");

        // Mixed dangerous characters
        let mixed_dangerous = "../etc$(cmd)`inject`;drop&table|rm>/dev/null";
        let result = sanitize_certificate_name(mixed_dangerous);
        assert!(result.is_ok());
        let sanitized = result.unwrap();
        assert!(!sanitized.contains("../"));
        assert!(!sanitized.contains("$"));
        assert!(!sanitized.contains("`"));
        assert!(!sanitized.contains(";"));
        assert!(!sanitized.contains("&"));
        assert!(!sanitized.contains("|"));
        assert!(!sanitized.contains(">"));
        assert!(!sanitized.contains("/"));
    }
}
