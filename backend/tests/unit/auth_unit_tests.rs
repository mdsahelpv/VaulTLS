use crate::auth::password_auth::Password;
use crate::constants::ARGON2;
use argon2::password_hash::SaltString;
use argon2::PasswordHasher;
use std::sync::Arc;

// Unit tests for authentication security features

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_v1_only_verification() {
        let password = "test123!@#";

        // Create V1 password hash (secure)
        let hash = Password::new_server_hash(password).unwrap();
        assert!(!hash.is_v2_hash()); // Should be V1

        // Should verify correctly
        assert!(hash.verify(password));

        // Should reject wrong password
        assert!(!hash.verify("wrong_password"));

        // Should reject empty password
        assert!(!hash.verify(""));
    }

    #[test]
    fn test_password_v2_hash_rejection() {
        // Create a mock V2 hash for testing (simulating old format)
        let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS";
        let salt = SaltString::encode_b64(salt_str.as_bytes()).unwrap();
        let client_hash = ARGON2.hash_password(b"test123", &salt).unwrap();
        let client_hash_string = client_hash.serialize();
        let v2_hash = ARGON2.hash_password(client_hash_string.as_bytes(), &SaltString::generate(&mut rand_core::OsRng).unwrap()).unwrap();
        let v2_hash_string = format!("v2{}", v2_hash.serialize());

        // Parse as V2 hash
        let password_hash = Password::try_from(v2_hash_string.as_str()).unwrap();
        assert!(password_hash.is_v2_hash()); // Should be detected as V2

        // Should reject V2 verification (security fix)
        assert!(!password_hash.verify("test123"));
        assert!(!password_hash.verify("any_password"));
    }

    #[test]
    fn test_password_hash_format_validation() {
        // Test V1 format parsing
        let v1_hash = "v1$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpams$aGVsbG93b3JsZA";
        let password = Password::try_from(v1_hash).unwrap();
        assert!(!password.is_v2_hash());

        // Test V2 format parsing
        let v2_hash = "v2$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpams$aGVsbG93b3JsZA";
        let password = Password::try_from(v2_hash).unwrap();
        assert!(password.is_v2_hash());

        // Test plain format (backward compatibility)
        let plain_hash = "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpams$aGVsbG93b3JsZA";
        let password = Password::try_from(plain_hash).unwrap();
        assert!(!password.is_v2_hash());
    }

    #[test]
    fn test_password_complexity_requirements() {
        let weak_passwords = vec![
            "",
            "1",
            "12",
            "123",
            "1234",
            "password",
            "12345678",
            "qwerty",
            "abc123",
        ];

        // All passwords should be accepted (complexity validation happens elsewhere)
        // This test ensures our hashing doesn't fail on various inputs
        for password in weak_passwords {
            let hash = Password::new_server_hash(password);
            assert!(hash.is_ok(), "Failed to hash password: {}", password);

            let hash = hash.unwrap();
            assert!(hash.verify(password), "Hash verification failed for: {}", password);
        }
    }

    #[test]
    fn test_password_hash_consistency() {
        let password = "SecureP@ssw0rd2024!";
        let hash1 = Password::new_server_hash(password).unwrap();
        let hash2 = Password::new_server_hash(password).unwrap();

        // Different hashes for same password (due to random salt)
        assert_ne!(hash1.to_string(), hash2.to_string());

        // But both should verify the same password
        assert!(hash1.verify(password));
        assert!(hash2.verify(password));
    }

    #[test]
    fn test_password_timing_attack_resistance() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let hash = Password::new_server_hash(password).unwrap();

        // Time the verification of correct password
        let start = std::time::Instant::now();
        let result_correct = hash.verify(password);
        let duration_correct = start.elapsed();

        // Time the verification of wrong password
        let start = std::time::Instant::now();
        let result_wrong = hash.verify(wrong_password);
        let duration_wrong = start.elapsed();

        // Results should be correct
        assert!(result_correct);
        assert!(!result_wrong);

        // Timings should be similar (within reasonable bounds to prevent timing attacks)
        // Argon2 is designed to have consistent timing, but we'll check they're reasonably close
        let ratio = duration_correct.as_millis() as f64 / duration_wrong.as_millis() as f64;
        assert!(ratio > 0.5 && ratio < 2.0, "Timing difference too large: {}ms vs {}ms (ratio: {})",
                duration_correct.as_millis(), duration_wrong.as_millis(), ratio);
    }

    #[test]
    fn test_password_hash_migration_scenario() {
        // Simulate a user with V2 hash trying to log in
        let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS";
        let salt = SaltString::encode_b64(salt_str.as_bytes()).unwrap();
        let client_hash = ARGON2.hash_password(b"migrate_me", &salt).unwrap();
        let client_hash_string = client_hash.serialize();
        let v2_hash = ARGON2.hash_password(client_hash_string.as_bytes(), &SaltString::generate(&mut rand_core::OsRng).unwrap()).unwrap();
        let v2_hash_string = format!("v2{}", v2_hash.serialize());

        let old_password_hash = Password::try_from(v2_hash_string.as_str()).unwrap();

        // V2 hash should be detected
        assert!(old_password_hash.is_v2_hash());

        // V2 verification should fail (security requirement)
        assert!(!old_password_hash.verify("migrate_me"));

        // Create new V1 hash for the same password
        let new_password_hash = Password::new_server_hash("migrate_me").unwrap();

        // New hash should be V1 and verify correctly
        assert!(!new_password_hash.is_v2_hash());
        assert!(new_password_hash.verify("migrate_me"));
    }

    #[test]
    fn test_password_hash_error_handling() {
        // Test invalid hash formats
        let invalid_hashes = vec![
            "",
            "invalid",
            "v3$invalid",
            "v1$not_argon2",
            "$argon2id$invalid",
        ];

        for invalid_hash in invalid_hashes {
            let result = Password::try_from(invalid_hash);
            assert!(result.is_err(), "Should fail to parse invalid hash: {}", invalid_hash);
        }
    }

    #[test]
    fn test_password_display_format() {
        let password = "test_password";
        let hash = Password::new_server_hash(password).unwrap();

        let display = format!("{}", hash);
        assert!(display.starts_with("v1"), "V1 hash should display with v1 prefix: {}", display);

        // Ensure display doesn't leak sensitive information
        assert!(!display.contains(password), "Display should not contain original password");
    }
}
