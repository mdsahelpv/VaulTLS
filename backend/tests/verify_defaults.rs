#[cfg(test)]
mod tests {
    use vaultls::cert::CertificateBuilder;

    #[test]
    fn test_default_rsa_key_size() {
        // No CA, no key type, no key size -> should be RSA 4096
        let builder = CertificateBuilder::new_with_ca_and_key_type_size(None, None, None).unwrap();
        assert_eq!(builder.get_key_size().unwrap(), 4096);
    }

    #[test]
    fn test_explicit_rsa_2048() {
        let builder = CertificateBuilder::new_with_ca_and_key_type_size(None, Some("RSA"), Some("2048")).unwrap();
        assert_eq!(builder.get_key_size().unwrap(), 2048);
    }
}
