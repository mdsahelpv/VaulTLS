use std::fs;
use std::path::Path;
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509;
use rusqlite::{Connection, Result};
use base64::{Engine as _, engine::general_purpose};

fn extract_cert_with_extensions() -> Result<()> {
    // Connect to database
    let conn = Connection::open("backend/database.db3")?;

    // Get the subordinate CA certificate
    let mut stmt = conn.prepare(
        "SELECT id, name, pkcs12, type FROM user_certificates WHERE id = 1"
    )?;

    let cert_iter = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;

    for cert in cert_iter {
        let (id, name, pkcs12_blob, cert_type) = cert?;

        println!("Certificate: {} (ID: {}, Type: {})", name, id, cert_type);

        // Parse PKCS#12 - try without password first, then with known password
        let parsed = if let Ok(parsed) = Pkcs12::from_der(&pkcs12_blob)?.parse("") {
            parsed
        } else if let Ok(parsed) = Pkcs12::from_der(&pkcs12_blob)?.parse("P@ssw0rd") {
            parsed
        } else {
            println!("  Failed to parse PKCS#12 (password protected)");
            continue;
        };

        // Get the certificate
        let cert = match parsed.cert {
            Some(cert) => cert,
            None => {
                println!("  No certificate in PKCS#12");
                continue;
            }
        };

        // Print subject
        println!("  Subject: {:?}", cert.subject_name().entries()
            .find(|e| e.object().nid().short_name().unwrap_or("unknown") == "CN")
            .and_then(|e| e.data().as_utf8().ok())
            .map(|d| d.to_string())
            .unwrap_or_else(|| "Unknown".to_string())
        );

        // Check for AIA and CDP extensions
        println!("  Checking extensions...");

        // Try using OpenSSL command-line to get proper extension info
        let pem = cert.to_pem().unwrap_or_default();
        let temp_cert_path = "/tmp/test_cert.pem";
        fs::write(temp_cert_path, &pem).unwrap_or_default();

        let output = std::process::Command::new("openssl")
            .args(["x509", "-in", temp_cert_path, "-text", "-noout"])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);

                println!("  Authority Information Access (AIA):");
                let has_aia = if text.contains("Authority Information Access") {
                    println!("    ✅ AIA extension found");
                    true
                } else {
                    println!("    ❌ No AIA extension found");
                    false
                };

                println!("  Certificate Revocation List (CDP):");
                let has_cdp = if text.contains("CRL Distribution Points") {
                    println!("    ✅ CDP extension found");
                    true
                } else {
                    println!("    ❌ No CDP extension found");
                    false
                };

                println!("  Extension Details:");
                if has_aia || has_cdp {
                    // Print relevant sections
                    let lines: Vec<&str> = text.lines().collect();
                    let mut in_aia = false;
                    let mut in_cdp = false;

                    for line in lines {
                        let trimmed = line.trim();
                        if trimmed.contains("Authority Information Access") {
                            in_aia = true;
                            println!("    {}", line.trim());
                        } else if trimmed.contains("CRL Distribution Points") {
                            in_cdp = true;
                            println!("    {}", line.trim());
                        } else if in_aia || in_cdp {
                            if !trimmed.is_empty() && (trimmed.contains("URI:") || trimmed.contains("caIssuers") || trimmed.contains("ca.crl")) {
                                println!("    {}", line.trim());
                            } else if trimmed.is_empty() {
                                if in_aia {
                                    in_aia = false;
                                }
                                if in_cdp {
                                    in_cdp = false;
                                }
                            }
                        }
                    }
                }

                // Clean up temp file
                let _ = fs::remove_file(temp_cert_path);

            },
            _ => {
                println!("  ❌ Failed to analyze certificate extensions");
            }
        }

        break; // Only process first cert
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("=== Checking Subordinate CA Certificate Extensions ===\n");
    extract_cert_with_extensions()?;
    println!("\n=== Done ===");
    Ok(())
}
