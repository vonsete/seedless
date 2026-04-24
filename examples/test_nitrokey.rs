/// Manual test for NitroKey 3
/// Usage: NITROPY_SECRETS_PASSWORD=123456 cargo run --example test_nitrokey --features hsm-nitrokey

#[cfg(feature = "hsm-nitrokey")]
fn main() {
    use seedless::frost;
    use std::process::Command;

    println!("🔍 Testing NitroKey 3 Support");

    // Check NK3 is connected
    let list_output = Command::new("nitropy")
        .args(["nk3", "list"])
        .output()
        .expect("nitropy not found. Install: python3 -m pipx install pynitrokey");

    let list_str = String::from_utf8_lossy(&list_output.stdout);
    println!("📱 {}", list_str.trim());

    if list_str.contains("No Nitrokey") || list_str.is_empty() {
        eprintln!("❌ No NitroKey 3 found");
        std::process::exit(1);
    }

    // Get PIN from env or prompt
    let pin_env = match std::env::var("NITROPY_SECRETS_PASSWORD") {
        Ok(pin) => {
            println!("✓ PIN from env var");
            pin
        }
        Err(_) => {
            println!("Enter NitroKey PIN (will not echo): ");
            let pin = rpassword::prompt_password("")
                .expect("Failed to read PIN");
            pin
        }
    };
    println!("✓ PIN set (len={})", pin_env.len());

    // Generate test shares
    println!("\n1️⃣  Generating FROST shares...");
    let (_group_pubkey, shares, _) = frost::generate_shares(2, 2).expect("Failed to generate shares");
    println!("✓ Generated {} shares", shares.len());

    // Write to NK3
    println!("\n2️⃣  Writing shares to NitroKey 3...");
    let pin_bytes = pin_env.as_bytes().to_vec();

    for (id, share) in shares.iter().enumerate() {
        let participant_id = (id + 1) as u16;

        // Create encrypted share
        let encrypted = encrypt_share(share, &pin_bytes).expect("Encryption failed");
        let hex_data = hex::encode(&encrypted);

        // Write to NK3 via nitropy
        let cred_name = format!("seedless-participant-{}", participant_id);
        let status = std::process::Command::new("nitropy")
            .args([
                "nk3",
                "secrets",
                "add-password",
                &cred_name,
                "--password",
                &hex_data,
            ])
            .env("NITROPY_SECRETS_PASSWORD", &pin_env)
            .status()
            .expect("Failed to run nitropy");

        if status.success() {
            println!("✓ Share {} written", participant_id);
        } else {
            eprintln!("❌ Failed to write share {}", participant_id);
            std::process::exit(1);
        }
    }

    // Read back from NK3
    println!("\n3️⃣  Reading shares back from NitroKey 3...");
    for (id, original_share) in shares.iter().enumerate() {
        let participant_id = (id + 1) as u16;
        let cred_name = format!("seedless-participant-{}", participant_id);

        // Read from NK3
        let output = std::process::Command::new("nitropy")
            .args([
                "nk3",
                "secrets",
                "get-password",
                &cred_name,
                "--password",
            ])
            .env("NITROPY_SECRETS_PASSWORD", &pin_env)
            .output()
            .expect("Failed to read from NK3");

        if !output.status.success() {
            eprintln!("❌ Failed to read share {}", participant_id);
            std::process::exit(1);
        }

        let output_str = String::from_utf8(output.stdout)
            .expect("Invalid UTF-8 from nitropy");

        // Extract only the hex part (skip nitropy header/footer)
        let hex_data = output_str
            .lines()
            .find(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty()
                    && !trimmed.starts_with("Command")
                    && !trimmed.starts_with("Please")
                    && !trimmed.starts_with("Done")
                    && !trimmed.starts_with("::")
            })
            .expect("No hex data found in output")
            .trim();

        println!("  Read {} bytes of hex data", hex_data.len());
        let encrypted = hex::decode(&hex_data)
            .map_err(|e| format!("Failed to decode hex: {}", e))
            .expect("Invalid hex in output");
        let decrypted = decrypt_share(&encrypted, &pin_bytes).expect("Decryption failed");

        // Verify
        if decrypted == *original_share {
            println!("✓ Share {} verified (encrypted/decrypted correctly)", participant_id);
        } else {
            eprintln!("❌ Share {} mismatch!", participant_id);
            eprintln!("   Original: {} bytes", original_share.len());
            eprintln!("   Decrypted: {} bytes", decrypted.len());
            std::process::exit(1);
        }
    }

    println!("\n✅ All tests passed!");
    println!("   - NitroKey 3 detected and working");
    println!("   - Write/read cycle successful");
    println!("   - Encryption/decryption verified");
}

#[cfg(not(feature = "hsm-nitrokey"))]
fn main() {
    println!("This example requires --features hsm-nitrokey");
    std::process::exit(1);
}

// Helper: encrypt share (same as in hsm/nitrokey.rs)
#[cfg(feature = "hsm-nitrokey")]
fn encrypt_share(share_data: &[u8], pin: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce, Key, aead::{Aead, KeyInit}};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use rand::RngCore;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin, b"seedless-frost-share", 100_000, &mut key);

    let key = Key::from(key);
    let cipher = ChaCha20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, share_data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

// Helper: decrypt share
#[cfg(feature = "hsm-nitrokey")]
fn decrypt_share(encrypted_data: &[u8], pin: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce, Key, aead::{Aead, KeyInit}};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin, b"seedless-frost-share", 100_000, &mut key);

    let key = Key::from(key);
    let cipher = ChaCha20Poly1305::new(&key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}
