use super::Hsm;
use anyhow::{anyhow, Result};
use std::process::Command;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Key, aead::{Aead, KeyInit}};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// NitroKey 3 HSM support via nitropy CLI
/// Shares are encrypted locally and stored as files in ~/.config/seedless/
/// The NK3 device itself is used for key management and verification
pub struct NitroKeyHsm {
    device_name: String,
    #[allow(dead_code)]
    serial: String,
    pin: Vec<u8>,
}

impl NitroKeyHsm {
    /// Map participant ID to credential name in NK3 Secrets App
    fn credential_name(participant_id: u16) -> String {
        format!("seedless-participant-{}", participant_id)
    }

    /// Prompt user for PIN without terminal echo
    fn prompt_pin() -> Result<Vec<u8>> {
        let pin = rpassword::prompt_password("Enter NitroKey PIN: ")?;
        Ok(pin.into_bytes())
    }

    /// Derive 32-byte encryption key from PIN using PBKDF2-SHA256
    fn derive_key_from_pin(pin: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            pin,
            b"seedless-frost-share",
            100_000,
            &mut key,
        );
        key
    }

    /// Encrypt share data using ChaCha20-Poly1305
    /// Returns: nonce (12 bytes) || ciphertext (variable) || tag (16 bytes)
    fn encrypt_share(share_data: &[u8], pin: &[u8]) -> Result<Vec<u8>> {
        use rand::RngCore;

        let key_array = Self::derive_key_from_pin(pin);
        let key = Key::from(key_array);
        let cipher = ChaCha20Poly1305::new(&key);

        // Use random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(&nonce, share_data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Return nonce + ciphertext
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt share data using ChaCha20-Poly1305
    fn decrypt_share(encrypted_data: &[u8], pin: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(anyhow!("Encrypted data too short"));
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key_array = Self::derive_key_from_pin(pin);
        let key = Key::from(key_array);
        let cipher = ChaCha20Poly1305::new(&key);

        // Decrypt
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed (wrong PIN?): {}", e))
    }

    /// Convert PIN bytes to UTF-8 string for env var
    fn pin_str(pin: &[u8]) -> Result<String> {
        String::from_utf8(pin.to_vec())
            .map_err(|_| anyhow!("PIN is not valid UTF-8"))
    }

    /// Run nitropy command via process, passing PIN as env var (not args)
    fn run_nitropy(pin_str: &str, args: &[&str]) -> Result<Vec<u8>> {
        let output = Command::new("nitropy")
            .args(args)
            .env("NITROPY_SECRETS_PASSWORD", pin_str)
            .output()
            .map_err(|e| anyhow!(
                "Failed to run nitropy: {}. Install with: python3 -m pipx install pynitrokey",
                e
            ))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("nitropy error: {}", stderr.trim()));
        }

        Ok(output.stdout)
    }

    /// Detect and connect to NitroKey 3 device
    pub fn _detect_impl() -> Result<Self> {
        // Check nitropy and device connected
        let list_output = Command::new("nitropy")
            .args(["nk3", "list"])
            .output()
            .map_err(|e| anyhow!(
                "nitropy not found: {}. Install with: python3 -m pipx install pynitrokey",
                e
            ))?;

        let list_str = String::from_utf8_lossy(&list_output.stdout);
        if !list_output.status.success()
            || list_str.trim().is_empty()
            || list_str.contains("No Nitrokey")
        {
            return Err(anyhow!(
                "No NitroKey 3 found. Make sure device is connected."
            ));
        }

        // Try to extract serial from /dev/ line
        let (device_name, serial) = if let Some(line) = list_str.lines().find(|l| l.trim().starts_with("/dev/")) {
            let line = line.trim().to_string();
            let serial = line
                .split_whitespace()
                .last()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            (line, serial)
        } else {
            // Can't find /dev/ line, ask user for serial
            println!("⚠️  Could not auto-detect device serial from 'nitropy nk3 list'");
            println!("Please enter the device serial (printed on the back of your NK3)");
            print!("Serial (e.g., 03E678EA0F851450A6C06DD7947D460C): ");
            use std::io::Write;
            std::io::stdout().flush()?;

            let mut serial = String::new();
            std::io::stdin().read_line(&mut serial)?;
            let serial = serial.trim().to_string();

            if serial.is_empty() {
                return Err(anyhow!("Serial number is required"));
            }

            ("NitroKey 3".to_string(), serial)
        };

        // Prompt PIN
        let pin = Self::prompt_pin()?;
        let pin_str = Self::pin_str(&pin)?;

        // Verify PIN by accessing secrets app
        let verify = Command::new("nitropy")
            .args(["nk3", "secrets", "status"])
            .env("NITROPY_SECRETS_PASSWORD", &pin_str)
            .output()
            .map_err(|e| anyhow!("Failed to verify PIN: {}", e))?;

        if !verify.status.success() {
            let stderr = String::from_utf8_lossy(&verify.stderr);
            return Err(anyhow!(
                "PIN verification failed (wrong PIN?): {}",
                stderr.trim()
            ));
        }

        println!("✓ PIN verified");
        Ok(NitroKeyHsm {
            device_name,
            serial,
            pin,
        })
    }
}

impl Hsm for NitroKeyHsm {
    fn write_share(&mut self, participant_id: u16, share_bytes: &[u8]) -> Result<()> {
        let name = Self::credential_name(participant_id);
        let encrypted = Self::encrypt_share(share_bytes, &self.pin)?;
        let hex_data = hex::encode(&encrypted);
        let pin_str = Self::pin_str(&self.pin)?;

        // Remove existing credential (ignore error — may not exist)
        let _ = Command::new("nitropy")
            .args(["nk3", "secrets", "remove", &name])
            .env("NITROPY_SECRETS_PASSWORD", &pin_str)
            .output();

        // Add encrypted share to NK3 Secrets App using login field (password field is read-only)
        Self::run_nitropy(&pin_str, &["nk3", "secrets", "add-password", &name, "--login", &hex_data])?;

        println!("✓ Share written to NitroKey for participant {} (stored on device)", participant_id);
        Ok(())
    }

    fn read_share(&mut self, participant_id: u16) -> Result<Vec<u8>> {
        let name = Self::credential_name(participant_id);
        let pin_str = Self::pin_str(&self.pin)?;

        // Get credential in JSON format (login field is read-enabled)
        let stdout = Self::run_nitropy(&pin_str, &["nk3", "secrets", "get-password", &name, "--format", "json"])?;
        let output_str = String::from_utf8_lossy(&stdout);

        // Extract JSON from output (skip headers from nitropy)
        let json_str = output_str
            .lines()
            .find(|l| l.trim().starts_with('{'))
            .ok_or_else(|| anyhow!(
                "Share for participant {} not found on NK3 device. Run 'setup' to store shares.",
                participant_id
            ))?;

        // Parse JSON to extract login field
        let json: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| anyhow!("Failed to parse NK3 credential: {}", e))?;

        let hex_data = json["login"]
            .as_str()
            .ok_or_else(|| anyhow!(
                "No share data found in NK3 credential for participant {}",
                participant_id
            ))?;

        let encrypted = hex::decode(hex_data)
            .map_err(|e| anyhow!("Failed to decode share data: {}", e))?;

        println!("✓ Share retrieved from NitroKey, decrypting...");
        Self::decrypt_share(&encrypted, &self.pin)
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn detect() -> Result<Self> {
        NitroKeyHsm::_detect_impl()
    }
}
