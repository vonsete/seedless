use super::Hsm;
use anyhow::{anyhow, Result};
use std::process::{Command, Stdio};
use std::path::PathBuf;
use std::os::unix::io::{FromRawFd, AsRawFd};
use std::io::Write;
use crate::config::Config;

/// YubiKey HSM support via age-plugin-yubikey
/// Shares are encrypted with the YubiKey's P-256 private key (ECIES)
/// Decryption requires YubiKey physical presence + PIN (3-attempt limit)
pub struct YubiKeyHsm {
    device_name: String,
    recipient: String,   // "age1yubikey1q..." public key
    shares_dir: PathBuf,
}

impl YubiKeyHsm {
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Detect connected YubiKey and extract age-plugin-yubikey recipient key
    pub fn _detect_impl() -> Result<Self> {
        // Run age-plugin-yubikey --list to find connected device + identity
        let output = Command::new("age-plugin-yubikey")
            .args(["--list"])
            .output()
            .map_err(|e| anyhow!(
                "age-plugin-yubikey not found: {}. Install with: cargo install age-plugin-yubikey",
                e
            ))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("age-plugin-yubikey --list failed: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse serial from "# Serial: 18220689, Slot: 1" line
        let serial = stdout.lines()
            .find(|l| l.contains("Serial:"))
            .and_then(|l| l.split("Serial:").nth(1))
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Parse recipient: first non-comment, non-empty line
        let recipient = stdout.lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .ok_or_else(|| anyhow!(
                "No age identity found on connected YubiKey.\n\
                 Generate one with: age-plugin-yubikey --generate --slot 1 \\\n  \
                 --pin-policy once --touch-policy always"
            ))?
            .trim()
            .to_string();

        if !recipient.starts_with("age1yubikey1") {
            return Err(anyhow!(
                "Unexpected recipient format: {} (expected age1yubikey1...)",
                recipient
            ));
        }

        let device_name = format!("YubiKey (serial: {})", serial);
        let shares_dir = Config::shares_dir()?;

        println!("✓ Detected: {} - recipient: {}", device_name, recipient);

        // Reset PIV applet state to ensure clean state
        let _ = Command::new("ykman")
            .args(["piv", "info"])
            .output();

        Ok(YubiKeyHsm {
            device_name,
            recipient,
            shares_dir,
        })
    }
}

impl Hsm for YubiKeyHsm {
    fn write_share(&mut self, participant_id: u16, share_bytes: &[u8]) -> Result<()> {
        // Encrypt share using age CLI with YubiKey recipient
        // No PIN needed here — we only use the recipient's public key
        let mut child = Command::new("age")
            .args(["--encrypt", "-r", &self.recipient])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn age: {}", e))?;

        {
            let stdin = child.stdin.as_mut().ok_or_else(|| anyhow!("age stdin unavailable"))?;
            stdin.write_all(share_bytes)
                .map_err(|e| anyhow!("Failed to write to age stdin: {}", e))?;
        }

        let output = child.wait_with_output()
            .map_err(|e| anyhow!("age encryption process error: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("age encryption failed: {}", stderr.trim()));
        }

        let share_file = Config::share_file(participant_id)?;
        std::fs::write(&share_file, &output.stdout)
            .map_err(|e| anyhow!("Failed to write share file {:?}: {}", share_file, e))?;

        println!("✓ Share written: {:?} ({} bytes encrypted)", share_file, output.stdout.len());

        // Reset PIV applet state to avoid "invalid object" errors
        let _ = Command::new("ykman")
            .args(["piv", "info"])
            .output();

        Ok(())
    }

    fn read_share(&mut self, participant_id: u16) -> Result<Vec<u8>> {
        let share_file = Config::share_file(participant_id)?;

        // Step 1: Get the AGE-PLUGIN-YUBIKEY-1... identity lines from connected YubiKey
        let identity_output = Command::new("age-plugin-yubikey")
            .args(["--identity"])
            .output()
            .map_err(|e| anyhow!("Failed to run age-plugin-yubikey --identity: {}", e))?;

        if !identity_output.status.success() {
            return Err(anyhow!(
                "age-plugin-yubikey --identity failed.\n\
                 Make sure your YubiKey is connected and has an age identity."
            ));
        }

        // Extract only the AGE-PLUGIN-YUBIKEY-1... identity lines
        let identity_str = String::from_utf8_lossy(&identity_output.stdout);
        let identity_lines = identity_str
            .lines()
            .filter(|l| l.starts_with("AGE-PLUGIN-YUBIKEY-"))
            .collect::<Vec<_>>()
            .join("\n");

        if identity_lines.is_empty() {
            return Err(anyhow!(
                "No age-plugin-yubikey identity found on connected YubiKey"
            ));
        }

        let identity_str_with_newline = identity_lines + "\n";

        // Step 2: Create Unix pipe to pass identity to age without temp file
        // This replicates bash: age -d -i <(age-plugin-yubikey --identity) <cipherfile>
        let (read_fd, write_fd) = unsafe {
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return Err(anyhow!("Failed to create pipe"));
            }
            (fds[0], fds[1])
        };

        // Clear CLOEXEC on read_fd so the child process (age) inherits it
        unsafe {
            let flags = libc::fcntl(read_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(anyhow!("fcntl F_GETFD failed"));
            }
            let result = libc::fcntl(read_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            if result < 0 {
                return Err(anyhow!("fcntl F_SETFD failed"));
            }
        }

        // Write identity to write end of pipe, then close it
        {
            let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
            write_file.write_all(identity_str_with_newline.as_bytes())
                .map_err(|e| anyhow!("Failed to write identity to pipe: {}", e))?;
            // write_file drops here, closing write_fd
        }

        // Step 3: Spawn age with identity fd and ciphertext file as argument
        // Let age write plaintext to file, don't capture stdout
        let identity_path = format!("/dev/fd/{}", read_fd);
        let share_filename = share_file.to_string_lossy().to_string();
        let output_filename = "/tmp/seedless_share_plaintext.tmp";

        let mut child = Command::new("age")
            .args(["--decrypt", "-i", &identity_path, "-o", output_filename, &share_filename])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn age: {}", e))?;

        // Close our copy of read_fd (child now has its own inherited copy)
        unsafe { libc::close(read_fd); }

        let status = child.wait()
            .map_err(|e| anyhow!("age decryption process error: {}", e))?;

        if !status.success() {
            std::fs::remove_file("/tmp/seedless_share_plaintext.tmp").ok();
            return Err(anyhow!(
                "age decryption failed\n\
                 (YubiKey requires PIN and touch to decrypt)"
            ));
        }

        let plaintext = std::fs::read("/tmp/seedless_share_plaintext.tmp")
            .map_err(|e| anyhow!("Failed to read decrypted share: {}", e))?;
        std::fs::remove_file("/tmp/seedless_share_plaintext.tmp").ok();

        println!("✓ Share decrypted for participant {}", participant_id);

        // Reset PIV applet state to avoid "invalid object" errors on subsequent operations
        // This prevents the YubiKey from getting stuck after age-plugin-yubikey access
        let _ = Command::new("ykman")
            .args(["piv", "info"])
            .output();

        Ok(plaintext)
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn detect() -> Result<Self> {
        Self::_detect_impl()
    }
}
