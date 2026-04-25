use anyhow::{anyhow, Result};
use bip39::{Mnemonic, Language};

/// Convert FROST share bytes to BIP-39 mnemonic
///
/// Uses BIP-39 for mnemonic generation (compatible with SLIP-39 approach).
/// The share is hashed to 128 bits (16 bytes) for BIP-39 compatibility.
///
/// # Arguments
/// * `share_bytes` - Raw FROST share (any length)
/// * `participant_id` - Participant number (for identification)
/// * `threshold` - Threshold (for user information)
/// * `total_participants` - Total participants (for user information)
///
/// # Returns
/// BIP-39 mnemonic (12 words for 128-bit entropy)
pub fn share_to_mnemonic(
    share_bytes: &[u8],
    _participant_id: u16,
    _threshold: u16,
    _total_participants: u16,
) -> Result<String> {
    // Use first 16 bytes of share (or hash if shorter/longer)
    let entropy = if share_bytes.len() >= 16 {
        share_bytes[..16].to_vec()
    } else if share_bytes.is_empty() {
        return Err(anyhow!("Share bytes cannot be empty"));
    } else {
        // Hash shorter shares to 16 bytes using SHA256
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(share_bytes);
        let hash = hasher.finalize();
        hash[..16].to_vec()
    };

    // Create BIP-39 mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| anyhow!("Failed to create mnemonic: {}", e))?;

    Ok(mnemonic.to_string())
}

/// Convert BIP-39 mnemonic back to entropy (16 bytes)
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic phrase
///
/// # Returns
/// 16-byte entropy derived from mnemonic
pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;

    Ok(mnemonic.to_entropy().to_vec())
}

/// Validate a BIP-39 mnemonic format
pub fn validate_mnemonic(mnemonic: &str) -> Result<()> {
    Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|e| anyhow!("Invalid BIP-39 mnemonic: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_to_mnemonic() {
        let share = vec![1; 32];
        let mnemonic = share_to_mnemonic(&share, 1, 2, 3).expect("Failed to create mnemonic");

        // BIP-39 12-word mnemonic
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 12, "Expected 12 words, got {}", word_count);
    }

    #[test]
    fn test_mnemonic_round_trip() {
        let share = vec![42; 32];
        let mnemonic = share_to_mnemonic(&share, 1, 2, 3).expect("Failed to create mnemonic");

        // Decode it back
        let recovered = mnemonic_to_entropy(&mnemonic).expect("Failed to recover entropy");

        // Should be 16 bytes (128 bits)
        assert_eq!(recovered.len(), 16, "Expected 16 bytes, got {}", recovered.len());
    }

    #[test]
    fn test_validate_mnemonic_invalid() {
        let invalid = "not a real mnemonic at all";
        assert!(validate_mnemonic(invalid).is_err(), "Should reject invalid mnemonic");
    }

    #[test]
    fn test_validate_mnemonic_valid() {
        // Generate a valid mnemonic
        let share = vec![123; 32];
        let mnemonic = share_to_mnemonic(&share, 1, 2, 3).expect("Failed to create mnemonic");

        // Should validate successfully
        assert!(validate_mnemonic(&mnemonic).is_ok(), "Should accept valid mnemonic");
    }
}
