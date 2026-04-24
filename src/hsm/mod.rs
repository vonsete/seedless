pub mod mock;

#[cfg(feature = "hsm-yubikey")]
pub mod yubikey;

#[cfg(feature = "hsm-nitrokey")]
pub mod nitrokey;

use anyhow::Result;

/// Abstract HSM interface for storing and retrieving key shares
pub trait Hsm {
    /// Store a key share in the HSM
    fn write_share(&mut self, participant_id: u16, share_bytes: &[u8]) -> Result<()>;

    /// Retrieve a key share from the HSM
    fn read_share(&mut self, participant_id: u16) -> Result<Vec<u8>>;

    /// Get human-readable device name
    fn device_name(&self) -> &str;

    /// Detect and connect to the next available HSM
    fn detect() -> Result<Self>
    where
        Self: Sized;
}

#[derive(Debug, Clone, Copy)]
pub enum HsmType {
    YubiKey,
    NitroKey,
    Mock,
}
