use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub threshold: u16,
    pub participants: u16,
    pub group_public_key: String, // hex encoded (32 bytes)
    pub xpub: Option<String>,     // BIP-86 xpub for watch-only import
    pub participant_ids: Vec<u16>,
    pub network: String, // "bitcoin", "testnet", "signet", "regtest"
    pub pubkey_package: Option<String>, // hex encoded PublicKeyPackage for signing aggregation
    #[serde(default)]
    pub age_recipients: HashMap<u16, String>, // participant_id -> age recipient key (age1yubikey1q...)
}

impl Config {
    pub fn config_dir() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("seedless");
        std::fs::create_dir_all(&config_dir)?;
        Ok(config_dir)
    }

    pub fn config_file() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_file()?;
        let contents = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_file()?;
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    pub fn exists() -> Result<bool> {
        Ok(Self::config_file()?.exists())
    }

    pub fn shares_dir() -> Result<PathBuf> {
        let dir = Self::config_dir()?.join("shares");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn share_file(participant_id: u16) -> Result<PathBuf> {
        Ok(Self::shares_dir()?.join(format!("p{}.share.age", participant_id)))
    }
}
