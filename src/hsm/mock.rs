use super::Hsm;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MockHsm {
    device_name: String,
    shares: HashMap<u16, Vec<u8>>,
}

impl MockHsm {
    pub fn new(device_name: &str) -> Self {
        MockHsm {
            device_name: device_name.to_string(),
            shares: HashMap::new(),
        }
    }
}

impl Hsm for MockHsm {
    fn write_share(&mut self, participant_id: u16, share_bytes: &[u8]) -> Result<()> {
        self.shares.insert(participant_id, share_bytes.to_vec());
        Ok(())
    }

    fn read_share(&mut self, participant_id: u16) -> Result<Vec<u8>> {
        self.shares
            .get(&participant_id)
            .cloned()
            .ok_or_else(|| anyhow!("No share found for participant {}", participant_id))
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn detect() -> Result<Self> {
        Ok(MockHsm::new("MockHSM"))
    }
}
