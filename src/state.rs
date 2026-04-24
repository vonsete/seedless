use anyhow::Result;
use std::collections::BTreeMap;

/// Manages the state of an ongoing signing session
/// This holds sensitive data (nonces) in memory - NEVER written to disk
pub struct SigningSession {
    pub message: Vec<u8>, // sighash bytes to be signed
    pub signers: Vec<u16>, // participant IDs participating in this session

    // Round 1 data
    pub signing_commitments: BTreeMap<u16, Vec<u8>>, // (signer_id -> commitments_bytes)
    pub secret_nonces: BTreeMap<u16, Vec<u8>>, // (signer_id -> nonces_bytes) - SINGLE USE, IN MEMORY ONLY

    // Round 2 data
    pub partial_signatures: BTreeMap<u16, Vec<u8>>, // (signer_id -> signature_bytes)
}

impl SigningSession {
    pub fn new(message: Vec<u8>, signers: Vec<u16>) -> Self {
        SigningSession {
            message,
            signers,
            signing_commitments: BTreeMap::new(),
            secret_nonces: BTreeMap::new(),
            partial_signatures: BTreeMap::new(),
        }
    }

    /// Store commitments from Round 1
    pub fn add_commitments(&mut self, signer_id: u16, commitments: Vec<u8>) -> Result<()> {
        self.signing_commitments.insert(signer_id, commitments);
        Ok(())
    }

    /// Store nonces from Round 1 (in memory only, never on disk)
    pub fn add_nonces(&mut self, signer_id: u16, nonces: Vec<u8>) -> Result<()> {
        self.secret_nonces.insert(signer_id, nonces);
        Ok(())
    }

    /// Get and remove nonces for Round 2 (ensures single-use)
    pub fn take_nonces(&mut self, signer_id: u16) -> Option<Vec<u8>> {
        self.secret_nonces.remove(&signer_id)
    }

    /// Store a partial signature from Round 2
    pub fn add_partial_signature(&mut self, signer_id: u16, partial_sig: Vec<u8>) -> Result<()> {
        self.partial_signatures.insert(signer_id, partial_sig);
        Ok(())
    }

    /// Check if all commitments received (Round 1 complete)
    pub fn round1_ready(&self) -> bool {
        self.signing_commitments.len() >= self.signers.len()
    }

    /// Check if all signatures received (Round 2 complete)
    pub fn round2_ready(&self) -> bool {
        self.partial_signatures.len() >= self.signers.len()
    }
}
