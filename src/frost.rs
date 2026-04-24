use anyhow::{anyhow, Result};
use frost_secp256k1_tr as frost;

/// Generate FROST key shares using trusted dealer
/// Returns: (group_pubkey_bytes, serialized_shares, pubkey_package_bytes)
pub fn generate_shares(
    threshold: u16,
    participants: u16,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)> {
    if threshold == 0 || threshold > participants {
        return Err(anyhow!(
            "Invalid threshold: must be 1 <= threshold <= participants"
        ));
    }

    // Use frost_secp256k1_tr to generate shares
    // Need a CryptoRng, so use OsRng for cryptographic randomness
    let mut rng = rand::rngs::OsRng;

    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer::<_>(
            participants,
            threshold,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .map_err(|e| anyhow!("Failed to generate shares: {:?}", e))?;

    // Serialize the group public key
    let group_pubkey_bytes = pubkey_package
        .verifying_key()
        .serialize()?
        .to_vec();

    // Serialize each share (shares is an iterator of (Identifier, SecretShare) tuples)
    let serialized_shares: Result<Vec<Vec<u8>>> = shares
        .iter()
        .map(|(_id, secret_share)| {
            // Serialize the secret share to bytes
            let bytes = secret_share.serialize()?;
            Ok(bytes.to_vec())
        })
        .collect();

    let serialized_shares = serialized_shares?;

    // Serialize the PublicKeyPackage (needed for aggregation in signing)
    let pubkey_package_bytes = pubkey_package.serialize()?;

    Ok((group_pubkey_bytes, serialized_shares, pubkey_package_bytes))
}

/// Round 1: Generate nonce commitments for a signer
/// Input: serialized SecretShare bytes
/// Output: (nonces_bytes, commitments_bytes) both serialized
pub fn round1_commit(share_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let secret_share = frost::keys::SecretShare::deserialize(share_bytes)
        .map_err(|e| anyhow!("Failed to deserialize secret share: {:?}", e))?;

    let key_package = frost::keys::KeyPackage::try_from(secret_share)
        .map_err(|e| anyhow!("Failed to create key package: {:?}", e))?;

    let mut rng = rand::rngs::OsRng;
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

    let nonces_bytes = nonces.serialize()
        .map_err(|e| anyhow!("Failed to serialize nonces: {:?}", e))?;
    let commitments_bytes = commitments.serialize()
        .map_err(|e| anyhow!("Failed to serialize commitments: {:?}", e))?;

    Ok((nonces_bytes, commitments_bytes))
}

/// Create signing package from commitments and message
/// Input: list of (participant_id, commitments_bytes), and the sighash message
/// Output: signing_package_bytes
pub fn create_signing_package(
    commitments: &[(u16, Vec<u8>)],
    message: &[u8],
) -> Result<Vec<u8>> {
    let mut commitment_map = std::collections::BTreeMap::new();

    for (id, commitment_bytes) in commitments {
        let identifier = frost::Identifier::try_from(*id)
            .map_err(|e| anyhow!("Failed to create identifier for {}: {:?}", id, e))?;

        let commitment = frost::round1::SigningCommitments::deserialize(commitment_bytes)
            .map_err(|e| anyhow!("Failed to deserialize commitment: {:?}", e))?;

        commitment_map.insert(identifier, commitment);
    }

    let signing_package = frost::SigningPackage::new(commitment_map, message);

    signing_package.serialize()
        .map_err(|e| anyhow!("Failed to serialize signing package: {:?}", e))
}

/// Round 2: Generate partial signature
/// Input: share_bytes, nonces_bytes, signing_package_bytes
/// Output: partial_signature bytes
pub fn round2_sign(
    share_bytes: &[u8],
    nonces_bytes: &[u8],
    signing_package_bytes: &[u8],
) -> Result<Vec<u8>> {
    let secret_share = frost::keys::SecretShare::deserialize(share_bytes)
        .map_err(|e| anyhow!("Failed to deserialize secret share: {:?}", e))?;

    let key_package = frost::keys::KeyPackage::try_from(secret_share)
        .map_err(|e| anyhow!("Failed to create key package: {:?}", e))?;

    let nonces = frost::round1::SigningNonces::deserialize(nonces_bytes)
        .map_err(|e| anyhow!("Failed to deserialize nonces: {:?}", e))?;

    let signing_package = frost::SigningPackage::deserialize(signing_package_bytes)
        .map_err(|e| anyhow!("Failed to deserialize signing package: {:?}", e))?;

    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| anyhow!("Failed to sign: {:?}", e))?;

    Ok(signature_share.serialize())
}

/// Aggregate partial signatures into final Schnorr signature
/// Input: signing_package_bytes, list of (participant_id, partial_sig_bytes), pubkey_package_bytes
/// Output: final BIP-340 Schnorr signature (64 bytes)
pub fn aggregate(
    signing_package_bytes: &[u8],
    signature_shares: &[(u16, Vec<u8>)],
    pubkey_package_bytes: &[u8],
) -> Result<[u8; 64]> {
    let signing_package = frost::SigningPackage::deserialize(signing_package_bytes)
        .map_err(|e| anyhow!("Failed to deserialize signing package: {:?}", e))?;

    let pubkey_package = frost::keys::PublicKeyPackage::deserialize(pubkey_package_bytes)
        .map_err(|e| anyhow!("Failed to deserialize pubkey package: {:?}", e))?;

    let mut sig_shares = std::collections::BTreeMap::new();

    for (id, sig_bytes) in signature_shares {
        let identifier = frost::Identifier::try_from(*id)
            .map_err(|e| anyhow!("Failed to create identifier for {}: {:?}", id, e))?;

        let sig_share = frost::round2::SignatureShare::deserialize(sig_bytes)
            .map_err(|e| anyhow!("Failed to deserialize signature share: {:?}", e))?;

        sig_shares.insert(identifier, sig_share);
    }

    let signature = frost::aggregate(&signing_package, &sig_shares, &pubkey_package)
        .map_err(|e| anyhow!("Failed to aggregate signatures: {:?}", e))?;

    // Serialize to BIP-340 64-byte format (R || z)
    let sig_bytes = signature.serialize()
        .map_err(|e| anyhow!("Failed to serialize signature: {:?}", e))?;

    if sig_bytes.len() != 64 {
        return Err(anyhow!("Invalid signature size: {} (expected 64)", sig_bytes.len()));
    }

    let mut result = [0u8; 64];
    result.copy_from_slice(&sig_bytes);
    Ok(result)
}
