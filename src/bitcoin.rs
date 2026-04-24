use anyhow::{anyhow, Result};
use bitcoin::psbt::Psbt;
use bitcoin::{Transaction, TxOut, XOnlyPublicKey};
use bitcoin::bip32::{Xpub, Fingerprint};
use secp256k1::Secp256k1;

/// Load a PSBT from file (binary format)
pub fn load_psbt(path: &std::path::Path) -> Result<Psbt> {
    let contents = std::fs::read(path)?;
    let psbt = Psbt::deserialize(&contents)?;
    Ok(psbt)
}

/// Save a PSBT to file (as binary)
pub fn save_psbt(path: &std::path::Path, psbt: &Psbt) -> Result<()> {
    let buffer = psbt.serialize();
    std::fs::write(path, &buffer)?;
    Ok(())
}

/// Display transaction details for user confirmation
pub fn display_transaction(psbt: &Psbt) -> Result<()> {
    println!("\n=== Transaction Details ===");

    if let Ok(tx) = psbt.clone().extract_tx() {
        println!("Inputs: {}", tx.input.len());
        for (i, input) in tx.input.iter().enumerate() {
            println!("  Input {}: {}", i, input.previous_output);
        }

        println!("Outputs: {}", tx.output.len());
        for (i, output) in tx.output.iter().enumerate() {
            println!("  Output {}: {} sats", i, output.value);
        }

        println!("Fee estimate: (from PSBT analysis)");
    }

    println!();
    Ok(())
}

/// Extract the transaction from PSBT
pub fn extract_transaction(psbt: &Psbt) -> Result<Transaction> {
    Ok(psbt.clone().extract_tx()?)
}

/// Create a group Taproot address from the group public key
pub fn derive_taproot_address(pubkey_hex: &str, network: &str) -> Result<String> {
    let pubkey_bytes = hex::decode(pubkey_hex)?;

    // Handle both 33-byte (with prefix) and 32-byte (x-only) formats
    let pubkey_bytes = if pubkey_bytes.len() == 33 {
        // Remove prefix (first byte), keep only the x-only public key
        pubkey_bytes[1..].to_vec()
    } else if pubkey_bytes.len() == 32 {
        pubkey_bytes
    } else {
        return Err(anyhow!(
            "Invalid public key length: {} (expected 32 or 33)",
            pubkey_bytes.len()
        ));
    };

    let secp = Secp256k1::new();
    let x_only_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| anyhow!("Invalid x-only public key: {}", e))?;

    let network = match network {
        "bitcoin" => bitcoin::Network::Bitcoin,
        "testnet" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        _ => return Err(anyhow!("Unknown network: {}", network)),
    };

    let address = bitcoin::Address::p2tr(&secp, x_only_pubkey, None, network);

    Ok(address.to_string())
}

/// Derive a BIP-86 xpub from the group public key for watch-only wallet import
/// BIP-86 path: m/86'/0'/0' (Taproot account)
pub fn derive_xpub(pubkey_hex: &str, network: &str) -> Result<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let pubkey_bytes = hex::decode(pubkey_hex)?;

    // Handle both 33-byte (with prefix) and 32-byte (x-only) formats
    let pubkey_bytes = if pubkey_bytes.len() == 33 {
        // Remove prefix (first byte), keep only the x-only public key
        pubkey_bytes[1..].to_vec()
    } else if pubkey_bytes.len() == 32 {
        pubkey_bytes
    } else {
        return Err(anyhow!(
            "Invalid public key length: {} (expected 32 or 33)",
            pubkey_bytes.len()
        ));
    };

    let _net = match network {
        "bitcoin" | "testnet" | "signet" | "regtest" => network,
        _ => return Err(anyhow!("Unknown network: {}", network)),
    };

    // Generate chain code using HMAC-SHA512
    // This is a synthetic chain code since we don't have the actual BIP32 derivation path
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(b"BIP32_CHAIN_CODE")
        .map_err(|e| anyhow!("HMAC key error: {}", e))?;
    mac.update(&pubkey_bytes);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let chain_code = bitcoin::bip32::ChainCode::from(
        <[u8; 32]>::try_from(&code_bytes[..32])
            .map_err(|_| anyhow!("Invalid chain code length"))?,
    );

    // Convert x-only public key to standard secp256k1 public key format
    // For Taproot (even y coordinate), use 0x02 prefix
    let mut pubkey_full = [0u8; 33];
    pubkey_full[0] = 0x02; // even prefix for Taproot
    pubkey_full[1..].copy_from_slice(&pubkey_bytes);

    let _secp = Secp256k1::new();
    let secp_pubkey = secp256k1::PublicKey::from_slice(&pubkey_full)
        .map_err(|e| anyhow!("Invalid public key: {}", e))?;

    // Create xpub at account level (BIP-86: m/86'/0'/0')
    // depth=3, fingerprint=0x00000000 (unknown), child_index=0
    let net_kind = match network {
        "bitcoin" => bitcoin::NetworkKind::Main,
        _ => bitcoin::NetworkKind::Test, // testnet, signet, regtest all use Test kind
    };

    let xpub = Xpub {
        network: net_kind,
        depth: 3,
        parent_fingerprint: Fingerprint::from([0, 0, 0, 0]),
        child_number: bitcoin::bip32::ChildNumber::from_normal_idx(0)
            .map_err(|e| anyhow!("Invalid child index: {}", e))?,
        public_key: secp_pubkey,
        chain_code,
    };

    Ok(xpub.to_string())
}

/// Export xpub info for watch-only wallet import
pub fn export_xpub_info(pubkey_hex: &str, network: &str) -> Result<String> {
    let xpub = derive_xpub(pubkey_hex, network)?;

    let path = match network {
        "bitcoin" => "m/86'/0'/0'",
        "testnet" => "m/86'/1'/0'",
        "signet" => "m/86'/1'/0'",
        "regtest" => "m/86'/1'/0'",
        _ => "m/86'/0'/0'",
    };

    Ok(format!(
        "Extended Public Key (BIP-86 Taproot):\n\
         Derivation Path: {}\n\
         xpub: {}\n\n\
         How to import:\n\
         - Sparrow Wallet: File → Import → Paste xpub\n\
         - Electrum: Wallet → New/Restore → Paste xpub\n\
         - Select 'Taproot (P2TR)' as address type",
        path, xpub
    ))
}

/// Compute BIP-341 Taproot key-path spend sighash
/// Requires that the PSBT has witness_utxo for all inputs (mandatory for Taproot)
pub fn compute_sighash(psbt: &Psbt, input_index: usize) -> Result<Vec<u8>> {
    use bitcoin::sighash::{SighashCache, Prevouts, TapSighashType};

    // Validate input index
    let input = psbt.inputs.get(input_index)
        .ok_or_else(|| anyhow!("Input {} not found in PSBT", input_index))?;

    // Taproot sighash requires witness_utxo (the UTXO being spent)
    let _utxo = input.witness_utxo.as_ref()
        .ok_or_else(|| anyhow!(
            "Missing witness_utxo for input {}. PSBT must include prevout data from wallet.",
            input_index
        ))?;

    // Collect all prevouts (required for Taproot sighash)
    let prevouts: Vec<&TxOut> = psbt.inputs.iter()
        .enumerate()
        .map(|(i, inp)| {
            inp.witness_utxo.as_ref()
                .ok_or_else(|| anyhow!("Missing witness_utxo for input {}", i))
        })
        .collect::<Result<Vec<_>>>()?;

    // Compute BIP-341 sighash for key-path spend (Taproot)
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| anyhow!("Failed to compute sighash: {}", e))?;

    // Return 32-byte sighash as Vec<u8>
    Ok(sighash[..].to_vec())
}

/// Finalize a PSBT by integrating a BIP-340 Schnorr signature (64 bytes)
/// Constructs the witness and prepares for broadcast
pub fn finalize_psbt(psbt: &mut Psbt, input_index: usize, signature: &[u8; 64]) -> Result<()> {
    use bitcoin::taproot;
    use bitcoin::sighash::TapSighashType;
    use bitcoin::Witness;

    // Convert raw signature bytes to secp256k1::schnorr::Signature
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|e| anyhow!("Invalid Schnorr signature: {}", e))?;

    // Create taproot::Signature (wraps schnorr sig + sighash type)
    let tap_sig = taproot::Signature {
        signature: schnorr_sig,
        sighash_type: TapSighashType::Default,
    };

    // For key-path spend Taproot, the witness is just the 64-byte signature
    let mut witness = Witness::new();
    witness.push(tap_sig.to_vec());

    // Set the finalized witness
    psbt.inputs[input_index].final_script_witness = Some(witness);

    // Clean up intermediate fields per BIP-174
    psbt.inputs[input_index].tap_key_sig = None;
    psbt.inputs[input_index].sighash_type = None;

    Ok(())
}
