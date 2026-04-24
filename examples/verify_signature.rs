use bitcoin::psbt::Psbt;
use secp256k1::{Secp256k1, schnorr::Signature, Message, XOnlyPublicKey};
use hex::{encode, decode};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let psbt_path = "/tmp/test.signed.psbt";
    let config_path = dirs::config_dir().unwrap().join("seedless/config.json");

    // Leer PSBT
    let psbt_bytes = fs::read(psbt_path).expect("Failed to read PSBT");
    let psbt = Psbt::deserialize(&psbt_bytes).expect("Failed to parse PSBT");

    // Leer config para obtener la clave pública del grupo
    let config_str = fs::read_to_string(&config_path)
        .expect("Failed to read config.json");
    let config: serde_json::Value = serde_json::from_str(&config_str)
        .expect("Invalid JSON");

    let pubkey_hex = config["group_public_key"].as_str()
        .expect("Missing group_public_key");

    println!("=== Signature Verification ===\n");
    println!("Group Public Key: {}", pubkey_hex);

    // Extraer la firma del witness
    if psbt.inputs.is_empty() {
        eprintln!("❌ No inputs in PSBT");
        return Ok(());
    }

    let input = &psbt.inputs[0];
    if let Some(witness) = &input.final_script_witness {
        if witness.is_empty() {
            eprintln!("❌ No witness signature");
            return Ok(());
        }

        // Get first item from witness stack (Schnorr signature)
        let sig_bytes = witness.nth(0).expect("No witness items");
        if sig_bytes.len() != 64 {
            eprintln!("❌ Invalid signature length: {} (expected 64)", sig_bytes.len());
            return Ok(());
        }

        println!("\n✓ Signature found: {} bytes", sig_bytes.len());
        println!("  Hex: {}", encode(sig_bytes));

        // Compute BIP-341 Taproot sighash (same as used during signing)
        let sighash = seedless::bitcoin::compute_sighash(&psbt, 0)?;
        println!("\n✓ Sighash (BIP-341): {}", encode(&sighash));

        // Verificar firma
        verify_schnorr_signature(pubkey_hex, &sighash, sig_bytes)?;
    } else {
        eprintln!("❌ No final witness in input");
    }

    Ok(())
}

fn verify_schnorr_signature(pubkey_hex: &str, sighash: &[u8], sig_bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Decode pubkey
    let pubkey_full = decode(pubkey_hex)?;

    // Extract x-only (skip 02/03 prefix if present)
    let x_only_bytes = if pubkey_full.len() == 33 {
        &pubkey_full[1..]
    } else if pubkey_full.len() == 32 {
        &pubkey_full[..]
    } else {
        return Err(format!("Invalid public key length: {}", pubkey_full.len()).into());
    };

    // Create secp256k1 context
    let secp = Secp256k1::new();

    // Parse public key
    let pubkey = XOnlyPublicKey::from_slice(x_only_bytes)?;

    // Parse signature
    let sig = Signature::from_slice(sig_bytes)?;

    // Parse message
    let msg = Message::from_digest_slice(sighash)?;

    // Verify
    secp.verify_schnorr(&sig, &msg, &pubkey)?;

    println!("\n✅ SIGNATURE VERIFICATION SUCCESSFUL");
    println!("   The witness signature is valid for the group public key!");

    Ok(())
}
