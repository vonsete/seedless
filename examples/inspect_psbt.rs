use bitcoin::psbt::Psbt;
use bitcoin::consensus::encode::serialize;
use bitcoin::script::ScriptBuf;
use bitcoin::address::Address;
use bitcoin::secp256k1::{XOnlyPublicKey, Secp256k1};
use bitcoin::Network;
use hex::encode;
use std::fs;

fn display_script_pubkey(label: &str, script_pubkey: &ScriptBuf) {
    let bytes = script_pubkey.as_bytes();
    println!("{}: {} bytes (hex: {})", label, bytes.len(), encode(bytes));

    if bytes.is_empty() {
        println!("    (empty script)");
        return;
    }

    if bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20 {
        let x_only_key = &bytes[2..34];
        println!("    Type: P2TR (Pay to Taproot)");
        println!("    X-only Key: {}", encode(x_only_key));

        if let Ok(xonly) = XOnlyPublicKey::from_slice(x_only_key) {
            let addr = Address::p2tr(&Secp256k1::new(), xonly, None, Network::Bitcoin);
            println!("    Address (mainnet): {}", addr);
        }
    } else if bytes.len() == 22 && bytes[0] == 0x00 && bytes[1] == 0x14 {
        println!("    Type: P2WPKH (Pay to Witness PubKey Hash)");
        println!("    Pubkey Hash: {}", encode(&bytes[2..]));
    } else if bytes.len() == 34 && bytes[0] == 0x00 && bytes[1] == 0x20 {
        println!("    Type: P2WSH (Pay to Witness Script Hash)");
        println!("    Script Hash: {}", encode(&bytes[2..]));
    } else if bytes.len() == 25 && bytes[0] == 0x76 && bytes[1] == 0xa9 && bytes[2] == 0x14 {
        println!("    Type: P2PKH (Pay to PubKey Hash)");
        println!("    Pubkey Hash: {}", encode(&bytes[3..23]));
    } else if bytes[0] == 0xaa {
        println!("    Type: OP_RETURN (Data)");
        if bytes.len() > 1 {
            println!("    Data: {}", encode(&bytes[1..]));
        }
    } else {
        println!("    (unrecognized script type)");
    }
}

fn main() {
    let psbt_path = "/tmp/test.signed.psbt";

    // Leer archivo PSBT
    let psbt_bytes = fs::read(psbt_path).expect("Failed to read PSBT file");

    println!("=== PSBT Inspection ===\n");
    println!("File: {}", psbt_path);
    println!("Size: {} bytes\n", psbt_bytes.len());

    // Parsear PSBT
    let psbt = Psbt::deserialize(&psbt_bytes).expect("Failed to parse PSBT");

    // Mostrar TX info
    println!("=== Unsigned Transaction ===");
    println!("Version: {}", psbt.unsigned_tx.version);
    println!("Lock time: {}", psbt.unsigned_tx.lock_time);
    println!("Inputs: {}", psbt.unsigned_tx.input.len());
    println!("Outputs: {}", psbt.unsigned_tx.output.len());

    // Mostrar detalles de inputs
    println!("\n=== Inputs (Previous Outputs) ===");
    for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
        println!("\nInput {}:", i);
        println!("  Spent Output: {}:{}", input.previous_output.txid, input.previous_output.vout);
        println!("  Sequence: {}", input.sequence);
        println!("  Script Sig: {} bytes", input.script_sig.len());

        // Try to show input script pubkey from witness_utxo
        if let Some(prev_output) = &psbt.inputs.get(i).and_then(|pi| pi.witness_utxo.as_ref()) {
            display_script_pubkey("  Script PubKey", &prev_output.script_pubkey);
        }
    }

    // Mostrar detalles de outputs
    println!("\n=== Outputs (Destinations) ===");
    for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
        println!("\nOutput {}:", i);
        let sats = output.value.to_sat();
        println!("  Value: {} sats ({:.8} BTC)", sats, sats as f64 / 1e8);
        display_script_pubkey("  Script PubKey", &output.script_pubkey);
    }

    // Mostrar PSBT inputs (con witness_utxo y signatures)
    println!("\n=== PSBT Input Details (Signing Info) ===");
    for (i, input) in psbt.inputs.iter().enumerate() {
        println!("\nInput {}:", i);

        if let Some(witness_utxo) = &input.witness_utxo {
            let sats = witness_utxo.value.to_sat();
            println!("  ✓ Input Amount: {} sats ({:.8} BTC)",
                     sats,
                     sats as f64 / 1e8);
            println!("  ✓ Script pubkey: {} bytes", witness_utxo.script_pubkey.len());
            if witness_utxo.script_pubkey.len() == 34 {
                println!("    (P2TR - Taproot key-path spending)");
            }
        } else {
            println!("  ✗ Witness UTXO missing");
        }

        if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let tx_bytes = serialize(non_witness_utxo);
            println!("  ✓ Non-witness UTXO present: {} bytes", tx_bytes.len());
        }

        // Mostrar witness si existe
        if let Some(witness) = &input.final_script_witness {
            if !witness.is_empty() {
                println!("\n  🔐 FINAL WITNESS (Signature Data)");
                println!("  ✓ Witness stack: {} item(s)", witness.len());
                for (j, witness_item) in witness.iter().enumerate() {
                    if witness_item.len() == 64 {
                        println!("    [{j}] Schnorr Signature (64 bytes)");
                        println!("        {}", encode(witness_item));
                        // Mostrar primeros y últimos bytes para identificación rápida
                        println!("        First 8 bytes: {}...", encode(&witness_item[..8]));
                        println!("        Last 8 bytes:  ...{}", encode(&witness_item[56..]));
                    } else {
                        println!("    [{j}] Data ({} bytes): {}",
                                 witness_item.len(),
                                 encode(witness_item));
                    }
                }
            } else {
                println!("  ✗ No final witness (empty)");
            }
        } else {
            println!("  ✗ No final witness");
        }

        // Mostrar taproot fields si existen
        if let Some(internal_key) = &input.tap_internal_key {
            println!("\n  ✓ Taproot Internal Key: {}", encode(internal_key.serialize().as_slice()));
        }
    }

    // Resumen de validez
    println!("\n=== Transaction Summary ===");
    let has_witness = psbt.inputs.iter()
        .any(|i| i.final_script_witness.as_ref().map_or(false, |w| !w.is_empty()));
    let has_utxo = psbt.inputs.iter().any(|i| i.witness_utxo.is_some());

    println!("Status: {}", if has_witness && has_utxo { "✅ SIGNED" } else { "⚠️ INCOMPLETE" });
    println!("  Signed: {}", if has_witness { "✓" } else { "✗" });
    println!("  UTXOs available: {}", if has_utxo { "✓" } else { "✗" });

    // Calcular fee si tenemos la información
    let total_input: u64 = psbt.inputs.iter()
        .filter_map(|i| i.witness_utxo.as_ref().map(|u| u.value.to_sat()))
        .sum();
    let total_output: u64 = psbt.unsigned_tx.output.iter()
        .map(|o| o.value.to_sat())
        .sum();

    if total_input > 0 && total_output > 0 {
        let fee = total_input.saturating_sub(total_output);
        println!("\nFee Summary:");
        println!("  Total Input:  {} sats ({:.8} BTC)", total_input, total_input as f64 / 1e8);
        println!("  Total Output: {} sats ({:.8} BTC)", total_output, total_output as f64 / 1e8);
        println!("  Fee:          {} sats ({:.8} BTC)", fee, fee as f64 / 1e8);

        let tx_size = serialize(&psbt.unsigned_tx).len();
        if fee > 0 && tx_size > 0 {
            let fee_rate = (fee as f64) / (tx_size as f64);
            println!("  Fee rate:     {:.2} sats/byte", fee_rate);
        }
    }

    // Mostrar bytes en hex (útil para broadcast)
    println!("\n=== Raw PSBT (hex) ===");
    println!("First 100 bytes: {}", encode(&psbt_bytes[..std::cmp::min(100, psbt_bytes.len())]));
    println!("\n=== Base64 (for broadcast/wallet import) ===");
    println!("{}", base64_encode(&psbt_bytes));
}

fn base64_encode(data: &[u8]) -> String {
    use std::process::Command;
    use std::io::Write;

    let mut child = Command::new("base64")
        .arg("-w").arg("0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn base64");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(data).expect("Failed to write to stdin");
    }

    let output = child.wait_with_output().expect("Failed to get base64 output");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}
