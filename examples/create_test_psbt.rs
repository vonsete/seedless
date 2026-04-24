use bitcoin::psbt::Psbt;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::OutPoint;
use bitcoin::Sequence;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Txid;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use std::fs;
use std::str::FromStr;

fn main() {
    let secp = Secp256k1::new();

    // Create realistic Taproot addresses for origin and destination
    // Generate from secret keys (deterministic for testing)

    // Origin: secret key 1
    let origin_sk = SecretKey::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001"
    ).expect("Invalid secret key");
    let origin_pk = origin_sk.public_key(&secp);
    let origin_address = Address::p2tr(&secp, origin_pk.x_only_public_key().0, None, Network::Bitcoin);

    // Destination: secret key 2
    let dest_sk = SecretKey::from_str(
        "0000000000000000000000000000000000000000000000000000000000000002"
    ).expect("Invalid secret key");
    let dest_pk = dest_sk.public_key(&secp);
    let dest_address = Address::p2tr(&secp, dest_pk.x_only_public_key().0, None, Network::Bitcoin);

    // Create a test transaction
    // Input: spending from origin_address (previous UTXO)
    let prev_txid = Txid::from_str(
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    ).expect("Invalid txid");

    let tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout: 0,  // First output from previous transaction
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: dest_address.script_pubkey(),
        }],
    };

    // Create PSBT from unsigned transaction
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("Failed to create PSBT");

    // Add witness UTXO (required for Taproot) - shows the previous output being spent
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: origin_address.script_pubkey(),
    });

    // Serialize and save
    let psbt_bytes = psbt.serialize();
    fs::write("/tmp/test.signed.psbt", &psbt_bytes).expect("Failed to write PSBT");

    println!("✓ Created test PSBT with real addresses: /tmp/test.signed.psbt");
    println!("  Size: {} bytes\n", psbt_bytes.len());
    println!("📍 Origin (Input):  {}", origin_address);
    println!("📍 Destination (Output): {}", dest_address);
    println!("\nRun: ./target/release/examples/inspect_psbt /tmp/test.signed.psbt");
}
