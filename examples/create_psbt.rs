use bitcoin::psbt::Psbt;
use bitcoin::{Transaction, TxIn, TxOut, OutPoint, Sequence, Amount, Address, Network, XOnlyPublicKey};
use secp256k1::Secp256k1;

fn main() {
    // Leer config para obtener el group_public_key (P2TR address source)
    let config_path = dirs::config_dir().unwrap().join("seedless/config.json");

    let script_pubkey = if config_path.exists() {
        // Leer config.json
        let config_str = std::fs::read_to_string(&config_path)
            .expect("Failed to read config.json");
        let config: serde_json::Value = serde_json::from_str(&config_str)
            .expect("Invalid JSON in config.json");

        // Obtener group_public_key
        let pubkey_hex = config["group_public_key"].as_str()
            .expect("Missing 'group_public_key' in config.json");

        let pubkey_bytes = hex::decode(pubkey_hex)
            .expect("Invalid hex in group_public_key");

        // Extract x-only (32 bytes) from compressed pubkey (33 bytes)
        let x_only_bytes = if pubkey_bytes.len() == 33 {
            &pubkey_bytes[1..]  // Skip the 02/03 prefix
        } else if pubkey_bytes.len() == 32 {
            &pubkey_bytes[..]
        } else {
            panic!("Invalid public key length: {}", pubkey_bytes.len());
        };

        // Crear dirección P2TR (Taproot)
        let x_only = XOnlyPublicKey::from_slice(x_only_bytes)
            .expect("Invalid x-only public key");
        let secp = Secp256k1::new();
        let network = Network::Regtest;  // O leer del config si está disponible
        let address = Address::p2tr(&secp, x_only, None, network);

        println!("✓ Usando P2TR address: {}", address);
        address.script_pubkey()
    } else {
        // Fallback: script vacío (para testing sin config)
        println!("⚠️  config.json no encontrado en {:?}", config_path);
        println!("    Usando script_pubkey vacío (no se podrá calcular sighash real)");
        bitcoin::ScriptBuf::new()
    };

    // Crear una transacción mínima válida
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }
        ],
    };

    // Crear PSBT desde la tx
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("Failed to create PSBT");

    // Añadir witness_utxo (obligatorio para Taproot sighash)
    // Simula un UTXO que el usuario está gastando
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),  // UTXO original tenía 100k sats
        script_pubkey,  // Script P2TR del grupo
    });

    // Serializar
    let psbt_bytes = psbt.serialize();

    // Escribir a archivo
    std::fs::write("/tmp/test.psbt", &psbt_bytes).expect("Failed to write PSBT");

    println!("✓ PSBT creado: {} bytes", psbt_bytes.len());
    println!("✓ Incluye witness_utxo: sí (necesario para Taproot sighash)");
    println!("Archivo: /tmp/test.psbt");
}
