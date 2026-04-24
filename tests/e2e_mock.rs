use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, XOnlyPublicKey};
use secp256k1::Secp256k1;
use seedless::bitcoin as sbtc;
use seedless::frost;
use seedless::hsm::mock::MockHsm;
use seedless::hsm::Hsm;

/// Test 1: Validate PSBT structure with witness_utxo
#[test]
fn test_psbt_structure() {
    // Create minimal TX
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // Add witness_utxo (required for Taproot sighash)
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: bitcoin::ScriptBuf::new_op_return(&[]),
    });

    // Verify structure
    assert_eq!(psbt.unsigned_tx.input.len(), 1, "Should have exactly 1 input");
    assert_eq!(psbt.unsigned_tx.output.len(), 1, "Should have exactly 1 output");
    assert!(
        psbt.inputs[0].witness_utxo.is_some(),
        "Input must have witness_utxo"
    );
    assert_eq!(
        psbt.inputs[0].witness_utxo.as_ref().unwrap().value.to_sat(),
        100_000,
        "witness_utxo amount should match"
    );
}

/// Test 2: Verify BIP-341 sighash computation returns 32 bytes and is deterministic
#[test]
fn test_sighash_computation() {
    // Generate a valid group pubkey for testing
    let (group_pubkey_bytes, _, _) =
        frost::generate_shares(2, 2).expect("Failed to generate shares for sighash test");

    // Create P2TR script_pubkey from the group pubkey
    let secp = Secp256k1::new();
    let xonly = XOnlyPublicKey::from_slice(&group_pubkey_bytes[1..])
        .expect("Valid x-only pubkey from group pubkey");
    let address = Address::p2tr(&secp, xonly, None, Network::Regtest);
    let script_pubkey = address.script_pubkey();

    // Create TX
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey,
    });

    // Compute sighash
    let sighash1 = sbtc::compute_sighash(&psbt, 0).expect("Sighash computation failed");

    // Verify size is 32 bytes
    assert_eq!(
        sighash1.len(),
        32,
        "Sighash must be exactly 32 bytes, got {}",
        sighash1.len()
    );

    // Verify determinism: same PSBT → same sighash
    let sighash2 = sbtc::compute_sighash(&psbt, 0).expect("Second sighash computation failed");
    assert_eq!(
        sighash1, sighash2,
        "Sighash must be deterministic for same PSBT"
    );
}

/// Test 3: Full FROST signing flow with MockHsm + cryptographic verification
#[test]
fn test_full_frost_signing() {
    // Step 1: Generate FROST shares (2-of-2)
    let (group_pubkey_bytes, shares, pubkey_package_bytes) =
        frost::generate_shares(2, 2).expect("Failed to generate shares");

    assert_eq!(group_pubkey_bytes.len(), 33, "Group pubkey should be 33 bytes (compressed)");
    assert_eq!(shares.len(), 2, "Should have 2 shares");

    // Step 2: Store shares in MockHsm instances (simulating 2 separate devices)
    let mut hsm1 = MockHsm::new("HSM-1");
    let mut hsm2 = MockHsm::new("HSM-2");

    hsm1.write_share(1, &shares[0])
        .expect("Failed to write share 1");
    hsm2.write_share(2, &shares[1])
        .expect("Failed to write share 2");

    // Step 3: Create PSBT with witness_utxo using the group pubkey
    let psbt = make_test_psbt(&group_pubkey_bytes);

    // Step 4: Compute sighash from PSBT (message to be signed)
    let sighash = sbtc::compute_sighash(&psbt, 0).expect("Failed to compute sighash");
    assert_eq!(sighash.len(), 32, "Sighash must be 32 bytes");

    // Step 5: FROST Round 1 - Nonce commitments
    let share1 = hsm1.read_share(1).expect("Failed to read share 1");
    let share2 = hsm2.read_share(2).expect("Failed to read share 2");

    let (nonces1, commitments1) =
        frost::round1_commit(&share1).expect("Round 1 failed for signer 1");
    let (nonces2, commitments2) =
        frost::round1_commit(&share2).expect("Round 1 failed for signer 2");

    // Step 6: Create signing package with commitments and message
    let commitments = vec![(1u16, commitments1), (2u16, commitments2)];
    let signing_pkg = frost::create_signing_package(&commitments, &sighash)
        .expect("Failed to create signing package");

    // Step 7: FROST Round 2 - Partial signatures
    let share1 = hsm1.read_share(1).expect("Failed to read share 1 for round 2");
    let share2 = hsm2.read_share(2).expect("Failed to read share 2 for round 2");

    let partial1 = frost::round2_sign(&share1, &nonces1, &signing_pkg)
        .expect("Round 2 failed for signer 1");
    let partial2 = frost::round2_sign(&share2, &nonces2, &signing_pkg)
        .expect("Round 2 failed for signer 2");

    // Step 8: Aggregate partial signatures into final Schnorr signature
    let sig_shares = vec![(1u16, partial1), (2u16, partial2)];
    let final_sig = frost::aggregate(&signing_pkg, &sig_shares, &pubkey_package_bytes)
        .expect("Failed to aggregate signatures");

    assert_eq!(
        final_sig.len(),
        64,
        "Final signature must be 64 bytes (BIP-340)"
    );

    // Step 9: Verify signature cryptographically (without blockchain)
    let secp = Secp256k1::new();

    // Convert sighash to Message
    let msg = secp256k1::Message::from_digest(
        sighash
            .as_slice()
            .try_into()
            .expect("Sighash length must be 32 bytes"),
    );

    // Convert signature bytes to schnorr::Signature
    let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&final_sig)
        .expect("Invalid Schnorr signature bytes");

    // Extract x-only pubkey from group_pubkey_bytes (skip 0x02 prefix, take 32 bytes)
    let xonly = secp256k1::XOnlyPublicKey::from_slice(&group_pubkey_bytes[1..])
        .expect("Invalid x-only public key");

    // Verify the signature - this will fail if signature is incorrect
    secp.verify_schnorr(&schnorr_sig, &msg, &xonly)
        .expect("Signature verification failed - FROST signing broken");

    // Step 10: Finalize PSBT with signature
    let mut psbt = psbt;
    sbtc::finalize_psbt(&mut psbt, 0, &final_sig).expect("Failed to finalize PSBT");

    // Verify witness is integrated
    assert!(
        psbt.inputs[0].final_script_witness.is_some(),
        "PSBT should have final_script_witness"
    );

    let witness = psbt.inputs[0]
        .final_script_witness
        .as_ref()
        .expect("Witness should exist");

    // For Taproot key-path spend, witness should have exactly 1 element (64-byte sig)
    assert_eq!(witness.len(), 1, "Witness should have exactly 1 element");
    assert_eq!(
        witness.iter().next().unwrap().len(),
        64,
        "Witness element should be 64 bytes"
    );
}

/// Helper: Create a test PSBT with valid P2TR script_pubkey and witness_utxo
fn make_test_psbt(group_pubkey_bytes: &[u8]) -> Psbt {
    // Verify input size: 33 bytes (0x02 prefix + 32 bytes x-only)
    assert_eq!(
        group_pubkey_bytes.len(),
        33,
        "Expected 33-byte group pubkey with prefix"
    );

    // Create P2TR address from group pubkey
    let secp = Secp256k1::new();
    let xonly = XOnlyPublicKey::from_slice(&group_pubkey_bytes[1..])
        .expect("Failed to create x-only pubkey from group key");
    let address = Address::p2tr(&secp, xonly, None, Network::Regtest);
    let script_pubkey = address.script_pubkey();

    // Create unsigned transaction
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };

    // Create PSBT and add witness_utxo
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("Failed to create PSBT");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey,
    });

    psbt
}
