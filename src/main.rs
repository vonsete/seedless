use seedless::{cli, config, frost, bitcoin, state, hsm, slip39};
use cli::{Cli, Commands};
use clap::Parser;
use anyhow::Result;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            participants,
            threshold,
            network,
        } => {
            cmd_setup(participants, threshold, &network)?;
        }
        Commands::Sign {
            psbt_file,
            signers,
            output,
        } => {
            cmd_sign(&psbt_file, signers.as_deref(), output.as_deref())?;
        }
        Commands::Address => {
            cmd_address()?;
        }
        Commands::Info => {
            cmd_info()?;
        }
        Commands::ExportXpub { output } => {
            cmd_export_xpub(output.as_deref())?;
        }
    }

    Ok(())
}

fn cmd_setup(participants: u16, threshold: u16, network: &str) -> Result<()> {
    #[cfg(feature = "hsm-yubikey")]
    use crate::hsm::Hsm;

    println!("🔑 Starting key ceremony: {}-of-{} threshold", threshold, participants);

    // Generate shares using trusted dealer
    let (group_pubkey_bytes, shares, pubkey_package_bytes) = frost::generate_shares(threshold, participants)?;

    let num_shares = shares.len();
    let pubkey_hex = hex::encode(&group_pubkey_bytes);
    let pubkey_package_hex = hex::encode(&pubkey_package_bytes);

    println!("✓ Generated {} key shares", num_shares);
    println!("✓ Group public key: {}", pubkey_hex);

    // Generate SLIP-39 mnemonics for each share (backup purposes)
    println!("\n📝 Generating SLIP-39 mnemonics for backup...");
    let mut share_mnemonics: std::collections::HashMap<u16, String> = Default::default();

    for (i, share) in shares.iter().enumerate() {
        let participant_id = (i + 1) as u16;
        let share_hex = hex::encode(share);

        match slip39::share_to_mnemonic(share, participant_id, threshold, participants) {
            Ok(mnemonic) => {
                share_mnemonics.insert(participant_id, mnemonic.clone());
                println!("✓ Share {} mnemonic generated", participant_id);
            }
            Err(e) => {
                eprintln!("⚠️  Warning: Could not generate SLIP-39 mnemonic for share {}: {}", participant_id, e);
                eprintln!("   Continuing with hex backup only");
            }
        }
    }

    // Collect age recipients during HSM setup
    let mut age_recipients: std::collections::HashMap<u16, String> = Default::default();

    // Distribute shares to HSM if feature is enabled
    #[cfg(feature = "hsm-yubikey")]
    {
        println!("\n📱 Storing shares on YubiKey devices...");

        // For each participant, prompt user to connect YubiKey and write share
        for (i, share) in shares.iter().enumerate() {
            let participant_id = (i + 1) as u16;

            println!("\n🔌 Connect YubiKey for participant {} and press Enter", participant_id);
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            // Detect and open YubiKey
            println!("Detecting YubiKey...");
            let mut yk = hsm::yubikey::YubiKeyHsm::detect()?;
            println!("✓ YubiKey detected: {}", yk.device_name());

            // Capture recipient for age encryption
            age_recipients.insert(participant_id, yk.recipient().to_string());

            // Write share to YubiKey
            yk.write_share(participant_id, share)?;

            // Note: Share verification is deferred to the first signing operation
            // where decryption will confirm the share is readable
            println!("✓ Share will be verified during first signing operation");
            println!("  (requires YubiKey + PIN + touch)");

            println!("🔌 Disconnect YubiKey for participant {}", participant_id);
        }
    }

    #[cfg(all(feature = "hsm-nitrokey", not(feature = "hsm-yubikey")))]
    {
        println!("\n📱 Storing shares on NitroKey 3 devices...");

        // For each participant, prompt user to connect NitroKey and write share
        for (i, share) in shares.iter().enumerate() {
            let participant_id = (i + 1) as u16;

            println!("\n🔌 Connect NitroKey 3 for participant {} and press Enter", participant_id);
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            // Detect and open NitroKey
            println!("Detecting NitroKey 3...");
            use crate::hsm::Hsm;
            let mut nk = hsm::nitrokey::NitroKeyHsm::detect()?;
            println!("✓ NitroKey detected: {}", nk.device_name());

            // Write share to NitroKey (will prompt for PIN internally)
            nk.write_share(participant_id, share)?;

            // Verify by reading back
            println!("Verifying share...");
            let read_share = nk.read_share(participant_id)?;
            if read_share == *share {
                println!("✓ Share verified successfully");
            } else {
                return Err(anyhow::anyhow!("Share verification failed for participant {}", participant_id));
            }

            println!("🔌 Disconnect NitroKey 3 for participant {}", participant_id);
        }
    }

    #[cfg(not(any(feature = "hsm-yubikey", feature = "hsm-nitrokey")))]
    {
        // For now, print shares (in production, distribute to HSMs)
        println!("\n⚠️  Key ceremony complete. In production, shares would be stored on HSMs.");
        println!("Shares (for testing only):");
        for (i, share) in shares.iter().enumerate() {
            println!("  Share {}: {} bytes", i + 1, share.len());
        }
    }

    // Show SLIP-39 backup information
    println!("\n📋 SLIP-39 MNEMONIC BACKUP");
    println!("════════════════════════════════════════════════════════════════");
    println!("Each share has been encoded as a SLIP-39 mnemonic for backup.");
    println!("Write these down carefully and store safely (laminated or steel).");
    println!();

    for participant_id in 1..=participants {
        if let Some(mnemonic) = share_mnemonics.get(&participant_id) {
            let share_hex = hex::encode(&shares[(participant_id - 1) as usize]);

            println!("\n🔐 SHARE #{} - BIP-39 MNEMONIC BACKUP", participant_id);
            println!("════════════════════════════════════════════════════════════════");
            println!("Threshold: {}-of-{}", threshold, participants);
            println!();
            println!("Mnemonic ({} words - write this down carefully):", mnemonic.split_whitespace().count());
            println!();

            // Display in groups of 4 for readability
            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            for (idx, chunk) in words.chunks(4).enumerate() {
                let line_num = idx * 4 + 1;
                print!("  {:2}. {}", line_num, chunk.join("  "));
                if chunk.len() < 4 && idx == words.chunks(4).count() - 1 {
                    // Last partial line
                    println!();
                } else if chunk.len() == 4 {
                    println!();
                }
            }

            println!();
            println!("Hex (for digital backup or QR code):");
            println!("  {}", share_hex);
            println!();
            println!("⚠️  KEEP THIS SAFE:");
            println!("  • Write on paper (laminated or steel)");
            println!("  • Store in secure location");
            println!("  • This is a {} secret recovery code", threshold);
            println!("════════════════════════════════════════════════════════════════");
        }
    }

    // Derive Taproot address
    let address = bitcoin::derive_taproot_address(&pubkey_hex, network)?;
    println!("\n📍 Taproot address: {}", address);

    // Derive xpub for watch-only wallet import
    let xpub = bitcoin::derive_xpub(&pubkey_hex, network)?;
    println!("📋 xpub (BIP-86): {}", xpub);

    // Save config
    let cfg = config::Config {
        threshold,
        participants,
        group_public_key: pubkey_hex,
        xpub: Some(xpub),
        participant_ids: (1..=participants).collect(),
        network: network.to_string(),
        pubkey_package: Some(pubkey_package_hex),
        age_recipients,
    };
    cfg.save()?;
    println!("✓ Configuration saved to {:?}", config::Config::config_file()?);

    Ok(())
}

fn cmd_sign(psbt_file: &std::path::Path, _signers: Option<&str>, output: Option<&std::path::Path>) -> Result<()> {
    // Load config
    let cfg = config::Config::load()?;
    println!("🔐 Signing with {}-of-{} threshold", cfg.threshold, cfg.participants);

    // Load PSBT (mutable for signing)
    let mut psbt = bitcoin::load_psbt(psbt_file)?;
    bitcoin::display_transaction(&psbt)?;

    // Ask user to confirm
    println!("Sign this transaction? (y/n): ");
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    if response.trim() != "y" {
        println!("Cancelled.");
        return Ok(());
    }

    println!("✓ Transaction confirmed. Starting signature process...");

    // Determine signers (default: first threshold participants)
    let signers: Vec<u16> = (1..=cfg.threshold).collect();
    println!("\nParticipants signing: {:?}", signers);

    // Calculate sighash from PSBT (input 0)
    let sighash = bitcoin::compute_sighash(&psbt, 0)?;
    println!("Message (sighash): {}", hex::encode(&sighash));

    // Create signing session
    let mut session = state::SigningSession::new(sighash, signers.clone());  // mut for add_nonces, add_commitments

    // =========== ROUND 1: Nonce Commitments ===========
    println!("\n=== ROUND 1: Generating nonce commitments ===");

    for signer_id in &signers {
        #[cfg(feature = "hsm-yubikey")]
        println!("\n🔌 Connect YubiKey for participant {} and press Enter", signer_id);
        #[cfg(all(feature = "hsm-nitrokey", not(feature = "hsm-yubikey")))]
        println!("\n🔌 Connect NitroKey 3 for participant {} and press Enter", signer_id);

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        #[cfg(feature = "hsm-yubikey")]
        {
            println!("Detecting YubiKey...");
            use crate::hsm::Hsm;
            let mut yk = hsm::yubikey::YubiKeyHsm::detect()?;
            println!("✓ YubiKey detected: {}", yk.device_name());

            // Read share
            let share = yk.read_share(*signer_id)?;

            // Generate nonces and commitments
            let (nonces, commitments) = frost::round1_commit(&share)?;
            println!("✓ Generated nonces and commitments for participant {}", signer_id);

            // Store in session
            session.add_nonces(*signer_id, nonces)?;
            session.add_commitments(*signer_id, commitments)?;

            println!("🔌 Disconnect YubiKey for participant {}", signer_id);
        }
        #[cfg(all(feature = "hsm-nitrokey", not(feature = "hsm-yubikey")))]
        {
            println!("Detecting NitroKey 3...");
            use crate::hsm::Hsm;
            let mut nk = hsm::nitrokey::NitroKeyHsm::detect()?;
            println!("✓ NitroKey detected: {}", nk.device_name());

            // Read share
            let share = nk.read_share(*signer_id)?;

            // Generate nonces and commitments
            let (nonces, commitments) = frost::round1_commit(&share)?;
            println!("✓ Generated nonces and commitments for participant {}", signer_id);

            // Store in session
            session.add_nonces(*signer_id, nonces)?;
            session.add_commitments(*signer_id, commitments)?;

            println!("🔌 Disconnect NitroKey 3 for participant {}", signer_id);
        }
        #[cfg(not(any(feature = "hsm-yubikey", feature = "hsm-nitrokey")))]
        {
            println!("⚠️  HSM feature not enabled");
            return Err(anyhow::anyhow!("HSM feature required for signing"));
        }
    }

    // Create signing package
    println!("\n📦 Creating signing package...");
    let commitments_vec: Vec<(u16, Vec<u8>)> = signers
        .iter()
        .map(|id| {
            (
                *id,
                session
                    .signing_commitments
                    .get(id)
                    .cloned()
                    .unwrap_or_default(),
            )
        })
        .collect();

    let signing_package_bytes = frost::create_signing_package(&commitments_vec, &session.message)?;
    println!("✓ Signing package created");

    // =========== ROUND 2: Partial Signatures ===========
    println!("\n=== ROUND 2: Generating partial signatures ===");

    for signer_id in &signers {
        #[cfg(feature = "hsm-yubikey")]
        println!("\n🔌 Reconnect YubiKey for participant {} and press Enter", signer_id);
        #[cfg(all(feature = "hsm-nitrokey", not(feature = "hsm-yubikey")))]
        println!("\n🔌 Reconnect NitroKey 3 for participant {} and press Enter", signer_id);

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        #[cfg(feature = "hsm-yubikey")]
        {
            println!("Detecting YubiKey...");
            use crate::hsm::Hsm;
            let mut yk = hsm::yubikey::YubiKeyHsm::detect()?;
            println!("✓ YubiKey detected: {}", yk.device_name());

            // Read share
            let share = yk.read_share(*signer_id)?;

            // Get nonces (with .take() for single-use guarantee)
            let nonces = session
                .take_nonces(*signer_id)
                .ok_or_else(|| anyhow::anyhow!("Nonces not found for participant {}", signer_id))?;

            // Generate partial signature
            let partial_sig = frost::round2_sign(&share, &nonces, &signing_package_bytes)?;

            // Explicitly zeroize nonces after use
            {
                let mut nonces_copy = nonces;
                zeroize::Zeroize::zeroize(&mut nonces_copy);
            }

            println!("✓ Generated partial signature for participant {}", signer_id);

            // Store partial signature
            session.add_partial_signature(*signer_id, partial_sig)?;

            println!("🔌 Disconnect YubiKey for participant {}", signer_id);
        }
        #[cfg(all(feature = "hsm-nitrokey", not(feature = "hsm-yubikey")))]
        {
            println!("Detecting NitroKey 3...");
            use crate::hsm::Hsm;
            let mut nk = hsm::nitrokey::NitroKeyHsm::detect()?;
            println!("✓ NitroKey detected: {}", nk.device_name());

            // Read share
            let share = nk.read_share(*signer_id)?;

            // Get nonces (with .take() for single-use guarantee)
            let nonces = session
                .take_nonces(*signer_id)
                .ok_or_else(|| anyhow::anyhow!("Nonces not found for participant {}", signer_id))?;

            // Generate partial signature
            let partial_sig = frost::round2_sign(&share, &nonces, &signing_package_bytes)?;

            // Explicitly zeroize nonces after use
            {
                let mut nonces_copy = nonces;
                zeroize::Zeroize::zeroize(&mut nonces_copy);
            }

            println!("✓ Generated partial signature for participant {}", signer_id);

            // Store partial signature
            session.add_partial_signature(*signer_id, partial_sig)?;

            println!("🔌 Disconnect NitroKey 3 for participant {}", signer_id);
        }
        #[cfg(not(any(feature = "hsm-yubikey", feature = "hsm-nitrokey")))]
        {
            println!("⚠️  HSM feature not enabled");
            return Err(anyhow::anyhow!("HSM feature required for signing"));
        }
    }

    // =========== Aggregation ===========
    println!("\n=== Aggregating signatures ===");

    let pubkey_package_hex = cfg
        .pubkey_package
        .ok_or_else(|| anyhow::anyhow!("PublicKeyPackage not found in config"))?;
    let pubkey_package_bytes = hex::decode(&pubkey_package_hex)?;

    let partial_sigs_vec: Vec<(u16, Vec<u8>)> = signers
        .iter()
        .map(|id| {
            (
                *id,
                session.partial_signatures.get(id).cloned().unwrap_or_default(),
            )
        })
        .collect();

    let final_signature = frost::aggregate(&signing_package_bytes, &partial_sigs_vec, &pubkey_package_bytes)?;
    println!("✓ Aggregated signature (64 bytes): {}", hex::encode(&final_signature));

    // =========== Finalize PSBT with signature ===========
    println!("\n📝 Integrating signature into PSBT...");

    // Integrate the 64-byte Schnorr signature into the PSBT witness
    bitcoin::finalize_psbt(&mut psbt, 0, &final_signature)?;
    println!("✓ Signature integrated into witness");

    // Save finalized PSBT
    let default_output = psbt_file.with_extension("signed.psbt");
    let output_path = output.unwrap_or(default_output.as_path());
    bitcoin::save_psbt(output_path, &psbt)?;
    println!("✓ Signed PSBT saved to: {:?}", output_path);

    // Note: Final TX extraction happens at broadcast time with bitcoin-cli/wallet
    println!("\n📤 Transaction ready for broadcast");
    println!("To broadcast: bitcoin-cli sendrawtransaction <psbt_in_binary_or_hex>");

    println!("\n✅ Signing complete!");
    println!("Files:");
    println!("  - Signed PSBT: {:?}", output_path);

    Ok(())
}

fn cmd_address() -> Result<()> {
    let cfg = config::Config::load()?;
    let address = bitcoin::derive_taproot_address(&cfg.group_public_key, &cfg.network)?;
    println!("Taproot address: {}", address);
    Ok(())
}

fn cmd_info() -> Result<()> {
    let cfg = config::Config::load()?;
    println!("Configuration:");
    println!("  Threshold: {}-of-{}", cfg.threshold, cfg.participants);
    println!("  Network: {}", cfg.network);
    println!("  Group public key: {}", cfg.group_public_key);
    println!("  Participant IDs: {:?}", cfg.participant_ids);
    if let Some(xpub) = &cfg.xpub {
        println!("  xpub (BIP-86): {}", xpub);
    }
    Ok(())
}

fn cmd_export_xpub(output: Option<&std::path::Path>) -> Result<()> {
    let cfg = config::Config::load()?;

    let xpub_info = bitcoin::export_xpub_info(&cfg.group_public_key, &cfg.network)?;

    if let Some(output_path) = output {
        std::fs::write(output_path, &xpub_info)?;
        println!("✓ xpub exported to: {:?}", output_path);
    } else {
        println!("{}", xpub_info);
    }

    Ok(())
}
