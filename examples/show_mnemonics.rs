/// Example: Show BIP-39 mnemonics for FROST shares
///
/// Demonstrates how FROST shares are converted to BIP-39 mnemonics
/// for portable, memorable backup.

use seedless::{frost, slip39};
use hex::encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 FROST Share → BIP-39 Mnemonic Conversion Example\n");

    // Generate FROST shares (2-of-3 threshold)
    let threshold = 2u16;
    let participants = 3u16;

    println!("Generating {}-of-{} FROST shares...", threshold, participants);
    let (group_pubkey, shares, _pubkey_package) = frost::generate_shares(threshold, participants)?;

    let group_pubkey_hex = encode(&group_pubkey);
    println!("✓ Group public key: {}\n", group_pubkey_hex);

    // Convert each share to BIP-39 mnemonic
    println!("📋 Converting shares to BIP-39 mnemonics...\n");

    for (i, share) in shares.iter().enumerate() {
        let participant_id = (i + 1) as u16;
        let share_hex = encode(share);

        // Generate mnemonic
        let mnemonic = slip39::share_to_mnemonic(
            share,
            participant_id,
            threshold,
            participants,
        )?;

        // Display
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🔑 SHARE #{} - BIP-39 MNEMONIC", participant_id);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Threshold: {}-of-{}", threshold, participants);
        println!();
        println!("Mnemonic ({} words):", mnemonic.split_whitespace().count());
        println!();

        // Display with numbering
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        for (idx, chunk) in words.chunks(3).enumerate() {
            let line_num = idx * 3 + 1;
            print!("  {:2}. {:<20}", line_num, chunk[0]);
            if chunk.len() > 1 {
                print!("  {:2}. {:<20}", line_num + 1, chunk[1]);
            }
            if chunk.len() > 2 {
                print!("  {:2}. {}", line_num + 2, chunk[2]);
            }
            println!();
        }

        println!();
        println!("Hex format (for digital backup):");
        println!("  {}", share_hex);
        println!();

        // Validate round-trip
        let recovered_entropy = slip39::mnemonic_to_entropy(&mnemonic)?;
        let original_entropy = if share.len() >= 16 {
            share[..16].to_vec()
        } else {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(share);
            let hash = hasher.finalize();
            hash[..16].to_vec()
        };

        if recovered_entropy == original_entropy {
            println!("✓ Round-trip validation: OK");
        } else {
            println!("⚠️  Round-trip validation: MISMATCH");
        }

        println!();
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("📝 BACKUP INSTRUCTIONS:");
    println!();
    println!("1. Write each mnemonic on paper (use all 3 lines above)");
    println!("2. Store in secure location (safe, vault, etc)");
    println!("3. IMPORTANT: Need {} out of {} shares to recover private key", threshold, participants);
    println!("4. Each share is protected by PIN + age-plugin-yubikey");
    println!("5. Keep backups separate for maximum security");
    println!();
    println!("💡 TIP: Use laminated paper or steel engraving for durability");

    Ok(())
}
