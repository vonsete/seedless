use bitcoin::psbt::Psbt;
use hex::encode;
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <psbt_file>", args[0]);
        eprintln!("Example: {} /tmp/test.signed.psbt", args[0]);
        std::process::exit(1);
    }

    let psbt_path = &args[1];

    let psbt_bytes = fs::read(psbt_path).expect("Failed to read PSBT file");
    let psbt = Psbt::deserialize(&psbt_bytes).expect("Failed to parse PSBT");

    println!("=== PSBT Export for Sparrow Wallet ===\n");

    // 1. Base64 (copy-paste into Sparrow)
    let base64 = base64_encode(&psbt_bytes);
    println!("📋 BASE64 (Copy to Sparrow → File → Import PSBT → Paste):");
    println!("{}\n", base64);

    // 2. Hex format
    let hex = encode(&psbt_bytes);
    println!("🔤 HEX FORMAT (Alternative):");
    println!("{}\n", hex);

    // 3. File path (direct import)
    println!("📁 FILE PATH (Direct import):");
    println!("{}\n", psbt_path);

    // 4. Save base64 to file for easy copy
    let base64_file = "/tmp/test.signed.psbt.base64";
    fs::write(&base64_file, &base64).expect("Failed to write base64 file");
    println!("✓ Saved base64 to: {}", base64_file);
    println!("  Run: cat {} | xclip -selection clipboard", base64_file);
    println!("  (to copy base64 to clipboard)\n");

    // 5. Save hex to file
    let hex_file = "/tmp/test.signed.psbt.hex";
    fs::write(&hex_file, &hex).expect("Failed to write hex file");
    println!("✓ Saved hex to: {}\n", hex_file);

    // 6. Show transaction details
    println!("=== Transaction Details ===");
    println!("Inputs: {}", psbt.unsigned_tx.input.len());
    println!("Outputs: {}", psbt.unsigned_tx.output.len());

    let total_in: u64 = psbt.inputs.iter()
        .filter_map(|i| i.witness_utxo.as_ref().map(|u| u.value.to_sat()))
        .sum();
    let total_out: u64 = psbt.unsigned_tx.output.iter()
        .map(|o| o.value.to_sat())
        .sum();

    println!("Total Input:  {} sats ({:.8} BTC)", total_in, total_in as f64 / 1e8);
    println!("Total Output: {} sats ({:.8} BTC)", total_out, total_out as f64 / 1e8);
    if total_in > 0 && total_out > 0 {
        let fee = total_in.saturating_sub(total_out);
        println!("Fee:          {} sats ({:.8} BTC)\n", fee, fee as f64 / 1e8);
    }

    // 7. Sparrow import instructions
    println!("=== Import into Sparrow Wallet ===\n");
    println!("Option 1: Copy-Paste Base64");
    println!("  1. Open Sparrow Wallet");
    println!("  2. Go to File → Import PSBT");
    println!("  3. Select 'Paste Text' tab");
    println!("  4. Paste the base64 above");
    println!("  5. Click 'Import PSBT'\n");

    println!("Option 2: Import from File");
    println!("  1. Open Sparrow Wallet");
    println!("  2. Go to File → Import PSBT");
    println!("  3. Select 'Load File' tab");
    println!("  4. Navigate to: {}", psbt_path);
    println!("  5. Click 'Import PSBT'\n");

    println!("Option 3: CLI (if Sparrow supports it)");
    println!("  sparrow-cli import {}", psbt_path);
    println!("  (or) sparrow-cli import-text {}", base64_file);
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
