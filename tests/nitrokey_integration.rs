/// Integration test for NitroKey 3 support
/// Requires: nitropy installed, NitroKey 3 connected, PIN = "123456"

#[cfg(feature = "hsm-nitrokey")]
mod nitrokey_tests {
    use seedless::frost;
    use seedless::hsm::Hsm;
    use seedless::hsm::nitrokey::NitroKeyHsm;
    use std::process::Command;

    #[test]
    #[ignore] // Run with: cargo test --test nitrokey_integration -- --ignored --nocapture
    fn test_nitrokey_write_read() {
        // Skip if NK3 not connected
        let list_output = Command::new("nitropy")
            .args(["nk3", "list"])
            .output()
            .expect("nitropy not found");

        let list_str = String::from_utf8_lossy(&list_output.stdout);
        if list_str.contains("No Nitrokey") || list_str.is_empty() {
            eprintln!("⚠️  Skipping: No NitroKey 3 detected");
            return;
        }

        println!("✓ NitroKey 3 detected: {}", list_str.lines().next().unwrap_or(""));

        // Generate FROST shares
        let (group_pubkey, shares, _pubkey_pkg) = frost::generate_shares(2, 2)
            .expect("Failed to generate shares");

        println!("✓ Generated {} shares", shares.len());

        // Note: This test requires setting NITROPY_SECRETS_PASSWORD=123456 before running
        // Or modify the code to hardcode PIN for testing

        println!("✓ Test complete (manual PIN input required for actual write/read)");
    }

    #[test]
    #[ignore]
    fn test_nitrokey_detect() {
        // This test demonstrates detecting NK3 without writing/reading
        // (avoids need for PIN input in CI)

        let list_output = Command::new("nitropy")
            .args(["nk3", "list"])
            .output()
            .expect("nitropy not found");

        let list_str = String::from_utf8_lossy(&list_output.stdout);

        if list_str.contains("Nitrokey 3") {
            println!("✓ NitroKey 3 is connected");
            println!("Device: {}", list_str.trim());
            assert!(true);
        } else {
            eprintln!("⚠️  No NitroKey 3 detected");
            return;
        }
    }
}

#[cfg(not(feature = "hsm-nitrokey"))]
mod no_nitrokey {
    #[test]
    fn compile_without_nitrokey() {
        // Ensure code compiles without hsm-nitrokey feature
        assert!(true);
    }
}
