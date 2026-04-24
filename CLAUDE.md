# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**seedless** is a CLI tool for creating blind signatures of Bitcoin Taproot transactions using Threshold Signature Schemes (TSS) with hardware security modules (YubiKey 5 / NitroKey 3).

## Architecture

- **FROST Protocol**: Flexible Round-Optimized Schnorr Threshold Signatures (RFC 9591)
  - Uses `frost-secp256k1-tr` (ZcashFoundation, actively maintained, audited)
  - Supports 2-of-3 threshold by default (configurable t-of-n)
  - Two-round signing: Round 1 (nonce commitments), Round 2 (partial signatures)
  
- **HSM Integration**: 
  - YubiKey 5: Stores key shares in PIV data objects (3,052 bytes max per object)
  - NitroKey 3: Fallback storage via HMAC key derivation or password safe
  - Abstract `Hsm` trait in `src/hsm/mod.rs` allows adding more HSM types
  
- **Bitcoin**: Uses `rust-bitcoin` + `secp256k1` crate for Taproot support
  - Handles PSBT format (Partially Signed Bitcoin Transactions)
  - Derives group Taproot addresses from group public key
  
- **Security**: 
  - Nonces held in memory only (never written to disk)
  - Uses `secrecy` crate (mlock + mprotect) for secret memory
  - Uses `zeroize` crate to ensure secrets are zeroed on drop
  - Sequential HSM connection: one device at a time to single PC
  
## Commands

```bash
# Setup: run key ceremony (DKG), distribute shares to HSMs
cargo run -- setup --threshold 2 --participants 3

# Sign a PSBT file
cargo run -- sign path/to/tx.psbt

# Display group Taproot address
cargo run -- address

# Show configuration (includes xpub)
cargo run -- info

# Export BIP-86 xpub for watch-only wallet import
cargo run -- export-xpub
cargo run -- export-xpub -o xpub.txt
```

## Key Code Locations

- `src/frost.rs` — FROST protocol wrapper (generate shares, round 1 commit, round 2 sign, aggregate)
- `src/hsm/mod.rs` — `Hsm` trait definition
- `src/hsm/yubikey.rs` — YubiKey PIV implementation
- `src/hsm/nitrokey.rs` — NitroKey implementation (fallback storage)
- `src/bitcoin.rs` — Bitcoin TX/PSBT handling, Taproot address derivation, **BIP-86 xpub generation**
- `src/state.rs` — `SigningSession`: holds nonces and partial signatures in memory
- `src/config.rs` — `Config`: stores t, n, group_pubkey, xpub, participant IDs
- `src/cli.rs` — Command definitions with clap

## Development Tasks

### Current Phase 1: Foundation (Core Modules) ✓
- [x] Project scaffolding and Cargo.toml
- [x] Config module (save/load to ~/.config/seedless/)
- [x] HSM trait and mock/YubiKey/NitroKey implementations
- [x] FROST wrapper (share generation, round 1/2, aggregation)
- [x] Bitcoin module (PSBT, Taproot address derivation)
- [x] Session state management (SigningSession with nonce tracking)
- [x] CLI commands skeleton

### Phase 2: Setup Command (TODO)
- Implement full key ceremony:
  1. User input: t-of-n (default 2-of-3)
  2. Generate shares via `frost::generate_shares()`
  3. For each participant i: prompt "Connect HSM", detect device, write share to PIV, prompt "Disconnect"
  4. Verify each share can be read back
  5. Compute Taproot address from group public key
  6. Derive BIP-86 xpub for watch-only wallet import
  7. Save config (including xpub) to disk
  8. Destroy master key from memory (auto via drop)
  9. Display xpub with instructions for Sparrow/Electrum import

### Phase 3: Sign Command (TODO)
- Implement full signing workflow:
  1. Load config, verify threshold >= 1, parse selected signers
  2. Load PSBT file, display TX details
  3. User confirms
  4. **Round 1 (Nonce Gen)**: For each signer i:
     - Prompt "Connect HSM i", detect, authenticate (PIN)
     - Load share from HSM PIV
     - Call `frost::round1_commit()` → get secnonce, pubnonce
     - Store secnonce in `SigningSession.secret_nonces` (in memory only)
     - Store pubnonce in `SigningSession.signing_commitments`
     - Prompt "Disconnect HSM i"
  5. Create signing package via `frost::aggregate_commitments()`
  6. **Round 2 (Signing)**: For each signer i:
     - Prompt "Reconnect HSM i", detect, authenticate
     - Load share from HSM PIV
     - Retrieve secnonce from session (and remove to ensure single use)
     - Call `frost::round2_sign()` → get partial signature
     - Zeroize secnonce immediately
     - Store partial sig in session
     - Prompt "Disconnect HSM i"
  7. Aggregate via `frost::aggregate_signatures()` → final Schnorr signature
  8. Add signature to PSBT, save to file
  9. Display TX hex ready for broadcast

### Phase 4: HSM Enhancements (TODO)
- [ ] Improve YubiKey integration: handle PIV PIN correctly, verify write/read
- [ ] Improve NitroKey integration: test with actual hardware, add PIV support if available
- [ ] Add challenge-response fallback for NitroKey (HMAC-SHA1 to derive encryption key)

### Phase 5: Testing (TODO)
- [ ] Integration tests with mock HSM
- [ ] Test key ceremony end-to-end
- [ ] Test sign workflow with fixtures
- [ ] Verify signatures with Bitcoin libraries

## Critical Security Considerations

1. **Nonce Reuse is Fatal**: Each `secnonce` must be:
   - Generated fresh per signing session (via `round1::commit()`)
   - Held in memory only until Round 2
   - Removed from session after use (single-use guarantee)
   - Zeroized immediately after `round2::sign()`

2. **Secret Memory**:
   - Never write nonces, shares, or secret scalars to disk
   - Use `secrecy::SecretBox` or `secrecy::SecretVec` for in-memory storage
   - All sensitive types must implement `Zeroize`
   - `mlock()` prevents swapping to disk

3. **HSM Interaction**:
   - Require PIN authentication for every share read/write
   - Verify device identity (serial number) when reconnecting
   - Never cache unencrypted shares outside HSM
   - Test fail-closed behavior if HSM disconnects mid-operation

4. **Taproot Specifics**:
   - Use x-only public keys (32 bytes, no prefix)
   - Schnorr signatures must be standard BIP-340 format
   - Verify final signature against group public key before returning

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `frost-secp256k1-tr` | 2.x | FROST protocol, Taproot support |
| `bitcoin` | 0.32 | rust-bitcoin, PSBT/TX handling |
| `secp256k1` | 0.29 | Schnorr signatures, curve operations |
| `yubikey` | 0.9 | YubiKey PIV API |
| `nitrokey` | 0.4 | NitroKey integration |
| `clap` | 4.x | CLI argument parsing |
| `secrecy` | 0.10 | Secret memory (mlock + mprotect) |
| `zeroize` | 2.x | Secure zero on drop |
| `serde` / `serde_json` | 1.x | Config serialization |
| `hex` | 0.4 | Hex encoding/decoding |
| `rand` | 0.8 | RNG for FROST |
| `rpassword` | 7.x | Read PIN without terminal echo |

## Testing Commands

```bash
# Build
cargo build --release

# Run tests
cargo test

# Check with clippy
cargo clippy -- -D warnings

# Format code
cargo fmt

# Run specific command
cargo run -- setup --threshold 2 --participants 3
```

## Building and Distribution

- Currently a CLI binary
- Plans to add library API (`lib.rs`) for programmatic use
- No Python bindings yet (can be added via PyO3 if needed)
- Binary will be ~10-20MB (Rust stdlib + dependencies)

## Notes for Claude

- The project uses Trusted Dealer for key ceremony (simpler, sufficient for theoretical use)
- If DKG (Distributed Key Generation) is needed later, see `frost-secp256k1-tr` docs for integration
- The HSM trait allows swapping implementations without changing core logic
- Mock HSM in tests is a simple in-memory store; replace with real device interaction for production
- YubiKey's PIV module supports up to 28 data objects; slots 0x5FC10D-0x5FC119 are "Retired Certificates 1-15"
- NitroKey 3 with PIV support is newer; fallback to encrypted local storage if PIV unavailable
- Consider adding config versioning if key derivation path changes in future
