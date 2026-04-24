# seedless

A Rust CLI tool for creating blind signatures of Bitcoin Taproot transactions using **Threshold Signature Schemes (TSS)** with hardware security modules (YubiKey 5 / NitroKey 3).

## Features

- **FROST Protocol** (RFC 9591): Flexible Round-Optimized Schnorr Threshold Signatures
  - Default 2-of-3 threshold (configurable)
  - Full BIP-340 (Schnorr) and BIP-341 (Taproot) support
  - Invisible on-chain: final signature indistinguishable from single-signer
  
- **Hardware Security Module Integration**:
  - YubiKey 5: Stores key shares in PIV data objects
  - NitroKey 3: Fallback storage with HMAC key derivation
  - Sequential connection: one device at a time to the same PC
  
- **Security**:
  - Nonces held only in memory (never written to disk)
  - Uses `secrecy` crate (mlock + mprotect) for protected memory
  - `zeroize` crate ensures secrets are zeroed on drop
  - PIN-protected HSM access for all operations

## Requirements

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- YubiKey 5 or NitroKey 3 (or mock HSM for testing)
- Bitcoin PSBT file for signing

## Installation

```bash
git clone <repo>
cd seedless
cargo build --release
```

The binary will be at `target/release/seedless`.

## Quick Start

### 1. Initialize Keys

Run the key ceremony to generate shares and store them on your HSMs:

```bash
cargo run -- setup --threshold 2 --participants 3
```

This will:
1. Generate a FROST key pair split into 3 shares
2. Prompt you to connect each HSM and write the share
3. Derive the group Taproot address
4. Generate BIP-86 xpub for watch-only wallet import
5. Save configuration to `~/.config/seedless/config.json`

The xpub will be displayed. You can import it into Sparrow Wallet or Electrum for watch-only balance monitoring.

### 2. Sign a Transaction

```bash
cargo run -- sign path/to/transaction.psbt
```

This performs 2-round signing:
- **Round 1**: Connect each HSM, generate nonce commitment
- **Round 2**: Reconnect each HSM, create partial signature
- Aggregate partial signatures → final Schnorr signature
- Save signed PSBT to `path/to/transaction.psbt.signed`

### 3. View Address

```bash
cargo run -- address
```

Displays the group Taproot address derived from your configured public key.

### 4. Check Configuration

```bash
cargo run -- info
```

Shows threshold, participants, network, group public key, and xpub.

### 5. Export xpub for Watch-Only Wallet

To import into Sparrow or Electrum for balance monitoring:

```bash
# Print xpub to terminal
cargo run -- export-xpub

# Or save to file
cargo run -- export-xpub -o xpub.txt
```

#### Importing into Sparrow Wallet
1. File → Import → Paste xpub (from `seedless export-xpub`)
2. Name: "seedless-watch"
3. Policy: None (watch-only)
4. Address Type: Taproot (P2TR)
5. Confirm and open wallet

#### Importing into Electrum
1. File → New/Restore
2. Wallet name: "seedless-watch"
3. Choose: Restore from extended key
4. Paste xpub (from `seedless export-xpub`)
5. Choose: Taproot
6. Next → Complete

## Architecture

```
seedless/
├── src/
│   ├── main.rs              # CLI entry point and command handlers
│   ├── cli.rs               # Command definitions (clap)
│   ├── config.rs            # Configuration persistence
│   ├── frost.rs             # FROST protocol wrapper
│   ├── bitcoin.rs           # Bitcoin TX/PSBT handling
│   ├── state.rs             # Signing session state (nonces, partial sigs)
│   └── hsm/
│       ├── mod.rs           # HSM trait definition
│       ├── yubikey.rs       # YubiKey PIV implementation
│       ├── nitrokey.rs      # NitroKey implementation
│       └── mock.rs          # Mock HSM for testing
└── tests/                   # Integration tests
```

## Signing Protocol

### Round 1: Nonce Commitments
For each of t signers:
1. Connect HSM → authenticate with PIN
2. Load key share from PIV data object
3. Generate fresh (secnonce, pubnonce) for this session
4. Store secnonce in memory, send pubnonce to coordinator
5. Disconnect HSM

### Round 2: Partial Signatures
For each signer (in same order as Round 1):
1. Reconnect HSM → authenticate with PIN
2. Load key share from HSM
3. Retrieve saved secnonce from session
4. Sign message with secnonce → generate partial signature
5. **Immediately zeroize secnonce** (single-use guarantee)
6. Disconnect HSM

### Aggregation
- Coordinator collects all t partial signatures
- Aggregate via FROST → final Schnorr signature
- Signature is valid for the group public key
- Add signature to PSBT → broadcast-ready transaction

## Security Considerations

### Nonce Handling
- Each nonce is **single-use only** (RFC 9591 requirement)
- Nonces are held only in RAM between Round 1 and Round 2
- Nonces are zeroized immediately after use
- No backup or recovery of nonces possible

### Key Share Storage
- Shares never leave the HSM (stored in PIV data object)
- Each share is encrypted/protected by HSM firmware
- Access requires PIN authentication
- Shares are never combined on disk (only in FROST protocol)

### Memory Protection
- Secret types use `secrecy` crate (mlock prevents swapping)
- All secret data implements `Zeroize` (zeroed on drop)
- Use `cargo run -- sign` only from trusted environments

## Dependencies

- **FROST**: `frost-secp256k1-tr` 2.x (ZcashFoundation, audited)
- **Bitcoin**: `rust-bitcoin` 0.32, `secp256k1` 0.29
- **HSM**: `yubikey` 0.9, `nitrokey` 0.4
- **CLI**: `clap` 4.x
- **Security**: `secrecy` 0.10, `zeroize` 2.x
- **Serialization**: `serde`, `serde_json`, `hex`

## Testing

```bash
# Build
cargo build

# Run tests (uses mock HSM)
cargo test

# Check code
cargo clippy -- -D warnings

# Format code
cargo fmt

# Build release
cargo build --release
```

## Development Status

**Phase 1 (Foundation)**: ✓ Complete
- Core modules, HSM trait, FROST wrapper, Bitcoin TX handling

**Phase 2 (Setup)**: In progress
- Full key ceremony with HSM interaction

**Phase 3 (Sign)**: Upcoming
- Complete 2-round signing workflow

**Phase 4 (HSM)**: Upcoming
- Enhanced YubiKey/NitroKey support, test with real hardware

**Phase 5 (Testing)**: Upcoming
- Integration tests, signature verification

## Known Limitations

- HSMs connect one at a time (sequential, not parallel)
- Currently uses Trusted Dealer for key ceremony (not DKG)
- NitroKey support is fallback-based (HMAC key derivation)
- No backup/recovery mechanism for key shares
- No support for key rotation yet

## Documentation

- `CLAUDE.md` — Architecture and development guidance
- `docs/XPUB.md` — Detailed guide on BIP-86 xpub for Sparrow/Electrum watch-only import
- FROST protocol: [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
- Taproot: [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki), [BIP-341 Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- BIP-86: [Key Derivation for Taproot](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)

## License

MIT
