# Quick Start: xpub with Sparrow/Electrum

## In 5 Minutes

### 1. Setup your keys
```bash
cd /home/alfonso/seedless
cargo run -- setup --threshold 2 --participants 3
```

The output will show:
```
📍 Taproot address: bc1p...
📋 xpub (BIP-86): xpub661MyMwAqRbcH...
✓ Configuration saved
```

**Copy the xpub value** (starts with `xpub...`)

### 2. Open Sparrow Wallet

#### Option A: New Wallet
1. File → New Wallet
2. Name: `seedless-watch`
3. Configure: Taproot (P2TR)

#### Option B: Import Existing
1. File → Import
2. Paste the xpub value
3. Select: Taproot (P2TR)
4. Confirm

### 3. View Your Balance

Once imported, Sparrow will:
- ✅ Show your balance
- ✅ List transactions
- ✅ Generate receive addresses
- ❌ Cannot sign (use `seedless sign` for that)

### 4. To Sign a Transaction

When you want to send coins:

```bash
# Export PSBT from Sparrow/Electrum
# Save as: tx.psbt

# Sign with seedless (requires HSMs connected)
cargo run -- sign tx.psbt

# Broadcast the signed tx from your wallet software
```

## For Electrum Users

Same process, different UI:

1. File → New Wallet
2. "Restore from text" → Paste xpub
3. "Taproot"
4. Confirm

## Notes

- The xpub is **public** - it's safe to share
- Your balance and addresses are visible in Sparrow/Electrum
- Only the HSM-protected shares can sign transactions
- Export xpub anytime: `cargo run -- export-xpub`
- Save xpub to file: `cargo run -- export-xpub -o my_xpub.txt`

## Troubleshooting

**"Invalid xpub" error?**
- Check it's not truncated (should be ~112 characters)
- Verify network matches (Bitcoin vs Testnet)

**Wallet shows 0 balance?**
- Give it a moment to fetch UTXOs
- Check your network connection
- Ensure you're on correct network (Bitcoin/Testnet)

See `docs/XPUB.md` for detailed guide.
