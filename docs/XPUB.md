# BIP-86 Extended Public Key (xpub) for Watch-Only Wallets

## Overview

The `seedless` tool generates a **BIP-86 compliant Extended Public Key (xpub)** from your FROST group public key. This allows you to monitor your wallet balance and transaction history using a watch-only wallet in Sparrow or Electrum **without exposing any signing keys**.

## What is an xpub?

An Extended Public Key (xpub) is a standard Bitcoin format (BIP-32) that allows:
- Deriving multiple child addresses from a single public key
- Watch-only wallet monitoring (balance, transactions, address history)
- No ability to sign transactions (only the HSM-protected shares can sign)

## How seedless generates xpub

```
Group Public Key (from FROST DKG)
    ↓
BIP-86 Derivation Path
m/86'/0'/0' (Taproot standard account)
    ↓
Extended Public Key (xpub...)
    ↓
Watch-only wallet (Sparrow/Electrum/BlueWallet)
```

### Derivation Paths by Network

| Network | Path | Purpose |
|---|---|---|
| Bitcoin | `m/86'/0'/0'` | Mainnet account |
| Testnet | `m/86'/1'/0'` | Testnet account |
| Signet | `m/86'/1'/0'` | Signet account |
| Regtest | `m/86'/1'/0'` | Regtest account |

### Chain Code Generation

Since FROST shares are distributed and don't follow the BIP-32 standard hierarchy, we generate a synthetic chain code using:

```
chain_code = HMAC-SHA512(key="BIP32_CHAIN_CODE", msg=group_pubkey)[0:32]
```

This ensures the xpub is valid and deterministic, but note that **child key derivation from the xpub is theoretical** (the actual addresses are managed by seedless based on the signing requests).

## Exporting Your xpub

### Option 1: During Setup
```bash
cargo run -- setup --threshold 2 --participants 3
```
The xpub will be printed during setup.

### Option 2: After Setup
```bash
# Display on terminal
cargo run -- export-xpub

# Save to file
cargo run -- export-xpub -o my_xpub.txt
```

### Option 3: View Stored xpub
```bash
cargo run -- info
```
Displays current configuration including stored xpub.

## Importing into Sparrow Wallet

### Steps

1. **Create New Wallet**
   - Open Sparrow
   - File → New Wallet
   - Name: `seedless-watch` (or your choice)

2. **Import xpub**
   - Choose import method: Paste extended key
   - Paste the xpub from `seedless export-xpub`

3. **Configure**
   - Policy: Leave as "None" (watch-only, no backup)
   - Choose "Taproot (P2TR)" as address type
   - Confirm import

4. **Use**
   - View balance and transaction history
   - Generate receiving addresses (optionally)
   - **Cannot sign transactions** ← This is by design

### Sparrow Features with xpub

✅ View balances  
✅ See transaction history  
✅ Generate addresses for receiving  
✅ Export PSBT for offline signing  
❌ Sign transactions (requires HSM + seedless)  

## Importing into Electrum

### Steps

1. **Create New Wallet**
   - File → New Wallet
   - Name: `seedless-watch`

2. **Restore from Key**
   - Choose "Restore from text"
   - Paste xpub

3. **Select Type**
   - Choose "Taproot"

4. **Confirm**
   - Electrum will derive addresses automatically
   - No password needed (watch-only)

5. **Use**
   - Same features as Sparrow
   - View transactions and balance
   - Export receive addresses

## Security Notes

### ✅ Safe to Share
- The xpub is **public** and safe to share
- It reveals your transaction history
- It cannot be used to sign transactions
- The HSM-protected shares remain secure

### ⚠️ Important Reminders
- The xpub is linked to your master group public key
- Keep your HSMs with the key shares secure
- Backup the xpub file separately from HSMs
- Don't rely on watch-only wallet for signing (always use `seedless sign`)

## Troubleshooting

### "Invalid xpub" error in Sparrow/Electrum

1. Verify the xpub is complete (no truncation)
2. Ensure network matches (Bitcoin vs Testnet)
3. Try re-exporting: `seedless export-xpub`
4. Check that config.json exists: `~/.config/seedless/config.json`

### xpub doesn't match my addresses

- Addresses are standard BIP-86 Taproot (P2TR format)
- Verify address type in wallet settings is "Taproot"
- Empty wallets may not show any transactions initially

### Wallet shows 0 balance when it should have funds

- Ensure you're using the correct network (Bitcoin vs Testnet)
- The first import may take a few seconds to fetch UTXOs
- Check that your transaction was confirmed on-chain

## Technical Details

### xpub Format

```
xpub[version][depth][parent-fingerprint][child-index][chain-code][public-key]
```

Example:
```
xpub661MyMwAqRbcH...
│││ │    │
└┬┴ │    └─ secp256k1 public key (33 bytes)
 │  │
 │  └─ Depth = 3 (m/86'/0'/0')
 │
 └─ Extended public key format
```

### Compatibility

- ✅ Sparrow Wallet
- ✅ Electrum 4.x+
- ✅ BlueWallet
- ✅ Bitcoin Core (with descriptor support)
- ✅ Ledger Live (import as "custom descriptor")

### BIP Standards Used

- **BIP-32**: Hierarchical Deterministic Wallets
- **BIP-86**: Key Derivation for Taproot
- **BIP-341**: Taproot address scheme (P2TR)

## Example Usage Flow

```bash
# 1. Setup keys
$ seedless setup --threshold 2 --participants 3
✓ Generated 3 key shares
✓ Group public key: 02abc123...
📋 xpub (BIP-86): xpub661MyMwAqRbcH...
✓ Configuration saved to ~/.config/seedless/config.json

# 2. Export xpub
$ seedless export-xpub
Extended Public Key (BIP-86 Taproot):
Derivation Path: m/86'/0'/0'
xpub: xpub661MyMwAqRbcH...

How to import:
- Sparrow Wallet: File → Import → Paste xpub
- Electrum: Wallet → New/Restore → Paste xpub
- Select 'Taproot (P2TR)' as address type

# 3. Import into Sparrow
# (manually in UI, paste xpub)

# 4. View transactions and balance in Sparrow
# (watch-only, no signing)

# 5. When ready to sign a transaction
$ seedless sign path/to/transaction.psbt
# (requires HSMs connected)
```

## FAQ

**Q: Can I derive new addresses from the xpub?**  
A: Yes, standard BIP-86 tools can derive child addresses. However, seedless manages address generation for PSBT signing. The xpub is primarily for balance monitoring.

**Q: What if I lose the xpub?**  
A: You can always regenerate it: `seedless export-xpub`. It's deterministic from your config.

**Q: Is the xpub as secret as the key shares?**  
A: No. The xpub is public information (it's in the blockchain). Keep the HSM shares secret.

**Q: Can someone steal my funds with the xpub?**  
A: No. The xpub is watch-only. They cannot sign transactions without the HSM shares.

**Q: Why use xpub instead of just the address?**  
A: xpub allows the wallet to generate and monitor multiple derived addresses automatically, following BIP-86 standards.

## References

- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-86: Key Derivation for Taproot](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
- [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [Sparrow Documentation](https://www.sparrowwallet.com/docs/)
- [Electrum Documentation](https://electrum.readthedocs.io/)
