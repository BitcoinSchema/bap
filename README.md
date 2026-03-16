# BAP - Bitcoin Attestation Protocol

> Identity-only library for sovereign digital identity on Bitcoin

[![npm version](https://badge.fury.io/js/bsv-bap.svg)](https://badge.fury.io/js/bsv-bap)
[![License](https://img.shields.io/badge/license-Open%20BSV-blue.svg)](LICENSE)

## What is BAP?

BAP creates deterministic digital identities from Bitcoin keypairs. Each identity is a **BAP ID** derived from a root address:

```
BAP ID = base58(ripemd160(sha256(rootAddress)))
```

No servers, no accounts, no intermediaries. Your identity is pure mathematics.

## 0.2.0 Architecture

BAP 0.2.0 is an **identity-only** library designed for BRC-100 wallet delegation:

- **`BAP` class** - Master key management, identity CRUD, crypto operations, API lookups
- **`MasterID` class** - Individual identity with key derivation and path management
- **No signing keys, no attributes, no transactions** - Wallets handle those via BRC-100

This separation means BAP manages *who you are* while your wallet manages *what you do*.

## Installation

```bash
bun add bsv-bap
# or
npm install bsv-bap
```

Peer dependency: `@bsv/sdk@^2.0.1`

## Quick Start

```typescript
import { BAP } from 'bsv-bap';
import { PrivateKey } from '@bsv/sdk';

// Create BAP instance with Type 42 derivation
const rootKey = PrivateKey.fromRandom();
const bap = new BAP({ rootPk: rootKey.toWif() });

// Create an identity
const identity = bap.newId();

console.log(identity.bapId);       // Deterministic BAP ID
console.log(identity.rootAddress); // Root Bitcoin address
console.log(identity.rootPath);    // "bap:0" (counter-based)

// Create a second identity
const second = bap.newId();
console.log(second.rootPath);      // "bap:1"

// Export master backup (encrypted ids + rootPk)
const backup = bap.exportForBackup('My Identities');
```

## API Reference

### BAP Class

The main class for managing identities.

#### Constructor

```typescript
// Type 42 mode (recommended)
const bap = new BAP({ rootPk: wifKey });

// BIP32 mode (legacy, deprecated)
const bap = new BAP(xprvKey);

// With API token and custom server
const bap = new BAP({ rootPk: wifKey }, token, server);
```

#### Identity Management

```typescript
bap.newId(customPath?: string, idSeed?: string): MasterID
bap.newIdWithCounter(counter: number): MasterID
bap.getId(bapId: string): MasterID | null
bap.listIds(): string[]
bap.removeId(bapId: string): void
bap.checkIdBelongs(id: MasterID): boolean
```

Type 42 identities use sequential counters (`bap:0`, `bap:1`, ...) for deterministic recovery:

```typescript
// Discover identities by checking sequential counters
for (let i = 0; i < 100; i++) {
  const identity = bap.newIdWithCounter(i);
  if (await existsOnChain(identity.bapId)) {
    console.log(`Found: ${identity.bapId}`);
  }
}
```

#### Import / Export

```typescript
// Encrypted identity blob (default)
const encrypted: string = bap.exportIds();
bap.importIds(encrypted);

// Unencrypted identity data
const plain = bap.exportIds(undefined, false);
bap.importIds(plain, false);

// Master backup (for bitcoin-backup compatibility)
const backup = bap.exportForBackup(label?, xprv?, mnemonic?);
```

#### Master-Level Crypto

```typescript
// ECIES encryption with the master key
const ciphertext = bap.encrypt('secret');
const plaintext = bap.decrypt(ciphertext);

// BSM signature verification
const valid = bap.verifySignature(message, address, signature);

// Challenge verification via API
const valid = await bap.verifyChallengeSignature(idKey, address, challenge, signature);
```

#### API Lookups

```typescript
// Query the BAP overlay network
const identity = await bap.getIdentity(bapId);
const identity = await bap.getIdentityFromAddress(address);
const attestations = await bap.getAttestationsForHash(hash);
```

### MasterID Class

Represents a single identity. Managed through the `BAP` class.

#### Properties

```typescript
identity.bapId: string       // Deterministic BAP ID
identity.rootAddress: string // Root Bitcoin address
identity.rootPath: string    // Derivation path (e.g., "bap:0")
identity.currentPath: string // Active path (for wallet rotation)
identity.previousPath: string
identity.idSeed: string      // Seed used for sub-derivation
```

#### Methods

```typescript
// Get the account-level private key (for BRC-100 wallet delegation)
identity.getAccountKey(): PrivateKey

// Export identity state
identity.export(): Identity

// Export account backup (WIF + BAP ID)
identity.exportAccountBackup(): BapAccountBackup

// Import identity state
identity.import(data: Identity | OldIdentity): void
```

### Utility Functions

```typescript
import { bapIdFromAddress, bapIdFromPubkey } from 'bsv-bap';

// Derive BAP ID from a root address
const bapId = bapIdFromAddress(rootAddress);

// Derive BAP ID from a member public key (e.g., BRC-31 identity key)
const bapId = bapIdFromPubkey(pubkeyHex);
```

## Key Derivation

### Type 42 (Recommended)

Uses `PrivateKey.deriveChild()` with counter-based invoice numbers:

```
Master Key (WIF)
  -> deriveChild(masterPubKey, "bap:0")  -> Identity 0
  -> deriveChild(masterPubKey, "bap:1")  -> Identity 1
  -> deriveChild(masterPubKey, "bap:N")  -> Identity N
```

Each identity's BAP ID is derived from the root address at its path.

### Wallet Rotation

The BAP ID stays stable while the wallet root advances:

```typescript
identity.rootPath    // "bap:0" (stable, defines the BAP ID)
identity.currentPath // "bap:0" (initially same as rootPath)

// After rotation:
identity.currentPath // "bap:0:1" then "bap:0:2", etc.
```

`rootPath` defines the identity. `currentPath` is the active wallet/signing root.

### BIP32 (Legacy)

Uses hierarchical deterministic derivation:

```
m/424150'/0'/0'/[identity]/[key]/[index]
```

BIP32 mode is deprecated. Use Type 42 for new projects.

## Backup Format

### Master Backup (Type 42)

```json
{
  "rootPk": "L...",
  "ids": "<encrypted blob>",
  "label": "My Identities",
  "createdAt": "2024-01-01T00:00:00.000Z"
}
```

### Master Backup (BIP32)

```json
{
  "xprv": "xprv...",
  "ids": "<encrypted blob>",
  "mnemonic": "word1 word2 ...",
  "createdAt": "2024-01-01T00:00:00.000Z"
}
```

### Account Backup

```json
{
  "wif": "L...",
  "id": "<bapId>"
}
```

Compatible with [bitcoin-backup](https://github.com/rohenaz/bitcoin-backup).

## CLI

The `bap` CLI manages identities from the terminal. Config is stored at `~/.bap/`.

### Identity Management

```bash
bap create [--name <label>] [--wif <wif>]   # Create new identity
bap list                                      # List all identities (* = active)
bap use <bapId>                               # Set active identity
bap info                                      # Show active identity details
bap remove <bapId>                            # Remove identity
```

### Backup

```bash
bap export                                    # Export master backup (JSON to stdout)
bap export-account [--id <bapId>]             # Export account backup (WIF + bapId)
bap import <file>                             # Import from backup file
```

### Crypto

```bash
bap encrypt <data>                            # Encrypt with master key (ECIES)
bap decrypt <ciphertext>                      # Decrypt with master key
bap verify <message> <signature> <address>    # Verify BSM signature
```

### API Lookups

```bash
bap lookup <bapId>                            # Lookup identity on overlay
bap lookup-address <address>                  # Lookup identity by address
bap attestations <hash>                       # Get attestations for attribute hash
```

### Utilities

```bash
bap id-from-address <address>                 # Derive BAP ID from address
bap id-from-pubkey <pubkey>                   # Derive BAP ID from pubkey
```

### Examples

```bash
# Create your first identity
bap create --name "Personal"

# Create a second identity
bap create --name "Work"

# List and switch
bap list
bap use <work-bap-id>

# Export account for a BRC-100 wallet
bap export-account > account.json

# Lookup someone on the network
bap lookup <their-bap-id>

# Encrypt a note to yourself
bap encrypt "remember: office safe combo is 1234" > note.enc
cat note.enc | xargs bap decrypt
```

## Migration from 0.1.x

### Breaking Changes

| 0.1.x | 0.2.0 | Notes |
|-------|-------|-------|
| `identity.identityKey` | `identity.bapId` | Renamed for clarity |
| `identity.getIdentityKey()` | `identity.bapId` | Now a property |
| `identity.idName` | Removed | Use external labels |
| `identity.setAttribute()` | Removed | Attributes removed from core |
| `identity.signMessage()` | Removed | Use BRC-100 wallet |
| `identity.encrypt/decrypt()` | Removed from MasterID | Use `bap.encrypt/decrypt()` for master-level |
| `identity.getEncryptionPublicKey()` | Removed | Use BRC-100 wallet |
| `identity.getCurrentAddress()` | Removed | Use `identity.getAccountKey()` |
| `MemberID` class | Removed | Use `identity.exportAccountBackup()` |
| `exportMemberBackup()` | `exportAccountBackup()` | Returns `{ wif, id }` |

### Migration Path

```typescript
// 0.1.x
const identity = bap.newId('My Identity');
const key = identity.getIdentityKey();
const addr = identity.getCurrentAddress();
const { address, signature } = identity.signMessage(msg);

// 0.2.0
const identity = bap.newId();
const key = identity.bapId;
const accountKey = identity.getAccountKey(); // PrivateKey for BRC-100 wallet
const backup = identity.exportAccountBackup(); // { wif, id }
```

## Protocol

For the complete BAP protocol specification, see [PROTOCOL.md](PROTOCOL.md).

## Related

- [Type 42 Key Derivation](docs/TYPE42_MIGRATION.md) - Modern derivation method
- [Author Identity Protocol](https://github.com/b-open-io/aip) - Signing protocol
- [Bitcoin Backup](https://github.com/rohenaz/bitcoin-backup) - Compatible backup format

## License

Open BSV License. See [LICENSE](LICENSE) for details.

## Acknowledgments

Created by Siggi with contributions from Attila Aros and Satchmo.
