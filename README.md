# BAP - Bitcoin Attestation Protocol

> Sovereign digital identity on the Bitcoin blockchain

[![npm version](https://badge.fury.io/js/bsv-bap.svg)](https://badge.fury.io/js/bsv-bap)
[![License](https://img.shields.io/badge/license-Open%20BSV-blue.svg)](LICENSE)

## Abstract

The Bitcoin Attestation Protocol (BAP) establishes a cryptographic system for creating, managing, and verifying digital identities directly on the Bitcoin blockchain. By treating Bitcoin keypairs as the fundamental identity primitive, BAP eliminates traditional authentication intermediaries while providing mathematical guarantees of identity ownership, attestation validity, and data sovereignty.

## Motivation

Current digital identity systems suffer from three critical failures:

1. **Centralized Control**: Identity providers act as gatekeepers, capable of suspending, deleting, or modifying user identities at will. Users possess accounts, not identities.

2. **Platform Fragmentation**: Each service maintains isolated identity silos, forcing users to recreate their digital presence repeatedly across platforms. Reputation, relationships, and verified attributes cannot move between systems.

3. **Trust Without Verification**: Traditional systems require blind trust in institutions to maintain identity records accurately and permanently. No mathematical proof exists that your identity data remains unaltered or accessible.

BAP resolves these failures by recognizing a simple axiom: **a cryptographic keypair IS an identity**. This principle, combined with Bitcoin's immutable ledger, creates a system where:

- Identity ownership is cryptographically provable
- Attestations form an auditable chain of trust
- Data persistence requires no institutional faith
- Interoperability emerges from shared protocols, not corporate agreements

## Core Principles

### Identity as Mathematics

In BAP, identity is not assigned but derived. Your identity emerges from the mathematical relationship between private and public keys:

```
IdentityKey = base58(ripemd160(sha256(rootAddress)))
```

This deterministic derivation means identity recovery requires only the original key material — no database lookups, no account recovery flows, no customer service.

### Attestations as Proofs

Trust in BAP is not declared but proven. When an entity attests to an identity attribute, they create a cryptographic proof:

```
Attestation = Sign(SHA256(attribute + identityKey), attestorKey)
```

These proofs are:
- **Independently verifiable**: Any party can validate without contacting the attestor
- **Temporally fixed**: The blockchain timestamp prevents backdating
- **Publicly auditable**: Anyone can examine an entity's attestation history

### Sovereignty Through Cryptography

BAP implements true data sovereignty through:

1. **Key Rotation**: Identity owners can update signing keys while maintaining identity continuity
2. **Selective Disclosure**: Share only specific attributes with cryptographic proof of the whole
3. **Encrypted Storage**: Sensitive data remains encrypted, with decryption controlled by identity owner

## Technical Architecture

### Protocol Structure

BAP transactions follow a deterministic format:

```
OP_RETURN
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT  # Protocol prefix
[ACTION]                            # ID | ATTEST | ALIAS | DATA | REVOKE
[DATA]                              # Action-specific payload
|                                   # Separator
[AIP_SIGNATURE]                     # Author Identity Protocol signature
```

### Identity Lifecycle

1. **Genesis**: Create identity by deriving key from root address
2. **Attestation**: Build trust through cryptographic attestations
3. **Rotation**: Update signing keys while preserving identity chain
4. **Revocation**: Cryptographically invalidate compromised keys

### Cryptographic Operations

Each identity possesses distinct keys for different operations:

- **Member Key**: The root key for each identity path, used for key derivation
- **Signing Key**: Derived from member key for transaction authorization and message signing
- **Encryption Key**: ECIES encryption for private data exchange
- **Derivation Path**: Hierarchical key generation for sub-identities

### Key Derivation Hierarchy

BAP uses a two-level key derivation for signing operations:

```
Root Key (HD or Type42 master)
    ↓ path derivation
Member Key (identity root at path)
    ↓ deriveChild(publicKey, "1-bap-identity")
Signing Key (used for on-chain operations)
```

The member key serves as the stable identity root. The signing key is deterministically derived from it for on-chain operations. This structure is compatible with BRC-100 wallet tooling, though BAP is not coupled to any specific wallet implementation.

## Implementation

### Installation

```bash
bun add bsv-bap
# or
npm install bsv-bap
```

Peer dependency: `@bsv/sdk@^2.0.1`

### Basic Usage

```typescript
import { BAP } from 'bsv-bap';
import { PrivateKey } from '@bsv/sdk';

// Initialize with Type 42 derivation (recommended)
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

// Export master backup
const backup = bap.exportForBackup('My Identities');
```

### Identity Discovery

Type 42 identities use sequential counters (`bap:0`, `bap:1`, etc.) for deterministic recovery. This enables identity discovery when restoring from a backup:

```typescript
// Discover identities by checking sequential counters
async function discoverIdentities(bap, existsOnChain) {
  const found = [];

  for (let i = 0; i < 100; i++) {
    const identity = bap.newIdWithCounter(i);

    if (await existsOnChain(identity.bapId)) {
      found.push(identity);
    }
  }

  return found;
}
```

### Wallet Rotation Semantics

The BAP ID is defined by the member key at `rootPath`, while the active wallet/signing root follows `currentPath`.

- `rootPath`: stable member key path, defines the BAP ID
- `currentPath`: active wallet root, used for signing and wallet operations
- `incrementPath()`: rotates the wallet/signing root without changing the BAP ID

For Type 42 identities the first rotation moves from `bap:0` to `bap:0:1`, then `bap:0:2`, and so on.

```typescript
const identity = bap.newId();

const stableBapId = identity.bapId;

identity.incrementPath();

// BAP ID is unchanged
console.log(identity.bapId === stableBapId); // true

// currentPath has advanced
console.log(identity.currentPath); // "bap:0:1"
```

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

# Export account key for use in a wallet
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
| `identity.signMessage()` | Removed | Use your wallet |
| `identity.encrypt/decrypt()` | Removed from MasterID | Use `bap.encrypt/decrypt()` for master-level |
| `identity.getEncryptionPublicKey()` | Removed | Use your wallet |
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
const accountKey = identity.getAccountKey(); // Account-level PrivateKey
const backup = identity.exportAccountBackup(); // { wif, id }
```

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

### Master Backup (BIP32, legacy)

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

## API Reference

### BAP Class

The main class for managing identities.

#### Constructor

```typescript
// Type 42 mode (recommended)
const bap = new BAP({ rootPk: wifKey });

// BIP32 mode (legacy)
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
identity.bapId: string        // Deterministic BAP ID
identity.rootAddress: string  // Root Bitcoin address
identity.rootPath: string     // Derivation path (e.g., "bap:0")
identity.currentPath: string  // Active path (advances on key rotation)
identity.previousPath: string
identity.idSeed: string       // Seed used for sub-derivation
```

#### Methods

```typescript
// Get the account-level private key
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

## Applications

### Primary Use Cases

- **Decentralized Authentication**: Replace passwords with cryptographic proofs
- **Portable Reputation**: Carry verified history across platforms
- **Regulatory Compliance**: Reusable KYC with selective disclosure
- **Digital Signatures**: Legally binding with blockchain timestamps

### Integration with UI Components

For React applications, [BigBlocks](https://bigblocks.dev) provides production-ready components for BAP integration:

```bash
npm install bigblocks
```

```jsx
import { BitcoinAuth } from 'bigblocks';

<BitcoinAuth
  onAuthenticated={(identity) => {
    console.log('Authenticated:', identity);
  }}
/>
```

## Protocol Specification

For complete technical specification including transaction formats, URN structures, and validation rules, see [PROTOCOL.md](PROTOCOL.md).

## Related Work

- [Type 42 Key Derivation](docs/TYPE42_MIGRATION.md) - Modern derivation method for enhanced privacy
- [Author Identity Protocol](https://github.com/b-open-io/aip) - Foundational signing protocol
- [Bitcoin Backup](https://github.com/rohenaz/bitcoin-backup) - Compatible backup format specification

## Contributing

We welcome contributions. See [Contributing Guidelines](CONTRIBUTING.md).

## License

Open BSV License. See [LICENSE](LICENSE) for details.

## Acknowledgments

Created by Siggi with contributions from Attila Aros and Satchmo.
