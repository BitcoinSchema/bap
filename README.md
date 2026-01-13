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

This deterministic derivation means identity recovery requires only the original key material - no database lookups, no account recovery flows, no customer service.

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

This structure ensures compatibility with BRC-100 wallet tooling while maintaining BAP's identity management features. The member key serves as the BRC-100 identity root, and the signing key is deterministically derived for on-chain operations.

## Implementation

### Installation

```bash
npm install bsv-bap
```

### Basic Usage

```javascript
import { BAP } from 'bsv-bap';
import { PrivateKey } from '@bsv/sdk';

// Initialize with Type 42 derivation (recommended)
const rootKey = PrivateKey.fromRandom();
const bap = new BAP({
  rootPk: rootKey.toWif()
});

// Create identity with meaningful name
const identity = bap.newId('Professional Identity');
identity.setAttribute('name', 'Satoshi Nakamoto');

// Generate ID transaction for blockchain
const idTransaction = identity.getInitialIdTransaction();

// Create attestation hash for verification
const attestationHash = identity.getAttestationHash('name');
```

### Identity Discovery

Type 42 identities use sequential counters (`bap:0`, `bap:1`, etc.) for deterministic recovery. This enables identity discovery when restoring from partial backups:

```javascript
// Discover identities by checking sequential counters
async function discoverIdentities(bap, checkExistsOnChain) {
  const found = [];
  
  for (let i = 0; i < 100; i++) {  // Check first 100 slots
    const identity = bap.newIdWithCounter(i, `Discovered Identity ${i}`);
    
    if (await checkExistsOnChain(identity.getIdentityKey())) {
      found.push(identity);
    }
  }
  
  return found;
}
```

### Migration from Legacy Derivation

Existing identities using the previous (pre-signing-key-derivation) format can be migrated:

```javascript
// Check if identity needs migration
if (identity.needsRotation(registeredOnChainAddress)) {
  // Get the rotation transaction OP_RETURN
  const opReturn = identity.getLegacyRotationTransaction();

  // App handles funding and broadcasting the transaction
  // This rotates from legacy address to new derived signing address
}

// Utility methods for migration
const legacyAddress = identity.getLegacyAddress();  // Pre-derivation address
const newAddress = identity.getCurrentAddress();     // New derived address
```

### Deprecation Notice

The BIP32 initialization format using extended private keys (xprv) is deprecated. For new implementations, use Type 42 initialization with `{ rootPk: wifKey }`. The legacy BIP32 format remains supported for backward compatibility but should not be used in new projects.

### Advanced Operations

For detailed API documentation, see the [Library Documentation](src/README.md).

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