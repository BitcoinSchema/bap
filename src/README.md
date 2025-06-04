# BAP Library Documentation

> Complete API reference for the bsv-bap JavaScript/TypeScript library

## Installation

```bash
npm install bsv-bap
```

```bash
yarn add bsv-bap
```

```bash
bun add bsv-bap
```

## Core Classes

### BAP

The main class for managing Bitcoin Attestation Protocol identities.

#### Constructor

```typescript
// BIP32 mode (legacy)
const bap = new BAP(xprvKey: string);

// Type 42 mode (recommended)
const bap = new BAP({
  rootPk: string  // WIF format private key
});
```

#### Methods

##### Identity Management

```typescript
// Create a new identity (new signature - Type 42 optimized)
newId(idName?: string, customPath?: string, identityAttributes?: IdentityAttributes, idSeed?: string): MasterID

// Create identity with specific counter (useful for discovery)
newIdWithCounter(counter: number, idName?: string): MasterID

// Get an identity by key
getId(idKey: string): MasterID | null

// List all identity keys
listIds(): string[]

// Remove an identity
removeId(idKey: string): void

// Check if identity belongs to this BAP instance
checkIdBelongs(id: MasterID): boolean
```

##### Import/Export

```typescript
// Export identities (encrypted by default)
exportIds(idKeys?: string[], encrypted?: boolean): string | Identities

// Export specific identity
exportId(idKey: string, encrypted?: boolean): string | Identities

// Import identities
importIds(identities: string | Identities, encrypted?: boolean): void

// Bitcoin-backup compatible export
exportForBackup(label?: string, xprv?: string, mnemonic?: string): BapMasterBackup

// Export member backup
exportMemberForBackup(idKey: string, label?: string): BapMemberBackup
```

##### Cryptographic Operations

```typescript
// Create attestation transaction
signAttestationWithAIP(
  attestationHash: string,
  identityKey: string,
  counter?: number,
  dataString?: string
): number[][]

// Verify attestation
verifyAttestationWithAIP(txData: number[][]): AttestationResult

// Verify signature
verifySignature(
  message: string | number[],
  address: string,
  signature: string
): boolean

// Verify challenge signature (with API validation)
async verifyChallengeSignature(
  idKey: string,
  address: string,
  challenge: string,
  signature: string
): Promise<boolean>
```

##### Encryption

```typescript
// Encrypt data using BAP master key
encrypt(data: string): string

// Decrypt data using BAP master key
decrypt(encryptedData: string): string
```

##### Configuration

```typescript
// Set/get API server
BAP_SERVER: string  // Default: https://api.sigmaidentity.com/v1

// Set/get API token
BAP_TOKEN: string
```

### MasterID

Represents an individual identity with HD key derivation support.

#### Properties

```typescript
idName: string              // Identity name
description: string         // Identity description
identityKey: string         // Unique identity key
rootAddress: string         // Root Bitcoin address
identityAttributes: IdentityAttributes
```

#### Methods

##### Attribute Management

```typescript
// Set attribute
setAttribute(name: string, value: string | IdentityAttribute): void

// Get attribute
getAttribute(name: string): IdentityAttribute | null

// Get all attributes
getAttributes(): IdentityAttributes

// Remove attribute
unsetAttribute(name: string): void

// Get attribute URN
getAttributeUrn(name: string): string | null
```

##### Key Management

```typescript
// Get current signing address
getCurrentAddress(): string

// Get address for specific path
getAddress(path: string): string

// Increment to next path
incrementPath(): void

// Get encryption public key
getEncryptionPublicKey(): string
```

##### Signing

```typescript
// Sign message
signMessage(
  message: number[],
  signingPath?: string
): { address: string; signature: string }

// Sign message with seed
signMessageWithSeed(
  message: string,
  seed: string
): { address: string; signature: string }

// Sign OP_RETURN with AIP
signOpReturnWithAIP(
  opReturn: number[][],
  signingPath?: string
): number[][]
```

##### Encryption

```typescript
// Encrypt data
encrypt(data: string, counterPartyPublicKey?: string): string

// Decrypt data
decrypt(ciphertext: string, counterPartyPublicKey?: string): string

// Encrypt with seed
encryptWithSeed(
  data: string,
  seed: string,
  counterPartyPublicKey?: string
): string

// Decrypt with seed
decryptWithSeed(
  ciphertext: string,
  seed: string,
  counterPartyPublicKey?: string
): string
```

##### Attestations

```typescript
// Get attestation hash for attribute
getAttestationHash(attribute: string): string | null

// Get attestation URN
getAttestation(urn: string): string

// Get all attestations for attribute (API call)
async getAttributeAttestations(attribute: string): Promise<GetAttestationResponse>
```

##### Transactions

```typescript
// Get initial ID transaction
getInitialIdTransaction(): number[][]

// Get ID transaction for rotation
getIdTransaction(previousPath?: string): number[][]
```

### MemberID

Represents a standalone member identity (non-HD).

#### Constructor

```typescript
const member = new MemberID(privateKey: PrivateKey, attributes?: IdentityAttributes);
```

#### Methods

##### Core Operations

```typescript
// Get public key
getPublicKey(): string

// Sign message
signMessage(message: number[]): { address: string; signature: string }

// Sign OP_RETURN with AIP
signOpReturnWithAIP(opReturn: number[][]): number[][]
```

##### Import/Export

```typescript
// Export member data
export(): MemberIdentity

// Import member data
import(memberData: MemberIdentity): void

// Export for backup
exportForBackup(label?: string): BapMemberBackup

// Create from backup
static fromBackup(backup: BapMemberBackup): MemberID

// Create from member identity
static fromMemberIdentity(identity: MemberIdentity): MemberID
```

## Type System

### Core Types

```typescript
interface IdentityAttribute {
  value: string;
  nonce: string;
}

interface IdentityAttributes {
  [key: string]: IdentityAttribute;
}

interface Identity {
  name: string;
  description: string;
  identityKey: string;
  rootPath: string;
  rootAddress: string;
  previousPath: string;
  currentPath: string;
  idSeed: string;
  identityAttributes: IdentityAttributes;
  lastIdPath: string;
}

interface MemberIdentity {
  name: string;
  description: string;
  derivedPrivateKey: string;
  address: string;
  identityAttributes: IdentityAttributes;
  identityKey: string;
}
```

### Backup Types

```typescript
// Type 42 format
interface BapMasterBackup {
  ids: string;       // Encrypted identity data
  rootPk: string;    // WIF format private key
  label?: string;    // Optional label
  createdAt: string; // ISO timestamp
}

// Legacy BIP32 format
interface BapMasterBackup {
  ids: string;       // Encrypted identity data
  xprv: string;      // Extended private key
  mnemonic: string;  // BIP39 mnemonic
  label?: string;    // Optional label
  createdAt: string; // ISO timestamp
}

interface BapMemberBackup {
  wif: string;       // WIF private key
  id: string;        // Encrypted member data
  label?: string;    // Optional label
  createdAt: string; // ISO timestamp
}
```

### API Types

```typescript
interface AttestationResult {
  type: string;
  hash: string;
  sequence: string;
  signingProtocol: string;
  signingAddress: string;
  signature: string;
  data?: string;
  verified?: boolean;
}
```

## Key Derivation

### BIP32 Mode (Legacy)

Uses hierarchical deterministic key derivation:

```
m/424150'/0'/0'/[identity]/[key]/[index]
```

### Type 42 Mode (Recommended)

Uses simple counter-based derivation with meaningful names:

```typescript
// Invoice numbers: "bap:0", "bap:1", "bap:2", etc.
const work = bap.newId("Work Identity");     // Uses bap:0
const personal = bap.newId("Personal");      // Uses bap:1

// Derivation uses counter as invoice number
derivedKey = masterKey.deriveChild(
  masterKey.toPublicKey(),
  "bap:0"  // Simple counter format
);

// Names are stored separately for UX
identity.idName = "Work Identity";  // Human-readable name
identity.rootPath = "bap:0";        // Cryptographic derivation path
```

**Discovery**: Sequential counters enable systematic identity recovery:

```typescript
// Find all identities by checking counters
for (let i = 0; i < 100; i++) {
  const identity = bap.newIdWithCounter(i);
  if (await blockchainHasActivity(identity.getIdentityKey())) {
    console.log(`Found identity: ${identity.idName}`);
  }
}
```

### Encryption Keys

Each identity has a unique encryption key:

```
BIP32: rootPath → m/424150'/2147483647'/2147483647'
Type 42: rootKey → deriveChild(rootPk.pubKey, path)
```

## Usage Examples

### Complete Identity Creation Flow

```typescript
import { BAP } from 'bsv-bap';
import { PrivateKey } from '@bsv/sdk';

// Create BAP instance (Type 42)
const rootKey = PrivateKey.fromRandom();
const bap = new BAP({
  rootPk: rootKey.toWif()
});

// Create identity
const identity = bap.newId();
identity.idName = "Professional Identity";
identity.description = "My verified professional identity";

// Set attributes
identity.setAttribute('name', 'John Smith');
identity.setAttribute('title', 'Software Engineer');
identity.setAttribute('company', 'Bitcoin Corp');

// Get attestation for verification
const nameHash = identity.getAttestationHash('name');
console.log('Name attestation hash:', nameHash);

// Create ID transaction
const idTx = identity.getInitialIdTransaction();
// Broadcast idTx to Bitcoin network...

// Export for backup
const backup = bap.exportForBackup('Main Identity');
// Save backup securely...
```

### Attestation Workflow

```typescript
// Company attests to employee identity
const companyBap = new BAP(companyXprv);
const companyId = companyBap.getId(companyIdKey);

// Create attestation
const attestation = companyBap.signAttestationWithAIP(
  employeeNameHash,
  companyIdKey,
  0,  // sequence
  JSON.stringify({ 
    verified: true,
    role: 'Senior Engineer',
    date: new Date().toISOString()
  })
);

// Verify attestation
const result = await companyBap.verifyAttestationWithAIP(attestation);
console.log('Attestation valid:', result.verified);
```

### Encrypted Communication

```typescript
// Alice encrypts message for Bob
const alice = bap.getId(aliceIdKey);
const bobPublicKey = await getBobsPublicKey();

const encrypted = alice.encrypt(
  'Secret message for Bob',
  bobPublicKey
);

// Bob decrypts message
const bob = bobBap.getId(bobIdKey);
const alicePublicKey = await getAlicesPublicKey();

const decrypted = bob.decrypt(
  encrypted,
  alicePublicKey
);
```

### Member Identity

```typescript
// Create standalone member identity
const memberKey = PrivateKey.fromRandom();
const member = new MemberID(memberKey);

member.idName = "Forum Member";
member.setAttribute('username', 'satoshi2024');

// Sign a message
const { address, signature } = member.signMessage(
  Buffer.from('I approve this message')
);

// Export for sharing
const memberBackup = member.exportForBackup('Forum Identity');
```

## Migration Guide

### From BIP32 to Type 42

```typescript
// Export from BIP32
const oldBap = new BAP(xprv);
const backup = oldBap.exportForBackup();

// Extract root key
const hdKey = HD.fromString(xprv);
const rootWif = hdKey.privKey.toWif();

// Create Type 42 instance
const newBap = new BAP({
  rootPk: rootWif
});

// Create new identity and link to old
const newId = newBap.newId();
// Create ID transaction pointing from last old address to new...
```

See [Type 42 Migration Guide](../docs/TYPE42_MIGRATION.md) for complete details.

## Best Practices

1. **Key Security**: Never expose private keys. Use encryption for all exports.
2. **Attribute Nonces**: Always use random nonces for attributes to prevent dictionary attacks.
3. **Path Management**: Let the library manage paths unless you have specific requirements.
4. **Backup Regularly**: Export and securely store identity backups.
5. **Verify Attestations**: Always verify attestations before trusting identity claims.

## Error Handling

```typescript
try {
  const identity = bap.getId(idKey);
  if (!identity) {
    throw new Error('Identity not found');
  }
  
  const encrypted = identity.encrypt(data);
} catch (error) {
  if (error.message.includes('not initialized')) {
    // Handle key initialization errors
  } else if (error.message.includes('not found')) {
    // Handle missing identity
  }
}
```

## API Reference

For protocol-level documentation, see [PROTOCOL.md](../PROTOCOL.md).

For blockchain API endpoints, see the [BAP API Documentation](https://api.sigmaidentity.com/docs).