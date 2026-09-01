# BAP Library Documentation

> API reference for bsv-bap 0.2.0

See the [main README](../README.md) for full documentation including installation, CLI usage, migration guide, and architecture overview.

This file covers the internal API surface for contributors.

## BAP Class

```typescript
class BAP {
  constructor(keySource: string | { rootPk: string }, token?: string, server?: string)

  // Identity CRUD
  newId(customPath?: string, idSeed?: string): MasterID
  newIdWithCounter(counter: number): MasterID
  getId(bapId: string): MasterID | null
  listIds(): string[]
  removeId(bapId: string): void
  checkIdBelongs(id: MasterID): boolean

  // Import/Export
  exportIds(idKeys?: string[], encrypted?: boolean): string | Identities
  exportId(idKey: string, encrypted?: boolean): string | Identities
  importIds(identities: string | Identities, encrypted?: boolean): void
  importOldIds(idData: OldIdentity[]): void
  exportForBackup(label?: string, xprv?: string, mnemonic?: string): Type42MasterBackup | Bip32MasterBackup

  // Master-level crypto
  encrypt(data: string): string
  decrypt(data: string): string
  verifySignature(message: string | number[], address: string, signature: string): boolean
  verifyAttestationWithAIP(tx: number[][]): Attestation

  // API (async)
  getIdentity(idKey: string): Promise<GetIdentityResponse>
  getIdentityFromAddress(address: string): Promise<GetIdentityByAddressResponse>
  getAttestationsForHash(hash: string): Promise<GetAttestationResponse>
  verifyChallengeSignature(idKey: string, address: string, challenge: string, signature: string): Promise<boolean>
  isValidAttestationTransaction(tx: number[][]): Promise<AttestationValidResponse | false>

  // Config
  BAP_SERVER: string
  BAP_TOKEN: string
  getPublicKey(childPath?: string): string
  getHdPublicKey(childPath?: string): string  // BIP32 only
}
```

## MasterID Class

```typescript
class MasterID {
  bapId: string
  rootAddress: string
  rootPath: string       // getter/setter
  currentPath: string    // getter/setter
  previousPath: string   // getter
  idSeed: string         // getter

  getAccountKey(): PrivateKey
  export(): Identity
  import(identity: Identity | OldIdentity): void
  exportAccountBackup(): BapAccountBackup
  validatePath(path: string): boolean  // BIP32 only
}
```

## Types

```typescript
interface Identity {
  bapId: string
  rootPath: string
  rootAddress: string
  currentPath: string
  previousPath: string
  lastIdPath: string
  idSeed: string
}

interface BapAccountBackup {
  wif: string  // Account private key in WIF
  id: string   // BAP ID
}

interface Type42MasterBackup {
  ids: string
  rootPk: string
  mnemonic?: string
  label?: string
  createdAt: string
}

interface Bip32MasterBackup {
  ids: string
  xprv: string
  mnemonic?: string
  label?: string
  createdAt: string
}
```

## Exported Utilities

```typescript
function bapIdFromAddress(address: string): string
function bapIdFromPubkey(pubkeyHex: string): string
```
