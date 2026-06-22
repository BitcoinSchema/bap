# Changelog

## [0.3.3] - 2026-06-22

### Changed
- **Migrated Touch ID to the provider-based `@1sat/vault` (>=0.0.6 architecture).** `@1sat/vault` `0.0.3` → `^0.0.8` (platform-agnostic vault interface) plus new `@1sat/wallet-mac` `^0.0.5` dependency (`SecureEnclaveProvider`), wired via `createVault(provider, FileVaultStorage)`. `trustedDependencies` updated from `@1sat/vault` to `@1sat/wallet-mac` (the package that now compiles the Secure Enclave binary on install). Vault entry location (`~/.secure-enclave-vault/bap-master.vault.json`) and the `se:bap-master` config sentinel are unchanged.

## [0.3.2] - 2026-06-12

### Added
- `BAP.isLegacyIdsExport(ids)` — detects a pre-0.3 ids export: returns true only when every entry's stored `rootAddress` matches the legacy (<= 0.2.x) derivation for this key. Returns false for current-format exports and for exports belonging to a different key.
- `BAP.recomputeLegacyIds(ids)` — explicit opt-in recovery path for old backup files. Verifies each entry against the legacy formula (wrong-key exports still throw `"ID does not belong to this private key"`), then re-derives the identity at its original `rootPath`/`idSeed` under the current BRC-100 identity-0 scheme. Same underlying keys, NEW bapIds; returns the old→new `LegacyIdRecompute[]` mapping. Callers must `exportIds()` and reissue the backup file — the legacy export is obsolete afterward. Supports Type 42 (`rootPk`), BIP32 (`xprv`), encrypted-string payloads, the pre-0.2 array format, and seeded (`idSeed`) identities. `importIds` remains strict: 0.3.0's derivation change is intentionally not backward compatible.
- `LegacyIdRecompute` type exported from the package root.

### Fixed
- CLI `--version` reported `0.2.0` since the 0.3.x releases (hardcoded constant and hardcoded test). The version test now reads `package.json` so drift fails in CI.


## [0.3.1] - 2026-05-22

### Fixed
- `MasterID.getAccountKey()` now returns the per-identity member key (`master.deriveChild(masterPub, rootPath)` for Type 42, `HD.derive(rootPath).privKey` for BIP32) instead of the unmodified master/HD root. Previously every identity returned the same master key, so consumers building BRC-100 wallets from `exportAccountBackup().wif` ended up with the same wallet root across all identities — and that wallet root didn't match what bsv-bap used internally to compute `bapId`, producing different bapIds on the wallet and identity sides.

## [0.3.0] - 2026-05-22

### Changed
- **Breaking:** `MasterID.rootAddress` now derives from the BRC-100 wallet's `identity-0` key (protocolID `[1, "sigma"]`, keyID `"identity-0"`, counterparty `self`, forSelf=true) instead of from the raw wallet-root address. `bapId` consequently changes for every identity. Aligns with `@1sat/actions` `computeBapId`, which BRC-100 wallets use when publishing — previously the two sides disagreed on what address to hash, producing different bapIds for the same identity.
- `BAP.checkIdBelongs` updated to use the new derivation.

### Added
- `BAP_PROTOCOL_ID = [1, "sigma"]` and `BAP_KEY_ID = "identity"` constants.
- `deriveIdentity0Address(walletRoot)` helper in `src/utils.ts`.

## [0.2.0] - 2026-03-16

### Breaking Changes
- `MemberID` class removed — use `identity.exportAccountBackup()` for account-level backup
- `identity.identityKey` renamed to `identity.bapId`
- `identity.getIdentityKey()` removed — use `identity.bapId` property
- `identity.idName` removed — use external labels
- `identity.setAttribute()` and all attribute methods removed from core
- `identity.signMessage()` removed — signing delegated to wallet
- `identity.encrypt/decrypt()` removed from MasterID — use `bap.encrypt/decrypt()` for master-level
- `identity.getEncryptionPublicKey()` removed
- `identity.getCurrentAddress()` removed — use `identity.getAccountKey()`
- `exportMemberBackup()` renamed to `exportAccountBackup()` (returns `{ wif, id }`)

### Added
- `MasterID.exportAccountBackup()` — returns `{ wif, id }` for account-level backup
- `BapAccountBackup` interface exported from package
- CLI rewrite with commander.js — 16 commands covering identity CRUD, backup, crypto, API lookups, utilities
- Multi-identity CLI support with active identity concept (`bap use <bapId>`)
- CLI storage at `~/.bap/` with `identity.json` and `active` file
- Comprehensive CLI test suite (41 tests)
- Header/social share image

### Changed
- Default BAP API server switched to `https://api.1sat.app/1sat/bap`
- README rewritten with 0.2.0 API reference, CLI docs, migration guide from 0.1.x
- `src/README.md` condensed to contributor API reference

### Fixed
- CLI `loadBAP()` now correctly detects BIP32 (xprv) vs Type42 (WIF) key format
- CLI `verify` command catches invalid signature format instead of crashing

## [0.2.0-alpha.0] - 2026-03-13

### Changed
- **Breaking:** BAP library redesigned around identity lifecycle only. Signing, encryption, rotation, and profile management delegated to BRC-100 wallet.
- `MemberID` replaced by `AccountID` — holds account key, signs create/revoke transactions only
- `MasterID` stripped to account derivation and backup serialization — no signing, no encryption, no attributes
- `BaseClass` stripped to BSM signing and AIP formatting — no encryption methods
- `identityKey` renamed to `bapId` throughout
- `Identity` interface reduced to path/address fields — attributes stored in wallet
- `newId()` simplified — no longer accepts identity attributes

### Removed
- `MemberID` class (replaced by `AccountID`)
- `MemberIdentity` interface
- Signing key derivation (`BAP_INVOICE_NUMBER`, `BAP_KEY_ID`, `BAP_PROTOCOL_ID`)
- Encryption methods on `BaseClass` and `MasterID` (master-level encrypt/decrypt for backup blob retained on BAP class)
- `ENCRYPTION_PATH` derivation on identity level
- `incrementPath()`, `rotate()`, counter management
- `exportMember()`, `exportForBackup()`, `fromBackup()` on identity level
- `exportMemberForBackup()` on BAP class
- All friend encryption methods
- Attribute management on `MasterID` (moved to wallet)

### Added
- `AccountID` class: `getBapId()`, `getRootAddress()`, `getRootPublicKey()`, `getInitialIdTransaction()`, `getRevocationTransaction()`
- `BAP.getAccountId(bapId)` — creates AccountID from master-derived account key

## [0.1.24] - 2026-03-13

### Changed
- **Breaking:** `BAP_PROTOCOL_ID` changed from `[1, "bap"]` to `[1, "sigma"]`; `BAP_INVOICE_NUMBER` from `"1-bap-identity"` to `"1-sigma-identity"`
- `MemberID` now uses counter-based two-level key derivation: member → `bap:{counter}` → `1-sigma-identity`
- `MasterID.exportMemberBackup()` includes `counter` and computes address using two-level derivation
- Renamed `MemberID.getLegacyAddress()` to `getRootAddress()`
- Renamed internal `getIdentitySigningKey()` to public `getSigningKey()`

### Added
- `MemberID.getCurrentKey()` — derives BRC-100 wallet root from member key via counter
- `MemberID.getSigningKey()` — derives signing key from current key
- `MemberID.signMessageWithRootKey()` / `signOpReturnWithAIPUsingRootKey()` — sign with member key directly (for identity publication)
- `MemberID.rotate()` — increments counter, updates signing address
- `MemberID.getCounter()` — accessor for rotation counter
- `counter` field on `MemberIdentity` interface

## [0.1.23] - 2026-03-08

### Added
- Explicit wallet-root APIs on `MasterID`: `getWalletRoot()` and `getWalletPubkey()`
- Regression coverage for Type 42 wallet rotation, stable member keys, and export/import round-trips

### Fixed
- Type 42 rotation paths now preserve the identity prefix during rotation (`bap:0 -> bap:0:1 -> bap:0:2`)
- `getMemberKey()` now consistently returns the stable member key at `rootPath`
- Legacy malformed Type 42 rotation paths stored as bare numbers (`"1"`, `"2"`) continue rotating for backward compatibility

### Documentation
- Clarified the Type 42 hierarchy: `rootPath` defines the stable BAP identity and `currentPath` defines the active wallet/signing root
- Documented wallet rotation semantics and the new wallet-root APIs across the public docs


## [0.1.21] - 2026-02-20

### Fixed
- `getIdentityFromAddress` now calls `/identity/validByAddress` endpoint (was `/identity/from-address`)

> Note: Skips 0.1.19 (unused) and 0.1.20 (retracted — incorrectly removed signing key derivation).


## [0.1.16] - 2026-01-16

### Fixed
- CLI now imports from `bsv-bap` package instead of relative path for proper global installation


## [0.1.15] - 2026-01-16

### Added
- CLI tool (`bap`) for command-line BAP operations: create, sign, verify, friend-pubkey, encrypt, decrypt, export, import, info
- BRC-43 constants for friend encryption: `FRIEND_SECURITY_LEVEL`, `FRIEND_PROTOCOL`

### Changed
- Friend key derivation now uses BRC-43 format: `2-friend-{sha256(friendBapId)}` instead of raw hash
- Updated `getEncryptionPrivateKeyWithSeed()` to use proper invoice number format


## [0.1.14] - 2026-01-13

### Added
- Identity signing key derivation using Type 42 (BRC-42) pattern for BRC-100 wallet compatibility
- Migration support for legacy identities: `getLegacyAddress()`, `needsRotation()`, `getLegacyRotationTransaction()`
- Seed-based encryption methods on MemberID: `encryptWithSeed()`, `decryptWithSeed()`, `getEncryptionKeyWithSeed()`
- Consolidated `signWithBSM()` helper in BaseClass

### Changed
- Signing keys now derived from member keys using `deriveChild(pubKey, "1-bap-identity")`
- Updated documentation with key hierarchy explanation


## [0.1.12] - 2025-06-18

### Added
- Exported all API types from root entry, so they can be imported directly from the package.

### Fixed
- Build now includes `apiTypes` definitions (`export * from './apiTypes'`).
- Minor linter clean-ups (`Number.parseInt`, `Number.isNaN`, trivial type removal).

### Chore
- Migrated to Biome v2 configuration.
- Lint to new standards


## [0.1.8] - 2025-05-06

### Fixed

- Corrected an issue where AIP OP_RETURN signing could add two pipe ('|') separators instead of one. Now correctly adds a single pipe separator before AIP protocol information.
- update dependencies


## [0.1.0] - 2025-02-03

### Breaking Changes

- Changed parameter order in `exportIds` function. New signature is `exportIds(idKeys?: string[], encrypted = true)` instead of `exportIds(encrypted = true, idKeys?: string[])`
- This change makes the parameter order consistent with other functions in the library like `exportId` and `importIds`

### Migration

Update any calls to `exportIds` to put the `idKeys` parameter first:

```javascript
// Old
bap.exportIds(true, ["key1", "key2"]);

// New
bap.exportIds(["key1", "key2"], true);
```
