# Changelog

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
