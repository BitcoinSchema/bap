# Changelog


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
