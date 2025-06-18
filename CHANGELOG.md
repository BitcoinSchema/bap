# Changelog


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
