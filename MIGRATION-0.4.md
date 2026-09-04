# bsv-bap 0.4 parity and release-stop ledger

**Status: planning only. 0.4 is not implemented. Do not ship.**

This is the authoritative migration ledger for a clean-break `bsv-bap` 0.4
release. Current published package is **0.3.7**. This document exists so a
0.4 cut cannot silently drop 0.1 capabilities.

0.4 **must not ship** until every **release-blocking** row below has either:

1. an implemented public replacement, or
2. an explicit product decision to retire the capability.

Three gaps have **no public replacement today** and are therefore hard stops:

- **attestation lookup** by attribute/hash
- attestation transaction **overlay validity**
- public master-level **arbitrary-data encryption** (`BAP.encrypt` / `BAP.decrypt`)

This PR is documentation. It does not change runtime code, versions, or
package contents. It does not claim the 0.4 migration is ready.

## Architecture: clean break, no shims

The target is a **clean 0.4 API**, not a compatibility wrapper around
`@1sat/client`.

Promised: none of the following.

- overloads that keep 0.1 / 0.3 call shapes
- aliases for removed methods
- a transport facade over the old `BAP` class
- any backward-compatibility shim

There is **no backward compatibility** contract from 0.1 or 0.3.7 into 0.4.
Consumers convert on **0.3.7** (legacy backup recompute, account export,
label inventory) and then adopt the new surfaces. Social APIs are
ticketed/deferred and are **out of this migration PR**.

## Disposition legend

Every 0.1 capability has exactly one disposition:

| Disposition | Meaning |
| --- | --- |
| **retained** | Survives in 0.4 under a clean, explicit API. |
| **replaced** | 0.1 method goes away; a named 0.4 / 1Sat successor is the path. |
| **retired** | Dropped. Convert on 0.3.7 before upgrading. |
| **release-blocking** | 0.4 cannot ship until a replacement exists or product retires it. |

## Capability ledger

| 0.1 capability | Disposition | 0.4 path |
| --- | --- | --- |
| Master identity creation, selection, removal (`newId` / `getId` / `listIds` / `removeId` / `setId` / `checkIdBelongs`) | **retained** | Future explicit `BAP` key-source API. Not a positional label. |
| Type42 and BIP32 key sources | **retained** | `{ rootPk }` and `{ xprv }` only. No WIF-as-HD. |
| Old backup import and legacy id recomputation (`importOldIds`, `isLegacyIdsExport`, `recomputeLegacyIds`) | **retired** | Users convert with **0.3.7** before upgrading. 0.4 will not recompute pre-0.3 backups. |
| Current-format master/account backup produced by 0.3.7 | **retired** as a 0.4 import path | Convert on 0.3.7; 0.4 reads the post-conversion key source, not historical blob formats. |
| `MemberID` construction and restoration (`exportMemberBackup`, member WIF round-trip, `getCurrentKey` / `getSigningKey`) | **replaced** | Wallet-managed identities or account backup (`{ wif, id }` on 0.3.7, then wallet ownership). |
| Names, descriptions, attribute CRUD, URNs (`idName`, `setAttribute`, `getAttribute`, attestation URNs) | **replaced** | BAP profile, or application-owned claim preparation. Not in-library attribute maps. |
| Initial identity and rotation builders (`getInitialIdTransaction`, `incrementPath`, `rotate`, `getLegacyRotationTransaction`) | **replaced** | `publishIdentity` / `rotateIdentity` (1Sat actions). |
| BSM, BAP/AIP, and OP_RETURN signing (`signMessage`, `signWithBSM` / `signBsm`, `signWithBap`, `signOpReturnWithAIP`) | **replaced** | Tested 1Sat actions/templates. See release stops: `signBsm` and `signWithBap` need real BSM round-trip proof. |
| Seeded and counterparty / friend encryption (`encryptWithSeed`, `getEncryptionKeyWithSeed`, BRC-43 friend keys) | **replaced** | 1Sat counterparty helpers. Does not replace public master-level arbitrary-data encrypt/decrypt. |
| Standalone identity-state import/export (`exportIds` / `importIds`, encrypted or plain) | **release-blocking** | **No verified 0.4 replacement.** Before release, wallet/account backup must demonstrably preserve every current identity, derivation path, seed, and counter needed to restore the same state, or product must explicitly retire this portability surface. |
| ECIES encoding used by the encrypted `exportIds` format | **retired** | This historical blob encoding does not survive merely to preserve a file format. Retiring the encoding does not retire identity-state portability, which remains separately release-blocking above. Distinct from public arbitrary-data encrypt/decrypt. |
| Public master-level arbitrary-data encryption (`BAP.encrypt` / `BAP.decrypt`, CLI `bap encrypt` / `bap decrypt`) | **release-blocking** | **No public replacement.** This is generic ECIES of caller data, not backup wrapping. Inspected 1Sat counterparty helpers and vault encrypt/decrypt are not this surface. 0.4 must not ship until a public replacement exists or product explicitly retires it. |
| Attestation creation and publication | **replaced** | `attest` and templates. |
| Raw BAP/AIP decoding (`verifyAttestationWithAIP` and related OP_RETURN parse) | **replaced** | BitCom / BAP / AIP decoders. Golden vectors are required before this counts as done. |
| Identity lookup (`getIdentity`) | **replaced** | `BapClient.getIdentity`. |
| Address validity (`getIdentityFromAddress` / `/identity/validByAddress`) | **replaced** | `BapClient.validByAddress`. |
| Signing-key history (`getSigningKeys` and address/sequence/revocation fields) | **release-blocking** | No 0.4 ship until reduced fields are accepted or the full history is expanded in the public client. |
| Challenge verification (`verifyChallengeSignature`) | **replaced** | Compose local BSM verification, `validByAddress`, and matching `identity.idKey`. Do not keep the old `/attestation/valid` challenge wrapper. |
| Attestation lookup by attribute/hash (`getAttestationsForHash`, CLI `bap attestations`) | **release-blocking** | **No public replacement.** 0.4 must not ship until one is implemented or product explicitly retires lookup. |
| Attestation transaction overlay validity (`isValidAttestationTransaction`) | **release-blocking** | **No public replacement.** 0.4 must not ship until overlay validity is implemented or product explicitly retires it. |
| Protocol constants and ID utilities (`BAP_BITCOM_ADDRESS`, `AIP_BITCOM_ADDRESS`, `bapIdFromAddress`, `bapIdFromPubkey`) | **retained** | Only when not already owned by templates/actions. Do not fork `BAP_PROTOCOL_ID` / `BAP_KEY_ID` if `@1sat/actions` already owns them. |
| `BAP_SERVER` / `BAP_TOKEN` and `api.sigmaidentity.com` | **retired** | No legacy response wrappers. No dependency on `api.sigmaidentity.com`. Overlay access is `BapClient` against the 1Sat BAP API. |
| Positional `newId(string)` as a human label | **retired** | No active consumer may pass a label to positional `newId(string)`. Labels are application-owned. |

## Release-blocking gaps

These are maintainer alerts, not backlog trivia. A green build on 0.3.7 does
not clear them.

### Attestation lookup by attribute/hash — no public replacement

0.1 exposes `BAP.getAttestationsForHash(hash)` (and the CLI `bap attestations
<hash>` command) against `/attestations`. 0.4 has no public `BapClient`
equivalent for **attestation lookup**. Shipping without it, or without an
explicit product decision to retire it, is a silent capability loss.

### Attestation transaction overlay validity — no public replacement

0.1 exposes `BAP.isValidAttestationTransaction(tx)`, which locally parses a
BAP/AIP OP_RETURN then asks the overlay `/attestation/valid`. 0.4 has no
public replacement for that **overlay validity** check. Same rule: implement
a replacement or retire it in writing before any 0.4 release.

### Public master-level arbitrary-data encryption — no public replacement

0.1 / 0.3.7 expose `BAP.encrypt` / `BAP.decrypt` (and CLI `bap encrypt` /
`bap decrypt`) as public ECIES of arbitrary caller data under the master
key. That is not the backup identity-blob wrap used by `exportIds` /
`importIds`. 0.4 has no public replacement for this surface. 1Sat
counterparty helpers replace seeded/friend encryption only; inspected
vault encrypt/decrypt is hardware-backed secret storage, not this API.
Shipping without a replacement, or without an explicit product decision to
retire it, is a silent capability loss.

### Standalone identity-state import/export — replacement unproven

0.1 / 0.3.7 expose `exportIds` / `importIds` as standalone encrypted or plain
identity-state portability, separate from `exportForBackup`. A 0.4 wallet or
account-backup replacement must prove that it restores every identity,
derivation path, seed, and counter needed to reproduce the same state. Until
that proof exists—or product explicitly retires the capability—0.4 remains
blocked. The historical encrypted-blob encoding itself may be retired without
pretending the portability capability was backup-only.

### Signing-key history

Signing-key history is **release-blocking** until reduced fields are accepted
or the public client expands to the full 0.1 field set (idKey, signing
address, sequence, block, txId, timestamp, revoked). Do not ship a partial
history and call the capability replaced.

## Additional release stops

None of these are optional polish. 0.4 stays blocked while any remain.

- `BapClient.listProfiles` is typed differently from the server response and
  needs contract tests.
- `signBsm` and `signWithBap` need real BSM round-trip proof; no skipped
  test.
- CLI tests currently run from a temporary home and resolve the wrong
  repository path, so they are not trustworthy until fixed. (Known 0.3.7
  baseline: 41 CLI failures from that path bug. Do not conceal them.)
- Sigma Auth Type42 and BIP32 recovery canaries must pass.
- Wallet Desktop must stop passing a WIF string as an HD key.
- No active consumer may pass a label to positional `newId(string)`.
- ESM, CommonJS, declarations, package contents, and any retained CLI must
  be verified.
- No legacy response wrappers or dependency on `api.sigmaidentity.com` may
  remain.

## Proposed 0.4 interfaces (not implemented)

The shapes below are **planning material**. This PR does not implement them.
Do not import them; they are not on the 0.3.7 public API.

```ts
type BapKeySource = { rootPk: string } | { xprv: string };
interface NewIdentityOptions { path?: string; idSeed?: string }
```

Intended use:

```ts
// proposed — not implemented
const bap = new BAP({ rootPk }); // Type42
const bap = new BAP({ xprv });   // BIP32; never a bare WIF string as HD

const identity = bap.newId();                          // next path / counter
const identity = bap.newId({ path: "bap:3" });         // explicit path
const identity = bap.newId({ idSeed: "deterministic" });
```

`newId` does not take a label. `BAP` in 0.4 is a key source plus identity
selection, not a wallet, not a signer, and not an overlay client. Overlay
reads go through `BapClient`. Signing, attestation, publication, and
rotation go through 1Sat actions/templates.

## Consumer-canary order

Prove 0.4 against live consumers in this order. Do not skip ahead.

1. Sigma Auth
2. 1Sat Wallet Desktop
3. Sigma Auth Web examples
4. Clawnet
5. Owner-classified older consumers

A canary is not “it compiles.” Type42 and BIP32 recovery must pass on Sigma
Auth. Wallet Desktop must not pass a WIF as an HD key. No remaining caller
may use positional `newId(string)` as a label.

## What 0.3.7 users do now

Stay on **0.3.7** until the release-blocking rows close.

1. Recompute any pre-0.3 backup with `isLegacyIdsExport` /
   `recomputeLegacyIds` and re-export.
2. Inventory labels; they will not be in 0.4.
3. Move attribute/profile data out of the library.
4. Prefer `exportAccountBackup()` / wallet-managed identities over
   `MemberID`.
5. Stop calling positional `newId("My Identity")`.

Do not treat this file as a 0.4 changelog. The 0.3.7 README remains the
usage guide for the published package.
