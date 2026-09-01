/**
 * Tests for legacy (<= 0.2.x) export detection and recompute.
 *
 * 0.3.0 changed Identity.rootAddress to the BRC-100 identity-0 derivation —
 * a deliberate, fully breaking change. importIds stays strict (old exports
 * throw). recomputeLegacyIds is the explicit opt-in path: verify an export
 * against the legacy formula, then re-derive the same paths under the
 * current scheme (same keys, NEW bapIds) so callers can reissue the backup.
 */

import { describe, expect, test } from "bun:test";
import { Utils as BSVUtils, Hash, HD, Mnemonic, PrivateKey } from "@bsv/sdk";
import { BAP } from "../src/index";
import { bapIdFromAddress } from "../src/utils";

const ROOT_PATH = "bap:0";

/** Legacy (0.2.x) Type 42 rootAddress: address of the derived key itself. */
function legacyType42Address(
  pk: PrivateKey,
  rootPath: string,
  idSeed = ""
): string {
  let base = pk;
  if (idSeed) {
    const seedHex = BSVUtils.toHex(Hash.sha256(idSeed, "utf8"));
    base = base.deriveChild(base.toPublicKey(), seedHex);
  }
  return base
    .deriveChild(base.toPublicKey(), rootPath)
    .toPublicKey()
    .toAddress();
}

function makeLegacyType42Entry(pk: PrivateKey, idSeed = "") {
  const rootAddress = legacyType42Address(pk, ROOT_PATH, idSeed);
  return {
    bapId: bapIdFromAddress(rootAddress),
    rootPath: ROOT_PATH,
    rootAddress,
    currentPath: ROOT_PATH,
    previousPath: ROOT_PATH,
    idSeed,
    lastIdPath: "",
  };
}

function freshType42(): { wif: string; pk: PrivateKey } {
  const pk = PrivateKey.fromRandom();
  return { wif: pk.toWif(), pk };
}

describe("legacy export detection and recompute (Type 42)", () => {
  test("importIds stays strict: a legacy export throws", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);
    const bap = new BAP({ rootPk: wif });

    expect(() =>
      bap.importIds({ lastIdPath: ROOT_PATH, ids: [entry] }, false)
    ).toThrow("ID does not belong to this private key");
  });

  test("isLegacyIdsExport: true for legacy, false for current and wrong-key", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);

    const bap = new BAP({ rootPk: wif });
    expect(bap.isLegacyIdsExport({ lastIdPath: ROOT_PATH, ids: [entry] })).toBe(
      true
    );

    // Current-format export is NOT legacy.
    const current = new BAP({ rootPk: wif });
    current.newId();
    expect(bap.isLegacyIdsExport(current.exportIds(undefined, false))).toBe(
      false
    );

    // A legacy export from a DIFFERENT key is not "legacy for this key".
    const stranger = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    expect(
      stranger.isLegacyIdsExport({ lastIdPath: ROOT_PATH, ids: [entry] })
    ).toBe(false);
  });

  test("recomputes a legacy Identities object: same path, new bapId", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);

    const reference = new BAP({ rootPk: wif });
    const expectedNewBapId = reference.newId(ROOT_PATH).bapId;

    const bap = new BAP({ rootPk: wif });
    const recomputed = bap.recomputeLegacyIds({
      lastIdPath: ROOT_PATH,
      ids: [entry],
    });

    expect(recomputed).toHaveLength(1);
    expect(recomputed[0].oldBapId).toBe(entry.bapId);
    expect(recomputed[0].newBapId).toBe(expectedNewBapId);
    expect(recomputed[0].newBapId).not.toBe(entry.bapId);
    expect(recomputed[0].rootPath).toBe(ROOT_PATH);
    expect(bap.listIds()).toContain(expectedNewBapId);
  });

  test("recomputes an encrypted legacy payload (string ids field)", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);

    // Encryption derivation is unchanged across 0.2.x -> 0.3.x, so a payload
    // encrypted with the same root key round-trips.
    const cryptoBap = new BAP({ rootPk: wif });
    const encrypted = cryptoBap.encrypt(
      JSON.stringify({ lastIdPath: ROOT_PATH, ids: [entry] })
    );

    const bap = new BAP({ rootPk: wif });
    const recomputed = bap.recomputeLegacyIds(encrypted);
    expect(recomputed).toHaveLength(1);
    expect(bap.listIds()).toContain(recomputed[0].newBapId);
  });

  test("recomputes the old-old array format (identityKey entries)", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);
    const oldFormat = [
      {
        identityKey: entry.bapId,
        rootPath: entry.rootPath,
        rootAddress: entry.rootAddress,
        currentPath: entry.currentPath,
        previousPath: entry.previousPath,
        idSeed: entry.idSeed,
      },
    ];

    const bap = new BAP({ rootPk: wif });
    const recomputed = bap.recomputeLegacyIds(oldFormat);
    expect(recomputed).toHaveLength(1);
    expect(recomputed[0].oldBapId).toBe(entry.bapId);
  });

  test("handles idSeed entries (seeded legacy derivation)", () => {
    const { wif, pk } = freshType42();
    const seed = "my-test-seed";
    const entry = makeLegacyType42Entry(pk, seed);

    const reference = new BAP({ rootPk: wif });
    const expectedNewBapId = reference.newId(ROOT_PATH, seed).bapId;

    const bap = new BAP({ rootPk: wif });
    const recomputed = bap.recomputeLegacyIds({
      lastIdPath: ROOT_PATH,
      ids: [entry],
    });
    expect(recomputed[0].newBapId).toBe(expectedNewBapId);
  });

  test("after recompute, a fresh newId() does not collide", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);

    const bap = new BAP({ rootPk: wif });
    const recomputed = bap.recomputeLegacyIds({
      lastIdPath: ROOT_PATH,
      ids: [entry],
    });

    const before = bap.listIds().length;
    const fresh = bap.newId();
    expect(fresh.bapId).not.toBe(recomputed[0].newBapId);
    expect(bap.listIds().length).toBe(before + 1);
  });

  test("wrong key: recomputeLegacyIds throws, never silently accepts", () => {
    const { pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);

    const stranger = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    expect(() =>
      stranger.recomputeLegacyIds({ lastIdPath: ROOT_PATH, ids: [entry] })
    ).toThrow("ID does not belong to this private key");
  });
});

describe("legacy export recompute (HD / xprv)", () => {
  test("recomputes a legacy HD export at its original signing path", () => {
    const hd = HD.fromSeed(Mnemonic.fromRandom().toSeed());
    const xprv = hd.toString();
    const rootPath = "m/424150'/0'/0'/0'/0'/0'";

    // Legacy (0.2.x) HD rootAddress: address of the key derived at the
    // signing path, no identity-0 child derivation.
    const rootAddress = hd.derive(rootPath).pubKey.toAddress();
    const entry = {
      bapId: bapIdFromAddress(rootAddress),
      rootPath,
      rootAddress,
      currentPath: rootPath,
      previousPath: rootPath,
      idSeed: "",
      lastIdPath: "",
    };

    const bap = new BAP(xprv);
    expect(bap.isLegacyIdsExport({ lastIdPath: rootPath, ids: [entry] })).toBe(
      true
    );

    const recomputed = bap.recomputeLegacyIds({
      lastIdPath: rootPath,
      ids: [entry],
    });
    expect(recomputed).toHaveLength(1);
    expect(recomputed[0].newBapId).not.toBe(entry.bapId);
    expect(bap.listIds()).toContain(recomputed[0].newBapId);
  });
});
