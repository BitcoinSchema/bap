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
import { bapIdFromAddress, deriveIdentity0Address, Utils } from "../src/utils";

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

function makeLegacyType42Entry(
  pk: PrivateKey,
  idSeed = "",
  paths: {
    rootPath?: string;
    currentPath?: string;
    previousPath?: string;
  } = {}
) {
  const rootPath = paths.rootPath ?? ROOT_PATH;
  const rootAddress = legacyType42Address(pk, rootPath, idSeed);
  return {
    bapId: bapIdFromAddress(rootAddress),
    rootPath,
    rootAddress,
    currentPath: paths.currentPath ?? rootPath,
    previousPath: paths.previousPath ?? rootPath,
    idSeed,
    lastIdPath: "",
  };
}

function legacyHdAddress(hd: HD, rootPath: string, idSeed = ""): string {
  let base = hd;
  if (idSeed) {
    const seedHex = BSVUtils.toHex(Hash.sha256(idSeed, "utf8"));
    base = base.derive(Utils.getSigningPathFromHex(seedHex));
  }
  return base.derive(rootPath).pubKey.toAddress();
}

function hdAccountKey(hd: HD, rootPath: string, idSeed = ""): PrivateKey {
  let base = hd;
  if (idSeed) {
    const seedHex = BSVUtils.toHex(Hash.sha256(idSeed, "utf8"));
    base = base.derive(Utils.getSigningPathFromHex(seedHex));
  }
  return base.derive(rootPath).privKey;
}

function type42AccountKey(
  pk: PrivateKey,
  rootPath: string,
  idSeed = ""
): PrivateKey {
  let base = pk;
  if (idSeed) {
    const seedHex = BSVUtils.toHex(Hash.sha256(idSeed, "utf8"));
    base = base.deriveChild(base.toPublicKey(), seedHex);
  }
  return base.deriveChild(base.toPublicKey(), rootPath);
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
    expect(bap.getId(expectedNewBapId)?.export()).toMatchObject({
      rootPath: ROOT_PATH,
      previousPath: ROOT_PATH,
      currentPath: ROOT_PATH,
    });
  });

  test("preserves advanced Type 42 lineage, seed, account key, and root key exactly", () => {
    const { wif, pk } = freshType42();
    const idSeed = "legacy seed / keep byte-for-byte";
    const rootPath = "bap:7";
    const previousPath = "bap:7:3";
    const currentPath = "bap:7:4";
    const entry = makeLegacyType42Entry(pk, idSeed, {
      rootPath,
      previousPath,
      currentPath,
    });
    const source = { lastIdPath: rootPath, ids: [entry] };
    const sourceBytes = JSON.stringify(source);
    const originalAccountWif = type42AccountKey(pk, rootPath, idSeed).toWif();

    const bap = new BAP({ rootPk: wif });
    expect(bap.isLegacyIdsExport(source)).toBe(true);
    const [mapping] = bap.recomputeLegacyIds(source);
    const restored = bap.getId(mapping.newBapId);

    expect(mapping.oldBapId).toBe(entry.bapId);
    expect(mapping.newBapId).not.toBe(entry.bapId);
    expect(restored?.export()).toEqual({
      bapId: mapping.newBapId,
      rootPath,
      rootAddress: deriveIdentity0Address(
        type42AccountKey(pk, rootPath, idSeed)
      ),
      previousPath,
      currentPath,
      idSeed,
      lastIdPath: "",
    });
    expect(restored?.rootAddress).not.toBe(entry.rootAddress);
    expect(restored?.exportAccountBackup().wif).toBe(originalAccountWif);
    expect(bap.exportIds(undefined, false).lastIdPath).toBe(rootPath);
    expect(bap.exportForBackup()).toMatchObject({ rootPk: wif });
    expect(JSON.stringify(source)).toBe(sourceBytes);

    const reissuedIds = bap.exportIds(undefined, false);
    const reloaded = new BAP({ rootPk: wif });
    reloaded.importIds(reissuedIds, false);
    expect(reloaded.getId(mapping.newBapId)?.export()).toEqual(
      restored?.export()
    );
  });

  test("preserves the historically supported numeric Type 42 lineage namespace", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk, "", {
      previousPath: "4",
      currentPath: "5",
    });
    const bap = new BAP({ rootPk: wif });

    const [mapping] = bap.recomputeLegacyIds({
      lastIdPath: ROOT_PATH,
      ids: [entry],
    });
    expect(bap.getId(mapping.newBapId)?.export()).toMatchObject({
      rootPath: ROOT_PATH,
      previousPath: "4",
      currentPath: "5",
    });
  });

  test("accepts the historical first numeric rotation for a nonzero identity index", () => {
    const { wif, pk } = freshType42();
    const rootPath = "bap:7";
    const entry = makeLegacyType42Entry(pk, "", {
      rootPath,
      previousPath: rootPath,
      currentPath: "8",
    });
    const bap = new BAP({ rootPk: wif });

    const [mapping] = bap.recomputeLegacyIds({
      lastIdPath: rootPath,
      ids: [entry],
    });
    expect(bap.getId(mapping.newBapId)?.export()).toMatchObject({
      rootPath,
      previousPath: rootPath,
      currentPath: "8",
    });
  });

  test("accepts an advanced historical numeric lineage after its valid nonzero start", () => {
    const { wif, pk } = freshType42();
    const rootPath = "bap:7";
    const entry = makeLegacyType42Entry(pk, "", {
      rootPath,
      previousPath: "10",
      currentPath: "11",
    });
    const bap = new BAP({ rootPk: wif });

    const [mapping] = bap.recomputeLegacyIds({
      lastIdPath: rootPath,
      ids: [entry],
    });
    expect(bap.getId(mapping.newBapId)?.export()).toMatchObject({
      rootPath,
      previousPath: "10",
      currentPath: "11",
    });
  });

  test("rejects numeric lineage before the historical start or with a skipped step", () => {
    const { wif, pk } = freshType42();
    const rootPath = "bap:7";
    const invalidEntries = [
      makeLegacyType42Entry(pk, "", {
        rootPath,
        previousPath: rootPath,
        currentPath: "1",
      }),
      makeLegacyType42Entry(pk, "", {
        rootPath,
        previousPath: "7",
        currentPath: "8",
      }),
      makeLegacyType42Entry(pk, "", {
        rootPath,
        previousPath: "8",
        currentPath: "10",
      }),
    ];

    for (const entry of invalidEntries) {
      const bap = new BAP({ rootPk: wif });
      const source = { lastIdPath: rootPath, ids: [entry] };
      expect(bap.isLegacyIdsExport(source)).toBe(false);
      expect(() => bap.recomputeLegacyIds(source)).toThrow(
        "impossible Type 42 lineage"
      );
      expect(bap.listIds()).toEqual([]);
    }
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

  test("the oldest array format may omit idSeed and preserves unrotated lineage", () => {
    const { wif, pk } = freshType42();
    const entry = makeLegacyType42Entry(pk);
    const oldFormat = [
      {
        identityKey: entry.bapId,
        rootPath: entry.rootPath,
        rootAddress: entry.rootAddress,
        currentPath: entry.currentPath,
        previousPath: entry.previousPath,
      },
    ];

    const bap = new BAP({ rootPk: wif });
    const [mapping] = bap.recomputeLegacyIds(oldFormat);
    expect(bap.getId(mapping.newBapId)?.export()).toMatchObject({
      rootPath: ROOT_PATH,
      previousPath: ROOT_PATH,
      currentPath: ROOT_PATH,
      idSeed: "",
    });
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

  test("rejects tampered and malformed lineage without partially importing", () => {
    const { wif, pk } = freshType42();
    const valid = makeLegacyType42Entry(pk);
    const skippedRotation = {
      ...makeLegacyType42Entry(pk, "", {
        previousPath: ROOT_PATH,
        currentPath: "bap:0:1",
      }),
      currentPath: "bap:0:3",
    };
    const wrongNamespace = {
      ...valid,
      previousPath: "bap:9:1",
      currentPath: "bap:9:2",
    };
    const tamperedBapId = { ...valid, bapId: `${valid.bapId}x` };
    const missingPrevious = { ...valid } as Partial<typeof valid>;
    delete missingPrevious.previousPath;

    for (const invalid of [
      skippedRotation,
      wrongNamespace,
      tamperedBapId,
      missingPrevious,
    ]) {
      const bap = new BAP({ rootPk: wif });
      const source = {
        lastIdPath: ROOT_PATH,
        ids: [valid, invalid],
      };
      expect(bap.isLegacyIdsExport(source as never)).toBe(false);
      expect(() => bap.recomputeLegacyIds(source as never)).toThrow();
      expect(bap.listIds()).toEqual([]);
    }
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
    expect(bap.getId(recomputed[0].newBapId)?.export()).toMatchObject({
      rootPath,
      previousPath: rootPath,
      currentPath: rootPath,
    });
  });

  test("preserves advanced HD lineage, seed, account key, xprv, and cursor exactly", () => {
    const hd = HD.fromSeed(Mnemonic.fromRandom().toSeed());
    const xprv = hd.toString();
    const idSeed = "legacy-hd-seed";
    const rootPath = "m/424150'/0'/0'/11/12/40";
    const previousPath = "m/424150'/0'/0'/11/12/44";
    const currentPath = "m/424150'/0'/0'/11/12/45";
    const lastIdPath = "/11/12/40";
    const rootAddress = legacyHdAddress(hd, rootPath, idSeed);
    const entry = {
      bapId: bapIdFromAddress(rootAddress),
      rootPath,
      rootAddress,
      currentPath,
      previousPath,
      idSeed,
      lastIdPath: "",
    };
    const source = { lastIdPath, ids: [entry] };
    const sourceBytes = JSON.stringify(source);
    const originalAccountWif = hdAccountKey(hd, rootPath, idSeed).toWif();

    const bap = new BAP(xprv);
    expect(bap.isLegacyIdsExport(source)).toBe(true);
    const [mapping] = bap.recomputeLegacyIds(source);
    const restored = bap.getId(mapping.newBapId);

    expect(mapping.newBapId).not.toBe(mapping.oldBapId);
    expect(restored?.export()).toEqual({
      bapId: mapping.newBapId,
      rootPath,
      rootAddress: deriveIdentity0Address(hdAccountKey(hd, rootPath, idSeed)),
      previousPath,
      currentPath,
      idSeed,
      lastIdPath: "",
    });
    expect(restored?.rootAddress).not.toBe(rootAddress);
    expect(restored?.exportAccountBackup().wif).toBe(originalAccountWif);
    expect(bap.exportIds(undefined, false).lastIdPath).toBe(lastIdPath);
    expect(bap.exportForBackup()).toMatchObject({ xprv });
    expect(JSON.stringify(source)).toBe(sourceBytes);

    const reissuedIds = bap.exportIds(undefined, false);
    const reloaded = new BAP(xprv);
    reloaded.importIds(reissuedIds, false);
    expect(reloaded.getId(mapping.newBapId)?.export()).toEqual(
      restored?.export()
    );
  });

  test("rejects malformed or impossible HD lineage", () => {
    const hd = HD.fromSeed(Mnemonic.fromRandom().toSeed());
    const xprv = hd.toString();
    const rootPath = "m/424150'/0'/0'/11/12/0";
    const rootAddress = legacyHdAddress(hd, rootPath);
    const entry = {
      bapId: bapIdFromAddress(rootAddress),
      rootPath,
      rootAddress,
      previousPath: "m/424150'/0'/0'/11/12/2",
      currentPath: "m/424150'/0'/0'/11/12/4",
      idSeed: "",
      lastIdPath: "",
    };
    const bap = new BAP(xprv);

    expect(
      bap.isLegacyIdsExport({ lastIdPath: "/11/12/0", ids: [entry] })
    ).toBe(false);
    expect(() =>
      bap.recomputeLegacyIds({ lastIdPath: "/11/12/0", ids: [entry] })
    ).toThrow("impossible BIP32 lineage");
    expect(bap.listIds()).toEqual([]);
  });
});
