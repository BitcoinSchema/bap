import { describe, expect, test } from "bun:test";
import {
  BSM,
  BigNumber,
  HD,
  PrivateKey,
  type Signature,
  Utils,
} from "@bsv/sdk";
import { BAP } from "../src";
import { ENCRYPTION_PATH, SIGNING_PATH_PREFIX } from "../src/constants";
import { MasterID } from "../src/MasterID";
import type { Identities, OldIdentity } from "../src/interface";
import fullId from "./data/ids.json";
import { HDPrivateKey, HDPublicKey } from "./data/keys";
import oldFullId from "./data/old-ids.json";

const { toArray } = Utils;

// Old test data uses identityKey format — BAP handles import via OldIdentity path
const legacyIdentityKey =
  "4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z";

describe("BAP class", () => {
  test("should initialize with random HD private key", () => {
    const randomHDPrivateKey = HD.fromRandom().toString();
    const bap = new BAP(randomHDPrivateKey);
    expect(bap.getHdPublicKey()).toMatch("xpub");
  });

  test("should throw error when initialized without key", () => {
    expect(() => {
      // @ts-ignore
      new BAP();
    }).toThrow();
  });

  test("with known key", () => {
    const bap = new BAP(HDPrivateKey);
    expect(bap.getPublicKey()).toBe(
      "02c23e9fc6a959bb5315159ac7438c5a6bff37c7197326d1060b176e3969d72af5"
    );
    expect(bap.getPublicKey(ENCRYPTION_PATH)).toBe(
      "02fc759e24d922c2d47766710613910c0f40bab7439777af9ad45bff55ec622994"
    );
    expect(bap.getHdPublicKey()).toBe(HDPublicKey);
  });

  test("checkIdBelongs", () => {
    const randomHDPrivateKey = HD.fromRandom().toString();
    const bap1 = new BAP(randomHDPrivateKey);
    const bap2 = new BAP(HDPrivateKey);

    const id1 = bap1.newId();
    const id2 = bap2.newId();

    expect(bap1.checkIdBelongs(id1)).toBe(true);
    expect(() => bap1.checkIdBelongs(id2)).toThrow();
    expect(bap2.checkIdBelongs(id2)).toBe(true);
    expect(() => bap2.checkIdBelongs(id1)).toThrow();
  });

  test("import old format ID", () => {
    const bap = new BAP(HDPrivateKey);
    const oldIds = oldFullId as OldIdentity[];
    bap.importOldIds(oldIds);

    expect(bap.listIds()).toStrictEqual([legacyIdentityKey]);

    const importedId = bap.getId(legacyIdentityKey);
    expect(importedId).not.toBeNull();
    expect(importedId).toBeInstanceOf(MasterID);
    expect(importedId?.bapId).toBe(legacyIdentityKey);
  });

  test("import full ID (old format with identityKey)", () => {
    const bap = new BAP(HDPrivateKey);
    // fullId uses old identityKey field — import handles mapping
    bap.importIds(fullId as any, false);

    expect(bap.listIds()).toStrictEqual([legacyIdentityKey]);
    const importedId = bap.getId(legacyIdentityKey);
    expect(importedId).not.toBeNull();
    expect(importedId?.bapId).toBe(legacyIdentityKey);
  });

  test("export/import encrypted ID", () => {
    const bap = new BAP(HDPrivateKey);
    bap.importIds(fullId as any, false);

    const encryptedExportData = bap.exportIds();
    expect(typeof encryptedExportData).toBe("string");

    const bap2 = new BAP(HDPrivateKey);
    bap2.importIds(encryptedExportData);
    expect(bap2.listIds()).toStrictEqual([legacyIdentityKey]);

    const importedId = bap2.getId(legacyIdentityKey);
    expect(importedId).toBeInstanceOf(MasterID);
    expect(importedId?.bapId).toBe(legacyIdentityKey);
  });

  test("getId / setId", () => {
    const bap = new BAP(HDPrivateKey);
    const newId = bap.newId();
    bap.setId(newId);

    expect(bap.getId("test")).toEqual(null);
    expect(bap.getId(newId.bapId)?.bapId).toBe(newId.bapId);
  });

  test("listIds", () => {
    const randomHDPrivateKey = HD.fromRandom().toString();
    const bap = new BAP(randomHDPrivateKey);
    expect(bap.listIds()).toStrictEqual([]);

    const newId = bap.newId();
    bap.setId(newId);
    expect(bap.listIds()).toStrictEqual([newId.bapId]);
  });

  test("newId", () => {
    const randomHDPrivateKey = HD.fromRandom().toString();
    const bap = new BAP(randomHDPrivateKey);
    const newId = bap.newId();
    expect(newId).toBeInstanceOf(MasterID);
    expect(bap.checkIdBelongs(newId)).toBe(true);
    expect(newId.rootPath).toBe(`${SIGNING_PATH_PREFIX}/0'/0'/0'`);
    expect(newId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0'/0'/1'`);
  });

  test("newId with custom path", () => {
    const bap = new BAP(HDPrivateKey);
    const newId = bap.newId("/123/124/0");
    expect(newId).toBeInstanceOf(MasterID);
    expect(bap.checkIdBelongs(newId)).toBe(true);
    expect(newId.rootPath).toBe(`${SIGNING_PATH_PREFIX}/123/124/0`);
    expect(newId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/123/124/1`);
  });

  test("newId creates unique IDs", () => {
    const randomHDPrivateKey = HD.fromRandom().toString();
    const bap = new BAP(randomHDPrivateKey);

    const firstId = bap.newId();
    const secondId = bap.newId();

    expect(secondId.bapId).not.toBe(firstId.bapId);
    expect(firstId.rootPath).toBe(`${SIGNING_PATH_PREFIX}/0'/0'/0'`);
    expect(secondId.rootPath).toBe(`${SIGNING_PATH_PREFIX}/0'/1'/0'`);
    expect(bap.listIds().length).toBe(2);
  });

  test("lastIdPath", () => {
    const fullBap = new BAP(HDPrivateKey);
    fullBap.importIds(fullId as any, false);
    expect(fullBap.lastIdPath).toBe("/26562456/876543/345346");

    const newId = fullBap.newId();
    expect(fullBap.lastIdPath).toBe("/26562456/876544/0");

    fullBap.removeId(newId.bapId);
    expect(fullBap.lastIdPath).toBe("/26562456/876544/0");
  });

  test("verifyAttestationWithAIP rejects invalid input", () => {
    const bap = new BAP(HDPrivateKey);
    expect(() => bap.verifyAttestationWithAIP([])).toThrow();
  });

  test("verifySignature", () => {
    const privateKey = PrivateKey.fromWif(
      "L4C6X6aJccc5KDzJRTLqskz6gxAwUx9QJVi2S4BZATfdzjw8TUJH"
    );
    const address = privateKey.toAddress();
    const message = "test message";
    const msg = toArray(message);
    const dummySig = BSM.sign(msg, privateKey, "raw") as Signature;
    const h = new BigNumber(BSM.magicHash(msg));
    const r = dummySig.CalculateRecoveryFactor(privateKey.toPublicKey(), h);
    const signature = dummySig.toCompact(r, true, "base64") as string;

    const bap = new BAP(HDPrivateKey);
    expect(bap.verifySignature(message, address, signature)).toBe(true);
  });

  test("exportForBackup BIP32", () => {
    const bap = new BAP(HDPrivateKey);
    bap.newId();
    const backup = bap.exportForBackup();
    expect("xprv" in backup).toBe(true);
    expect(typeof backup.ids).toBe("string");
    expect(backup.createdAt).toBeTruthy();
  });

  test("exportForBackup Type42", () => {
    const pk = PrivateKey.fromRandom();
    const bap = new BAP({ rootPk: pk.toWif() });
    bap.newId();
    const backup = bap.exportForBackup();
    expect("rootPk" in backup).toBe(true);
    expect(typeof backup.ids).toBe("string");
  });
});
