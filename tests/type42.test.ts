import { expect, test, describe } from "bun:test";
import { BAP } from "../src/index";
import { HD } from "@bsv/sdk";

describe("Type 42 support in BAP", () => {
  const testHDKey =
    "xprv9s21ZrQH143K4CwNNfZMtuZLSinrrbh6KUbJJgxLxPWpisKUWKYRrniPAjYRZbopxuzWNUMwuMj9VzWHfKw1yJ8Ktc4ZPPuFcrRqQ3EE3xW";
  const testWif = "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6";

  describe("BAP constructor", () => {
    test("should accept HDPrivateKey for BIP32 mode", () => {
      const bap = new BAP(testHDKey);
      expect(bap).toBeDefined();
    });

    test("should accept Type42Params for Type 42 mode", () => {
      const bap = new BAP({ rootPk: testWif });
      expect(bap).toBeDefined();
    });
  });

  describe("Key derivation", () => {
    test("BIP32 and Type 42 should derive different addresses for same path", () => {
      const bapBIP32 = new BAP(testHDKey);
      const hdKey = HD.fromString(testHDKey);
      const rootWif = hdKey.privKey.toWif();
      const bapType42 = new BAP({ rootPk: rootWif });

      const pathToTest = "m/424150'/0'/0'/0/0/0";
      const bip32Address = bapBIP32.getPublicKey(pathToTest);
      const type42Address = bapType42.getPublicKey(pathToTest);

      expect(bip32Address).not.toBe(type42Address);
    });

    test("getHdPublicKey should throw error in Type 42 mode", () => {
      const bap = new BAP({ rootPk: testWif });
      expect(() => bap.getHdPublicKey()).toThrow("HD public keys are not available in Type 42 mode");
    });
  });

  describe("Export methods", () => {
    test("exportForBackup should handle Type 42 mode", () => {
      const bap = new BAP({ rootPk: testWif });
      const backup = bap.exportForBackup("Test Label");

      expect(backup).toHaveProperty("ids");
      expect(backup).toHaveProperty("rootPk");
      expect(backup).not.toHaveProperty("xprv");
      expect(backup.rootPk).toBe(testWif);
      expect(backup.label).toBe("Test Label");
      expect(typeof backup.ids).toBe("string");
    });

    test("exportForBackup should handle BIP32 mode", () => {
      const bap = new BAP(testHDKey);
      const backup = bap.exportForBackup("Test Label", testHDKey, "test mnemonic");

      expect(backup).toHaveProperty("ids");
      expect(backup).toHaveProperty("xprv");
      expect(backup).toHaveProperty("mnemonic");
      expect(backup).not.toHaveProperty("rootPk");
      expect(backup.xprv).toBe(testHDKey);
      expect(backup.mnemonic).toBe("test mnemonic");
    });
  });

  describe("ID creation in Type 42 mode", () => {
    test("should create new ID with Type 42 derivation", () => {
      const bap = new BAP({ rootPk: testWif });
      const id = bap.newId();
      expect(id).toBeDefined();
      expect(id.bapId).toBeDefined();
      expect(id.rootAddress).toBeDefined();
    });

    test("Type 42 counter-based IDs are unique", () => {
      const bap = new BAP({ rootPk: testWif });
      const id1 = bap.newId();
      const id2 = bap.newId();

      expect(id1.bapId).not.toBe(id2.bapId);
      expect(id1.rootPath).toBe("bap:0");
      expect(id2.rootPath).toBe("bap:1");
    });

    test("newIdWithCounter creates ID at specific counter", () => {
      const bap = new BAP({ rootPk: testWif });
      const id = bap.newIdWithCounter(5);
      expect(id.rootPath).toBe("bap:5");
    });
  });

  describe("Master-level encryption", () => {
    test("Type 42 encryption should work", () => {
      const bap = new BAP({ rootPk: testWif });
      const testData = "Hello Type 42!";
      const encrypted = bap.encrypt(testData);
      expect(typeof encrypted).toBe("string");
      expect(bap.decrypt(encrypted)).toBe(testData);
    });

    test("BIP32 and Type 42 encrypted data should be incompatible", () => {
      const bapBIP32 = new BAP(testHDKey);
      const hdKey = HD.fromString(testHDKey);
      const bapType42 = new BAP({ rootPk: hdKey.privKey.toWif() });

      const encrypted = bapBIP32.encrypt("Cross encryption test");
      expect(() => bapType42.decrypt(encrypted)).toThrow();
    });
  });
});
