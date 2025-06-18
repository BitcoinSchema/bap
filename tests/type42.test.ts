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
      const bap = new BAP({
        rootPk: testWif
      });
      expect(bap).toBeDefined();
    });
  });

  describe("Key derivation", () => {
    test("BIP32 and Type 42 should derive different addresses for same path", () => {
      const bapBIP32 = new BAP(testHDKey);
      
      // Get the root private key from the HD key to use for Type 42
      const hdKey = HD.fromString(testHDKey);
      const rootWif = hdKey.privKey.toWif();
      
      const bapType42 = new BAP({
        rootPk: rootWif
      });
      
      const pathToTest = "m/424150'/0'/0'/0/0/0";
      const bip32Address = bapBIP32.getPublicKey(pathToTest);
      const type42Address = bapType42.getPublicKey(pathToTest);
      
      // These should be different because derivation methods are different
      expect(bip32Address).not.toBe(type42Address);
    });

    test("getHdPublicKey should throw error in Type 42 mode", () => {
      const bap = new BAP({
        rootPk: testWif
      });
      
      expect(() => bap.getHdPublicKey()).toThrow("HD public keys are not available in Type 42 mode");
    });
  });

  describe("Export methods", () => {
    test("exportForBackup should handle Type 42 mode automatically", () => {
      const bap = new BAP({
        rootPk: testWif
      });
      
      const backup = bap.exportForBackup("Test Label");
      
      expect(backup).toHaveProperty("ids");
      expect(backup).toHaveProperty("rootPk");
      expect(backup).not.toHaveProperty("xprv");
      expect(backup).not.toHaveProperty("mnemonic");
      expect(backup).toHaveProperty("label");
      expect(backup).toHaveProperty("createdAt");
      
      expect(backup.rootPk).toBe(testWif);
      expect(backup.label).toBe("Test Label");
      expect(typeof backup.ids).toBe("string"); // Should be encrypted
    });

    test("exportForBackup should handle BIP32 mode automatically", () => {
      const bap = new BAP(testHDKey);
      
      const backup = bap.exportForBackup("Test Label", testHDKey, "test mnemonic");
      
      expect(backup).toHaveProperty("ids");
      expect(backup).toHaveProperty("xprv");
      expect(backup).toHaveProperty("mnemonic");
      expect(backup).not.toHaveProperty("rootPk");
      expect(backup).toHaveProperty("label");
      expect(backup).toHaveProperty("createdAt");
      
      expect(backup.xprv).toBe(testHDKey);
      expect(backup.mnemonic).toBe("test mnemonic");
      expect(backup.label).toBe("Test Label");
      expect(typeof backup.ids).toBe("string"); // Should be encrypted
    });
  });

  describe("ID creation in Type 42 mode", () => {
    test("should create new ID with Type 42 derivation", () => {
      const bap = new BAP({
        rootPk: testWif
      });
      
      const id = bap.newId();
      expect(id).toBeDefined();
      expect(id.getIdentityKey()).toBeDefined();
      expect(id.rootAddress).toBeDefined();
    });

    test("should create ID with attributes", () => {
      const bap = new BAP({
        rootPk: testWif
      });
      
      const id = bap.newId(undefined, {
        name: { value: "Test User", nonce: "123" }
      });
      
      expect(id).toBeDefined();
      const attrs = id.getAttributes();
      expect(attrs.name).toBeDefined();
      expect(attrs.name.value).toBe("Test User");
    });
  });

  describe("Encryption/Decryption", () => {
    test("Type 42 encryption should work", async () => {
      const bap = new BAP({
        rootPk: testWif
      });
      
      const testData = "Hello Type 42!";
      const encrypted = bap.encrypt(testData);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe("string");
      
      const decrypted = bap.decrypt(encrypted);
      expect(decrypted).toBe(testData);
    });

    test("BIP32 and Type 42 encrypted data should be incompatible", () => {
      const bapBIP32 = new BAP(testHDKey);
      
      // Get the root private key from the HD key
      const hdKey = HD.fromString(testHDKey);
      const rootWif = hdKey.privKey.toWif();
      
      const bapType42 = new BAP({
        rootPk: rootWif
      });
      
      const testData = "Cross encryption test";
      
      // Encrypt with BIP32
      const encryptedBIP32 = bapBIP32.encrypt(testData);
      
      // Try to decrypt with Type 42 - should fail
      expect(() => bapType42.decrypt(encryptedBIP32)).toThrow();
    });
  });

  describe("Migration scenario", () => {
    test("should demonstrate identity migration from BIP32 to Type 42", () => {
      // Create BIP32 BAP instance
      const bapOld = new BAP(testHDKey);
      const idOld = bapOld.newId();
      idOld.setAttribute("name", "Migration Test");
      
      // Get the last address from BIP32
      const lastBIP32Address = idOld.getCurrentAddress();
      const identityKey = idOld.getIdentityKey();
      
      // Create Type 42 BAP instance with same root key
      const hdKey = HD.fromString(testHDKey);
      const rootWif = hdKey.privKey.toWif();
      
      const bapNew = new BAP({
        rootPk: rootWif
      });
      
      // Create new identity with Type 42
      const idNew = bapNew.newId();
      
      // The identity keys will be different
      expect(idNew.getIdentityKey()).not.toBe(identityKey);
      expect(idNew.getCurrentAddress()).not.toBe(lastBIP32Address);
      // This demonstrates that migration requires creating a new identity
      // and linking it via an ID transaction from the old identity
    });
  });
});