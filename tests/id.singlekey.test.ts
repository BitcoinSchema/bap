/// <reference types="bun" />
import { describe, test, expect, beforeAll } from "bun:test";
import { BAP_ID } from "../src/id";
import { PrivateKey } from "@bsv/sdk";

// Define a simple identity attributes object for testing
const identityAttributes = {
  testAttr: {
    value: "testValue",
    nonce: "123",
  },
};

describe("bap-id single key functionality", () => {
  let singlePrivateKey: PrivateKey;
  let bapId: BAP_ID;

  beforeAll(() => {
    singlePrivateKey = PrivateKey.fromRandom();
    bapId = new BAP_ID(singlePrivateKey, identityAttributes);
  });

  test("getEncryptionPublicKey returns single key's public key", () => {
    const pubKey = bapId.getEncryptionPublicKey();
    const expectedPubKey = singlePrivateKey.toPublicKey().toString();
    expect(pubKey).toBe(expectedPubKey);
  });

  test("signMessage works with single key", () => {
    const message = "Hello, world!";
    const result = bapId.signMessage(message);
    const expectedAddress = singlePrivateKey.toPublicKey().toAddress();
    expect(result.address).toBe(expectedAddress);
    expect(typeof result.signature).toBe("string");
  });

  test("export returns object with derivedPrivateKey and other properties", () => {
    const exported = bapId.export() as {
      derivedPrivateKey: string;
      idSeed: string;
      rootAddress: string;
      identityAttributes: { [key: string]: { value: string; nonce: string } };
    };
    expect(exported.derivedPrivateKey).toBe(singlePrivateKey.toString());
    expect(exported.idSeed).toBe("");
    expect(exported.rootAddress).toBe(singlePrivateKey.toPublicKey().toAddress());
    expect(exported.identityAttributes.testAttr.value).toBe("testValue");
    expect(exported.identityAttributes.testAttr.nonce).toBe("123");
  });

  test("encryption methods throw error for single key", () => {
    expect(() => bapId.encrypt("test string")).toThrow("HDPrivateKey not set");
    expect(() => bapId.decrypt("ciphertext")).toThrow("HDPrivateKey not set");
    expect(() => bapId.getEncryptionPublicKeyWithSeed("seed")).toThrow("HDPrivateKey not set");
    expect(() => bapId.encryptWithSeed("test string", "seed")).toThrow("HDPrivateKey not set");
    expect(() => bapId.decryptWithSeed("ciphertext", "seed")).toThrow("HDPrivateKey not set");
  });
}); 