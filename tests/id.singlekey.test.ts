/// <reference types="bun" />
import { MemberID } from "../src";
import { describe, test, expect, beforeAll } from "bun:test";
import { PrivateKey } from "@bsv/sdk";

// Define a simple identity attributes object for testing
const identityAttributes = {
  testAttr: {
    value: "testValue",
    nonce: "123",
  },
};

describe("MemberID single key functionality", () => {
  let singlePrivateKey: PrivateKey;
  let memberId: MemberID;

  beforeAll(() => {
    singlePrivateKey = PrivateKey.fromRandom();
    memberId = new MemberID(singlePrivateKey, identityAttributes);
  });

  test("signMessage works with single key", () => {
    const message = "Hello, world!";
    const result = memberId.signMessage(message);
    const expectedAddress = singlePrivateKey.toPublicKey().toAddress();
    expect(result.address).toBe(expectedAddress);
    expect(typeof result.signature).toBe("string");
  });

  test("export returns object with derivedPrivateKey and other properties", () => {
    const exported = memberId.export() as {
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

  test("encryption and decryption work with single key", () => {
    const testString = "test string";
    const encrypted = memberId.encrypt(testString, singlePrivateKey);
    const decrypted = memberId.decrypt(encrypted, singlePrivateKey);
    expect(decrypted).toBe(testString);
  });

  test("encryption and decryption work with counterparty", () => {
    const testString = "test string";
    const counterPartyKey = PrivateKey.fromRandom();
    const counterPartyPubKey = counterPartyKey.toPublicKey().toString();
    
    // Encrypt with our key for counterparty
    const encrypted = memberId.encrypt(testString, singlePrivateKey, counterPartyPubKey);
    // Decrypt with counterparty key
    const decrypted = memberId.decrypt(encrypted, counterPartyKey);
    expect(decrypted).toBe(testString);
  });

  test("getEncryptionPublicKey returns the member's public key", () => {
    const publicKey = memberId.getEncryptionPublicKey();
    expect(publicKey).toBe(singlePrivateKey.toPublicKey().toString());
  });

  test("encryption methods with seed throw appropriate error", () => {
    expect(() => memberId.getEncryptionPublicKeyWithSeed("seed")).toThrow("HDPrivateKey not set");
    expect(() => memberId.encryptWithSeed("test string", "seed")).toThrow("HDPrivateKey not set");
    expect(() => memberId.decryptWithSeed("ciphertext", "seed")).toThrow("HDPrivateKey not set");
  });
}); 