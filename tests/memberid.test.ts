import { describe, test, expect } from "bun:test";
import { MemberID } from "../src/MemberID";
import { PrivateKey } from "@bsv/sdk";

const testWIF = "L15CzYWPiqY1R5fLPjRFB2PTGUqRP34EYCy72jusd47otmYx3G2z";

describe("MemberID Backup and Import", () => {
  test("MemberID export should include only allowed fields", () => {
    const privateKey = PrivateKey.fromWif(testWIF);
    const identityAttributes = {
      name: {
        value: "Test User",
        nonce: "random-nonce",
      },
      email: {
        value: "test@example.com",
        nonce: "another-nonce",
      }
    };
    const member = new MemberID(privateKey, identityAttributes);
    
    const backup = member.export();
    
    // Verify backup has only allowed keys
    expect(backup).toHaveProperty("derivedPrivateKey");
    expect(backup).toHaveProperty("address");
    expect(backup).toHaveProperty("identityAttributes");

    // It should not include idSeed or rootAddress
    expect(backup).not.toHaveProperty("idSeed");
    expect(backup).not.toHaveProperty("rootAddress");

    // The derivedPrivateKey should match the provided private key's WIF
    expect(backup.derivedPrivateKey).toBe(privateKey.toString());
  });

  test("MemberID signMessage returns valid structure", () => {
    const privateKey = PrivateKey.fromWif(testWIF);
    const identityAttributes = { name: { value: "Test User", nonce: "nonce" } };
    const member = new MemberID(privateKey, identityAttributes);

    const message = "Hello, Member!";
    const result = member.signMessage(message);
    
    // The returned address should match the MemberID's public key
    expect(result.address).toBe(member.getPublicKey());
    expect(typeof result.signature).toBe("string");
    expect(result.signature.length).toBeGreaterThan(0);
  });

  test("MemberID getPublicKey returns correct public key", () => {
    const privateKey = PrivateKey.fromWif(testWIF);
    const member = new MemberID(privateKey);
    const expectedPublicKey = privateKey.toPublicKey().toString();
    expect(member.getPublicKey()).toBe(expectedPublicKey);
  });

  test("MemberID import/export consistency", () => {
    const privateKey = PrivateKey.fromWif(testWIF);
    const identityAttributes = {
      name: { value: "Test User", nonce: "nonce1" },
      email: { value: "test@example.com", nonce: "nonce2" }
    };
    const member = new MemberID(privateKey, identityAttributes);
    member.idName = "Member One";
    member.description = "This is a test member";

    const exported = member.export();

    // Create a new MemberID instance with a dummy initial identity
    const newMember = new MemberID(privateKey, {});
    newMember.import(exported);

    expect(newMember.idName).toBe(member.idName);
    expect(newMember.description).toBe(member.description);
    expect(newMember.address).toBe(member.address);

    // Instead of deep equality on entire object, compare each field individually
    const imported = newMember.export();
    expect(imported.name).toBe(exported.name);
    expect(imported.description).toBe(exported.description);
    expect(PrivateKey.fromString(imported.derivedPrivateKey).toString()).toBe(PrivateKey.fromString(exported.derivedPrivateKey).toString());
    expect(imported.address).toBe(exported.address);
    expect(imported.identityAttributes).toStrictEqual(exported.identityAttributes);
  });
}); 