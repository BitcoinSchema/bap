import { describe, test, expect } from "bun:test";
import { MasterID } from "../src/MasterID";
import { MemberID } from "../src/MemberID";
import { HD, PrivateKey } from "@bsv/sdk";

describe("Migration Support", () => {
  test("getLegacyAddress returns pre-derivation address", () => {
    const hdKey = HD.fromRandom();
    const master = new MasterID(hdKey);

    const legacyAddr = master.getLegacyAddress();
    const currentAddr = master.getCurrentAddress();

    // Legacy and current should be different (current has extra derivation)
    expect(legacyAddr).not.toBe(currentAddr);
  });

  test("needsRotation returns true for legacy address", () => {
    const hdKey = HD.fromRandom();
    const master = new MasterID(hdKey);

    // Pass a legacy address - should return true
    const legacyAddr = master.getLegacyAddress(master.getRootPath());
    expect(master.needsRotation(legacyAddr)).toBe(true);

    // Pass a new address - should return false
    const newAddr = master.getCurrentAddress();
    expect(master.needsRotation(newAddr)).toBe(false);
  });

  test("getLegacyRotationTransaction signs with legacy key", () => {
    const hdKey = HD.fromRandom();
    const master = new MasterID(hdKey);

    const rotationTx = master.getLegacyRotationTransaction();

    // Should be array of arrays (OP_RETURN data)
    expect(Array.isArray(rotationTx)).toBe(true);
    expect(rotationTx.length).toBeGreaterThan(0);

    // OP_RETURN format:
    // [0] BAP_BITCOM_ADDRESS, [1] "ID", [2] identityKey, [3] newAddress
    // [4] "|", [5] AIP_BITCOM_ADDRESS, [6] "BITCOIN_ECDSA", [7] signingAddress, [8] signature
    const legacyAddress = master.getLegacyAddress(master.getRootPath());
    const newAddress = master.getAddress(master.getRootPath());

    // Convert the signing address from the OP_RETURN (index 7)
    const signingAddressBytes = rotationTx[7];
    const signingAddress = String.fromCharCode(...signingAddressBytes);

    // Must be signed with legacy address (proves ownership of old key)
    expect(signingAddress).toBe(legacyAddress);
    expect(signingAddress).not.toBe(newAddress);
  });

  test("getLegacyRotationTransaction contains new derived address in payload", () => {
    const hdKey = HD.fromRandom();
    const master = new MasterID(hdKey);

    const rotationTx = master.getLegacyRotationTransaction();

    // The new address (index 3 in the OP_RETURN) should be the NEW derived address
    const newAddressBytes = rotationTx[3];
    const newAddressInTx = String.fromCharCode(...newAddressBytes);

    const expectedNewAddress = master.getAddress(master.getRootPath());
    const legacyAddress = master.getLegacyAddress(master.getRootPath());

    // The payload should contain the NEW address (what we're rotating TO)
    expect(newAddressInTx).toBe(expectedNewAddress);
    expect(newAddressInTx).not.toBe(legacyAddress);
  });

  test("Type42 mode: getLegacyAddress returns pre-derivation address", () => {
    const key = PrivateKey.fromRandom();
    const master = new MasterID({ rootPk: key });

    const legacyAddr = master.getLegacyAddress();
    const currentAddr = master.getCurrentAddress();

    // Legacy and current should be different (current has extra derivation)
    expect(legacyAddr).not.toBe(currentAddr);
  });

  test("MemberID getLegacyAddress returns direct address", () => {
    const key = PrivateKey.fromRandom();
    const member = new MemberID(key);

    const legacyAddr = member.getLegacyAddress();
    const currentAddr = member.address;

    // Legacy and current should be different
    expect(legacyAddr).not.toBe(currentAddr);
    // Legacy should be direct from member key
    expect(legacyAddr).toBe(key.toPublicKey().toAddress());
  });
});
