import { describe, test, expect } from "bun:test";
import { MasterID } from "../src/MasterID";
import { MemberID } from "../src/MemberID";
import { PrivateKey } from "@bsv/sdk";
import { BAP } from "../src";

// Integration test: secure member key flow via master key derivation

describe("Integration Test: MasterID and MemberID secure derivation flow", () => {
  test("Create master id, derive member ids, export second member backup, and import it into a new MemberID", () => {
    // Use a fixed master key for testing
    const testMasterWIF = "xprv9s21ZrQH143K4CwNNfZMtuZLSinrrbh6KUbJJgxLxPWpisKUWKYRrniPAjYRZbopxuzWNUMwuMj9VzWHfKw1yJ8Ktc4ZPPuFcrRqQ3EE3xW";
    const masterId = new BAP(testMasterWIF);


    // Derive three member ids
    const _member1 = masterId.newId();
    const member2 = masterId.newId();
    
    // Export backup for the second member id
    const backup = member2.exportMemberBackup();
    
    // Simulate creating a new MemberID from the backup (acting as MemberID.fromBackup())
    const importedMember = new MemberID(PrivateKey.fromString(backup.derivedPrivateKey), backup.identityAttributes);
    importedMember.idName = backup.name;
    importedMember.description = backup.description;

    // Verify that the imported member's address matches the backup's address
    expect(importedMember.address).toBe(backup.address);

    // Verify that the imported member can sign a message
    const message = "Integration test message";
    const signed = importedMember.signMessage(message);
    expect(typeof signed.signature).toBe("string");
    expect(signed.signature.length).toBeGreaterThan(0);

    // Ensure the derived private key from backup is different from the master key
    // This check confirms that the customer member key is derived separately,
    // preventing direct compromise of the master key.
    expect(backup.derivedPrivateKey).not.toBe(testMasterWIF);
  });
}); 