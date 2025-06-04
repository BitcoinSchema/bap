import { expect, test, describe } from "bun:test";
import { BAP, MemberID } from "../src/index";
import { PrivateKey } from "@bsv/sdk";

describe("bitcoin-backup export methods", () => {
  const testHDKey =
    "xprv9s21ZrQH143K4CwNNfZMtuZLSinrrbh6KUbJJgxLxPWpisKUWKYRrniPAjYRZbopxuzWNUMwuMj9VzWHfKw1yJ8Ktc4ZPPuFcrRqQ3EE3xW";
  const testMnemonic =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

  test("BAP exportForBackup should return bitcoin-backup compatible format for BIP32", () => {
    const bap = new BAP(testHDKey);
    const bapId = bap.newId();
    bapId.setAttribute("name", "Test User");

    const backup = bap.exportForBackup("Test Label", testHDKey, testMnemonic);

    expect(backup).toHaveProperty("ids");
    expect(backup).toHaveProperty("xprv");
    expect(backup).toHaveProperty("mnemonic");
    expect(backup).toHaveProperty("label");
    expect(backup).toHaveProperty("createdAt");
    expect(backup).not.toHaveProperty("rootPk");

    expect(backup.xprv).toBe(testHDKey);
    expect(backup.mnemonic).toBe(testMnemonic);
    expect(backup.label).toBe("Test Label");
    expect(typeof backup.ids).toBe("string"); // Should be encrypted
    expect(backup.createdAt).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/); // ISO date format
  });

  test("BAP exportMemberForBackup should return bitcoin-backup compatible format", () => {
    const bap = new BAP(testHDKey);
    const bapId = bap.newId();
    bapId.setAttribute("name", "Test User");
    const idKey = bapId.getIdentityKey();

    const memberBackup = bap.exportMemberForBackup(idKey, "Member Label");

    expect(memberBackup).toHaveProperty("wif");
    expect(memberBackup).toHaveProperty("id");
    expect(memberBackup).toHaveProperty("label");
    expect(memberBackup).toHaveProperty("createdAt");

    expect(memberBackup.label).toBe("Member Label");
    expect(typeof memberBackup.wif).toBe("string");
    expect(typeof memberBackup.id).toBe("string"); // Should be encrypted
    expect(memberBackup.createdAt).toMatch(
      /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/
    ); // ISO date format
  });

  test("MemberID exportForBackup should return bitcoin-backup compatible format", () => {
    const testWif = "L156TApxcSCDGQgXRNahKiivZ57ZavGHREy1df4p6PuaRvXE3a1D";
    const memberID = new MemberID(PrivateKey.fromWif(testWif));
    memberID.idName = "Test Member";
    memberID.setAttribute("email", "test@example.com");

    const backup = memberID.exportForBackup("Direct Member Label");

    expect(backup).toHaveProperty("wif");
    expect(backup).toHaveProperty("id");
    expect(backup).toHaveProperty("label");
    expect(backup).toHaveProperty("createdAt");

    expect(backup.wif).toBe(testWif);
    expect(backup.label).toBe("Direct Member Label");
    expect(typeof backup.id).toBe("string"); // Should be encrypted
    expect(backup.createdAt).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/); // ISO date format
  });

  test("Export without label should not include label field", () => {
    const bap = new BAP(testHDKey);
    bap.newId();

    const backup = bap.exportForBackup();

    expect(backup).toHaveProperty("ids");
    expect(backup).toHaveProperty("xprv");
    expect(backup).toHaveProperty("mnemonic");
    expect(backup).toHaveProperty("createdAt");
    expect(backup).not.toHaveProperty("label");
  });

  test("BAP exportForBackup should return bitcoin-backup compatible format for Type 42", () => {
    const testWif = "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6";
    const bap = new BAP({ rootPk: testWif });
    const bapId = bap.newId();
    bapId.setAttribute("name", "Test User");

    const backup = bap.exportForBackup("Test Label");

    expect(backup).toHaveProperty("ids");
    expect(backup).toHaveProperty("rootPk");
    expect(backup).toHaveProperty("label");
    expect(backup).toHaveProperty("createdAt");
    expect(backup).not.toHaveProperty("xprv");
    expect(backup).not.toHaveProperty("mnemonic");

    expect(backup.rootPk).toBe(testWif);
    expect(backup.label).toBe("Test Label");
    expect(typeof backup.ids).toBe("string"); // Should be encrypted
    expect(backup.createdAt).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/); // ISO date format
  });
});
