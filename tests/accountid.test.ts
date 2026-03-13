import { describe, expect, test } from "bun:test";
import { PrivateKey, Utils } from "@bsv/sdk";
import { AccountID } from "../src/AccountID";
import { BAP } from "../src";
import { HDPrivateKey } from "./data/keys";

const { toUTF8 } = Utils;

describe("AccountID", () => {
  test("getBapId is deterministic", () => {
    const key = PrivateKey.fromRandom();
    const a1 = new AccountID(key);
    const a2 = new AccountID(key);
    expect(a1.getBapId()).toBe(a2.getBapId());
  });

  test("getRootAddress matches key address", () => {
    const key = PrivateKey.fromRandom();
    const account = new AccountID(key);
    expect(account.getRootAddress()).toBe(key.toPublicKey().toAddress());
  });

  test("getRootPublicKey matches key pubkey", () => {
    const key = PrivateKey.fromRandom();
    const account = new AccountID(key);
    expect(account.getRootPublicKey()).toBe(key.toPublicKey().toString());
  });

  test("signMessage produces valid BSM signature", () => {
    const key = PrivateKey.fromRandom();
    const account = new AccountID(key);
    const message = [1, 2, 3, 4];
    const { address, signature } = account.signMessage(message);

    expect(address).toBe(key.toPublicKey().toAddress());
    expect(typeof signature).toBe("string");
    expect(signature.length).toBeGreaterThan(0);
  });

  test("getInitialIdTransaction creates valid OP_RETURN", () => {
    const key = PrivateKey.fromRandom();
    const account = new AccountID(key);
    const firstSigningAddress = PrivateKey.fromRandom().toPublicKey().toAddress();

    const tx = account.getInitialIdTransaction(firstSigningAddress);

    // Should have: OP_RETURN, BAP prefix, "ID", bapId, firstSigningAddress, "|", AIP prefix, algo, address, signature
    expect(tx.length).toBe(10);
    expect(toUTF8(tx[2])).toBe("ID");
    expect(toUTF8(tx[3])).toBe(account.getBapId());
    expect(toUTF8(tx[4])).toBe(firstSigningAddress);

    // AIP section
    expect(toUTF8(tx[5])).toBe("|");
    expect(toUTF8(tx[8])).toBe(account.getRootAddress());
  });

  test("getRevocationTransaction sends BAP ID to 0", () => {
    const key = PrivateKey.fromRandom();
    const account = new AccountID(key);

    const tx = account.getRevocationTransaction();

    expect(tx.length).toBe(10);
    expect(toUTF8(tx[2])).toBe("ID");
    expect(toUTF8(tx[3])).toBe(account.getBapId());
    expect(toUTF8(tx[4])).toBe("0");

    // Signed by root address
    expect(toUTF8(tx[8])).toBe(account.getRootAddress());
  });

  test("AccountID from BAP class matches MasterID", () => {
    const bap = new BAP(HDPrivateKey);
    const masterId = bap.newId();
    const accountId = bap.getAccountId(masterId.bapId);

    expect(accountId).not.toBeNull();
    expect(accountId!.getBapId()).toBe(masterId.bapId);
    expect(accountId!.getRootAddress()).toBe(masterId.rootAddress);
  });

  test("different keys produce different BAP IDs", () => {
    const a1 = new AccountID(PrivateKey.fromRandom());
    const a2 = new AccountID(PrivateKey.fromRandom());
    expect(a1.getBapId()).not.toBe(a2.getBapId());
  });
});
