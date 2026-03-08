import { describe, expect, test } from "bun:test";
import { PrivateKey } from "@bsv/sdk";
import { BAP, bapIdFromPubkey } from "../src";
import { Utils } from "../src/utils";

describe("Type 42 rotation semantics", () => {
  test("getNextPath increments Type 42 rotation paths without losing the bap prefix", () => {
    expect(Utils.getNextPath("bap:0")).toBe("bap:0:1");
    expect(Utils.getNextPath("bap:0:1")).toBe("bap:0:2");
    expect(Utils.getNextPath("bap:5:9")).toBe("bap:5:10");
    expect(Utils.getNextPath("1")).toBe("2");
  });

  test("getNextPath preserves BIP32 behavior and rejects unsupported non-BIP32 paths", () => {
    expect(Utils.getNextPath("m/424150'/0'/0'/0'/0'/1'")).toBe(
      "m/424150'/0'/0'/0'/0'/2'"
    );
    expect(() => Utils.getNextPath("wallet:0")).toThrow(
      "Unsupported non-BIP32 path: wallet:0"
    );
  });

  test("rotation keeps the BAP ID stable while moving the active wallet root", () => {
    const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    const identity = bap.newId("Test");

    const identityKeyBefore = identity.getIdentityKey();
    const memberKeyBefore = identity.getMemberKey();
    const walletPubkeyBefore = identity.getWalletPubkey();
    const currentAddressBefore = identity.getCurrentAddress();

    expect(identity.rootPath).toBe("bap:0");
    expect(identity.currentPath).toBe("bap:0");
    expect(bapIdFromPubkey(memberKeyBefore)).toBe(identityKeyBefore);

    identity.incrementPath();

    expect(identity.getIdentityKey()).toBe(identityKeyBefore);
    expect(identity.rootPath).toBe("bap:0");
    expect(identity.previousPath).toBe("bap:0");
    expect(identity.currentPath).toBe("bap:0:1");
    expect(identity.getMemberKey()).toBe(memberKeyBefore);
    expect(bapIdFromPubkey(identity.getMemberKey())).toBe(identityKeyBefore);
    expect(identity.getWalletPubkey()).not.toBe(walletPubkeyBefore);
    expect(identity.getCurrentAddress()).not.toBe(currentAddressBefore);
  });

  test("getIdTransaction signs with the previous active path after rotation", () => {
    const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    const identity = bap.newId("Test");

    identity.incrementPath();

    const tx = identity.getIdTransaction();
    const currentAddress = String.fromCharCode(...tx[3]);
    const signingAddress = String.fromCharCode(...tx[7]);

    expect(currentAddress).toBe(identity.getCurrentAddress());
    expect(signingAddress).toBe(identity.getAddress("bap:0"));
    expect(signingAddress).not.toBe(identity.getCurrentAddress());
  });

  test("rotated Type 42 paths survive export and import", () => {
    const rootPk = PrivateKey.fromRandom().toWif();
    const bap = new BAP({ rootPk });
    const created = bap.newId("Test");
    created.incrementPath();

    const encryptedIds = bap.exportIds();

    const restored = new BAP({ rootPk });
    restored.importIds(encryptedIds);

    const restoredIdentity = restored.getId(created.getIdentityKey());

    expect(restoredIdentity).not.toBeNull();
    expect(restoredIdentity?.rootPath).toBe("bap:0");
    expect(restoredIdentity?.previousPath).toBe("bap:0");
    expect(restoredIdentity?.currentPath).toBe("bap:0:1");
    expect(restoredIdentity?.getMemberKey()).toBe(created.getMemberKey());
    expect(restoredIdentity?.getWalletPubkey()).toBe(created.getWalletPubkey());
  });

  test("legacy numeric Type 42 rotation paths continue rotating for backward compatibility", () => {
    const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    const identity = bap.newId("Legacy numeric path");
    const memberKeyBefore = identity.getMemberKey();
    const walletPubkeyBefore = identity.getWalletPubkey();

    identity.currentPath = "1";
    expect(identity.currentPath).toBe("1");

    identity.incrementPath();

    expect(identity.currentPath).toBe("2");
    expect(identity.getMemberKey()).toBe(memberKeyBefore);
    expect(identity.getWalletPubkey()).not.toBe(walletPubkeyBefore);
  });
});
