import { describe, expect, it } from "bun:test";
import { BAP } from "../src";

import testVectors from "./data/test-vectors.json";
import { Utils } from "@bsv/sdk";
const { toArray } = Utils;

describe("test-vectors", () => {
  it("regression", () => {
    for (const v of testVectors) {
      const bap = new BAP(v.HDPrivateKey);
      const id = bap.newId();
      expect(id.rootAddress).toBe(v.rootAddress);
      expect(id.getIdentityKey()).toBe(v.idKey);
      expect(id.rootPath).toBe(v.rootPath);
      const tx = id.getInitialIdTransaction();
      expect(typeof tx[8]).toBe("object");
      expect(typeof v.tx[8]).toBe("string");
      delete tx[8]; // remove the signature, will be different
      delete v.tx[8]; // remove the signature, will be different
      expect(tx).toStrictEqual(v.tx.map((t) => toArray(t, "hex")));
    }
  });
});
