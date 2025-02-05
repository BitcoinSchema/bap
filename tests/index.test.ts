import { describe, expect, test } from "bun:test";
import { BSM, BigNumber, HD, PrivateKey, Utils } from "@bsv/sdk";
import type { Signature } from "@bsv/sdk";
import { MasterID, MemberID } from "../src";
import { ENCRYPTION_PATH, SIGNING_PATH_PREFIX } from "../src/constants";
import { HDPrivateKey, HDPublicKey } from "./data/keys";

// Tests for MasterID (HD keys)
describe("MasterID", () => {
  test("should initialize with random HD private key", () => {
    const randomHDPrivateKey = HD.fromRandom().toString();
    const master = new MasterID(randomHDPrivateKey);
    expect(master.getHdPublicKey()).toMatch(/xpub/);
  });

  test("should throw error when initialized without key", () => {
    expect(() => {
      // @ts-ignore - Testing invalid input
      new MasterID();
    }).toThrow();
  });

  test("should work with known key", () => {
    const master = new MasterID(HDPrivateKey);
    expect(master.getPublicKey()).toBe("02c23e9fc6a959bb5315159ac7438c5a6bff37c7197326d1060b176e3969d72af5");
    expect(master.getHdPublicKey()).toBe(HDPublicKey);
    expect(master.getPublicKey(ENCRYPTION_PATH)).toBe("02fc759e24d922c2d47766710613910c0f40bab7439777af9ad45bff55ec622994");
    expect(master.getHdPublicKey(ENCRYPTION_PATH)).toMatch(/xpub6/);
  });

  test("should set and get BAP_SERVER and BAP_TOKEN", () => {
    const master = new MasterID(HDPrivateKey);
    expect(master.BAP_SERVER).toEqual("https://api.sigmaidentity.com/v1");
    expect(master.BAP_TOKEN).toEqual("");
    const newServer = "https://bapdev.legallychained.com/";
    master.BAP_SERVER = newServer;
    expect(master.BAP_SERVER).toEqual(newServer);
    const newToken = "token_string";
    master.BAP_TOKEN = newToken;
    expect(master.BAP_TOKEN).toEqual(newToken);
  });

  test("should sign and verify attestation with AIP", () => {
    const attrs = {
      name: {
        value: "John Doe",
        nonce: "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa"
      }
    };
    const master = new MasterID(HDPrivateKey, attrs);
    const attestationHash = master.getAttestationHash("name");
    expect(attestationHash).not.toBeNull();
    expect(attestationHash).toBe("d6cbf280ad7515e549c7b154a02555fff3eeb05c6b245039813d39d3c0397b4a");
    const transaction = master.signAttestationWithAIP(attestationHash, master.getIdentityKey());
    expect(typeof transaction).toBe("string");
    const verify = master.verifyAttestationWithAIP(transaction);
    expect(verify.verified).toBe(true);
  });

  test("should verify challenge signature", async () => {
    const privateKey = PrivateKey.fromWif('L4C6X6aJccc5KDzJRTLqskz6gxAwUx9QJVi2S4BZATfdzjw8TUJH');
    const address = privateKey.toAddress();
    const message = 'test message';
    const messageBuffer = Buffer.from(message);
    const msg = Utils.toArray(messageBuffer.toString('hex'), 'hex');
    const dummySig = BSM.sign(msg, privateKey, 'raw') as unknown as Signature;
    const h = new BigNumber(BSM.magicHash(msg));
    const r = dummySig.CalculateRecoveryFactor(privateKey.toPublicKey(), h);
    const signature = dummySig.toCompact(r, true, "base64");
    const master = new MasterID(HDPrivateKey);
    const localVerify = master.verifySignature(message, address.toString(), signature);
    expect(localVerify).toBe(true);

    const originalFetch = global.fetch;
    try {
      global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const mockResponse = {
          status: "success",
          result: {
            valid: true,
            block: 12345,
            timestamp: Date.now()
          }
        };
        return new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }) as typeof global.fetch;
      const result = await master.verifyChallengeSignature(master.getIdentityKey(), address.toString(), message, signature);
      expect(result).toBe(true);
    } finally {
      global.fetch = originalFetch;
    }
  });
});

// Tests for MemberID (single key)
describe("MemberID", () => {
  test("should initialize with a single private key", () => {
    const privKey = PrivateKey.fromWif('L4C6X6aJccc5KDzJRTLqskz6gxAwUx9QJVi2S4BZATfdzjw8TUJH');
    const member = new MemberID(privKey);
    expect(member.getPublicKey()).toMatch(/^02/);
    expect(typeof member.getHdPublicKey).toBe("undefined");
  });

  test("should sign and verify message", () => {
    const privKey = PrivateKey.fromWif('L4C6X6aJccc5KDzJRTLqskz6gxAwUx9QJVi2S4BZATfdzjw8TUJH');
    const member = new MemberID(privKey);
    const message = "Hello, world!";
    const signature = member.sign(message);
    expect(typeof signature).toBe("string");
    const verified = member.verify(message, signature);
    expect(verified).toBe(true);
  });
});
