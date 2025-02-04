import type { IdentityAttributes } from "./interface";
import { Utils } from "./utils";
import { Hash, Utils as BSVUtils } from "@bsv/sdk";
const { toHex, toBase58 } = BSVUtils;

export abstract class IdentityBase {
  public name = "ID 1";
  public description = "";
  public identityAttributes: IdentityAttributes = {};
  public identityKey: string;
  // Note: we no longer throw if rootAddress is not yet set.
  // The subclass (MasterID or MemberID) must assign rootAddress appropriately.
  public rootAddress = "";

  constructor(attrs?: IdentityAttributes | string) {
    if (attrs) {
      this.identityAttributes = this.parseAttributes(attrs);
    }
    // Do not enforce rootAddress here since the subclass might not have set it yet.
    this.identityKey = this.deriveIdentityKey(this.rootAddress);
  }

  protected parseAttributes(attrs: IdentityAttributes | string): IdentityAttributes {
    if (typeof attrs === "string") {
      return this.parseStringUrns(attrs);
    }
    for (const key in attrs) {
      const attribute = attrs[key];
      if (!attribute.value || !attribute.nonce) {
        throw new Error(`Invalid attribute for key "${key}"`);
      }
    }
    return attrs;
  }

  protected parseStringUrns(urnString: string): IdentityAttributes {
    const result: IdentityAttributes = {};
    const lines = urnString
      .split("\n")
      .map(line => line.trim())
      .filter(line => line.length > 0);
    for (const line of lines) {
      const parts = line.split(":");
      // Expecting format: urn:bap:id:<attributeName>:<attributeValue>:<nonce>
      if (parts.length >= 6 && parts[0] === "urn" && parts[1] === "bap" && parts[2] === "id") {
        const attrName = parts[3];
        const attrValue = parts[4];
        const nonce = parts[5];
        result[attrName] = { value: attrValue, nonce };
      }
    }
    return result;
  }

  protected deriveIdentityKey(address: string): string {
    // identityKey = base58( ripemd160 ( sha256 ( address ) ) )
    // Use Hash.sha256 and Hash.ripemd160 from @bsv/sdk.
    const sha256Hash = toHex(Hash.sha256(address, "utf8"));
    const ripemd160Hash = Hash.ripemd160(sha256Hash, "hex");
    return toBase58(ripemd160Hash);
  }

  public getAttributeUrn(attributeName: string): string | null {
    const attribute = this.identityAttributes[attributeName];
    if (!attribute) return null;
    return `urn:bap:id:${attributeName}:${attribute.value}:${attribute.nonce}`;
  }

  public addAttribute(attributeName: string, value: string, nonce?: string): void {
    const finalNonce = nonce || Utils.getRandomString(32);
    this.identityAttributes[attributeName] = { value, nonce: finalNonce };
  }

  public getAttestation(urn: string): string {
    // Re-create the attestation string as per the original implementation.
    const urnHash = toHex(Hash.sha256(urn, "utf8"));
    return `bap:attest:${urnHash}:${this.identityKey}`;
  }

  public abstract signMessage(msg: string | Buffer): { address: string; signature: string };
}