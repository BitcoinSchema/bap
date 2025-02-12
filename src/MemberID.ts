import { BSM, type Signature, BigNumber, PrivateKey, Utils, Hash } from "@bsv/sdk";

const { toHex, toBase58, toArray } = Utils;
const { magicHash } = BSM;
import type { IdentityAttributes } from "./interface";

export interface MemberIdentity {
  name: string;
  description: string;
  derivedPrivateKey: string;
  address: string;
  identityAttributes: IdentityAttributes;
}

class MemberID {
    private key: PrivateKey;
    public identityAttributes: IdentityAttributes;
    public address: string;
    public idName: string;
    public description: string;

    constructor(key: PrivateKey, identityAttributes: IdentityAttributes | string = {}) {
      this.key = key;
      // If identityAttributes is a string, parse it using parseStringUrns, otherwise use as is
      this.identityAttributes = typeof identityAttributes === 'string' ? this.parseStringUrns(identityAttributes) : identityAttributes;
      this.address = this.key.toAddress();
      this.idName = "Member ID 1";
      this.description = "";
    }

    // Basic message signing using the member's derived private key
    public signMessage(message: string | Buffer): { address: string; signature: string } {
      const msgBuffer = typeof message === 'string' ? Buffer.from(message) : message;
      const childPk = this.key;
      const address = childPk.toPublicKey().toString();
      // Sign using the raw message buffer directly
      const dummySig = BSM.sign(toArray(msgBuffer), childPk, 'raw') as Signature;
      const h = new BigNumber(magicHash(toArray(msgBuffer, "utf8")));
      const r = dummySig.CalculateRecoveryFactor(childPk.toPublicKey(), h);
      const signature = (BSM.sign(toArray(msgBuffer), childPk, 'raw') as Signature).toCompact(r, true, "base64") as string;
      return { address, signature };
    }
  
    // Return the member's public key
    public getPublicKey(): string {
      return this.key.toPublicKey().toString();
    }
  
    // Import the member identity from an object containing the derived private key and identity data
    public import(identity: MemberIdentity): void {
      this.idName = identity.name;
      this.description = identity.description;
      this.key = PrivateKey.fromString(identity.derivedPrivateKey);
      this.address = this.key.toAddress();
      this.identityAttributes = identity.identityAttributes;
    }

    static fromImport(identity: MemberIdentity): MemberID {
      const member = new MemberID(PrivateKey.fromString(identity.derivedPrivateKey));
      member.import(identity);
      return member;
    }

    // Export the member identity as an object containing the derived private key and identity data
    public export(): MemberIdentity {
      return {
        name: this.idName,
        description: this.description,
        derivedPrivateKey: this.key.toString(),
        address: this.address,
        identityAttributes: this.identityAttributes
      } as MemberIdentity;
    }
  
    // Helper to parse identity attributes from a string of URNs
    private parseStringUrns(urnIdentityAttributes: string): IdentityAttributes {
      const attrs: IdentityAttributes = {};
      const lines = urnIdentityAttributes.replace(/^[ \t]+/gm, "").trim().split("\n");
      for (const line of lines) {
        const parts = line.split(":");
        if (parts.length >= 6 && parts[0] === "urn" && parts[1] === "bap" && parts[2] === "id") {
          attrs[parts[3]] = { value: parts[4], nonce: parts[5] };
        }
      }
      return attrs;
    }
  }

  export { MemberID };