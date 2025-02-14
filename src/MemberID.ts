import { BSM, type Signature, BigNumber, PrivateKey, Utils } from "@bsv/sdk";
import { BaseClass } from "./BaseClass";
import type { IdentityAttributes } from "./interface";

const { toHex, toBase58, toArray } = Utils;
const { magicHash } = BSM;

export interface MemberIdentity {
  name: string;
  description: string;
  derivedPrivateKey: string;
  address: string;
  identityAttributes?: IdentityAttributes;
}

export class MemberID extends BaseClass {
  private key: PrivateKey;
  public idName: string;
  public description: string;
  public address: string;

  constructor(key: PrivateKey) {
    super();
    this.key = key;
    this.address = key.toAddress();
    this.idName = "Member ID 1";
    this.description = "";
    this.identityAttributes = {};
  }

  // Implement the abstract signMessage method from BaseClass
  public signMessage(message: number[], _signingPath?: string): { address: string; signature: string } {
    const childPk = this.key;
    const address = childPk.toPublicKey().toString();
    
    // Sign using the raw message buffer directly
    const dummySig = BSM.sign(message, childPk, 'raw') as Signature;
    const h = new BigNumber(magicHash(message));
    const r = dummySig.CalculateRecoveryFactor(childPk.toPublicKey(), h);
    
    const signature = (BSM.sign(message, childPk, 'raw') as Signature).toCompact(
      r,
      true,
      "base64"
    ) as string;
    
    return { address, signature };
  }

  // Implement signOpReturnWithAIP - MemberID ignores signing path
  public signOpReturnWithAIP(
    opReturn: number[][],
    _signingPath?: string,
  ): number[][] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(aipMessageBuffer);
    return this.formatAIPOutput(opReturn, address, signature);
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
    this.identityAttributes = identity.identityAttributes || {};
  }

  static fromBackup(identity: MemberIdentity): MemberID {
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
      identityAttributes: this.getAttributes()
    };
  }
}