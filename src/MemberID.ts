import type { IdentityAttributes } from "./interface";
import { IdentityBase } from "./identityBase";
import { type PrivateKey, BSM, type Signature, BigNumber, Utils as BSVUtils } from "@bsv/sdk";
import { Utils } from "./utils";

const { toArray, toUTF8, toBase64 } = BSVUtils;

export class MemberID extends IdentityBase {
  private key: PrivateKey;

  constructor(key: PrivateKey, attrs?: IdentityAttributes | string) {
    // For single-key mode, use the public address from the key.
    super(attrs);
    this.key = key;
    this.rootAddress = key.toPublicKey().toAddress();
    this.identityKey = this.deriveIdentityKey(this.rootAddress);
  }

  public signMessage(msg: string | Buffer): { address: string; signature: string } {
    const address = this.key.toPublicKey().toAddress();
    const msgBuffer = typeof msg === "string" ? Buffer.from(msg, "utf8") : msg;
    const msgArray = toArray(msgBuffer.toString("hex"), "hex");
    const dummySig = BSM.sign(msgArray, this.key, "raw") as Signature;
    const h = new BigNumber(BSM.magicHash(msgArray));
    const r = dummySig.CalculateRecoveryFactor(this.key.toPublicKey(), h);
    const signature = (BSM.sign(msgArray, this.key, "raw") as Signature).toCompact(r, true, "base64") as string;
    return { address, signature };
  }

  // The following encryption methods are not supported in single key mode.
  public getEncryptionPublicKey(): string {
    throw new Error("Encryption not supported in single key mode");
  }
  public getEncryptionPublicKeyWithSeed(seed: string): string {
    throw new Error("Encryption with seed not supported in single key mode");
  }
  public encrypt(stringData: string, counterPartyPublicKey?: string): string {
    throw new Error("Encryption not supported in single key mode");
  }
  public decrypt(ciphertext: string, counterPartyPublicKey?: string): string {
    throw new Error("Decryption not supported in single key mode");
  }
  public encryptWithSeed(stringData: string, seed: string, counterPartyPublicKey?: string): string {
    throw new Error("Encryption with seed not supported in single key mode");
  }
  public decryptWithSeed(ciphertext: string, seed: string, counterPartyPublicKey?: string): string {
    throw new Error("Decryption with seed not supported in single key mode");
  }
}