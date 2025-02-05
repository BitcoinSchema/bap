/* eslint-disable @typescript-eslint/consistent-type-imports */

/**
 * @fileoverview Disable consistent-type-imports rule for BSV SDK imports
 */

import { type PrivateKey, BSM, Signature, BigNumber, Utils as BSVUtils, PublicKey, ECIES } from "@bsv/sdk";

const { toArray, toBase64, toUTF8, toHex } = BSVUtils;

import type { IdentityAttributes, MemberIdentity } from "./interface";
import { IdentityBase } from "./identityBase";

export class MemberID extends IdentityBase implements MemberIdentity {
  private readonly key: PrivateKey;
  public idSeed = "";

  constructor(key: PrivateKey, attrs?: IdentityAttributes | string) {
    super(attrs);
    this.key = key;
    this.rootAddress = key.toPublicKey().toAddress();
    this.identityKey = this.deriveIdentityKey(this.rootAddress);
  }

  public signMessage(msg: string | Buffer): { address: string; signature: string } {
    const address = this.key.toAddress();
    const msgBuffer = typeof msg === "string" ? Buffer.from(msg, "utf8") : msg;
    const msgArray = toArray(msgBuffer.toString("hex"), "hex");
    const dummySig = BSM.sign(msgArray, this.key, "raw") as Signature;
    const h = new BigNumber(BSM.magicHash(msgArray));
    const r = dummySig.CalculateRecoveryFactor(this.key.toPublicKey(), h);
    const signature = (BSM.sign(msgArray, this.key, "raw") as Signature).toCompact(r, true, "base64") as string;
    return { address, signature };
  }

  public encrypt(stringData: string, encryptionKey: PrivateKey, counterPartyPublicKey?: string): string {
    const publicKey = encryptionKey.toPublicKey();
    const pubKey = counterPartyPublicKey ? PublicKey.fromString(counterPartyPublicKey) : publicKey;
    return toBase64(ECIES.electrumEncrypt(toArray(stringData), pubKey, encryptionKey));
  }

  public decrypt(ciphertext: string, encryptionKey: PrivateKey, counterPartyPublicKey?: string): string {
    let pubKey: PublicKey | undefined;
    if (counterPartyPublicKey) {
      pubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(ECIES.electrumDecrypt(toArray(ciphertext, "base64"), encryptionKey, pubKey));
  }

  export(): object {
    return {
      idSeed: this.idSeed || "",
      rootAddress: this.rootAddress,
      identityAttributes: this.identityAttributes,
      derivedPrivateKey: this.derivedPrivateKey
    };
  }

  get derivedPrivateKey(): string {
    return this.key.toString();
  }

  public sign(message: string): string {
    return this.signMessage(message).signature;
  }

  public verify(message: string, signature: string): boolean {
    const address = this.key.toAddress();
    return this.verifySignature(message, address, signature);
  }

  public verifySignature(message: string | Buffer, address: string, signature: string): boolean {
    const msgBuffer = typeof message === "string" ? Buffer.from(message, "utf8") : message;
    const msgArray = toArray(msgBuffer.toString("hex"), "hex");
    try {
      const sigFromCompact = Signature.fromCompact(signature, "base64");
      for (let recovery = 0; recovery < 4; recovery++) {
        try {
          const publicKey = sigFromCompact.RecoverPublicKey(recovery, new BigNumber(BSM.magicHash(msgArray)));
          if (BSM.verify(msgArray, sigFromCompact, publicKey) && publicKey.toAddress() === address) {
            return true;
          }
        } catch (e) {
          // try next recovery factor
        }
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  public getPublicKey(): string {
    return this.key.toPublicKey().toString();
  }

  // Implementing encryption methods for MemberID
  public getEncryptionPublicKey(): string {
    return this.key.toPublicKey().toString();
  }

  public getEncryptionPublicKeyWithSeed(seed: string): string {
    throw new Error("HDPrivateKey not set");
  }

  public encryptWithSeed(stringData: string, seed: string): string {
    throw new Error("HDPrivateKey not set");
  }

  public decryptWithSeed(ciphertext: string, seed: string): string {
    throw new Error("HDPrivateKey not set");
  }
}