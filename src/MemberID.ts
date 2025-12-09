import {
  BSM,
  PublicKey,
  PrivateKey,
  BigNumber,
  Hash,
  Utils as BSVUtils,
  ECIES,
} from "@bsv/sdk";
import type { Signature } from "@bsv/sdk";
import { BaseClass } from "./BaseClass";
import type { IdentityAttributes, MemberIdentity } from "./interface";
import { ENCRYPTION_PATH } from "./constants";
const { magicHash } = BSM;
const { toArray, toUTF8, toBase64, toHex } = BSVUtils;
const { electrumDecrypt, electrumEncrypt } = ECIES;

export class MemberID extends BaseClass {
  private key: PrivateKey;
  public idName: string;
  public description: string;
  public address: string;
  public identityKey: string;

  constructor(key: PrivateKey, identityAttributes: IdentityAttributes = {}) {
    super();
    this.key = key;
    this.address = key.toAddress();
    this.idName = "Member ID 1";
    this.description = "";
    this.identityKey = "";
    this.identityAttributes = this.parseAttributes(identityAttributes);
  }

  // Implement the abstract signMessage method from BaseClass
  public signMessage(
    message: number[],
    _signingPath?: string
  ): { address: string; signature: string } {
    const childPk = this.key;
    const address = childPk.toAddress();

    // Sign using the raw message buffer directly
    const dummySig = BSM.sign(message, childPk, "raw") as Signature;
    const h = new BigNumber(magicHash(message));
    const r = dummySig.CalculateRecoveryFactor(childPk.toPublicKey(), h);

    const signature = (
      BSM.sign(message, childPk, "raw") as Signature
    ).toCompact(r, true, "base64") as string;

    return { address, signature };
  }

  // Implement signOpReturnWithAIP - MemberID ignores signing path
  public signOpReturnWithAIP(opReturn: number[][]): number[][] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(aipMessageBuffer.flat());
    return this.formatAIPOutput(aipMessageBuffer, address, signature);
  }

  // Return the member's public key
  public getPublicKey(): string {
    return this.key.toPublicKey().toString();
  }

  // Import the member identity from an object containing the derived private key and identity data
  public import(identity: MemberIdentity): void {
    this.idName = identity.name;
    this.description = identity.description;
    this.key = PrivateKey.fromWif(identity.derivedPrivateKey);
    this.address = this.key.toAddress();
    this.identityAttributes = identity.identityAttributes || {};
    this.identityKey = identity.identityKey;
  }

  static fromMemberIdentity(identity: MemberIdentity): MemberID {
    const member = new MemberID(PrivateKey.fromWif(identity.derivedPrivateKey));
    member.import(identity);
    return member;
  }

  static fromBackup(singleBackup: { wif: string; id: string }): MemberID {
    // decrypt the id and set the details
    const member = new MemberID(PrivateKey.fromWif(singleBackup.wif));
    const id = JSON.parse(member.decrypt(singleBackup.id));
    member.import(id);
    return member;
  }

  // Export the member identity as an object containing the derived private key and identity data
  public export(): MemberIdentity {
    return {
      name: this.idName,
      description: this.description,
      derivedPrivateKey: this.key.toWif(),
      address: this.address,
      identityAttributes: this.getAttributes(),
      identityKey: this.identityKey,
    };
  }

  /**
   * Get the encryption key pair for this identity
   * We use the same key for both signing and encryption for simplicity
   */
  getEncryptionKey(): { privKey: PrivateKey; pubKey: PublicKey } {
    // Derive the encryption key from the private key using the ENCRYPTION_PATH
    // Since member keys are not HD keys, we use the path as the invoice number,
    // and use our own public key as the other party's public key
    return {
      privKey: this.key.deriveChild(this.key.toPublicKey(), ENCRYPTION_PATH),
      pubKey: this.key
        .deriveChild(this.key.toPublicKey(), ENCRYPTION_PATH)
        .toPublicKey(),
    };
  }

  /**
   * Get the public key for encrypting data for this identity
   */
  getEncryptionPublicKey(): string {
    const { pubKey } = this.getEncryptionKey();
    return pubKey.toString();
  }

  /**
   * Get a derived encryption key using a seed string (Type42 derivation)
   * This allows deriving unique encryption keys per friend/conversation
   * @param seed - The seed string (e.g., friend's BAP ID)
   * @returns The derived private key for this seed
   */
  private getEncryptionPrivateKeyWithSeed(seed: string): PrivateKey {
    // Hash the seed to get a deterministic value
    const seedHash = toHex(Hash.sha256(seed, "utf8"));
    // Use Type42 derivation: deriveChild(publicKey, invoice)
    return this.key.deriveChild(this.key.toPublicKey(), seedHash);
  }

  /**
   * Get the encryption key pair for a specific seed
   * @param seed - The seed string (e.g., friend's BAP ID)
   */
  getEncryptionKeyWithSeed(seed: string): { privKey: PrivateKey; pubKey: PublicKey } {
    const privKey = this.getEncryptionPrivateKeyWithSeed(seed);
    return {
      privKey,
      pubKey: privKey.toPublicKey(),
    };
  }

  /**
   * Get the public key for encrypting data for a specific seed
   * This is the public key to include in friend requests
   * @param seed - The seed string (e.g., friend's BAP ID)
   */
  getEncryptionPublicKeyWithSeed(seed: string): string {
    return this.getEncryptionPrivateKeyWithSeed(seed).toPublicKey().toString();
  }

  /**
   * Encrypt data using a seed-derived key
   * @param stringData - The data to encrypt
   * @param seed - The seed string for key derivation (e.g., friend's BAP ID)
   * @param counterPartyPublicKey - Optional public key of the recipient
   * @returns Base64 encoded encrypted data
   */
  encryptWithSeed(stringData: string, seed: string, counterPartyPublicKey?: string): string {
    const derivedKey = this.getEncryptionPrivateKeyWithSeed(seed);
    const pubKey = derivedKey.toPublicKey();
    // Import PublicKey type-safely - counterPartyPublicKey is already a hex pubkey string
    const PublicKeyClass = this.key.toPublicKey().constructor as typeof import("@bsv/sdk").PublicKey;
    const targetPubKey = counterPartyPublicKey
      ? PublicKeyClass.fromString(counterPartyPublicKey)
      : pubKey;
    return toBase64(electrumEncrypt(toArray(stringData), targetPubKey, derivedKey));
  }

  /**
   * Decrypt data using a seed-derived key
   * @param ciphertext - Base64 encoded encrypted data
   * @param seed - The seed string for key derivation (e.g., friend's BAP ID)
   * @param counterPartyPublicKey - Optional public key of the sender
   * @returns Decrypted string
   */
  decryptWithSeed(ciphertext: string, seed: string, counterPartyPublicKey?: string): string {
    const derivedKey = this.getEncryptionPrivateKeyWithSeed(seed);
    let senderPubKey: PublicKey | undefined;
    if (counterPartyPublicKey) {
      senderPubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(electrumDecrypt(toArray(ciphertext, "base64"), derivedKey, senderPubKey));
  }

  /**
   * Export member data in bitcoin-backup compatible format
   * @param label Optional user-defined label
   * @returns BapMemberBackup compatible object
   */
  exportForBackup(label?: string): {
    wif: string;
    id: string;
    label?: string;
    createdAt: string;
  } {
    const memberData = this.export();
    const encryptedData = this.encrypt(JSON.stringify(memberData));

    return {
      wif: this.key.toWif(),
      id: encryptedData,
      ...(label && { label }),
      createdAt: new Date().toISOString(),
    };
  }
}
