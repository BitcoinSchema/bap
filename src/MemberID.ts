import {
  PublicKey,
  PrivateKey,
  Hash,
  Utils as BSVUtils,
  ECIES,
} from "@bsv/sdk";
import { BaseClass } from "./BaseClass";
import type { IdentityAttributes, MemberIdentity } from "./interface";
import { ENCRYPTION_PATH, BAP_INVOICE_NUMBER, FRIEND_SECURITY_LEVEL, FRIEND_PROTOCOL } from "./constants";
const { toArray, toUTF8, toBase64, toHex } = BSVUtils;
const { electrumDecrypt, electrumEncrypt } = ECIES;

export class MemberID extends BaseClass {
  private key: PrivateKey;
  public idName: string;
  public description: string;
  public address: string;
  public identityKey: string;
  private counter: number;

  constructor(key: PrivateKey, identityAttributes: IdentityAttributes = {}, counter = 0) {
    super();
    this.key = key;
    this.counter = counter;
    this.address = this.getSigningKey().toPublicKey().toAddress();
    this.idName = "Member ID 1";
    this.description = "";
    this.identityKey = "";
    this.identityAttributes = this.parseAttributes(identityAttributes);
  }

  /**
   * Get the current BRC-100 wallet root key
   * Derived from member key using the rotation counter
   */
  public getCurrentKey(): PrivateKey {
    return this.key.deriveChild(this.key.toPublicKey(), `bap:${this.counter}`);
  }

  /**
   * Get the signing key derived from the current wallet root
   * currentKey → Type42("1-sigma-identity") → signingKey
   */
  public getSigningKey(): PrivateKey {
    const currentKey = this.getCurrentKey();
    return currentKey.deriveChild(currentKey.toPublicKey(), BAP_INVOICE_NUMBER);
  }

  /**
   * Get the member key's public key
   * This is the root key for this member before signing key derivation
   * @returns The member's public key hex string
   */
  public getMemberKey(): string {
    return this.key.toPublicKey().toString();
  }

  /**
   * Get the root address (the member key's address)
   * This is the address used for identity publication and BAP ID derivation
   */
  public getRootAddress(): string {
    return this.key.toPublicKey().toAddress();
  }

  // Signs with the signing key (current key → BAP_INVOICE_NUMBER derivation)
  public signMessage(
    message: number[],
    _signingPath?: string
  ): { address: string; signature: string } {
    return this.signWithBSM(message, this.getSigningKey());
  }

  /**
   * Sign with the root key (member key directly)
   * Used for identity publication and key rotation transactions
   */
  public signMessageWithRootKey(
    message: number[]
  ): { address: string; signature: string } {
    return this.signWithBSM(message, this.key);
  }

  /**
   * Sign OP_RETURN with AIP using the root key
   * Used for identity publication transactions
   */
  public signOpReturnWithAIPUsingRootKey(opReturn: number[][]): number[][] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessageWithRootKey(aipMessageBuffer.flat());
    return this.formatAIPOutput(aipMessageBuffer, address, signature);
  }

  // Sign OP_RETURN with AIP using the signing key
  public signOpReturnWithAIP(opReturn: number[][]): number[][] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(aipMessageBuffer.flat());
    return this.formatAIPOutput(aipMessageBuffer, address, signature);
  }

  // Return the signing public key
  public getPublicKey(): string {
    return this.getSigningKey().toPublicKey().toString();
  }

  public getCounter(): number {
    return this.counter;
  }

  /**
   * Increment the rotation counter
   * This changes the current key and signing key
   */
  public rotate(): void {
    this.counter++;
    this.address = this.getSigningKey().toPublicKey().toAddress();
  }

  public import(identity: MemberIdentity): void {
    this.idName = identity.name;
    this.description = identity.description;
    this.key = PrivateKey.fromWif(identity.derivedPrivateKey);
    this.counter = identity.counter ?? 0;
    this.address = this.getSigningKey().toPublicKey().toAddress();
    this.identityAttributes = identity.identityAttributes || {};
    this.identityKey = identity.identityKey;
  }

  static fromMemberIdentity(identity: MemberIdentity): MemberID {
    const member = new MemberID(PrivateKey.fromWif(identity.derivedPrivateKey), {}, identity.counter ?? 0);
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

  public export(): MemberIdentity {
    return {
      name: this.idName,
      description: this.description,
      derivedPrivateKey: this.key.toWif(),
      address: this.address,
      identityAttributes: this.getAttributes(),
      identityKey: this.identityKey,
      counter: this.counter,
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
   * Uses BRC-43 format: `${securityLevel}-${protocol}-${keyID}`
   * @param seed - The seed string (e.g., friend's BAP ID)
   * @returns The derived private key for this seed
   */
  private getEncryptionPrivateKeyWithSeed(seed: string): PrivateKey {
    // Hash the seed to get a deterministic key ID
    const seedHash = toHex(Hash.sha256(seed, "utf8"));
    // BRC-43 format: security level 2 (counterparty-specific)
    const invoiceNumber = `${FRIEND_SECURITY_LEVEL}-${FRIEND_PROTOCOL}-${seedHash}`;
    // Use Type42 derivation: deriveChild(publicKey, invoice)
    return this.key.deriveChild(this.key.toPublicKey(), invoiceNumber);
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
