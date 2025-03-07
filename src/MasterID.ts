import { BSM, Utils as BSVUtils, ECIES, Hash, PublicKey, type PrivateKey, BigNumber } from "@bsv/sdk";
import type { HD, Signature } from "@bsv/sdk";

import { type APIFetcher, apiFetcher } from "./api";
import type { GetAttestationResponse, GetSigningKeysResponse } from "./apiTypes";
import {
  AIP_BITCOM_ADDRESS,
  BAP_BITCOM_ADDRESS,
  BAP_SERVER,
  ENCRYPTION_PATH,
  MAX_INT,
  SIGNING_PATH_PREFIX,
} from "./constants";
import type {
  Identity,
  IdentityAttribute,
  IdentityAttributes,
  OldIdentity,
  MemberIdentity,
} from "./interface";
import { Utils } from "./utils";
import { MemberID } from './MemberID';
import { BaseClass } from "./BaseClass";
const { toArray, toHex, toBase58, toUTF8, toBase64 } = BSVUtils;
const { electrumDecrypt, electrumEncrypt } = ECIES;
const { magicHash } = BSM;
/**
 * MasterID class
 *
 * This class should be used in conjunction with the BAP class
 *
 * @type {MasterID}
 */
class MasterID extends BaseClass {
  #HDPrivateKey: HD;
  #BAP_SERVER: string = BAP_SERVER;
  #BAP_TOKEN = "";
  #rootPath: string;
  #previousPath: string;
  #currentPath: string;
  #idSeed: string;

  idName: string;
  description: string;

  rootAddress: string;
  identityKey: string;
  identityAttributes: IdentityAttributes;

  getApiData: APIFetcher

  constructor(
    HDPrivateKey: HD,
    identityAttributes: IdentityAttributes = {},
    idSeed = "",
  ) {
    super();
    
    if (idSeed) {
      // create a new HDPrivateKey based on the seed
      const seedHex = toHex(Hash.sha256(idSeed, "utf8"));
      const seedPath = Utils.getSigningPathFromHex(seedHex);
      this.#HDPrivateKey = HDPrivateKey.derive(seedPath);
    } else {
      this.#HDPrivateKey = HDPrivateKey;
    }

    this.#idSeed = idSeed;
    this.idName = "ID 1";
    this.description = "";

    this.#rootPath = `${SIGNING_PATH_PREFIX}/0/0/0`;
    this.#previousPath = `${SIGNING_PATH_PREFIX}/0/0/0`;
    this.#currentPath = `${SIGNING_PATH_PREFIX}/0/0/1`;

    const rootChild = this.#HDPrivateKey.derive(this.#rootPath);
    this.rootAddress = rootChild.privKey.toPublicKey().toAddress();
    this.identityKey = this.deriveIdentityKey(this.rootAddress);

    // unlink the object
    const attributes = { ...identityAttributes };
    this.identityAttributes = this.parseAttributes(attributes);

    this.getApiData = apiFetcher(this.#BAP_SERVER, this.#BAP_TOKEN);
  }

  set BAP_SERVER(bapServer) {
    this.#BAP_SERVER = bapServer;
  }

  get BAP_SERVER(): string {
    return this.#BAP_SERVER;
  }

  set BAP_TOKEN(token) {
    this.#BAP_TOKEN = token;
  }

  get BAP_TOKEN(): string {
    return this.#BAP_TOKEN;
  }

  deriveIdentityKey(address: string): string {
    // base58( ripemd160 ( sha256 ( rootAddress ) ) )
    const rootAddressHash = toHex(Hash.sha256(address, "utf8"));
    return toBase58(Hash.ripemd160(rootAddressHash, "hex"));
  }

  /**
   * Helper function to parse identity attributes
   *
   * @param identityAttributes
   * @returns {{}}
   */
  parseAttributes(
    identityAttributes: IdentityAttributes | string,
  ): IdentityAttributes {
    if (typeof identityAttributes === "string") {
      return this.parseStringUrns(identityAttributes);
    }

    for (const key in identityAttributes) {
      if (!identityAttributes[key].value || !identityAttributes[key].nonce) {
        throw new Error("Invalid identity attribute");
      }
    }

    return identityAttributes || {};
  }

  /**
   * Parse a text of urn string into identity attributes
   *
   * urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
   * urn:bap:id:birthday:1990-05-22:e61f23cbbb2284842d77965e2b0e32f0ca890b1894ca4ce652831347ee3596d9
   * urn:bap:id:over18:1:480ca17ccaacd671b28dc811332525f2f2cd594d8e8e7825de515ce5d52d30e8
   *
   * @param urnIdentityAttributes
   */
  parseStringUrns(urnIdentityAttributes: string): IdentityAttributes {
    const identityAttributes: IdentityAttributes = {};
    // avoid forEach

    const attributesRaw = urnIdentityAttributes
      .replace(/^\s+/g, "")
      .replace(/\r/gm, "")
      .split("\n");

    for (const line of attributesRaw) {
      // remove any whitespace from the string (trim)
      const attribute = line.replace(/^\s+/g, "").replace(/\s+$/g, "");
      const urn = attribute.split(":");
      if (
        urn[0] === "urn" &&
        urn[1] === "bap" &&
        urn[2] === "id" &&
        urn[3] &&
        urn[4] &&
        urn[5]
      ) {
        identityAttributes[urn[3]] = {
          value: urn[4],
          nonce: urn[5],
        };
      }
    }

    return identityAttributes;
  }

  /**
   * Returns the identity key
   *
   * @returns {*|string}
   */
  getIdentityKey(): string {
    return this.identityKey;
  }

  /**
   * This should be called with the last part of the signing path (/.../.../...)
   * This library assumes the first part is m/424150'/0'/0' as defined at the top of this file
   *
   * @param path The second path of the signing path in the format [0-9]{0,9}/[0-9]{0,9}/[0-9]{0,9}
   */
  set rootPath(path: string) {
    if (this.#HDPrivateKey) {
      let pathToUse = path;
      if (path.split("/").length < 5) {
        pathToUse = `${SIGNING_PATH_PREFIX}${path}`;
      }

      if (!this.validatePath(pathToUse)) {
        throw new Error(`invalid signing path given ${pathToUse}`);
      }

      this.#rootPath = pathToUse;

      const derivedChild = this.#HDPrivateKey.derive(pathToUse);
      this.rootAddress = derivedChild.pubKey.toAddress();
      // Identity keys should be derivatives of the root address - this allows checking
      // of the creation transaction
      this.identityKey = this.deriveIdentityKey(this.rootAddress);

      // we also set this previousPath / currentPath to the root as we seem to be (re)setting this ID
      this.#previousPath = pathToUse;
      this.#currentPath = pathToUse;
    }
  }

  get rootPath(): string {
    return this.#rootPath;
  }

  getRootPath(): string {
    return this.#rootPath;
  }

  /**
   * This should be called with the last part of the signing path (/.../.../...)
   * This library assumes the first part is m/424150'/0'/0' as defined at the top of this file
   *
   * @param path The second path of the signing path in the format [0-9]{0,9}/[0-9]{0,9}/[0-9]{0,9}
   */
  set currentPath(path) {
    let pathToUse = path;
    if (path.split("/").length < 5) {
      pathToUse = `${SIGNING_PATH_PREFIX}${path}`;
    }

    if (!this.validatePath(pathToUse)) {
      throw new Error("invalid signing path given");
    }

    this.#previousPath = this.#currentPath;
    this.#currentPath = pathToUse;
  }

  get currentPath(): string {
    return this.#currentPath;
  }

  get previousPath(): string {
    return this.#previousPath;
  }

  /**
   * This can be used to break the deterministic way child keys are created to make it harder for
   * an attacker to steal the identites when the root key is compromised. This does however require
   * the seeds to be stored at all times. If the seed is lost, the identity will not be recoverable.
   */
  get idSeed(): string {
    return this.#idSeed;
  }

  /**
   * Increment current path to a new path
   *
   * @returns {*}
   */
  incrementPath(): void {
    this.currentPath = Utils.getNextPath(this.currentPath);
  }

  /**
   * Check whether the given path is a valid path for use with this class
   * The signing paths used here always have a length of 3
   *
   * @param path The last part of the signing path (example "/0/0/1")
   * @returns {boolean}
   */
  validatePath(path: string) {
    /* eslint-disable max-len */
    if (
      path.match(
        /\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?/,
      )
    ) {
      const pathValues = path.split("/");
      if (
        pathValues.length === 7 &&
        Number(pathValues[1].replace("'", "")) <= MAX_INT &&
        Number(pathValues[2].replace("'", "")) <= MAX_INT &&
        Number(pathValues[3].replace("'", "")) <= MAX_INT &&
        Number(pathValues[4].replace("'", "")) <= MAX_INT &&
        Number(pathValues[5].replace("'", "")) <= MAX_INT &&
        Number(pathValues[6].replace("'", "")) <= MAX_INT
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get the OP_RETURN for the initial ID transaction (signed with root address)
   *
   * @returns {[]}
   */
  getInitialIdTransaction() {
    return this.getIdTransaction(this.#rootPath);
  }

  /**
   * Get the OP_RETURN for the ID transaction of the current address / path
   *
   * @returns {[]}
   */
  getIdTransaction(previousPath = "") {
    if (this.#currentPath === this.#rootPath) {
      throw new Error(
        "Current path equals rootPath. ID was probably not initialized properly",
      );
    }

    const opReturn = [
      toArray(BAP_BITCOM_ADDRESS),
      toArray("ID"),
      toArray(this.identityKey),
      toArray(this.getCurrentAddress()),
    ];

    return this.signOpReturnWithAIP(
      opReturn,
      previousPath || this.#previousPath,
    );
  }

  /**
   * Get address for given path
   *
   * @param path
   * @returns {*}
   */
  getAddress(path: string): string {
    const derivedChild = this.#HDPrivateKey.derive(path);
    return derivedChild.privKey.toPublicKey().toAddress();
  }

  /**
   * Get current signing address
   *
   * @returns {*}
   */
  getCurrentAddress(): string {
    return this.getAddress(this.#currentPath);
  }

  /**
   * Get the encryption key pair for this identity
   */
  getEncryptionKey(): { privKey: PrivateKey, pubKey: PublicKey } {
    const HDPrivateKey = this.#HDPrivateKey.derive(this.#rootPath);
    const encryptionKey = HDPrivateKey.derive(ENCRYPTION_PATH).privKey;
    return {
      privKey: encryptionKey,
      pubKey: encryptionKey.toPublicKey()
    };
  }

  /**
   * Get the encryption key using type 42 (different key / incompatible with above)
   */
  getEncryptionKeyType42(): { privKey: PrivateKey, pubKey: PublicKey } {
    const HDPrivateKey = this.#HDPrivateKey.derive(this.#rootPath);
    const encryptionKey = HDPrivateKey.privKey.deriveChild(HDPrivateKey.toPublic().pubKey, ENCRYPTION_PATH);
    return {
      privKey: encryptionKey,
      pubKey: encryptionKey.toPublicKey()
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
   * Get the public key for encrypting data for this identity, using a seed for the encryption
   */
  getEncryptionPublicKeyWithSeed(seed: string): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    return encryptionKey.toPublicKey().toString();
  }

  /**
   * Encrypt the given string data with the identity encryption key
   * @param stringData
   * @param counterPartyPublicKey Optional public key of the counterparty
   * @return string Base64
   */
  encrypt(stringData: string, counterPartyPublicKey?: string): string {
    const HDPrivateKey = this.#HDPrivateKey.derive(this.#rootPath);
    const encryptionKey = HDPrivateKey.derive(ENCRYPTION_PATH).privKey;
    const publicKey = encryptionKey.toPublicKey();
    const pubKey = counterPartyPublicKey
      ? PublicKey.fromString(counterPartyPublicKey)
      : publicKey;
    // @ts-ignore - remove this when SDK is updated
    return toBase64(electrumEncrypt(toArray(stringData), pubKey, null));
  }

  /**
   * Decrypt the given ciphertext with the identity encryption key
   * @param ciphertext
   */
  decrypt(ciphertext: string, counterPartyPublicKey?: string): string {
    const HDPrivateKey = this.#HDPrivateKey.derive(this.#rootPath);
    const encryptionKey = HDPrivateKey.derive(ENCRYPTION_PATH).privKey;
    let pubKey = undefined
    if (counterPartyPublicKey) {
      pubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(electrumDecrypt(toArray(ciphertext, "base64"), encryptionKey, pubKey));
  }

  /**
   * Encrypt the given string data with the identity encryption key
   * @param stringData
   * @param seed String seed
   * @param counterPartyPublicKey Optional public key of the counterparty
   * @return string Base64
   */
  encryptWithSeed(
    stringData: string,
    seed: string,
    counterPartyPublicKey?: string,
  ): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    const publicKey = encryptionKey.toPublicKey();
    const pubKey = counterPartyPublicKey
      ? PublicKey.fromString(counterPartyPublicKey)
      : publicKey;
    return toBase64(electrumEncrypt(toArray(stringData), pubKey, encryptionKey));
  }

  /**
   * Decrypt the given ciphertext with the identity encryption key
   * @param ciphertext
   * @param seed String seed
  //  * @param counterPartyPublicKey Public key of the counterparty
   */
  decryptWithSeed(ciphertext: string, seed: string, counterPartyPublicKey?: string): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    let pubKey = undefined
    if (counterPartyPublicKey) {
      pubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(electrumDecrypt(toArray(ciphertext, "base64"), encryptionKey, pubKey));
  }

  private getEncryptionPrivateKeyWithSeed(seed: string) {
    const pathHex = toHex(Hash.sha256(seed, "utf8"));
    const path = Utils.getSigningPathFromHex(pathHex);

    const HDPrivateKey = this.#HDPrivateKey.derive(this.#rootPath);
    return HDPrivateKey.derive(path).privKey;
  }

  /**
   * Get an attestation string for the given urn for this identity
   *
   * @param urn
   * @returns {string}
   */
  getAttestation(urn: string) {
    const urnHash = Hash.sha256(urn, "utf8");
    return `bap:attest:${toHex(urnHash)}:${this.getIdentityKey()}`;
  }

  /**
   * Generate and return the attestation hash for the given attribute of this identity
   *
   * @param attribute Attribute name (name, email etc.)
   * @returns {string}
   */
  getAttestationHash(attribute: string) {
    const urn = this.getAttributeUrn(attribute);
    if (!urn) return null;

    const attestation = this.getAttestation(urn);
    const attestationHash = Hash.sha256(attestation, "utf8");

    return toHex(attestationHash);
  }

  /**
   * Sign a message with the current signing address of this identity
   *
   * @param message
   * @param signingPath
   * @returns {{address: string, signature: string}}
   */
  signMessage(message: number[], signingPath?: string): { address: string; signature: string } {
    const pathToUse = signingPath || this.#currentPath;
    const childPk = this.#HDPrivateKey.derive(pathToUse).privKey;
    const address = childPk.toAddress();

    // Needed to calculate the recovery factor
    const dummySig = BSM.sign(message, childPk, 'raw') as Signature;
    const h = new BigNumber(magicHash(message));
    const r = dummySig.CalculateRecoveryFactor(
      childPk.toPublicKey(),
      h,
    );
    const signature = (BSM.sign(message, childPk, 'raw') as Signature).toCompact(
      r,
      true,
      "base64"
    ) as string;

    return { address, signature };
  }

  /**
   * Sign a message using a key based on the given string seed
   *
   * This works by creating a private key from the root key of this identity. It will always
   * work with the rootPath / rootKey, to be deterministic. It will not change even if the keys
   * are rotated for this ID.
   *
   * This is used in for instance deterministic login systems, that do not support BAP.
   *
   * @param message
   * @param seed {string} String seed that will be used to generate a path
   */
  signMessageWithSeed(
    message: string,
    seed: string,
  ): { address: string; signature: string } {
    const pathHex = toHex(Hash.sha256(seed, "utf8"));
    const path = Utils.getSigningPathFromHex(pathHex);

    const HDPrivateKey = this.#HDPrivateKey.derive(this.#rootPath);
    const derivedChild = HDPrivateKey.derive(path);
    const address = derivedChild.privKey.toPublicKey().toAddress();

    const messageArray = toArray(message, "utf8");
    const dummySig = BSM.sign(messageArray, derivedChild.privKey, 'raw') as Signature;

    const h = new BigNumber(magicHash(messageArray));
    const r = dummySig.CalculateRecoveryFactor(
      derivedChild.privKey.toPublicKey(),
      h,
    );

    const signature = (BSM.sign(messageArray, derivedChild.privKey, 'raw') as Signature).toCompact(
      r,
      true,
      "base64"
    ) as string;

    return { address, signature };
  }

  /**
   * Sign an op_return hex array with AIP
   * @param opReturn {array}
   * @param signingPath {string}
   * @return {number[]}
   */
  signOpReturnWithAIP(
    opReturn: number[][],
    signingPath = "",
  ): number[][] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(aipMessageBuffer.flat(), signingPath);
    return this.formatAIPOutput(opReturn, address, signature);
  }

  /**
   * Get all signing keys for this identity
   */
  async getIdSigningKeys(): Promise<GetSigningKeysResponse> {
    const signingKeys = await this.getApiData<GetSigningKeysResponse>("/signing-keys", {
      idKey: this.identityKey,
    });
    console.log("getIdSigningKeys", signingKeys);

    return signingKeys;
  }

  /**
   * Get all attestations for the given attribute
   *
   * @param attribute
   */
  async getAttributeAttestations(attribute: string): Promise<GetAttestationResponse> {
    // This function needs to make a call to a BAP server to get all the attestations for this
    // identity for the given attribute
    const attestationHash = this.getAttestationHash(attribute);

    // get all BAP ATTEST records for the given attestationHash
    const attestations = await this.getApiData<GetAttestationResponse>("/attestation/get", {
      hash: attestationHash,
    });
    console.log("getAttestations", attribute, attestationHash, attestations);

    return attestations;
  }

  /**
   * Import an identity from a JSON object
   *
   * @param identity{{}}
   */
  import(identity: Identity | OldIdentity): void {
    this.idName = identity.name;
    this.description = identity.description || "";
    this.identityKey = identity.identityKey;
    this.#rootPath = identity.rootPath;
    this.rootAddress = identity.rootAddress;
    this.#previousPath = identity.previousPath;
    this.#currentPath = identity.currentPath;
    this.#idSeed = ('idSeed' in identity ? identity.idSeed : "") || "";
    this.identityAttributes = this.parseAttributes(identity.identityAttributes);
  }

  /**
   * Export this identity to a JSON object
   * @returns {{}}
   */
  export(): Identity {
    return {
      name: this.idName,
      description: this.description,
      identityKey: this.identityKey,
      rootPath: this.#rootPath,
      rootAddress: this.rootAddress,
      previousPath: this.#previousPath,
      currentPath: this.#currentPath,
      idSeed: this.#idSeed,
      identityAttributes: this.getAttributes(),
      lastIdPath: "",
    };
  }

  // New method to export a member-friendly backup, containing only the derived signing key
  exportMemberBackup(): MemberIdentity {
    const derivedKey = this.#HDPrivateKey.derive(this.#currentPath).privKey;
    return {
      name: this.idName,
      description: this.description,
      derivedPrivateKey: derivedKey.toWif(),
      address: derivedKey.toPublicKey().toAddress(),
      identityAttributes: this.getAttributes(),
      identityKey: this.identityKey,
    };
  }

  // New method to derive a new member ID from the master HD key
  public newId(): MemberID {
    // Assuming incrementPath updates the internal current path
    this.incrementPath();
    const derivedKey = this.#HDPrivateKey.derive(this.#currentPath).privKey;
    return new MemberID(derivedKey);
  }
}
export { MasterID };

