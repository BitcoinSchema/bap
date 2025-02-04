import { BSM, Utils as BSVUtils, BigNumber, ECIES, HD, Hash, type PrivateKey, PublicKey, type Signature } from "@bsv/sdk";
import { type APIFetcher, apiFetcher } from "./api";
import type { GetAttestationResponse, GetSigningKeysResponse } from "./apiTypes";
import {
  AIP_BITCOM_ADDRESS,
  BAP_BITCOM_ADDRESS,
  BAP_SERVER,
  ENCRYPTION_PATH,
  MAX_INT,
  SIGNING_PATH_PREFIX
} from "./constants";
import type {
  Identity,
  IdentityAttribute,
  IdentityAttributes,
  OldIdentity
} from "./interface";
import { Utils } from "./utils";
const { toArray, toHex, toBase58, toUTF8, toBase64 } = BSVUtils;
const { electrumDecrypt, electrumEncrypt } = ECIES;
const { magicHash } = BSM;
/**
 * BAP_ID class
 *
 * This class should be used in conjunction with the BAP class
 *
 * @type {BAP_ID}
 */
export class BAP_ID {
  #HDPrivateKey?: HD;
  #singlePrivateKey?: PrivateKey;
  #rootPath?: string;
  #currentPath?: string;
  #previousPath?: string;
  lastIdPath = "";
  #idSeed: string;
  name: string;
  description: string;
  identityKey: string;
  rootAddress: string;
  identityAttributes: IdentityAttributes;
  private BAP_SERVER_: string;
  private BAP_TOKEN_: string;
  getApiData: APIFetcher;

  constructor(
    key: HD | PrivateKey,
    identityAttributes: IdentityAttributes = {},
    idSeed = "",
  ) {
    this.#idSeed = idSeed;
    this.BAP_SERVER_ = BAP_SERVER;
    this.BAP_TOKEN_ = "";
    this.getApiData = apiFetcher(this.BAP_SERVER_, this.BAP_TOKEN_);
    this.name = "ID 1";
    this.description = "";

    if (key instanceof HD) {
      this.#HDPrivateKey = key;
      if (idSeed) {
        const seedHex = toHex(Hash.sha256(idSeed, "utf8"));
        const seedPath = Utils.getSigningPathFromHex(seedHex);
        this.#HDPrivateKey = key.derive(seedPath);
      }

      this.rootPath = `${SIGNING_PATH_PREFIX}/0/0/0`;
      this.#previousPath = this.rootPath;
      this.#currentPath = `${SIGNING_PATH_PREFIX}/0/0/1`;

      const rootChild = this.#HDPrivateKey.derive(this.rootPath);
      this.rootAddress = rootChild.privKey.toPublicKey().toAddress();
    } else {
      this.#singlePrivateKey = key;
      this.rootAddress = key.toPublicKey().toAddress();
    }

    this.identityKey = this.deriveIdentityKey(this.rootAddress);

    // Deep clone the attributes to unlink the object
    const attributes = JSON.parse(JSON.stringify(identityAttributes));
    this.identityAttributes = this.parseAttributes(attributes);
  }

  get BAP_SERVER(): string {
    return this.BAP_SERVER_;
  }

  set BAP_SERVER(value: string) {
    this.BAP_SERVER_ = value;
    this.getApiData = apiFetcher(this.BAP_SERVER_, this.BAP_TOKEN_);
  }

  get BAP_TOKEN(): string {
    return this.BAP_TOKEN_;
  }

  set BAP_TOKEN(value: string) {
    this.BAP_TOKEN_ = value;
    this.getApiData = apiFetcher(this.BAP_SERVER_, this.BAP_TOKEN_);
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
   * Returns all the attributes in the identity
   *
   * @returns {*}
   */
  getAttributes(): IdentityAttributes {
    return this.identityAttributes;
  }

  /**
   * Get the value of the given attribute
   *
   * @param attributeName
   * @returns {{}|null}
   */
  getAttribute(attributeName: string): IdentityAttribute | null {
    if (this.identityAttributes[attributeName]) {
      return this.identityAttributes[attributeName];
    }

    return null;
  }

  /**
   * Set the value of the given attribute
   *
   * If an empty value ('' || null || false) is given, the attribute is removed from the ID
   *
   * @param attributeName string
   * @param attributeValue any
   * @returns {{}|null}
   */
  setAttribute(attributeName: string, attributeValue: string | Record<string, string>): void {
    if (!attributeValue) {
      return;
    }

    if (this.identityAttributes[attributeName]) {
      this.updateExistingAttribute(attributeName, attributeValue);
    } else {
      this.createNewAttribute(attributeName, attributeValue);
    }
  }

  private updateExistingAttribute(
    attributeName: string,
    attributeValue: string | Record<string, string>
  ): void {
    if (typeof attributeValue === 'string') {
      this.identityAttributes[attributeName].value = attributeValue;
      return;
    }

    this.identityAttributes[attributeName].value = attributeValue.value || '';
    if (attributeValue.nonce) {
      this.identityAttributes[attributeName].nonce = attributeValue.nonce;
    }
  }

  private createNewAttribute(
    attributeName: string,
    attributeValue: string | Record<string, string>
  ): void {
    if (typeof attributeValue === 'string') {
      this.addAttribute(attributeName, attributeValue);
      return;
    }

    this.addAttribute(
      attributeName,
      attributeValue.value || '',
      attributeValue.nonce
    );
  }

  /**
   * Unset the given attribute from the ID
   *
   * @param attributeName
   * @returns {{}|null}
   */
  unsetAttribute(attributeName: string): void {
    delete this.identityAttributes[attributeName];
  }

  /**
   * Get all attribute urn's for this id
   *
   * @returns {string}
   */
  getAttributeUrns(): string {
    let urns = "";
    for (const key in this.identityAttributes) {
      const urn = this.getAttributeUrn(key);
      if (urn) {
        urns += `${urn}\n`;
      }
    }

    return urns;
  }

  /**
   * Create an return the attribute urn for the given attribute
   *
   * @param attributeName
   * @returns {string|null}
   */
  getAttributeUrn(attributeName: string): string | null {
    const attribute = this.identityAttributes[attributeName];
    if (attribute) {
      return `urn:bap:id:${attributeName}:${attribute.value}:${attribute.nonce}`;
    }

    return null;
  }

  /**
   * Add an attribute to this identity
   *
   * @param attributeName
   * @param value
   * @param nonce
   */
  addAttribute(attributeName: string, value: string, nonce = ""): void {
    let nonceToUse = nonce;
    if (!nonce) {
      nonceToUse = Utils.getRandomString();
    }

    this.identityAttributes[attributeName] = {
      value,
      nonce: nonceToUse,
    };
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
    if (!this.#rootPath) {
      throw new Error("rootPath not set");
    }

    return this.#rootPath;
  }

  getRootPath(): string {
    if (!this.#rootPath) {
      throw new Error("rootPath not set");
    }

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
    if (!this.#currentPath) {
      throw new Error("currentPath not set");
    }

    return this.#currentPath;
  }

  get previousPath(): string {
    if (!this.#previousPath) {
      throw new Error("previousPath not set");
    }

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
      Buffer.from(BAP_BITCOM_ADDRESS).toString("hex"),
      Buffer.from("ID").toString("hex"),
      Buffer.from(this.identityKey).toString("hex"),
      Buffer.from(this.getCurrentAddress()).toString("hex"),
    ];

    return this.signOpReturnWithAIP(
      opReturn,
      previousPath || this.#previousPath,
    );
  }

  /**
   * Get address for given path. Only works if HDPrivateKey is set
   *
   * @param path
   * @returns {*}
   */
  getAddress(path: string): string {
    if (!this.#HDPrivateKey) {
      throw new Error("HDPrivateKey not set");
    }

    const derivedChild = this.#HDPrivateKey.derive(path);
    return derivedChild.privKey.toPublicKey().toAddress();
  }

  /**
   * Get current signing address
   *
   * @returns {*}
   */
  getCurrentAddress(): string {
    if (!this.#currentPath) {
      // get the address from the single key
      if (!this.#singlePrivateKey) {
        throw new Error("currentPath not set");
      }
      return this.#singlePrivateKey.toPublicKey().toAddress();
    }

    return this.getAddress(this.#currentPath);
  }

  /**
   * Get the encryption public key for this identity
   * This key is derived from the identity's root path + ENCRYPTION_PATH
   */
  getEncryptionPublicKey(): string {
    if (this.#HDPrivateKey) {
      const rootChild = this.#HDPrivateKey.derive(this.rootPath);
      const encryptionChild = rootChild.derive(ENCRYPTION_PATH);
      return encryptionChild.pubKey.toString();
    }
    if (!this.#singlePrivateKey) {
      throw new Error("No private key available for encryption");
    }
    return this.#singlePrivateKey.toPublicKey().toString();
  }

  /**
   * Get the encryption public key for this identity with a seed
   * This key is derived from the identity's root path + ENCRYPTION_PATH + seed path
   */
  getEncryptionPublicKeyWithSeed(seed: string): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    return encryptionKey.toPublicKey().toString();
  }

  /**
   * Encrypt data using this identity's encryption key
   */
  encrypt(stringData: string, counterPartyPublicKey?: string): string {
    if (!this.#HDPrivateKey) {
      throw new Error("HDPrivateKey not set");
    }
    const rootChild = this.#HDPrivateKey.derive(this.rootPath);
    const encryptionKey = rootChild.derive(ENCRYPTION_PATH).privKey;
    const publicKey = encryptionKey.toPublicKey();
    const pubKey = counterPartyPublicKey
      ? PublicKey.fromString(counterPartyPublicKey)
      : publicKey;
    return toBase64(electrumEncrypt(toArray(stringData), pubKey, encryptionKey));
  }

  /**
   * Decrypt data using this identity's encryption key
   */
  decrypt(ciphertext: string, counterPartyPublicKey?: string): string {
    if (!this.#HDPrivateKey) {
      throw new Error("HDPrivateKey not set");
    }
    const rootChild = this.#HDPrivateKey.derive(this.rootPath);
    const encryptionKey = rootChild.derive(ENCRYPTION_PATH).privKey;
    let pubKey: PublicKey | undefined;
    if (counterPartyPublicKey) {
      pubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(electrumDecrypt(toArray(ciphertext, "base64"), encryptionKey, pubKey));
  }

  /**
   * Encrypt data using this identity's encryption key with a seed
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
   * Decrypt data using this identity's encryption key with a seed
   */
  decryptWithSeed(ciphertext: string, seed: string, counterPartyPublicKey?: string): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    const publicKey = encryptionKey.toPublicKey();
    let pubKey = publicKey;
    if (counterPartyPublicKey) {
      pubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(electrumDecrypt(toArray(ciphertext, "base64"), encryptionKey, pubKey));
  }

  private getEncryptionPrivateKeyWithSeed(seed: string) {
    if (!this.#HDPrivateKey) {
      throw new Error("HDPrivateKey not set");
    }
    if (!this.#rootPath) {
      throw new Error("rootPath not set");
    }
    const seedHex = toHex(Hash.sha256(seed, "utf8"));
    const seedPath = Utils.getSigningPathFromHex(seedHex);
    const rootChild = this.#HDPrivateKey.derive(this.rootPath);
    return rootChild.derive(seedPath).privKey;
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
  signMessage(
    msg: string | Buffer,
    signingPath = "",
  ): { address: string; signature: string } {
    if (!this.#HDPrivateKey && !this.#singlePrivateKey) {
      throw new Error("No private key available");
    }

    if (this.#HDPrivateKey) {
      if (!this.#currentPath) {
        throw new Error("currentPath not set");
      }

      const path = signingPath || this.#currentPath;
      const childPk = this.#HDPrivateKey.derive(path).privKey;
      const address = childPk.toPublicKey().toAddress();

      const dummySig = BSM.sign(toArray(msg), childPk, 'raw') as Signature;
      const h = new BigNumber(magicHash(toArray(msg, "utf8")));
      const r = dummySig.CalculateRecoveryFactor(
        childPk.toPublicKey(),
        h,
      );
      const signature = (BSM.sign(toArray(msg), childPk, 'raw') as Signature).toCompact(
        r,
        true,
        "base64",
      ) as string;

      return { address, signature };
    }

    // At this point, we know this.#singlePrivateKey is defined because of the first check
    const privateKey = this.#singlePrivateKey as PrivateKey;
    const address = privateKey.toPublicKey().toAddress();
    const dummySig = BSM.sign(toArray(msg), privateKey, 'raw') as Signature;
    const h = new BigNumber(magicHash(toArray(msg, "utf8")));
    const r = dummySig.CalculateRecoveryFactor(
      privateKey.toPublicKey(),
      h,
    );
    const signature = (BSM.sign(toArray(msg), privateKey, 'raw') as Signature).toCompact(
      r,
      true,
      "base64",
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
    if (!this.#HDPrivateKey) {
      throw new Error("HDPrivateKey not set");
    }
    if (!this.#rootPath) {
      throw new Error("rootPath not set");
    }
    const pathHex = toHex(Hash.sha256(seed, "utf8"));
    const path = Utils.getSigningPathFromHex(pathHex);

    const HDPrivateKey = this.#HDPrivateKey.derive(this.#rootPath);
    const derivedChild = HDPrivateKey.derive(path);
    const address = derivedChild.privKey.toPublicKey().toAddress();

    const dummySig = BSM.sign(toArray(message), derivedChild.privKey, 'raw') as Signature;

    const h = new BigNumber(magicHash(toArray(message, "utf8")));
    const r = dummySig.CalculateRecoveryFactor(
      derivedChild.privKey.toPublicKey(),
      h,
    );

    const signature = (BSM.sign(
      toArray(Buffer.from(message)),
      derivedChild.privKey,
      'raw',
    ) as Signature).toCompact(r, true, "base64") as string;

    return { address, signature };
  }

  /**
   * Sign an op_return hex array with AIP
   * @param opReturn {array}
   * @param signingPath {string}
   * @param outputType {string}
   * @return {[]}
   */
  signOpReturnWithAIP(
    opReturn: string[],
    signingPath = "",
    outputType: BufferEncoding = "hex",
  ): string[] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(
      aipMessageBuffer,
      signingPath,
    );

    return opReturn.concat([
      Buffer.from("|").toString(outputType),
      Buffer.from(AIP_BITCOM_ADDRESS).toString(outputType),
      Buffer.from("BITCOIN_ECDSA").toString(outputType),
      Buffer.from(address).toString(outputType),
      Buffer.from(signature, "base64").toString(outputType),
    ]);
  }

  /**
   * Construct an AIP buffer from the op return data
   * @param opReturn
   * @returns {Buffer}
   */
  getAIPMessageBuffer(opReturn: string[]): Buffer {
    const buffers = [];
    if (opReturn[0].replace("0x", "") !== "6a") {
      // include OP_RETURN in constructing the signature buffer
      buffers.push(Buffer.from("6a", "hex"));
    }
    for (const op of opReturn) {
      buffers.push(Buffer.from(op.replace("0x", ""), "hex"));
    }
    // add a trailing "|" - this is the AIP way
    buffers.push(Buffer.from("|"));

    return Buffer.concat([...buffers] as unknown as Uint8Array[]);
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
  import(id: Identity | OldIdentity): void {
    this.name = ('name' in id && typeof id.name === 'string' ? id.name : "ID 1");
    this.description = id.description || "";
    this.identityKey = id.identityKey;
    this.rootAddress = id.rootAddress;
    if ('rootPath' in id && 'currentPath' in id && 'previousPath' in id) {
      this.#rootPath = id.rootPath;
      this.#currentPath = id.currentPath;
      this.#previousPath = id.previousPath;
    }
    this.#idSeed = id.idSeed || "";
    this.identityAttributes = this.parseAttributes(id.identityAttributes);
  }

  /**
   * Export this identity to a JSON object
   * @returns {{}}
   */
  export(): Identity {
    if (this.#HDPrivateKey) {
      if (!this.#rootPath || !this.#currentPath || !this.#previousPath) {
        throw new Error("Required paths are not set");
      }
      return {
        rootPath: this.#rootPath,
        currentPath: this.#currentPath,
        previousPath: this.#previousPath,
        lastIdPath: this.lastIdPath,
        idSeed: this.#idSeed,
        name: this.name,
        description: this.description,
        identityKey: this.identityKey,
        rootAddress: this.rootAddress,
        identityAttributes: this.identityAttributes
      };
    }
    if (!this.#singlePrivateKey) {
      throw new Error("Neither HDPrivateKey nor singlePrivateKey is set");
    }
    return {
      derivedPrivateKey: this.#singlePrivateKey.toString(),
      idSeed: this.#idSeed,
      name: this.name,
      description: this.description,
      identityKey: this.identityKey,
      rootAddress: this.rootAddress,
      identityAttributes: this.identityAttributes
    };
  }
}

// export { BAP_ID };
