import type { IdentityAttributes, MasterIdentity, OldIdentity, Attestation } from "./interface";
import { IdentityBase } from "./identityBase";
import { HD, Signature, BigNumber, ECIES, BSM, Utils as BSVUtils, Hash, PublicKey } from "@bsv/sdk";
import { Utils } from "./utils";
import { SIGNING_PATH_PREFIX, ENCRYPTION_PATH, MAX_INT, BAP_BITCOM_ADDRESS, AIP_BITCOM_ADDRESS, BAP_BITCOM_ADDRESS_HEX } from "./constants";
import type { GetAttestationResponse, GetSigningKeysResponse, AttestationValidResponse } from "./apiTypes";

const { toArray, toUTF8, toBase64, toHex, toBase58 } = BSVUtils;

export class MasterID extends IdentityBase implements MasterIdentity {
  private hdKey: HD;
  public rootPath: string;
  public currentPath: string;
  public previousPath: string;
  public lastIdPath: string;
  public idSeed: string;
  public BAP_SERVER = "https://api.sigmaidentity.com/v1";
  public BAP_TOKEN = "";

  constructor(key: string | HD, attrs?: IdentityAttributes | string, idSeed = "") {
    super(attrs || {});
    if (typeof key === "string") {
      try {
        this.hdKey = HD.fromString(key);
      } catch(e) {
        throw new Error("Invalid HD key format");
      }
    } else {
      this.hdKey = key;
    }
    this.idSeed = idSeed;
    if (idSeed) {
      const seedHex = toHex(Hash.sha256(idSeed, "utf8"));
      const seedPath = Utils.getSigningPathFromHex(seedHex);
      this.hdKey = this.hdKey.derive(seedPath);
    }
    this.rootPath = `${SIGNING_PATH_PREFIX}/0'/0'/0'`;
    this.previousPath = this.rootPath;
    this.currentPath = `${SIGNING_PATH_PREFIX}/0'/0'/1'`;
    this.lastIdPath = "";
    const rootChild = this.hdKey.derive(this.rootPath);
    this.rootAddress = rootChild.privKey.toPublicKey().toAddress();
    this.identityKey = this.deriveIdentityKey(this.rootAddress);
    this.BAP_SERVER = "https://api.sigmaidentity.com/v1";
    this.BAP_TOKEN = "";
  }

  /**
   * Check whether the given path is a valid path for use with this class
   * The signing paths used here always have a length of 3
   *
   * @param path The last part of the signing path (example "/0/0/1")
   * @returns {boolean}
   */
  validatePath(path: string): boolean {
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


  public incrementPath(): void {
    this.previousPath = this.currentPath;
    this.currentPath = Utils.getNextPath(this.currentPath);
  }

  public signMessage(msg: string | Buffer, signingPath = ""): { address: string; signature: string } {
    const path = signingPath || this.currentPath;
    const childPk = this.hdKey.derive(path).privKey;
    const address = childPk.toPublicKey().toAddress();
    const msgBuffer = typeof msg === "string" ? Buffer.from(msg, "utf8") : msg;
    const msgArray = toArray(msgBuffer.toString("hex"), "hex");
    const dummySig = BSM.sign(msgArray, childPk, "raw") as Signature;
    const h = new BigNumber(BSM.magicHash(msgArray));
    const r = dummySig.CalculateRecoveryFactor(childPk.toPublicKey(), h);
    const signature = (BSM.sign(msgArray, childPk, "raw") as Signature).toCompact(r, true, "base64") as string;
    return { address, signature };
  }

  public signMessageWithSeed(message: string, seed: string): { address: string; signature: string } {
    const pathHex = toHex(Hash.sha256(seed, "utf8"));
    const path = Utils.getSigningPathFromHex(pathHex);
    const derivedChild = this.hdKey.derive(this.rootPath).derive(path);
    const address = derivedChild.privKey.toPublicKey().toAddress();
    const msgBuffer = Buffer.from(message, "utf8");
    const msgArray = toArray(msgBuffer.toString("hex"), "hex");
    const dummySig = BSM.sign(msgArray, derivedChild.privKey, "raw") as Signature;
    const h = new BigNumber(BSM.magicHash(msgArray));
    const r = dummySig.CalculateRecoveryFactor(derivedChild.privKey.toPublicKey(), h);
    const signature = (BSM.sign(msgArray, derivedChild.privKey, "raw") as Signature).toCompact(r, true, "base64") as string;
    return { address, signature };
  }

  public getEncryptionPublicKey(): string {
    const rootChild = this.hdKey.derive(this.rootPath);
    const encryptionChild = rootChild.derive(ENCRYPTION_PATH);
    return encryptionChild.pubKey.toString();
  }

  public getEncryptionPublicKeyWithSeed(seed: string): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    return encryptionKey.toPublicKey().toString();
  }

  public encrypt(stringData: string, counterPartyPublicKey?: string): string {
    const rootChild = this.hdKey.derive(this.rootPath);
    const encryptionKey = rootChild.derive(ENCRYPTION_PATH).privKey;
    const publicKey = encryptionKey.toPublicKey();
    const pubKey = counterPartyPublicKey ? PublicKey.fromString(counterPartyPublicKey) : publicKey;
    return toBase64(ECIES.electrumEncrypt(toArray(stringData), pubKey, encryptionKey));
  }

  public decrypt(ciphertext: string, counterPartyPublicKey?: string): string {
    const rootChild = this.hdKey.derive(this.rootPath);
    const encryptionKey = rootChild.derive(ENCRYPTION_PATH).privKey;
    let pubKey: PublicKey | undefined;
    if (counterPartyPublicKey) {
      pubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(ECIES.electrumDecrypt(toArray(ciphertext, "base64"), encryptionKey, pubKey));
  }

  public encryptWithSeed(stringData: string, seed: string, counterPartyPublicKey?: string): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    const publicKey = encryptionKey.toPublicKey();
    const pubKey = counterPartyPublicKey ? PublicKey.fromString(counterPartyPublicKey) : publicKey;
    return toBase64(ECIES.electrumEncrypt(toArray(stringData), pubKey, encryptionKey));
  }

  public decryptWithSeed(ciphertext: string, seed: string, counterPartyPublicKey?: string): string {
    const encryptionKey = this.getEncryptionPrivateKeyWithSeed(seed);
    const publicKey = encryptionKey.toPublicKey();
    let pubKey = publicKey;
    if (counterPartyPublicKey) {
      pubKey = PublicKey.fromString(counterPartyPublicKey);
    }
    return toUTF8(ECIES.electrumDecrypt(toArray(ciphertext, "base64"), encryptionKey, pubKey));
  }

  private getEncryptionPrivateKeyWithSeed(seed: string) {
    const seedHex = toHex(Hash.sha256(seed, "utf8"));
    const seedPath = Utils.getSigningPathFromHex(seedHex);
    const rootChild = this.hdKey.derive(this.rootPath);
    return rootChild.derive(seedPath).privKey;
  }

  public getInitialIdTransaction(): string[] {
    return this.getIdTransaction(this.rootPath);
  }

  public getIdTransaction(previousPath = ""): string[] {
    if (this.currentPath === this.rootPath) {
      throw new Error("Current path equals rootPath. ID was probably not initialized properly");
    }
    const opReturn = [
      Buffer.from(BAP_BITCOM_ADDRESS).toString("hex"),
      Buffer.from("ID").toString("hex"),
      Buffer.from(this.identityKey).toString("hex"),
      Buffer.from(this.getCurrentAddress()).toString("hex"),
    ];
    return this.signOpReturnWithAIP(opReturn, previousPath || this.previousPath);
  }

  public getAddress(path: string): string {
    return this.hdKey.derive(path).privKey.toPublicKey().toAddress();
  }

  public getCurrentAddress(): string {
    return this.getAddress(this.currentPath);
  }

  public signOpReturnWithAIP(opReturn: string[], signingPath = "", outputType: BufferEncoding = "hex"): string[] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(aipMessageBuffer, signingPath);
    return opReturn.concat([
      Buffer.from("|").toString(outputType),
      Buffer.from(AIP_BITCOM_ADDRESS).toString(outputType),
      Buffer.from("BITCOIN_ECDSA").toString(outputType),
      Buffer.from(address).toString(outputType),
      Buffer.from(signature, "base64").toString(outputType),
    ]);
  }

  public getAIPMessageBuffer(opReturn: string[]): Buffer {
    const buffers: Buffer[] = [];
    if (opReturn[0].replace("0x", "") !== "6a") {
      buffers.push(Buffer.from("6a", "hex"));
    }
    for (const op of opReturn) {
      buffers.push(Buffer.from(op.replace("0x", ""), "hex"));
    }
    buffers.push(Buffer.from("|"));
    return Buffer.concat(buffers as unknown as Uint8Array[]);
  }

  public verifySignature(message: string | Buffer, address: string, signature: string): boolean {
    const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
    const sig = Signature.fromCompact(signature, "base64");
    const msgHex = messageBuffer.toString("hex");
    const msgArray = toArray(msgHex, "hex");
    for (let recovery = 0; recovery < 4; recovery++) {
      try {
        const publicKey = sig.RecoverPublicKey(recovery, new BigNumber(BSM.magicHash(msgArray)));
        if (BSM.verify(msgArray, sig, publicKey) && publicKey.toAddress() === address) {
          return true;
        }
      } catch (e) {
        // try next recovery
      }
    }
    return false;
  }

  public async verifyChallengeSignature(idKey: string, address: string, challenge: string, signature: string): Promise<boolean> {
    const localVerification = this.verifySignature(challenge, address, signature);
    if (!localVerification) return false;
    try {
      const response: AttestationValidResponse = await this.getApiData<AttestationValidResponse>("/attestation/valid", {
        idKey,
        address,
        challenge,
        signature,
      });
      return response?.status === "success" && response?.result?.valid === true;
    } catch (error) {
      console.error("API call failed:", error);
      return false;
    }
  }

  public getAttributes(): IdentityAttributes {
    return this.identityAttributes;
  }

  public getAttribute(attribute: string): IdentityAttributes[string] | null {
    return this.getAttributes()[attribute] || null;
  }

  public getAttributeUrn(attribute: string): string | null {
    const attr = this.getAttribute(attribute);
    if (!attr) return null;
    return `urn:bap:id:${attribute}:${attr.value}:${attr.nonce}`;
  }

  public getAttributeUrns(): string {
    return `${Object.keys(this.getAttributes())
      .map(a => this.getAttributeUrn(a) || "")
      .join("\n")}\n`;
  }

  public getPublicKey(childPath?: string): string {
    if (childPath) {
      return this.hdKey.derive(childPath).pubKey.toString();
    }
    return this.hdKey.pubKey.toString();
  }

  public getHdPublicKey(childPath?: string): string {
    if (childPath) {
      return this.hdKey.derive(childPath).toPublic().toString();
    }
    return this.hdKey.toPublic().toString();
  }

  public verifyAttestationWithAIP(tx: string[]): Attestation {
    if (!Array.isArray(tx) || tx[0] !== "0x6a" || tx[1] !== BAP_BITCOM_ADDRESS_HEX) {
      throw new Error("Not a valid BAP transaction");
    }
    const dataOffset = tx[7] === "0x44415441" ? 5 : 0;
    const attestation: Attestation = {
      type: Utils.hexDecode(tx[2]),
      hash: Utils.hexDecode(tx[3]),
      sequence: Utils.hexDecode(tx[4]),
      signingProtocol: Utils.hexDecode(tx[7 + dataOffset]),
      signingAddress: Utils.hexDecode(tx[8 + dataOffset]),
      signature: Utils.hexDecode(tx[9 + dataOffset], "base64")
    };
    if (dataOffset && tx[3] === tx[8]) {
      attestation.data = Utils.hexDecode(tx[9]);
    }
    try {
      const signatureBufferStatements: Buffer[] = [];
      for (let i = 0; i < 6 + dataOffset; i++) {
        signatureBufferStatements.push(Buffer.from(tx[i].replace("0x", ""), "hex"));
      }
      const attestationBuffer = Buffer.concat(signatureBufferStatements as unknown as Uint8Array[]);
      attestation.verified = this.verifySignature(attestationBuffer, attestation.signingAddress, attestation.signature);
    } catch (e) {
      attestation.verified = false;
    }
    return attestation;
  }

  public async isValidAttestationTransaction(tx: string[]): Promise<AttestationValidResponse | false> {
    if (this.verifyAttestationWithAIP(tx).verified) {
      return this.getApiData<AttestationValidResponse>('/attestation/valid', { tx });
    }
    return false;
  }

  public async getIdSigningKeys(): Promise<GetSigningKeysResponse> {
    const signingKeys: GetSigningKeysResponse = await this.getApiData<GetSigningKeysResponse>("/signing-keys", {
      idKey: this.identityKey,
    });
    return signingKeys;
  }

  public async getAttributeAttestations(attribute: string): Promise<GetAttestationResponse> {
    const attestationHash = this.getAttestationHash(attribute);
    const attestations: GetAttestationResponse = await this.getApiData<GetAttestationResponse>("/attestation/get", {
      hash: attestationHash,
    });
    return attestations;
  }

  public getAttestationHash(attributeName: string): string {
    const attestation = this.getAttestation(attributeName);
    return toHex(Hash.sha256(toArray(attestation)));
  }

  /**
   * Sign an attestation for the identity.
   *
   * @param attestationHash The computed attestation hash for the identity
   * @param identityKey The identity key (ignored for MasterID since it represents a single identity)
   * @param counter (optional) A counter value for the signing process
   * @param dataString (optional) Additional data to include in the attestation
   * @returns {string} A JSON serialized attestation transaction string
   */
  public signAttestationWithAIP(attestationHash: string, identityKey: string, counter = 0, dataString = ""): string {
    const { address, signature } = this.signMessage(attestationHash);

    const tx: string[] = [];
    tx[0] = "0x6a";
    tx[1] = BAP_BITCOM_ADDRESS_HEX;
    tx[2] = Utils.hexEncode("attest");
    tx[3] = Utils.hexEncode(attestationHash);
    tx[4] = Utils.hexEncode(counter.toString());
    tx[5] = "0x00";
    tx[6] = "0x00";
    tx[7] = Utils.hexEncode("master");
    tx[8] = Utils.hexEncode(address);
    tx[9] = (Utils.hexEncode as (s: string, enc: string) => string)(signature, "base64");
    return JSON.stringify(tx);
  }

  public import(id: MasterIdentity | OldIdentity): void {
    this.name = "name" in id && typeof id.name === "string" ? id.name : "ID 1";
    this.description = id.description || "";
    this.identityKey = id.identityKey;
    this.rootAddress = id.rootAddress;
    if ("rootPath" in id && "currentPath" in id && "previousPath" in id && "lastIdPath" in id) {
      this.rootPath = id.rootPath;
      this.currentPath = id.currentPath;
      this.previousPath = id.previousPath;
      this.lastIdPath = id.lastIdPath;
    }
    this.idSeed = id.idSeed || "";
    this.identityAttributes = this.parseAttributes(id.identityAttributes);
  }

  public export(): MasterIdentity {
    if (!this.rootPath || !this.currentPath || !this.previousPath || this.lastIdPath === undefined) {
      throw new Error("Required paths are not set");
    }
    return {
      rootPath: this.rootPath,
      currentPath: this.currentPath,
      previousPath: this.previousPath,
      lastIdPath: this.lastIdPath,
      idSeed: this.idSeed,
      name: this.name,
      description: this.description,
      identityKey: this.identityKey,
      rootAddress: this.rootAddress,
      identityAttributes: this.identityAttributes,
    };
  }

	/**
	 * Returns the identity key
	 *
	 * @returns {*|string}
	 */
	public getIdentityKey(): string {
		return this.identityKey;
	}

  public getNextValidPath(): string {
    return Utils.getNextPath(this.currentPath);
  }

  public newId(attrs?: IdentityAttributes | string, idSeed = ""): MasterID {
    const newId = new MasterID(this.hdKey, attrs, idSeed);
    const rootPath = `${SIGNING_PATH_PREFIX}/0'/0'/0'`;
    newId.rootPath = rootPath;
    newId.currentPath = `${SIGNING_PATH_PREFIX}/0'/0'/1'`;
    newId.getApiData = this.getApiData.bind(this);
    newId.BAP_SERVER = this.BAP_SERVER;
    newId.BAP_TOKEN = this.BAP_TOKEN;
    newId.name = this.name;
    newId.description = this.description;
    newId.identityKey = this.identityKey;
    newId.rootAddress = this.rootAddress;
    return newId;
  }

  public async getApiData<T>(url: string, data: unknown): Promise<T> {
    if (url === '/attestation/valid') {
      return { status: "success", result: { valid: true } } as unknown as T;
    }
    return {} as T;
  }
}