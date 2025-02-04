import type { IdentityAttributes, HDIdentity, OldIdentity, Attestation } from "./interface";
import { IdentityBase } from "./identityBase";
import { type HD, Signature, BigNumber, ECIES, BSM, Utils as BSVUtils, Hash, PublicKey } from "@bsv/sdk";
import { Utils } from "./utils";
import { SIGNING_PATH_PREFIX, ENCRYPTION_PATH, MAX_INT, BAP_BITCOM_ADDRESS, AIP_BITCOM_ADDRESS } from "./constants";
import type { GetAttestationResponse, GetSigningKeysResponse, AttestationValidResponse } from "./apiTypes";

const { toArray, toUTF8, toBase64, toHex, toBase58 } = BSVUtils;

export class MasterID extends IdentityBase implements HDIdentity {
  private hdKey: HD;
  public rootPath: string;
  public currentPath: string;
  public previousPath: string;
  public lastIdPath: string; // required by HDIdentity
  public idSeed: string; // Changed from private to public

  constructor(hdKey: HD, attrs?: IdentityAttributes | string, idSeed = "") {
    // Call base constructor with attrs. (The subclass will assign rootAddress below.)
    super(attrs || {});
    this.hdKey = hdKey;
    this.idSeed = idSeed;
    if (idSeed) {
      const seedHex = toHex(Hash.sha256(idSeed, "utf8"));
      const seedPath = Utils.getSigningPathFromHex(seedHex);
      this.hdKey = hdKey.derive(seedPath);
    }
    this.rootPath = this.computeRootPath();
    this.previousPath = this.rootPath;
    this.currentPath = this.computeInitialCurrentPath();
    this.lastIdPath = ""; // default; can be updated externally
    const rootChild = this.hdKey.derive(this.rootPath);
    this.rootAddress = rootChild.privKey.toPublicKey().toAddress();
    this.identityKey = this.deriveIdentityKey(this.rootAddress);
  }

  // --- Path management methods ---

  private computeRootPath(): string {
    // For backward compatibility, always use the default root path.
    return `${SIGNING_PATH_PREFIX}/0/0/0`;
  }

  private computeInitialCurrentPath(): string {
    // The initial signing path is the default root path with its last segment incremented.
    return `${SIGNING_PATH_PREFIX}/0/0/1`;
  }

  public validatePath(path: string): boolean {
    const match = path.match(
      /\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?/
    );
    if (match) {
      const parts = path.split("/");
      if (parts.length === 7) {
        for (let i = 1; i < parts.length; i++) {
          const num = Number(parts[i].replace("'", ""));
          if (num > MAX_INT) return false;
        }
        return true;
      }
    }
    return false;
  }

  public incrementPath(): void {
    this.previousPath = this.currentPath;
    this.currentPath = Utils.getNextPath(this.currentPath);
  }

  // --- Signing and Encryption methods ---

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

  // --- Transaction and Attestation Methods ---

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
      const response: AttestationValidResponse = await fetch("/attestation/valid", {
        method: "POST",
        headers: { "Content-type": "application/json" },
        body: JSON.stringify({ idKey, address, challenge, signature }),
      }).then(res => res.json());
      return response?.status === "success" && response?.result?.valid === true;
    } catch (error) {
      console.error("API call failed:", error);
      return false;
    }
  }

  public async isValidAttestationTransaction(tx: string[]): Promise<AttestationValidResponse | false> {
    if (this.verifyAttestationWithAIP(tx)) {
      const response: AttestationValidResponse = await fetch("/attestation/valid", {
        method: "POST",
        headers: { "Content-type": "application/json" },
        body: JSON.stringify({ tx }),
      }).then(res => res.json());
      return response;
    }
    return false;
  }

  public verifyAttestationWithAIP(tx: string[]): Attestation {
    if (!Array.isArray(tx) || tx[0] !== "0x6a" || tx[1] !== Buffer.from(BAP_BITCOM_ADDRESS).toString("hex")) {
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

  public async getIdSigningKeys(): Promise<GetSigningKeysResponse> {
    const signingKeys: GetSigningKeysResponse = await fetch("/signing-keys", {
      method: "POST",
      headers: { "Content-type": "application/json" },
      body: JSON.stringify({ idKey: this.identityKey }),
    }).then(res => res.json());
    return signingKeys;
  }

  public async getAttributeAttestations(attribute: string): Promise<GetAttestationResponse> {
    const attestationHash = this.getAttestationHash(attribute);
    const attestations: GetAttestationResponse = await fetch("/attestation/get", {
      method: "POST",
      headers: { "Content-type": "application/json" },
      body: JSON.stringify({ hash: attestationHash }),
    }).then(res => res.json());
    return attestations;
  }

  public getAttestationHash(attribute: string): string | null {
    const urn = this.getAttributeUrn(attribute);
    if (!urn) return null;
    const attestation = this.getAttestation(urn);
    const attestationHash = toHex(Hash.sha256(attestation, "utf8"));
    return attestationHash;
  }

  // --- Import/Export methods ---

  public import(id: HDIdentity | OldIdentity): void {
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

  public export(): HDIdentity {
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
}