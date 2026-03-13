import {
  BSM,
  BigNumber,
  ECIES,
  HD,
  OP,
  Signature,
  PrivateKey,
} from "@bsv/sdk";

import { Utils as BSVUtils } from "@bsv/sdk";
import { type APIFetcher, apiFetcher } from "./api";
import type {
  AttestationValidResponse,
  GetAttestationResponse,
  GetIdentityByAddressResponse,
  GetIdentityResponse,
} from "./apiTypes";
import {
  AIP_BITCOM_ADDRESS,
  BAP_BITCOM_ADDRESS,
  BAP_BITCOM_ADDRESS_HEX,
  BAP_SERVER,
  ENCRYPTION_PATH,
} from "./constants";
import { MasterID } from "./MasterID";
import { AccountID } from "./AccountID";
import type {
  Attestation,
  Identity,
  OldIdentity,
  PathPrefix,
} from "./interface";
import { Utils } from "./utils";
const { toArray, toUTF8, toBase64, toHex } = BSVUtils;
const { electrumEncrypt, electrumDecrypt } = ECIES;

type Identities = { lastIdPath: string; ids: Identity[] };

/** Backup format for Type 42 mode (rootPk-based) */
export interface Type42MasterBackup {
  ids: string;
  rootPk: string;
  mnemonic?: string;
  label?: string;
  createdAt: string;
}

/** Backup format for BIP32 mode (xprv-based, legacy) */
export interface Bip32MasterBackup {
  ids: string;
  xprv: string;
  mnemonic?: string;
  label?: string;
  createdAt: string;
}

interface Type42Params {
  rootPk: string;
}

export class BAP {
  #HDPrivateKey: HD | undefined;
  #masterPrivateKey: PrivateKey | undefined;
  #isType42: boolean;
  #ids: { [key: string]: MasterID } = {};
  #BAP_SERVER = BAP_SERVER;
  #BAP_TOKEN = "";
  #lastIdPath = "";
  #identityCounter = 0;
  getApiData: APIFetcher;

  constructor(keySource: string | Type42Params, token = "", server = "") {
    if (!keySource) {
      throw new Error("No key source given");
    }

    if (typeof keySource === "string") {
      this.#HDPrivateKey = HD.fromString(keySource);
      this.#isType42 = false;
    } else {
      this.#masterPrivateKey = PrivateKey.fromWif(keySource.rootPk);
      this.#isType42 = true;
    }

    if (token) this.#BAP_TOKEN = token;
    if (server) this.#BAP_SERVER = server;

    this.getApiData = apiFetcher(this.#BAP_SERVER, this.#BAP_TOKEN);
  }

  get lastIdPath(): string {
    return this.#lastIdPath;
  }

  getPublicKey(childPath = ""): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      if (childPath) {
        const derivedKey = this.#masterPrivateKey.deriveChild(
          this.#masterPrivateKey.toPublicKey(),
          childPath
        );
        return derivedKey.toPublicKey().toString();
      }
      return this.#masterPrivateKey.toPublicKey().toString();
    }

    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    if (childPath) {
      return this.#HDPrivateKey.derive(childPath).pubKey.toString();
    }
    return this.#HDPrivateKey.pubKey.toString();
  }

  getHdPublicKey(childPath = ""): string {
    if (this.#isType42) {
      throw new Error("HD public keys are not available in Type 42 mode");
    }
    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    if (childPath) {
      return this.#HDPrivateKey.derive(childPath).toPublic().toString();
    }
    return this.#HDPrivateKey.toPublic().toString();
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

  checkIdBelongs(bapId: MasterID): boolean {
    let checkRootAddress: string;

    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      const derivedKey = this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        bapId.rootPath
      );
      checkRootAddress = derivedKey.toPublicKey().toAddress();
    } else {
      if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
      const derivedChild = this.#HDPrivateKey.derive(bapId.rootPath);
      checkRootAddress = derivedChild.pubKey.toAddress();
    }

    if (checkRootAddress !== bapId.rootAddress) {
      throw new Error("ID does not belong to this private key");
    }

    return true;
  }

  listIds(): string[] {
    return Object.keys(this.#ids);
  }

  newId(customPath?: string, idSeed = ""): MasterID {

    let pathToUse: string;
    if (customPath) {
      pathToUse = customPath;
    } else if (this.#isType42) {
      pathToUse = `bap:${this.#identityCounter}`;
      this.#identityCounter++;
    } else {
      pathToUse = this.getNextValidPath();
    }

    let newIdentity: MasterID;
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Type 42 parameters not initialized");
      newIdentity = new MasterID({ rootPk: this.#masterPrivateKey }, idSeed);
    } else {
      if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
      newIdentity = new MasterID(this.#HDPrivateKey, idSeed);
    }

    newIdentity.rootPath = pathToUse;

    if (this.#isType42) {
      newIdentity.currentPath = pathToUse;
    } else {
      newIdentity.currentPath = Utils.getNextPath(pathToUse);
    }

    this.#ids[newIdentity.bapId] = newIdentity;
    this.#lastIdPath = pathToUse;

    return this.#ids[newIdentity.bapId];
  }

  removeId(bapId: string): void {
    delete this.#ids[bapId];
  }

  getNextValidPath(): PathPrefix {
    if (this.#lastIdPath) {
      return Utils.getNextIdentityPath(this.#lastIdPath);
    }
    return `/0'/${Object.keys(this.#ids).length}'/0'`;
  }

  newIdWithCounter(counter: number): MasterID {
    if (!this.#isType42) {
      throw new Error("newIdWithCounter only works in Type 42 mode");
    }
    return this.newId(`bap:${counter}`);
  }

  getId(bapId: string): MasterID | null {
    return this.#ids[bapId] || null;
  }

  /**
   * Get an AccountID for the given BAP ID.
   * The AccountID holds the account key and can sign create/revoke transactions.
   */
  getAccountId(bapId: string): AccountID | null {
    const masterId = this.#ids[bapId];
    if (!masterId) return null;
    return new AccountID(masterId.getAccountKey());
  }

  setId(bapId: MasterID): void {
    this.checkIdBelongs(bapId);
    this.#ids[bapId.bapId] = bapId;
  }

  importIds(idData: Identities | string, encrypted = true): void {
    if (encrypted && typeof idData === "string") {
      this.importEncryptedIds(idData);
      return;
    }
    const identity = idData as Identities;
    if (!identity.lastIdPath) {
      throw new Error("ID cannot be imported as it is not complete");
    }
    if (!identity.ids) {
      throw new Error(`ID data is not in the correct format: ${idData}`);
    }

    let lastIdPath = identity.lastIdPath;
    for (const id of identity.ids) {
      if (!id.rootAddress) {
        throw new Error("ID cannot be imported as it is not complete");
      }

      let importId: MasterID;
      if (this.#isType42) {
        if (!this.#masterPrivateKey) throw new Error("Type 42 parameters not initialized");
        importId = new MasterID({ rootPk: this.#masterPrivateKey }, id.idSeed);
      } else {
        if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
        importId = new MasterID(this.#HDPrivateKey, id.idSeed);
      }

      importId.import(id);
      if (lastIdPath === "") {
        lastIdPath = importId.currentPath;
      }

      this.checkIdBelongs(importId);
      this.#ids[importId.bapId] = importId;

      if (this.#isType42 && importId.rootPath.startsWith('bap:')) {
        const pathParts = importId.rootPath.split(':');
        if (pathParts.length >= 2) {
          const counter = Number.parseInt(pathParts[1], 10);
          if (!Number.isNaN(counter)) {
            this.#identityCounter = Math.max(this.#identityCounter, counter + 1);
          }
        }
      }
    }

    this.#lastIdPath = lastIdPath;
  }

  importEncryptedIds(idData: string): void {
    const decrypted = this.decrypt(idData);
    const ids = JSON.parse(decrypted) as Identities;

    const isOldFormat = Array.isArray(ids);
    if (isOldFormat) {
      this.importOldIds(ids);
      return;
    }
    if (typeof ids !== "object") {
      throw new Error("decrypted, but found unrecognized identities format");
    }
    this.importIds(ids, false);
  }

  importOldIds(idData: OldIdentity[]): void {
    for (const id of idData) {
      let importId: MasterID;
      if (this.#isType42) {
        if (!this.#masterPrivateKey) throw new Error("Type 42 parameters not initialized");
        importId = new MasterID({ rootPk: this.#masterPrivateKey }, id.idSeed ?? "");
      } else {
        if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
        importId = new MasterID(this.#HDPrivateKey, id.idSeed ?? "");
      }

      importId.import(id);
      this.checkIdBelongs(importId);
      this.#ids[importId.bapId] = importId;
      this.#lastIdPath = importId.currentPath;
    }
  }

  exportIds(idKeys?: string[], encrypted?: true): string;
  exportIds(idKeys: string[] | undefined, encrypted: false): Identities;
  exportIds(idKeys?: string[], encrypted = true): Identities | string {
    const idData: Identities = {
      lastIdPath: this.#lastIdPath,
      ids: [] as Identity[],
    };

    const keysToExport = idKeys || Object.keys(this.#ids);
    for (const key of keysToExport) {
      if (!this.#ids[key]) throw new Error(`Identity ${key} not found`);
      idData.ids.push(this.#ids[key].export());
    }

    if (encrypted) {
      return this.encrypt(JSON.stringify(idData));
    }
    return idData;
  }

  exportId(idKey: string, encrypted?: true): string;
  exportId(idKey: string, encrypted: false): Identities;
  exportId(idKey: string, encrypted = true): Identities | string {
    const idData: Identities = {
      lastIdPath: this.#lastIdPath,
      ids: [] as Identity[],
    };
    idData.ids.push(this.#ids[idKey].export());
    if (encrypted) {
      return this.encrypt(JSON.stringify(idData));
    }
    return idData;
  }

  // Master-level encryption for the ids blob in the backup
  encrypt(string: string): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      const encryptionKey = this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        ENCRYPTION_PATH
      );
      return toBase64(
        electrumEncrypt(toArray(string), encryptionKey.toPublicKey())
      );
    }

    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    const derivedChild = this.#HDPrivateKey.derive(ENCRYPTION_PATH);
    return toBase64(
      electrumEncrypt(toArray(string), derivedChild.pubKey)
    );
  }

  decrypt(string: string): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      const encryptionKey = this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        ENCRYPTION_PATH
      );
      return toUTF8(
        electrumDecrypt(toArray(string, "base64"), encryptionKey)
      );
    }

    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    const derivedChild = this.#HDPrivateKey.derive(ENCRYPTION_PATH);
    return toUTF8(
      electrumDecrypt(toArray(string, "base64"), derivedChild.privKey)
    );
  }

  signAttestationWithAIP(
    attestationHash: string,
    bapId: string,
    counter = 0,
    dataString = ""
  ) {
    const id = this.getId(bapId);
    if (!id) throw new Error("Could not find identity to attest with");

    // Attestation signing now needs to go through the wallet.
    // This method builds the transaction data but signing should be
    // delegated to the BRC-100 wallet in the calling code.
    const attestationBuffer = this.getAttestationBuffer(
      attestationHash,
      counter,
      dataString
    );

    return this.createAttestationTransaction(
      attestationHash,
      counter,
      "", // address — caller must provide from wallet
      "", // signature — caller must provide from wallet
      dataString
    );
  }

  verifyAttestationWithAIP(tx: number[][]): Attestation {
    if (
      !tx.every((t) => Array.isArray(t)) ||
      tx[0][0] !== OP.OP_RETURN ||
      toHex(tx[1]) !== BAP_BITCOM_ADDRESS_HEX
    ) {
      throw new Error("Not a valid BAP transaction");
    }
    const dataOffset = toHex(tx[7]) === "44415441" ? 5 : 0;
    const attestation: Attestation = {
      type: toUTF8(tx[2]),
      hash: toHex(tx[3]),
      sequence: toUTF8(tx[4]),
      signingProtocol: toUTF8(tx[7 + dataOffset]),
      signingAddress: toUTF8(tx[8 + dataOffset]),
      signature: toBase64(tx[9 + dataOffset]),
    };

    if (dataOffset && tx[3] === tx[8]) {
      attestation.data = toHex(tx[9]);
    }

    try {
      const signatureBufferStatements: number[][] = [];
      for (let i = 0; i < 6 + dataOffset; i++) {
        signatureBufferStatements.push(tx[i]);
      }
      attestation.verified = this.verifySignature(
        signatureBufferStatements.flat(),
        attestation.signingAddress,
        attestation.signature
      );
    } catch {
      attestation.verified = false;
    }

    return attestation;
  }

  createAttestationTransaction(
    attestationHash: string,
    counter: number,
    address: string,
    signature: string,
    dataString = ""
  ): number[][] {
    const elements: number[][] = [
      [OP.OP_RETURN],
      toArray(BAP_BITCOM_ADDRESS),
      toArray("ATTEST"),
      toArray(attestationHash),
      toArray(`${counter}`),
      toArray("|"),
    ];

    if (dataString) {
      elements.push(
        toArray(BAP_BITCOM_ADDRESS),
        toArray("DATA"),
        toArray(attestationHash),
        toArray(dataString),
        toArray("|")
      );
    }

    elements.push(
      toArray(AIP_BITCOM_ADDRESS),
      toArray("BITCOIN_ECDSA"),
      toArray(address),
      toArray(signature, "base64")
    );

    return elements;
  }

  getAttestationBuffer(
    attestationHash: string,
    counter = 0,
    dataString = ""
  ): number[] {
    const elements = [
      [OP.OP_RETURN],
      toArray(BAP_BITCOM_ADDRESS),
      toArray("ATTEST"),
      toArray(attestationHash),
      toArray(`${counter}`),
      toArray("|"),
    ];

    if (dataString) {
      elements.push(
        toArray(BAP_BITCOM_ADDRESS),
        toArray("DATA"),
        toArray(attestationHash),
        toArray(dataString),
        toArray("|")
      );
    }

    return elements.flat();
  }

  verifySignature(
    message: string | number[],
    address: string,
    signature: string
  ): boolean {
    let msg: number[];
    if (Array.isArray(message)) {
      msg = message;
    } else if (Buffer.isBuffer(message)) {
      msg = [...message];
    } else {
      msg = toArray(message, "utf8");
    }

    const sig = Signature.fromCompact(signature, "base64");

    for (let recovery = 0; recovery < 4; recovery++) {
      try {
        const publicKey = sig.RecoverPublicKey(
          recovery,
          new BigNumber(BSM.magicHash(msg))
        );
        if (BSM.verify(msg, sig, publicKey) && publicKey.toAddress() === address) {
          return true;
        }
      } catch {
        // try next recovery
      }
    }
    return false;
  }

  async verifyChallengeSignature(
    idKey: string,
    address: string,
    challenge: string,
    signature: string
  ): Promise<boolean> {
    const localVerification = this.verifySignature(challenge, address, signature);
    if (!localVerification) return false;

    try {
      const response = await this.getApiData<AttestationValidResponse>(
        "/attestation/valid",
        { idKey, address, challenge, signature }
      );
      return response?.status === "success" && response?.result?.valid === true;
    } catch {
      return false;
    }
  }

  async isValidAttestationTransaction(
    tx: number[][]
  ): Promise<AttestationValidResponse | false> {
    if (this.verifyAttestationWithAIP(tx)) {
      return this.getApiData<AttestationValidResponse>("/attestation/valid", { tx });
    }
    return false;
  }

  async getIdentityFromAddress(address: string): Promise<GetIdentityByAddressResponse> {
    return this.getApiData<GetIdentityByAddressResponse>("/identity/validByAddress", { address });
  }

  async getIdentity(idKey: string): Promise<GetIdentityResponse> {
    return this.getApiData<GetIdentityResponse>("/identity/get", { idKey });
  }

  async getAttestationsForHash(attestationHash: string): Promise<GetAttestationResponse> {
    return this.getApiData<GetAttestationResponse>("/attestations", { hash: attestationHash });
  }

  exportForBackup(
    label?: string,
    xprv?: string,
    mnemonic?: string
  ): Type42MasterBackup | Bip32MasterBackup {
    const ids = this.exportIds();
    const baseBackup = {
      ids,
      ...(label && { label }),
      createdAt: new Date().toISOString(),
    };

    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Type 42 parameters not initialized");
      return { ...baseBackup, rootPk: this.#masterPrivateKey.toWif() };
    }

    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    return {
      ...baseBackup,
      xprv: xprv || this.#HDPrivateKey.toString(),
      mnemonic: mnemonic || "",
    };
  }
}

export { MasterID, AccountID };
export { bapIdFromAddress, bapIdFromPubkey } from "./utils";
export type {
  Attestation,
  Identity,
  PathPrefix,
  Type42Params,
};
export * from "./apiTypes";
