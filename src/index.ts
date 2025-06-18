import {
  BSM,
  BigNumber,
  ECIES,
  HD,
  OP,
  type PublicKey,
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
import type {
  Attestation,
  Identity,
  IdentityAttributes,
  MemberIdentity,
  OldIdentity,
  PathPrefix,
} from "./interface";
import { Utils } from "./utils";
import { MemberID } from "./MemberID";
const { toArray, toUTF8, toBase64, toHex } = BSVUtils;
const { electrumEncrypt, electrumDecrypt } = ECIES;

type Identities = { lastIdPath: string; ids: Identity[] };

// Type 42 parameters
interface Type42Params {
  rootPk: string;  // WIF format private key
}

/**
 * BAP class
 *
 * Creates an instance of the BAP class and uses the given HDPrivateKey for all BAP operations.
 * Supports both BIP32 (HD) and Type 42 key derivation methods.
 *
 * @deprecated When initializing with a string (xprv), the BIP32 format is used which is deprecated 
 * for new implementations. Use Type 42 initialization with { rootPk: wifKey } instead.
 * 
 * @param keySource Either an HDPrivateKey string (xprv) for BIP32 or Type42Params for Type 42
 */
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

    // Determine if we're using Type 42 or BIP32
    if (typeof keySource === "string") {
      // BIP32 mode
      this.#HDPrivateKey = HD.fromString(keySource);
      this.#isType42 = false;
    } else {
      // Type 42 mode
      this.#masterPrivateKey = PrivateKey.fromWif(keySource.rootPk);
      this.#isType42 = true;
    }

    if (token) {
      this.#BAP_TOKEN = token;
    }

    if (server) {
      this.#BAP_SERVER = server;
    }

    this.getApiData = apiFetcher(this.#BAP_SERVER, this.#BAP_TOKEN);
  }

  get lastIdPath(): string {
    return this.#lastIdPath;
  }

  /**
   * Get the public key of the given childPath, or of the current HDPrivateKey of childPath is empty
   *
   * @param childPath Full derivation path for this child (BIP32) or invoice number (Type 42)
   * @returns {*}
   */
  getPublicKey(childPath = ""): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      if (childPath) {
        // In Type 42, we use the path as an invoice number
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

  /**
   * Get the HD public key of the given childPath (BIP32 only)
   *
   * @param childPath Full derivation path for this child
   * @returns {*}
   */
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
    for (const key in this.#ids) {
      this.#ids[key].BAP_SERVER = bapServer;
    }
  }

  get BAP_SERVER(): string {
    return this.#BAP_SERVER;
  }

  set BAP_TOKEN(token) {
    this.#BAP_TOKEN = token;
    for (const key in this.#ids) {
      // @ts-ignore - does not recognize private fields that can be set
      this.#ids[key].BAP_TOKEN = token;
    }
  }

  get BAP_TOKEN(): string {
    return this.#BAP_TOKEN;
  }

  /**
   * This function verifies that the given bapId matches the given root address
   * This is used as a data integrity check
   *
   * @param bapId MasterID instance
   */
  checkIdBelongs(bapId: MasterID): boolean {
    let checkRootAddress: string;
    
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      // In Type 42, we derive using the path as invoice number
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

  /**
   * Returns a list of all the identity keys that are stored in this instance
   *
   * @returns {string[]}
   */
  listIds(): string[] {
    return Object.keys(this.#ids);
  }

  /**
   * Create a new Id and link it to this BAP instance
   *
   * For Type 42 mode, uses simple counter for derivation: bap:{counter}
   * For BIP32 mode (legacy), uses traditional HD paths or provided customPath
   *
   * New signature: newId(idName, customPath?, identityAttributes?, idSeed?)
   * Legacy signature: newId(path?, identityAttributes?, idSeed?) - for backward compatibility
   *
   * @param idNameOrPath The human-readable name for this identity OR legacy path parameter
   * @param customPathOrAttributes Optional custom derivation path OR legacy identityAttributes
   * @param identityAttributes Optional identity attributes
   * @param idSeed Optional seed for deterministic key generation
   * @returns {MasterID} The created identity
   */
  newId(
    idNameOrPath?: string | IdentityAttributes,
    customPathOrAttributes?: string | IdentityAttributes,
    identityAttributes: IdentityAttributes = {},
    idSeed = ""
  ): MasterID {
    // Handle backward compatibility - detect old vs new signature
    let idName: string;
    let customPath: string | undefined;
    let finalAttributes: IdentityAttributes;
    
    if (typeof idNameOrPath === 'object' || idNameOrPath === undefined || 
        (typeof idNameOrPath === 'string' && idNameOrPath.startsWith('/'))) {
      // Legacy signature: newId(path?, identityAttributes?, idSeed?)
      // First param is path (undefined, starts with '/') or identityAttributes (object)
      customPath = typeof idNameOrPath === 'string' ? idNameOrPath : undefined;
      finalAttributes = (typeof idNameOrPath === 'object' ? idNameOrPath : 
                        typeof customPathOrAttributes === 'object' ? customPathOrAttributes : {});
      idName = "Default Identity";
    } else {
      // New signature: newId(idName, customPath?, identityAttributes?, idSeed?)
      idName = idNameOrPath;
      customPath = typeof customPathOrAttributes === 'string' ? customPathOrAttributes : undefined;
      finalAttributes = typeof customPathOrAttributes === 'object' ? customPathOrAttributes : identityAttributes;
    }
    let pathToUse: string;
    
    if (customPath) {
      // Use provided custom path
      pathToUse = customPath;
    } else if (this.#isType42) {
      // Type 42: Use simple counter for discovery - name is just UX
      pathToUse = `bap:${this.#identityCounter}`;
      this.#identityCounter++;
    } else {
      // BIP32: Use traditional HD path
      pathToUse = this.getNextValidPath();
    }

    let newIdentity: MasterID;
    if (this.#isType42) {
      if (!this.#masterPrivateKey) {
        throw new Error("Type 42 parameters not initialized");
      }
      // For Type 42, pass the key source object
      newIdentity = new MasterID(
        {
          rootPk: this.#masterPrivateKey
        },
        finalAttributes,
        idSeed
      );
    } else {
      if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
      newIdentity = new MasterID(
        this.#HDPrivateKey,
        finalAttributes,
        idSeed
      );
    }
    
    newIdentity.BAP_SERVER = this.#BAP_SERVER;
    newIdentity.BAP_TOKEN = this.#BAP_TOKEN;
    newIdentity.idName = idName;
    newIdentity.rootPath = pathToUse;
    
    // Set current path based on mode
    if (this.#isType42) {
      // For Type 42, current path is same as root path (invoice number)
      newIdentity.currentPath = pathToUse;
    } else {
      // For BIP32, calculate next path
      newIdentity.currentPath = Utils.getNextPath(pathToUse);
    }

    const idKey = newIdentity.getIdentityKey();
    this.#ids[idKey] = newIdentity;
    this.#lastIdPath = pathToUse;

    return this.#ids[idKey];
  }

  /**
   * Remove identity
   *
   * @param idKey
   * @returns {*}
   */
  removeId(idKey: string): void {
    delete this.#ids[idKey];
  }

  /**
   * Get the next valid path for the used HDPrivateKey and loaded #ids
   *
   * @returns {string}
   */
  getNextValidPath(): PathPrefix {
    // prefer hardened paths
    if (this.#lastIdPath) {
      return Utils.getNextIdentityPath(this.#lastIdPath);
    }

    return `/0'/${Object.keys(this.#ids).length}'/0'`;
  }

  /**
   * Create an identity with a specific counter value (useful for discovery)
   * Only works in Type 42 mode
   *
   * @param counter The specific counter value to use
   * @param idName Optional name for the identity
   * @returns {MasterID} The created identity
   */
  newIdWithCounter(
    counter: number,
    idName = `Identity ${counter}`
  ): MasterID {
    if (!this.#isType42) {
      throw new Error("newIdWithCounter only works in Type 42 mode");
    }
    
    const customPath = `bap:${counter}`;
    return this.newId(idName, customPath);
  }

  /**
   * Get a certain Id
   *
   * @param identityKey
   * @returns {null}
   */
  getId(identityKey: string): MasterID | null {
    return this.#ids[identityKey] || null;
  }

  /**
   * This function is used when manipulating ID's, adding or removing attributes etc
   * First create an id through this class and then use getId to get it. Then you can add/edit or
   * increment the signing path and then re-set it with this function.
   *
   * Note: when you getId() from this class, you will be working on the same object as this class
   * has and any changes made will be propagated to the id in this class. When you call exportIds
   * your new changes will also be included, without having to setId().
   *
   * @param bapId
   */
  setId(bapId: MasterID): void {
    this.checkIdBelongs(bapId);
    this.#ids[bapId.getIdentityKey()] = bapId;
  }

  /**
   * This function is used to import IDs and attributes from some external storage
   *
   * The ID information should NOT be stored together with the HD private key !
   *
   * @param idData Array of ids that have been exported
   * @param encrypted Whether the data should be treated as being encrypted (default true)
   */
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

    let lastIdPath = (idData as Identities).lastIdPath;
    for (const id of identity.ids) {
      if (!id.identityKey || !id.identityAttributes || !id.rootAddress) {
        throw new Error("ID cannot be imported as it is not complete");
      }
      
      let importId: MasterID;
      if (this.#isType42) {
        if (!this.#masterPrivateKey) {
          throw new Error("Type 42 parameters not initialized");
        }
        importId = new MasterID(
          {
            rootPk: this.#masterPrivateKey
          },
          {},
          id.idSeed
        );
      } else {
        if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
        importId = new MasterID(this.#HDPrivateKey, {}, id.idSeed);
      }
      
      importId.BAP_SERVER = this.#BAP_SERVER;
      importId.BAP_TOKEN = this.#BAP_TOKEN;
      importId.import(id);
      if (lastIdPath === "") {
        lastIdPath = importId.currentPath;
      }

      this.checkIdBelongs(importId);
      this.#ids[importId.getIdentityKey()] = importId;
      
      // For Type 42, update identity counter based on imported paths
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
    // decrypt the ids array using ECIES
    const decrypted = this.decrypt(idData);
    const ids = JSON.parse(decrypted) as Identities;

    const isOldFormat = Array.isArray(ids);
    if (isOldFormat) {
      console.log("Importing old format:\n", ids);
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
        if (!this.#masterPrivateKey) {
          throw new Error("Type 42 parameters not initialized");
        }
        importId = new MasterID(
          {
            rootPk: this.#masterPrivateKey
          },
          {},
          id.idSeed ?? ""
        );
      } else {
        if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
        importId = new MasterID(this.#HDPrivateKey, {}, id.idSeed ?? "");
      }
      
      importId.BAP_SERVER = this.#BAP_SERVER;
      importId.BAP_TOKEN = this.#BAP_TOKEN;
      importId.import(id);

      this.checkIdBelongs(importId);
      this.#ids[importId.getIdentityKey()] = importId;
      this.#lastIdPath = importId.currentPath;
    }
  }

  /**
   * Export identities. If no idKeys are provided, exports all identities.
   * @param idKeys Optional array of identity keys to export. If omitted, exports all identities.
   * @param encrypted Whether to encrypt the export data
   */
  // Overload signatures
  exportIds(idKeys?: string[], encrypted?: true): string;
  exportIds(idKeys: string[] | undefined, encrypted: false): Identities;
  exportIds(idKeys?: string[], encrypted = true): Identities | string {
    const idData: Identities = {
      lastIdPath: this.#lastIdPath,
      ids: [] as Identity[],
    };

    const keysToExport = idKeys || Object.keys(this.#ids);

    for (const key of keysToExport) {
      if (!this.#ids[key]) {
        throw new Error(`Identity ${key} not found`);
      }
      idData.ids.push(this.#ids[key].export());
    }

    if (encrypted) {
      return this.encrypt(JSON.stringify(idData));
    }
    return idData;
  }

  /**
   * Export a given ID from this instance for external storage
   *
   * By default this function will encrypt the data, using a derivative child of the main HD key
   *
   * @param idKey The key of the identity to export
   * @param encrypted Whether the data should be encrypted (default true)
   * @returns {[]|*}
   */
  // Overload signatures
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

  /**
   * Encrypt a string of data
   *
   * @param string
   * @returns {string}
   */
  encrypt(string: string): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      // For Type 42, we use the encryption path as an invoice number
      const encryptionKey = this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        ENCRYPTION_PATH
      );
      return toBase64(
        // @ts-ignore - you can remove the null when this is merged https://github.com/bitcoin-sv/ts-sdk/pull/123
        electrumEncrypt(toArray(string), encryptionKey.toPublicKey(), null)
      );
    }
    
    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    const derivedChild = this.#HDPrivateKey.derive(ENCRYPTION_PATH);
    return toBase64(
      // @ts-ignore - you can remove the null when this is merged https://github.com/bitcoin-sv/ts-sdk/pull/123
      electrumEncrypt(toArray(string), derivedChild.pubKey, null)
    );
  }

  /**
   * Decrypt a string of data
   *
   * @param string
   * @returns {string}
   */
  decrypt(string: string): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      // For Type 42, we use the encryption path as an invoice number
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

  /**
   * Sign an attestation for a user
   *
   * @param attestationHash The computed attestation hash for the user - this should be calculated with the MasterID class for an identity for the user
   * @param identityKey The identity key we are using for the signing
   * @param counter
   * @param dataString Optional data string that will be appended to the BAP attestation
   * @returns {string[]}
   */
  signAttestationWithAIP(
    attestationHash: string,
    identityKey: string,
    counter = 0,
    dataString = ""
  ) {
    const id = this.getId(identityKey);
    if (!id) {
      throw new Error("Could not find identity to attest with");
    }

    const attestationBuffer = this.getAttestationBuffer(
      attestationHash,
      counter,
      dataString
    );
    const { address, signature } = id.signMessage(attestationBuffer);

    return this.createAttestationTransaction(
      attestationHash,
      counter,
      address,
      signature,
      dataString
    );
  }

  /**
   * Verify an AIP signed attestation for a user
   *
   * [
   *   '0x6a',
   *   '0x31424150537561506e66476e53424d33474c56397968785564596534764762644d54',
   *   '0x415454455354',
   *   '0x33656166366361396334313936356538353831366439336439643034333136393032376633396661623034386333633031333663343364663635376462383761',
   *   '0x30',
   *   '0x7c',
   *   '0x313550636948473232534e4c514a584d6f5355615756693757537163376843667661',
   *   '0x424954434f494e5f4543445341',
   *   '0x31477531796d52567a595557634638776f6f506a7a4a4c764d383550795a64655876',
   *   '0x20ef60c5555001ddb1039bb0f215e46571fcb39ee46f48b089d1c08b0304dbcb3366d8fdf8bafd82be24b5ac42dcd6a5e96c90705dd42e3ad918b1b47ac3ce6ac2'
   * ]
   *
   * @param tx Array of hex values for the OP_RETURN values
   * @returns {{}}
   */
  verifyAttestationWithAIP(tx: number[][]): Attestation {
    if (
      !tx.every((t) => Array.isArray(t)) ||
      tx[0][0] !== OP.OP_RETURN ||
      toHex(tx[1]) !== BAP_BITCOM_ADDRESS_HEX
    ) {
      throw new Error("Not a valid BAP transaction");
    }
    const dataOffset = toHex(tx[7]) === "44415441" ? 5 : 0; // DATA
    const attestation: Attestation = {
      type: toUTF8(tx[2]),
      hash: toHex(tx[3]),
      sequence: toUTF8(tx[4]),
      signingProtocol: toUTF8(tx[7 + dataOffset]),
      signingAddress: toUTF8(tx[8 + dataOffset]),
      signature: toBase64(tx[9 + dataOffset]),
    };

    if (dataOffset && tx[3] === tx[8]) {
      // valid data addition
      attestation.data = toHex(tx[9]);
    }

    console.log({ attestation });

    try {
      const signatureBufferStatements: number[][] = [];
      for (let i = 0; i < 6 + dataOffset; i++) {
        signatureBufferStatements.push(tx[i]);
      }
      // const attestationBuffer = Buffer.concat(signatureBufferStatements as unknown as Uint8Array[]);
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

  /**
   * For BAP attestations we use all fields for the attestation
   *
   * @param attestationHash
   * @param counter
   * @param address
   * @param signature
   * @param dataString Optional data string that will be appended to the BAP attestation
   * @returns {number[]}
   */
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
      // data should be a string, either encrypted or stringified JSON if applicable
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

    console.log({ elements });
    return elements;
  }

  /**
   * This is a re-creation of how the bitcoinfiles-sdk creates a hash to sign for AIP
   *
   * @param attestationHash
   * @param counter
   * @param dataString Optional data string
   * @returns {number[]}
   */
  getAttestationBuffer(
    attestationHash: string,
    counter = 0,
    dataString = ""
  ): number[] {
    // re-create how AIP creates the buffer to sign
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

  /**
   * Verify that the identity challenge is signed by the address
   *
   * @param message Buffer, number[] or utf-8 string
   * @param address Bitcoin address of signee
   * @param signature Signature base64 string
   *
   * @return boolean
   */
  verifySignature(
    message: string | number[],
    address: string,
    signature: string
  ): boolean {
    // Convert message to number[]
    let msg: number[];
    if (Array.isArray(message)) {
      msg = message;
    } else if (Buffer.isBuffer(message)) {
      msg = [...message];
    } else {
      msg = toArray(message, "utf8");
    }

    const sig = Signature.fromCompact(signature, "base64");
    let publicKey: PublicKey | undefined;

    for (let recovery = 0; recovery < 4; recovery++) {
      try {
        publicKey = sig.RecoverPublicKey(
          recovery,
          new BigNumber(BSM.magicHash(msg))
        );
        const sigFitsPubkey = BSM.verify(msg, sig, publicKey);
        if (sigFitsPubkey && publicKey.toAddress() === address) {
          return true;
        }
      } catch {
        // try next recovery
        
      }
    }
    return false;
  }

  /**
   * Check whether the given transaction (BAP OP_RETURN) is valid, is signed and that the
   * identity signing is also valid at the time of signing
   *
   * @param idKey
   * @param address
   * @param challenge
   * @param signature
   *
   * @returns {Promise<boolean|*>}
   */
  async verifyChallengeSignature(
    idKey: string,
    address: string,
    challenge: string,
    signature: string
  ): Promise<boolean> {
    // first we test locally before sending to server
    const localVerification = this.verifySignature(
      challenge,
      address,
      signature
    );

    if (!localVerification) {
      return false;
    }

    try {
      const response = await this.getApiData<AttestationValidResponse>(
        "/attestation/valid",
        {
          idKey,
          address,
          challenge,
          signature,
        }
      );

      // Ensure we have a valid response with the expected structure
      if (response?.status === "success" && response?.result?.valid === true) {
        return true;
      }

      return false;
    } catch (error) {
      console.error("API call failed:", error);
      return false;
    }
  }

  /**
   * Check whether the given transaction (BAP OP_RETURN) is valid, is signed and that the
   * identity signing is also valid at the time of signing
   *
   * @param tx
   * @returns {Promise<boolean|*>}
   */
  async isValidAttestationTransaction(
    tx: number[][]
  ): Promise<AttestationValidResponse | false> {
    if (this.verifyAttestationWithAIP(tx)) {
      return this.getApiData<AttestationValidResponse>("/attestation/valid", {
        tx,
      });
    }
    return false;
  }

  /**
   * Get all signing keys for the given idKey
   *
   * @param address
   * @returns {Promise<*>}
   */
  async getIdentityFromAddress(
    address: string
  ): Promise<GetIdentityByAddressResponse> {
    return this.getApiData<GetIdentityByAddressResponse>(
      "/identity/from-address",
      {
        address,
      }
    );
  }

  /**
   * Get all signing keys for the given idKey
   *
   * @param idKey
   * @returns {Promise<*>}
   */
  async getIdentity(idKey: string): Promise<GetIdentityResponse> {
    return this.getApiData<GetIdentityResponse>("/identity/get", {
      idKey,
    });
  }

  /**
   * Get all attestations for the given attestation hash
   *
   * @param attestationHash
   */
  async getAttestationsForHash(
    attestationHash: string
  ): Promise<GetAttestationResponse> {
    // get all BAP ATTEST records for the given attestationHash
    return this.getApiData<GetAttestationResponse>("/attestations", {
      hash: attestationHash,
    });
  }

  /**
   * Export master BAP data in bitcoin-backup compatible format
   * Automatically handles both BIP32 and Type 42 modes
   * 
   * @deprecated BIP32 format export (when initialized with xprv) is deprecated. 
   * Use Type 42 initialization with { rootPk: wifKey } for new implementations.
   * 
   * @param label Optional user-defined label
   * @param xprv Extended private key (BIP32 mode only - if not provided, the HDPrivateKey will be used)
   * @param mnemonic BIP39 mnemonic phrase (BIP32 mode only - optional)
   * @returns BapMasterBackup compatible object (format depends on key type)
   */
  exportForBackup(
    label?: string,
    xprv?: string,
    mnemonic?: string
  ): {
    ids: string;
    xprv?: string;
    mnemonic?: string;
    rootPk?: string;
    label?: string;
    createdAt: string;
  } {
    const ids = this.exportIds(); // This returns encrypted string by default
    const baseBackup = {
      ids,
      ...(label && { label }),
      createdAt: new Date().toISOString(),
    };

    if (this.#isType42) {
      // Type 42 mode
      if (!this.#masterPrivateKey) {
        throw new Error("Type 42 parameters not initialized");
      }
      return {
        ...baseBackup,
        rootPk: this.#masterPrivateKey.toWif(),
      };
    }
      // BIP32 mode
      if (!this.#HDPrivateKey) {
        throw new Error("HD private key not initialized");
      }
      return {
        ...baseBackup,
        xprv: xprv || this.#HDPrivateKey.toString(),
        mnemonic: mnemonic || "",
      };
  }

  /**
   * Export a specific member ID in bitcoin-backup compatible format
   * @param idKey The key of the identity to export
   * @param label Optional user-defined label
   * @returns BapMemberBackup compatible object
   */
  exportMemberForBackup(
    idKey: string,
    label?: string
  ): {
    wif: string;
    id: string;
    label?: string;
    createdAt: string;
  } {
    const memberID = this.#ids[idKey];
    if (!memberID) {
      throw new Error(`Identity ${idKey} not found`);
    }

    // Get the member export and derive the WIF
    const memberExport = memberID.exportMember();

    return {
      wif: memberExport.wif,
      id: memberExport.encryptedData,
      ...(label && { label }),
      createdAt: new Date().toISOString(),
    };
  }
}

export { MasterID, MemberID };
export type {
  Attestation,
  Identity,
  MemberIdentity,
  IdentityAttributes,
  PathPrefix,
  Type42Params,
};
export * from "./apiTypes";
