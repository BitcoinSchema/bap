import {
  ECIES,
  Hash,
  type PrivateKey,
  type PublicKey,
  HD,
  Utils as BSVUtils,
} from "@bsv/sdk";

import {
  SIGNING_PATH_PREFIX,
  MAX_INT,
} from "./constants";
import type {
  BapAccountBackup,
  Identity,
  OldIdentity,
} from "./interface";
import { Utils, bapIdFromAddress } from "./utils";

interface Type42KeySource {
  rootPk: PrivateKey;
}

class MasterID {
  #HDPrivateKey: HD | undefined;
  #masterPrivateKey: PrivateKey | undefined;
  #isType42: boolean;
  #rootPath: string;
  #currentPath: string;
  #previousPath: string;
  #idSeed: string;

  rootAddress: string;
  bapId: string;

  constructor(
    keySource: HD | Type42KeySource,
    idSeed = ""
  ) {
    if (keySource instanceof HD) {
      this.#isType42 = false;
      if (idSeed) {
        const seedHex = BSVUtils.toHex(Hash.sha256(idSeed, "utf8"));
        const seedPath = Utils.getSigningPathFromHex(seedHex);
        this.#HDPrivateKey = keySource.derive(seedPath);
      } else {
        this.#HDPrivateKey = keySource;
      }
    } else {
      this.#isType42 = true;
      this.#masterPrivateKey = keySource.rootPk;
      if (idSeed) {
        const seedHex = BSVUtils.toHex(Hash.sha256(idSeed, "utf8"));
        this.#masterPrivateKey = this.#masterPrivateKey.deriveChild(
          this.#masterPrivateKey.toPublicKey(),
          seedHex
        );
      }
    }

    this.#idSeed = idSeed;

    this.#rootPath = `${SIGNING_PATH_PREFIX}/0/0/0`;
    this.#previousPath = `${SIGNING_PATH_PREFIX}/0/0/0`;
    this.#currentPath = `${SIGNING_PATH_PREFIX}/0/0/1`;

    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      const rootKey = this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        this.#rootPath
      );
      this.rootAddress = rootKey.toPublicKey().toAddress();
    } else {
      if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
      const rootChild = this.#HDPrivateKey.derive(this.#rootPath);
      this.rootAddress = rootChild.privKey.toPublicKey().toAddress();
    }

    this.bapId = bapIdFromAddress(this.rootAddress);
  }

  set rootPath(path: string) {
    if (this.#isType42) {
      this.#rootPath = path;
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      const derivedKey = this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        path
      );
      this.rootAddress = derivedKey.toPublicKey().toAddress();
      this.#previousPath = path;
      this.#currentPath = path;
    } else {
      let pathToUse = path;
      if (path.split("/").length < 5) {
        pathToUse = `${SIGNING_PATH_PREFIX}${path}`;
      }
      if (!this.validatePath(pathToUse)) {
        throw new Error(`invalid signing path given ${pathToUse}`);
      }
      this.#rootPath = pathToUse;
      if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
      const derivedChild = this.#HDPrivateKey.derive(pathToUse);
      this.rootAddress = derivedChild.pubKey.toAddress();
      this.#previousPath = pathToUse;
      this.#currentPath = pathToUse;
    }
    this.bapId = bapIdFromAddress(this.rootAddress);
  }

  get rootPath(): string {
    return this.#rootPath;
  }

  set currentPath(path: string) {
    if (this.#isType42) {
      this.#previousPath = this.#currentPath;
      this.#currentPath = path;
    } else {
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
  }

  get currentPath(): string {
    return this.#currentPath;
  }

  get previousPath(): string {
    return this.#previousPath;
  }

  get idSeed(): string {
    return this.#idSeed;
  }

  getAccountKey(): PrivateKey {
    if (this.#isType42) {
      if (!this.#masterPrivateKey) throw new Error("Master private key not initialized");
      return this.#masterPrivateKey;
    }
    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    return this.#HDPrivateKey.privKey;
  }

  validatePath(path: string): boolean {
    if (
      path.match(
        /\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?/
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

  import(identity: Identity | OldIdentity): void {
    this.bapId = "bapId" in identity ? identity.bapId : (identity as OldIdentity).identityKey;
    this.#rootPath = identity.rootPath;
    this.rootAddress = identity.rootAddress;
    this.#previousPath = identity.previousPath;
    this.#currentPath = identity.currentPath;
    this.#idSeed = ("idSeed" in identity ? identity.idSeed : "") || "";
  }

  export(): Identity {
    return {
      bapId: this.bapId,
      rootPath: this.#rootPath,
      rootAddress: this.rootAddress,
      previousPath: this.#previousPath,
      currentPath: this.#currentPath,
      idSeed: this.#idSeed,
      lastIdPath: "",
    };
  }

  exportAccountBackup(): BapAccountBackup {
    return {
      wif: this.getAccountKey().toWif(),
      id: this.bapId,
    };
  }

  /**
   * Derive a friend-specific private key using Type42 (BRC-42) derivation.
   *
   * The seed (typically a friend's BAP ID) is used as the invoice number
   * in the BRC-42 key derivation. The member's own public key serves as
   * the counterparty public key, making this a self-derivation that
   * produces deterministic, seed-specific child keys.
   *
   * In BIP32 mode, the seed is hashed to produce a derivation path.
   *
   * @param seed - The derivation seed (e.g., friend's BAP ID)
   * @returns The derived private key
   */
  #deriveKeyFromSeed(seed: string): PrivateKey {
    if (this.#isType42) {
      if (!this.#masterPrivateKey)
        throw new Error("Master private key not initialized");
      return this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        seed
      );
    }
    if (!this.#HDPrivateKey)
      throw new Error("HD private key not initialized");
    const seedHex = BSVUtils.toHex(Hash.sha256(seed, "utf8"));
    const seedPath = Utils.getSigningPathFromHex(seedHex);
    return this.#HDPrivateKey.derive(seedPath).privKey;
  }

  /**
   * Get a friend-specific public key derived from this member's key
   * and a seed (typically the friend's BAP ID).
   *
   * This public key should be shared with the friend (e.g., in a friend
   * request transaction) so they can use it as the counterparty key
   * when encrypting messages to this member.
   *
   * @param seed - The derivation seed (e.g., friend's BAP ID)
   * @returns The derived public key
   */
  getEncryptionPublicKeyWithSeed(seed: string): PublicKey {
    return this.#deriveKeyFromSeed(seed).toPublicKey();
  }

  /**
   * Encrypt data using a friend-specific derived key and ECIES.
   *
   * Derives a private key from this member's key + seed, then uses
   * Electrum ECIES to encrypt the data to the counterparty's public key.
   * The counterparty can decrypt using their corresponding private key
   * and this member's derived public key.
   *
   * @param data - The data to encrypt (string or binary)
   * @param seed - The derivation seed (e.g., friend's BAP ID)
   * @param counterPartyPublicKey - The friend's derived public key
   * @returns Base64-encoded encrypted payload
   */
  encryptWithSeed(
    data: string | number[],
    seed: string,
    counterPartyPublicKey: PublicKey
  ): string {
    const derivedKey = this.#deriveKeyFromSeed(seed);
    const messageBuf =
      typeof data === "string" ? BSVUtils.toArray(data, "utf8") : data;
    const encrypted = ECIES.electrumEncrypt(
      messageBuf,
      counterPartyPublicKey,
      derivedKey,
      true
    );
    return BSVUtils.toBase64(encrypted);
  }

  /**
   * Decrypt data using a friend-specific derived key and ECIES.
   *
   * Derives a private key from this member's key + seed, then uses
   * Electrum ECIES to decrypt data that was encrypted by the
   * counterparty using this member's derived public key.
   *
   * @param ciphertext - Base64-encoded encrypted payload
   * @param seed - The derivation seed (e.g., friend's BAP ID)
   * @param counterPartyPublicKey - The friend's derived public key
   * @returns The decrypted data as a UTF-8 string
   */
  decryptWithSeed(
    ciphertext: string,
    seed: string,
    counterPartyPublicKey: PublicKey
  ): string {
    const derivedKey = this.#deriveKeyFromSeed(seed);
    const encBuf = BSVUtils.toArray(ciphertext, "base64");
    const decrypted = ECIES.electrumDecrypt(
      encBuf,
      derivedKey,
      counterPartyPublicKey
    );
    return BSVUtils.toUTF8(decrypted);
  }
}

export { MasterID };
