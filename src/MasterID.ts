import {
  Hash,
  type PrivateKey,
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
}

export { MasterID };
