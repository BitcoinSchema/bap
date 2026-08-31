import {
  BigNumber,
  BSM,
  Utils as BSVUtils,
  ECIES,
  Hash,
  HD,
  OP,
  PrivateKey,
  Signature,
} from "@bsv/sdk";
import { type APIFetcher, apiFetcher } from "./api";
import type {
  AttestationValidResponse,
  GetAttestationResponse,
  GetIdentityByAddressResponse,
  GetIdentityResponse,
} from "./apiTypes";
import {
  BAP_BITCOM_ADDRESS_HEX,
  BAP_SERVER,
  ENCRYPTION_PATH,
  MAX_INT,
} from "./constants";
import type {
  Attestation,
  BapAccountBackup,
  Identity,
  LegacyIdRecompute,
  OldIdentity,
  PathPrefix,
} from "./interface";
import { MasterID } from "./MasterID";
import { bapIdFromAddress, deriveIdentity0Address, Utils } from "./utils";

const { toArray, toUTF8, toBase64, toHex } = BSVUtils;
const { electrumEncrypt, electrumDecrypt } = ECIES;

type Identities = { lastIdPath: string; ids: Identity[] };

type ParsedIdEntry = {
  bapId: string;
  rootPath: string;
  rootAddress: string;
  currentPath: string;
  previousPath: string;
  idSeed: string;
};

type ParsedIdsExport = {
  entries: ParsedIdEntry[];
  lastIdPath?: string;
};

type Bip32PathPart = {
  hardened: boolean;
  value: number;
};

const CANONICAL_UINT = /^(?:0|[1-9]\d*)$/;

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Legacy entry has invalid ${field}`);
  }
  return value;
}

function parseBip32Path(path: string): Bip32PathPart[] | null {
  const rawParts = path.split("/");
  if (rawParts.length !== 7 || rawParts[0] !== "m") return null;

  const parts: Bip32PathPart[] = [];
  for (const rawPart of rawParts.slice(1)) {
    const match = rawPart.match(/^((?:0|[1-9]\d*))('?)$/);
    if (!match) return null;
    const value = Number(match[1]);
    if (!Number.isSafeInteger(value) || value > MAX_INT) return null;
    parts.push({ value, hardened: match[2] === "'" });
  }

  if (
    parts[0].value !== 424150 ||
    !parts[0].hardened ||
    parts[1].value !== 0 ||
    !parts[1].hardened ||
    parts[2].value !== 0 ||
    !parts[2].hardened
  ) {
    return null;
  }

  return parts;
}

function isCanonicalBip32Cursor(path: string): boolean {
  if (parseBip32Path(path)) return true;
  const rawParts = path.split("/");
  if (rawParts.length !== 4 || rawParts[0] !== "") return false;
  return rawParts.slice(1).every((part) => {
    const match = part.match(/^((?:0|[1-9]\d*))('?)$/);
    if (!match) return false;
    const value = Number(match[1]);
    return Number.isSafeInteger(value) && value <= MAX_INT;
  });
}

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
      if (!this.#masterPrivateKey)
        throw new Error("Master private key not initialized");
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
    let walletRoot: PrivateKey;

    if (this.#isType42) {
      if (!this.#masterPrivateKey)
        throw new Error("Master private key not initialized");
      let base = this.#masterPrivateKey;
      if (bapId.idSeed) {
        const seedHex = toHex(Hash.sha256(bapId.idSeed, "utf8"));
        base = base.deriveChild(base.toPublicKey(), seedHex);
      }
      walletRoot = base.deriveChild(base.toPublicKey(), bapId.rootPath);
    } else {
      if (!this.#HDPrivateKey)
        throw new Error("HD private key not initialized");
      let baseHd = this.#HDPrivateKey;
      if (bapId.idSeed) {
        const seedHex = toHex(Hash.sha256(bapId.idSeed, "utf8"));
        baseHd = baseHd.derive(Utils.getSigningPathFromHex(seedHex));
      }
      walletRoot = baseHd.derive(bapId.rootPath).privKey;
    }

    if (deriveIdentity0Address(walletRoot) !== bapId.rootAddress) {
      throw new Error("ID does not belong to this private key");
    }

    return true;
  }

  /**
   * Compute the pre-0.3 (legacy) rootAddress for an identity entry: the
   * address of the key derived at rootPath (seeded by idSeed when present),
   * with NO identity-0 child derivation. This is how bsv-bap <= 0.2.x
   * computed Identity.rootAddress before the BRC-100 identity-0 change
   * (0.3.0), which is intentionally NOT backward compatible.
   */
  #legacyRootAddress(rootPath: string, idSeed = ""): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey)
        throw new Error("Master private key not initialized");
      let base = this.#masterPrivateKey;
      if (idSeed) {
        const seedHex = toHex(Hash.sha256(idSeed, "utf8"));
        base = base.deriveChild(base.toPublicKey(), seedHex);
      }
      return base
        .deriveChild(base.toPublicKey(), rootPath)
        .toPublicKey()
        .toAddress();
    }
    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    let baseHd = this.#HDPrivateKey;
    if (idSeed) {
      const seedHex = toHex(Hash.sha256(idSeed, "utf8"));
      baseHd = baseHd.derive(Utils.getSigningPathFromHex(seedHex));
    }
    return baseHd.derive(rootPath).pubKey.toAddress();
  }

  /** Normalize an ids export (encrypted string, Identities object, or old array). */
  #parseIdsExport(
    idData: Identities | OldIdentity[] | string
  ): ParsedIdsExport {
    let parsed: unknown = idData;
    if (typeof parsed === "string") {
      parsed = JSON.parse(this.decrypt(parsed));
    }

    const isOldArray = Array.isArray(parsed);
    const entries = isOldArray
      ? parsed
      : (parsed as Partial<Identities> | null)?.ids;
    if (!Array.isArray(entries)) {
      throw new Error("Unrecognized identities format");
    }

    let lastIdPath: string | undefined;
    if (!isOldArray) {
      lastIdPath = requireNonEmptyString(
        (parsed as Partial<Identities>).lastIdPath,
        "lastIdPath"
      );
    }

    return {
      entries: entries.map((rawEntry) => {
        if (!rawEntry || typeof rawEntry !== "object") {
          throw new Error("Legacy entry must be an object");
        }
        const entry = rawEntry as Partial<Identity & OldIdentity>;
        const bapId =
          "bapId" in entry
            ? entry.bapId
            : (entry as Partial<OldIdentity>).identityKey;
        const idSeed = entry.idSeed;
        if (idSeed !== undefined && typeof idSeed !== "string") {
          throw new Error("Legacy entry has invalid idSeed");
        }
        if (!isOldArray && idSeed === undefined) {
          throw new Error("Legacy entry has invalid idSeed");
        }

        return {
          bapId: requireNonEmptyString(bapId, "bapId"),
          rootPath: requireNonEmptyString(entry.rootPath, "rootPath"),
          rootAddress: requireNonEmptyString(entry.rootAddress, "rootAddress"),
          currentPath: requireNonEmptyString(entry.currentPath, "currentPath"),
          previousPath: requireNonEmptyString(
            entry.previousPath,
            "previousPath"
          ),
          // idSeed was optional only in the oldest array schema.
          idSeed: idSeed ?? "",
        };
      }),
      lastIdPath,
    };
  }

  #validateType42Lineage(entry: ParsedIdEntry): void {
    const rootMatch = entry.rootPath.match(/^bap:((?:0|[1-9]\d*))$/);
    if (!rootMatch || !Number.isSafeInteger(Number(rootMatch[1]))) {
      throw new Error("Legacy entry has invalid Type 42 rootPath");
    }

    if (entry.currentPath === entry.rootPath) {
      if (entry.previousPath !== entry.rootPath) {
        throw new Error("Legacy entry has an impossible Type 42 lineage");
      }
      return;
    }

    const identityIndex = rootMatch[1];
    const numericRotationStart = BigInt(identityIndex) + 1n;
    const parseRotation = (
      path: string
    ): { namespace: "numeric" | "scoped"; rotation: bigint } | null => {
      if (CANONICAL_UINT.test(path) && path !== "0") {
        return { namespace: "numeric", rotation: BigInt(path) };
      }
      const scoped = path.match(
        new RegExp(`^bap:${identityIndex}:((?:0|[1-9]\\d*))$`)
      );
      if (!scoped || scoped[1] === "0") return null;
      return { namespace: "scoped", rotation: BigInt(scoped[1]) };
    };

    const current = parseRotation(entry.currentPath);
    if (!current) {
      throw new Error("Legacy entry has invalid Type 42 currentPath");
    }

    if (entry.previousPath === entry.rootPath) {
      // Before the scoped bap:N:R format, getNextPath("bap:N") stripped
      // non-digits and incremented N, producing the bare string "N+1".
      const expectedFirstRotation =
        current.namespace === "numeric" ? numericRotationStart : 1n;
      if (current.rotation !== expectedFirstRotation) {
        throw new Error("Legacy entry has an impossible Type 42 lineage");
      }
      return;
    }

    const previous = parseRotation(entry.previousPath);
    if (
      !previous ||
      previous.namespace !== current.namespace ||
      (previous.namespace === "numeric" &&
        previous.rotation < numericRotationStart) ||
      current.rotation !== previous.rotation + 1n
    ) {
      throw new Error("Legacy entry has an impossible Type 42 lineage");
    }
  }

  #validateBip32Lineage(entry: ParsedIdEntry): void {
    const root = parseBip32Path(entry.rootPath);
    const previous = parseBip32Path(entry.previousPath);
    const current = parseBip32Path(entry.currentPath);
    if (!root || !previous || !current) {
      throw new Error("Legacy entry has an invalid BIP32 lineage path");
    }

    if (entry.currentPath === entry.rootPath) {
      if (entry.previousPath !== entry.rootPath) {
        throw new Error("Legacy entry has an impossible BIP32 lineage");
      }
      return;
    }

    const sameIdentityNamespace = (candidate: Bip32PathPart[]): boolean =>
      root
        .slice(0, 5)
        .every(
          (part, index) =>
            part.value === candidate[index].value &&
            part.hardened === candidate[index].hardened
        ) && root[5].hardened === candidate[5].hardened;

    if (
      !sameIdentityNamespace(previous) ||
      !sameIdentityNamespace(current) ||
      previous[5].value < root[5].value ||
      current[5].value !== previous[5].value + 1
    ) {
      throw new Error("Legacy entry has an impossible BIP32 lineage");
    }
  }

  #validateLegacyEntry(entry: ParsedIdEntry): void {
    if (this.#isType42) {
      this.#validateType42Lineage(entry);
    } else {
      this.#validateBip32Lineage(entry);
    }

    if (
      this.#legacyRootAddress(entry.rootPath, entry.idSeed) !==
      entry.rootAddress
    ) {
      throw new Error("ID does not belong to this private key");
    }
    if (bapIdFromAddress(entry.rootAddress) !== entry.bapId) {
      throw new Error("Legacy entry bapId does not match rootAddress");
    }
  }

  #validateLegacyCursor(lastIdPath: string | undefined): void {
    if (lastIdPath === undefined) return;
    if (this.#isType42) {
      if (!/^bap:(?:0|[1-9]\d*)$/.test(lastIdPath)) {
        throw new Error("Legacy export has invalid Type 42 lastIdPath");
      }
      return;
    }
    if (!isCanonicalBip32Cursor(lastIdPath)) {
      throw new Error("Legacy export has invalid BIP32 lastIdPath");
    }
  }

  /**
   * Check whether an ids export was produced by bsv-bap <= 0.2.x with this
   * key: every entry's stored rootAddress must match the legacy derivation
   * of its rootPath, its bapId must match that address, and its lineage must
   * be locally well-formed. Returns false for current-format exports, exports
   * that belong to a different key, and malformed lineage metadata.
   *
   * currentPath/previousPath were not signed in the legacy backup format.
   * Local validation can reject impossible transitions, but cannot prove the
   * authenticity of an otherwise valid substituted transition.
   */
  isLegacyIdsExport(idData: Identities | OldIdentity[] | string): boolean {
    try {
      const parsed = this.#parseIdsExport(idData);
      this.#validateLegacyCursor(parsed.lastIdPath);
      return (
        parsed.entries.length > 0 &&
        parsed.entries.every((entry) => {
          this.#validateLegacyEntry(entry);
          return true;
        })
      );
    } catch {
      return false;
    }
  }

  /**
   * Recompute identities from a legacy (<= 0.2.x) export under the current
   * BRC-100 identity-0 derivation. Each entry is verified against the
   * legacy formula first — proving the export belongs to this key — then
   * re-derived at its original rootPath/idSeed. The key container, rootPath,
   * idSeed, currentPath, and previousPath are unchanged byte-for-byte; only
   * rootAddress/bapId adopt the current public derivation. No rotation or key
   * conversion occurs. Callers must re-export (`exportIds`) and reissue the
   * backup file; the legacy export is obsolete after this.
   *
   * @throws if any entry does not match the legacy derivation either
   * (wrong key or unrecognized format) — never silently accepts.
   */
  recomputeLegacyIds(
    idData: Identities | OldIdentity[] | string
  ): LegacyIdRecompute[] {
    const parsed = this.#parseIdsExport(idData);
    if (parsed.entries.length === 0) {
      throw new Error("Legacy export contains no identities");
    }
    this.#validateLegacyCursor(parsed.lastIdPath);
    for (const entry of parsed.entries) this.#validateLegacyEntry(entry);

    const staged = parsed.entries.map((entry) => {
      let identity: MasterID;
      if (this.#isType42) {
        if (!this.#masterPrivateKey)
          throw new Error("Type 42 parameters not initialized");
        identity = new MasterID(
          { rootPk: this.#masterPrivateKey },
          entry.idSeed
        );
      } else {
        if (!this.#HDPrivateKey)
          throw new Error("HD private key not initialized");
        identity = new MasterID(this.#HDPrivateKey, entry.idSeed);
      }

      identity.rootPath = entry.rootPath;
      const newBapId = identity.bapId;
      const newRootAddress = identity.rootAddress;
      identity.import({
        bapId: newBapId,
        rootPath: entry.rootPath,
        rootAddress: newRootAddress,
        currentPath: entry.currentPath,
        previousPath: entry.previousPath,
        idSeed: entry.idSeed,
        lastIdPath: "",
      });

      return {
        identity,
        mapping: {
          oldBapId: entry.bapId,
          newBapId,
          rootPath: entry.rootPath,
        } satisfies LegacyIdRecompute,
      };
    });

    const stagedIds = new Set<string>();
    for (const { identity } of staged) {
      if (stagedIds.has(identity.bapId) || this.#ids[identity.bapId]) {
        throw new Error("Legacy export contains a duplicate identity");
      }
      stagedIds.add(identity.bapId);
    }

    for (const { identity } of staged) {
      this.#ids[identity.bapId] = identity;

      // Keep the Type 42 counter monotonic so a later argument-less newId()
      // cannot collide with a recomputed bap:N identity.
      if (this.#isType42) {
        const counter = Number(identity.rootPath.split(":")[1]);
        this.#identityCounter = Math.max(this.#identityCounter, counter + 1);
      }
    }

    // Old array exports predate the container cursor. Preserve a real cursor
    // when one exists; otherwise retain the prior behavior of using the final
    // identity's root path for subsequent identity creation.
    this.#lastIdPath =
      parsed.lastIdPath ?? staged[staged.length - 1].identity.rootPath;

    return staged.map(({ mapping }) => mapping);
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
      if (!this.#masterPrivateKey)
        throw new Error("Type 42 parameters not initialized");
      newIdentity = new MasterID({ rootPk: this.#masterPrivateKey }, idSeed);
    } else {
      if (!this.#HDPrivateKey)
        throw new Error("HD private key not initialized");
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
        if (!this.#masterPrivateKey)
          throw new Error("Type 42 parameters not initialized");
        importId = new MasterID({ rootPk: this.#masterPrivateKey }, id.idSeed);
      } else {
        if (!this.#HDPrivateKey)
          throw new Error("HD private key not initialized");
        importId = new MasterID(this.#HDPrivateKey, id.idSeed);
      }

      importId.import(id);
      if (lastIdPath === "") {
        lastIdPath = importId.currentPath;
      }

      this.checkIdBelongs(importId);
      this.#ids[importId.bapId] = importId;

      if (this.#isType42 && importId.rootPath.startsWith("bap:")) {
        const pathParts = importId.rootPath.split(":");
        if (pathParts.length >= 2) {
          const counter = Number.parseInt(pathParts[1], 10);
          if (!Number.isNaN(counter)) {
            this.#identityCounter = Math.max(
              this.#identityCounter,
              counter + 1
            );
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
        if (!this.#masterPrivateKey)
          throw new Error("Type 42 parameters not initialized");
        importId = new MasterID(
          { rootPk: this.#masterPrivateKey },
          id.idSeed ?? ""
        );
      } else {
        if (!this.#HDPrivateKey)
          throw new Error("HD private key not initialized");
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

  encrypt(string: string): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey)
        throw new Error("Master private key not initialized");
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
    return toBase64(electrumEncrypt(toArray(string), derivedChild.pubKey));
  }

  decrypt(string: string): string {
    if (this.#isType42) {
      if (!this.#masterPrivateKey)
        throw new Error("Master private key not initialized");
      const encryptionKey = this.#masterPrivateKey.deriveChild(
        this.#masterPrivateKey.toPublicKey(),
        ENCRYPTION_PATH
      );
      return toUTF8(electrumDecrypt(toArray(string, "base64"), encryptionKey));
    }

    if (!this.#HDPrivateKey) throw new Error("HD private key not initialized");
    const derivedChild = this.#HDPrivateKey.derive(ENCRYPTION_PATH);
    return toUTF8(
      electrumDecrypt(toArray(string, "base64"), derivedChild.privKey)
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
        if (
          BSM.verify(msg, sig, publicKey) &&
          publicKey.toAddress() === address
        ) {
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
    const localVerification = this.verifySignature(
      challenge,
      address,
      signature
    );
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
      return this.getApiData<AttestationValidResponse>("/attestation/valid", {
        tx,
      });
    }
    return false;
  }

  async getIdentityFromAddress(
    address: string
  ): Promise<GetIdentityByAddressResponse> {
    return this.getApiData<GetIdentityByAddressResponse>(
      "/identity/validByAddress",
      { address }
    );
  }

  async getIdentity(idKey: string): Promise<GetIdentityResponse> {
    return this.getApiData<GetIdentityResponse>("/identity/get", { idKey });
  }

  async getAttestationsForHash(
    attestationHash: string
  ): Promise<GetAttestationResponse> {
    return this.getApiData<GetAttestationResponse>("/attestations", {
      hash: attestationHash,
    });
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
      if (!this.#masterPrivateKey)
        throw new Error("Type 42 parameters not initialized");
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

export { MasterID };
// Protocol prefixes (Bitcom addresses) re-exported for consumer convenience —
// e.g. building AIP signatures or BAP transactions.
export {
  AIP_BITCOM_ADDRESS,
  AIP_BITCOM_ADDRESS_HEX,
  BAP_BITCOM_ADDRESS,
  BAP_BITCOM_ADDRESS_HEX,
} from "./constants";
export { bapIdFromAddress, bapIdFromPubkey } from "./utils";
export type {
  Attestation,
  BapAccountBackup,
  Identity,
  LegacyIdRecompute,
  PathPrefix,
  Type42Params,
};
export * from "./apiTypes";
