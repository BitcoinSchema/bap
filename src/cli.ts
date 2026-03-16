#!/usr/bin/env bun
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { PrivateKey } from "@bsv/sdk";
import { BAP, bapIdFromAddress, bapIdFromPubkey } from "bsv-bap";
import { Command } from "commander";
import {
  getTouchIDStatus,
  isTouchIDSupported,
  protectRootKey,
  removeProtection,
  unlockRootKey,
} from "./touchid.js";

// Storage paths
const CONFIG_DIR = join(homedir(), ".bap");
const CONFIG_FILE = join(CONFIG_DIR, "identity.json");
const ACTIVE_FILE = join(CONFIG_DIR, "active");

// Stored config shape — rootPk is plaintext, rootPkEncrypted is Touch ID protected.
// Only one should be present at a time.
interface StoredConfig {
  rootPk?: string;
  rootPkEncrypted?: string;
  ids: string;
  labels: Record<string, string>;
  createdAt: string;
}

function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

function loadConfig(): StoredConfig | null {
  if (!existsSync(CONFIG_FILE)) return null;
  return JSON.parse(readFileSync(CONFIG_FILE, "utf-8")) as StoredConfig;
}

function createBAP(key: string): BAP {
  // xprv keys start with "xprv" — use BIP32 mode; otherwise Type42
  if (key.startsWith("xprv")) {
    return new BAP(key);
  }
  return new BAP({ rootPk: key });
}

/**
 * Resolve the root private key from config.
 * If Touch ID protected, triggers biometric auth to decrypt.
 * Returns the plaintext key string (WIF or xprv).
 */
async function resolveRootKey(config: StoredConfig): Promise<string> {
  if (config.rootPk) {
    return config.rootPk;
  }

  if (config.rootPkEncrypted) {
    return unlockRootKey(config.rootPkEncrypted);
  }

  // Legacy format: older BAP configs used "wif" instead of "rootPk"
  const legacy = config as Record<string, unknown>;
  if (typeof legacy.wif === "string") {
    return legacy.wif;
  }

  throw new Error(
    "Config has neither rootPk nor rootPkEncrypted. File may be corrupt."
  );
}

async function loadBAP(): Promise<{
  bap: BAP;
  config: StoredConfig;
  rootPk: string;
}> {
  const config = loadConfig();
  if (!config) {
    console.error("No identity found. Run 'bap create' first.");
    process.exit(1);
  }
  const rootPk = await resolveRootKey(config);
  const bap = createBAP(rootPk);
  if (config.ids) {
    bap.importIds(config.ids);
  }
  return { bap, config, rootPk };
}

function saveConfig(
  bap: BAP,
  rootPk: string,
  labels: Record<string, string>,
  createdAt?: string,
  encrypted?: { rootPkEncrypted: string }
): void {
  ensureConfigDir();
  const config: StoredConfig = {
    ids: bap.exportIds(),
    labels,
    createdAt: createdAt ?? new Date().toISOString(),
  };

  if (encrypted) {
    config.rootPkEncrypted = encrypted.rootPkEncrypted;
  } else {
    config.rootPk = rootPk;
  }

  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

function getActiveBapId(): string | null {
  if (!existsSync(ACTIVE_FILE)) return null;
  return readFileSync(ACTIVE_FILE, "utf-8").trim();
}

function setActiveBapId(bapId: string): void {
  ensureConfigDir();
  writeFileSync(ACTIVE_FILE, bapId);
}

function getActiveIdentity(bap: BAP, config: StoredConfig) {
  const activeBapId = getActiveBapId();
  const ids = bap.listIds();

  if (ids.length === 0) {
    console.error("No identities found. Run 'bap create' first.");
    process.exit(1);
  }

  const bapId = activeBapId && ids.includes(activeBapId) ? activeBapId : ids[0];
  const identity = bap.getId(bapId);
  if (!identity) {
    console.error(`Identity ${bapId} not found.`);
    process.exit(1);
  }
  return { identity, bapId, label: config.labels?.[bapId] };
}

/**
 * Attempt to protect a root key with Touch ID.
 * Returns { rootPkEncrypted } on success, or null if Touch ID is unavailable.
 * Prints status messages.
 *
 * Set BAP_NO_TOUCHID=1 to disable (used by tests and non-interactive environments).
 */
async function tryProtectWithTouchID(
  rootPk: string
): Promise<{ rootPkEncrypted: string } | null> {
  if (process.env.BAP_NO_TOUCHID === "1") {
    return null;
  }

  if (!isTouchIDSupported()) {
    console.log(
      "  Touch ID:      not available (platform unsupported) -- key stored as plaintext"
    );
    return null;
  }

  try {
    const status = await getTouchIDStatus(false);
    if (!status.available) {
      console.log(
        `  Touch ID:      not available (${status.biometryType}) -- key stored as plaintext`
      );
      return null;
    }

    const rootPkEncrypted = await protectRootKey(rootPk);
    console.log(`  Touch ID:      protected (${status.biometryType})`);
    return { rootPkEncrypted };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`  Touch ID:      failed (${msg}) -- key stored as plaintext`);
    return null;
  }
}

// --- CLI ---

const program = new Command();

program
  .name("bap")
  .description("BAP - Bitcoin Attestation Protocol CLI")
  .version("0.2.0");

// Identity Management

program
  .command("create")
  .description("Create a new identity")
  .option("--name <name>", "Human-readable label for the identity")
  .option("--wif <wif>", "Use an existing WIF key as the master key")
  .option("--no-touchid", "Skip Touch ID protection")
  .action(async (opts) => {
    const config = loadConfig();
    let rootPk: string;
    let labels: Record<string, string>;
    let createdAt: string | undefined;
    let bap: BAP;
    let encrypted: { rootPkEncrypted: string } | undefined;

    if (config) {
      // Existing master -- add a new identity
      rootPk = await resolveRootKey(config);
      labels = config.labels;
      createdAt = config.createdAt;
      bap = createBAP(rootPk);
      bap.importIds(config.ids);

      // Preserve existing protection state
      if (config.rootPkEncrypted) {
        encrypted = { rootPkEncrypted: config.rootPkEncrypted };
      }
    } else {
      // New master
      rootPk = opts.wif ?? PrivateKey.fromRandom().toWif();
      labels = {};
      bap = createBAP(rootPk);

      // Protect new key with Touch ID if available
      if (opts.touchid !== false) {
        const protection = await tryProtectWithTouchID(rootPk);
        if (protection) {
          encrypted = protection;
        }
      }
    }

    const identity = bap.newId();
    const bapId = identity.bapId;

    if (opts.name) {
      labels[bapId] = opts.name;
    }

    saveConfig(bap, rootPk, labels, createdAt, encrypted);
    setActiveBapId(bapId);

    console.log("Identity created:");
    console.log(`  BAP ID:        ${bapId}`);
    if (opts.name) console.log(`  Label:         ${opts.name}`);
    console.log(`  Root Address:  ${identity.rootAddress}`);
    console.log(`  Root Path:     ${identity.rootPath}`);
    console.log(`  Stored at:     ${CONFIG_FILE}`);
  });

program
  .command("list")
  .description("List all identities (* = active)")
  .action(async () => {
    const { bap, config } = await loadBAP();
    const ids = bap.listIds();
    const active = getActiveBapId();

    if (ids.length === 0) {
      console.log("No identities. Run 'bap create' to get started.");
      return;
    }

    for (const bapId of ids) {
      const marker = bapId === active ? " *" : "  ";
      const label = config.labels?.[bapId];
      const suffix = label ? ` (${label})` : "";
      console.log(`${marker} ${bapId}${suffix}`);
    }
  });

program
  .command("use")
  .description("Set active identity")
  .argument("<bapId>", "BAP ID to activate")
  .action(async (bapId: string) => {
    const { bap } = await loadBAP();
    const ids = bap.listIds();

    if (!ids.includes(bapId)) {
      console.error(`Identity ${bapId} not found.`);
      process.exit(1);
    }

    setActiveBapId(bapId);
    console.log(`Active identity: ${bapId}`);
  });

program
  .command("info")
  .description("Show active identity details")
  .action(async () => {
    const { bap, config } = await loadBAP();
    const { identity, bapId, label } = getActiveIdentity(bap, config);

    console.log("Active Identity:");
    console.log(`  BAP ID:        ${bapId}`);
    if (label) console.log(`  Label:         ${label}`);
    console.log(`  Root Address:  ${identity.rootAddress}`);
    console.log(`  Root Path:     ${identity.rootPath}`);
    console.log(`  Current Path:  ${identity.currentPath}`);
    console.log(`  Previous Path: ${identity.previousPath}`);
    console.log(
      `  Account Key:   ${identity.getAccountKey().toPublicKey().toString()}`
    );
  });

program
  .command("remove")
  .description("Remove an identity")
  .argument("<bapId>", "BAP ID to remove")
  .action(async (bapId: string) => {
    const { bap, config, rootPk } = await loadBAP();

    if (!bap.getId(bapId)) {
      console.error(`Identity ${bapId} not found.`);
      process.exit(1);
    }

    bap.removeId(bapId);
    if (config.labels) delete config.labels[bapId];

    // Preserve Touch ID protection state
    const encrypted = config.rootPkEncrypted
      ? { rootPkEncrypted: config.rootPkEncrypted }
      : undefined;
    saveConfig(bap, rootPk, config.labels, config.createdAt, encrypted);

    // Clear active if it was this one
    if (getActiveBapId() === bapId) {
      const remaining = bap.listIds();
      if (remaining.length > 0) {
        setActiveBapId(remaining[0]);
      } else {
        writeFileSync(ACTIVE_FILE, "");
      }
    }

    console.log(`Removed identity: ${bapId}`);
  });

// Backup

program
  .command("export")
  .description("Export master backup (JSON to stdout)")
  .action(async () => {
    const { bap } = await loadBAP();
    const backup = bap.exportForBackup();
    console.log(JSON.stringify(backup, null, 2));
  });

program
  .command("export-account")
  .description("Export account backup for active or specified identity")
  .option("--id <bapId>", "Specific BAP ID to export")
  .action(async (opts) => {
    const { bap, config } = await loadBAP();

    const identity = opts.id
      ? (() => {
          const id = bap.getId(opts.id);
          if (!id) {
            console.error(`Identity ${opts.id} not found.`);
            process.exit(1);
          }
          return id;
        })()
      : getActiveIdentity(bap, config).identity;

    const backup = identity.exportAccountBackup();
    console.log(JSON.stringify(backup, null, 2));
  });

program
  .command("import")
  .description("Import from backup file")
  .argument("<file>", "Path to backup JSON file")
  .option("--no-touchid", "Skip Touch ID protection")
  .action(async (file: string, opts) => {
    if (!existsSync(file)) {
      console.error(`File not found: ${file}`);
      process.exit(1);
    }

    const backup = JSON.parse(readFileSync(file, "utf-8"));

    if (!backup.rootPk && !backup.xprv) {
      console.error("Invalid backup format: missing rootPk or xprv");
      process.exit(1);
    }

    let bap: BAP;
    let rootPk: string;

    if (backup.rootPk) {
      bap = new BAP({ rootPk: backup.rootPk });
      rootPk = backup.rootPk;
    } else {
      bap = new BAP(backup.xprv);
      rootPk = backup.xprv;
    }

    if (backup.ids) {
      bap.importIds(backup.ids);
    }

    const labels: Record<string, string> = {};
    if (backup.label) {
      // Apply label to first identity as a default
      const ids = bap.listIds();
      if (ids.length > 0) {
        labels[ids[0]] = backup.label;
      }
    }

    // Protect with Touch ID if available
    let encrypted: { rootPkEncrypted: string } | undefined;
    if (opts.touchid !== false) {
      const protection = await tryProtectWithTouchID(rootPk);
      if (protection) {
        encrypted = protection;
      }
    }

    saveConfig(bap, rootPk, labels, undefined, encrypted);

    const ids = bap.listIds();
    if (ids.length > 0) {
      setActiveBapId(ids[0]);
    }

    console.log("Backup imported:");
    console.log(`  Identities: ${ids.length}`);
    if (backup.label) console.log(`  Label: ${backup.label}`);
    console.log(`  Stored at: ${CONFIG_FILE}`);
  });

// Crypto

program
  .command("encrypt")
  .description("Encrypt data with master key (ECIES)")
  .argument("<data>", "Data to encrypt")
  .action(async (data: string) => {
    const { bap } = await loadBAP();
    console.log(bap.encrypt(data));
  });

program
  .command("decrypt")
  .description("Decrypt ciphertext with master key")
  .argument("<ciphertext>", "Base64 ciphertext to decrypt")
  .action(async (ciphertext: string) => {
    const { bap } = await loadBAP();
    console.log(bap.decrypt(ciphertext));
  });

program
  .command("verify")
  .description("Verify a BSM signature")
  .argument("<message>", "Original message")
  .argument("<signature>", "Base64 signature")
  .argument("<address>", "Signing address")
  .action((message: string, signature: string, address: string) => {
    const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    let valid = false;
    try {
      valid = bap.verifySignature(message, address, signature);
    } catch {
      // Invalid signature format -- treat as not valid
    }
    console.log(
      JSON.stringify({ valid, message, address, signature }, null, 2)
    );
  });

// API Lookups

program
  .command("lookup")
  .description("Lookup identity on the BAP overlay")
  .argument("<bapId>", "BAP ID to lookup")
  .action(async (bapId: string) => {
    const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    const result = await bap.getIdentity(bapId);
    console.log(JSON.stringify(result, null, 2));
  });

program
  .command("lookup-address")
  .description("Lookup identity by Bitcoin address")
  .argument("<address>", "Bitcoin address to lookup")
  .action(async (address: string) => {
    const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    const result = await bap.getIdentityFromAddress(address);
    console.log(JSON.stringify(result, null, 2));
  });

program
  .command("attestations")
  .description("Get attestations for an attribute hash")
  .argument("<hash>", "Attribute hash to lookup")
  .action(async (hash: string) => {
    const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() });
    const result = await bap.getAttestationsForHash(hash);
    console.log(JSON.stringify(result, null, 2));
  });

// Utilities

program
  .command("id-from-address")
  .description("Derive BAP ID from a Bitcoin address")
  .argument("<address>", "Bitcoin address (must be the root/member address)")
  .action((address: string) => {
    console.log(bapIdFromAddress(address));
  });

program
  .command("id-from-pubkey")
  .description("Derive BAP ID from a compressed public key")
  .argument("<pubkey>", "Compressed public key hex (must be the member key)")
  .action((pubkey: string) => {
    console.log(bapIdFromPubkey(pubkey));
  });

// Touch ID Management

const touchid = program
  .command("touchid")
  .description("Manage Touch ID key protection");

touchid
  .command("status")
  .description("Check Touch ID availability and protection status")
  .action(async () => {
    const config = loadConfig();
    const hasEncryptedKey = !!config?.rootPkEncrypted;
    const status = await getTouchIDStatus(hasEncryptedKey);

    console.log("Touch ID Status:");
    console.log(`  Available:     ${status.available}`);
    console.log(`  Biometry:      ${status.biometryType}`);
    console.log(`  Key Protected: ${status.protected}`);

    if (config && !hasEncryptedKey && status.available) {
      console.log("\n  Your identity key is stored as plaintext.");
      console.log("  Run 'bap touchid enable' to protect it with Touch ID.");
    }
  });

touchid
  .command("enable")
  .description("Protect identity key with Touch ID")
  .action(async () => {
    const config = loadConfig();
    if (!config) {
      console.error("No identity found. Run 'bap create' first.");
      process.exit(1);
    }

    if (config.rootPkEncrypted) {
      if (config.rootPkEncrypted.startsWith("se:")) {
        console.log("Identity key is already protected with Secure Enclave.");
      } else {
        console.error(
          'Identity key uses the old Keychain format which is no longer supported. Re-import your backup with "bap import <file>" to migrate.'
        );
      }
      return;
    }

    // Support legacy "wif" field from older BAP configs
    const plainKey = config.rootPk ?? (config as Record<string, unknown>).wif as string | undefined;
    if (!plainKey) {
      console.error(
        "Config has no plaintext key to protect. File may be corrupt."
      );
      process.exit(1);
    }

    if (!isTouchIDSupported()) {
      console.error(
        "Secure Enclave is not available on this platform (requires macOS arm64)."
      );
      process.exit(1);
    }

    const status = await getTouchIDStatus(false);
    if (!status.available) {
      console.error(
        `Touch ID is not available on this machine (biometry type: ${status.biometryType}).`
      );
      process.exit(1);
    }

    console.log("Encrypting identity key with Secure Enclave...");
    const rootPkEncrypted = await protectRootKey(plainKey);

    // Rewrite config: replace rootPk with rootPkEncrypted (sentinel "se:bap-master")
    const newConfig: StoredConfig = {
      rootPkEncrypted,
      ids: config.ids,
      labels: config.labels,
      createdAt: config.createdAt,
    };
    writeFileSync(CONFIG_FILE, JSON.stringify(newConfig, null, 2));

    console.log("Identity key is now protected with Secure Enclave + Touch ID.");
    console.log("The plaintext key has been removed from disk.");
  });

touchid
  .command("disable")
  .description("Remove Touch ID protection (stores key as plaintext)")
  .action(async () => {
    const config = loadConfig();
    if (!config) {
      console.error("No identity found. Run 'bap create' first.");
      process.exit(1);
    }

    if (!config.rootPkEncrypted) {
      console.log(
        "Identity key is not Touch ID protected. Nothing to disable."
      );
      return;
    }

    if (!config.rootPkEncrypted.startsWith("se:")) {
      console.error(
        "Identity key uses the old Keychain format which is no longer supported."
      );
      console.error(
        "You will need to re-import your backup. Run 'bap export' if you can still decrypt, or use your backup file."
      );
      process.exit(1);
    }

    console.log("Decrypting identity key (Touch ID required)...");
    const rootPk = await unlockRootKey(config.rootPkEncrypted);

    // Rewrite config: replace rootPkEncrypted with rootPk
    const newConfig: StoredConfig = {
      rootPk,
      ids: config.ids,
      labels: config.labels,
      createdAt: config.createdAt,
    };
    writeFileSync(CONFIG_FILE, JSON.stringify(newConfig, null, 2));

    // Remove the Secure Enclave key and vault file
    await removeProtection();

    console.log("Secure Enclave protection removed. Key is now stored as plaintext.");
    console.log(
      "WARNING: Your identity key is no longer hardware-protected."
    );
  });

program.parse();
