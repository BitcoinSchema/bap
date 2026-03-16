#!/usr/bin/env bun
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { PrivateKey } from "@bsv/sdk";
import { Command } from "commander";
import { BAP, bapIdFromAddress, bapIdFromPubkey } from "bsv-bap";

// Storage paths
const CONFIG_DIR = join(homedir(), ".bap");
const CONFIG_FILE = join(CONFIG_DIR, "identity.json");
const ACTIVE_FILE = join(CONFIG_DIR, "active");

// Stored config shape
interface StoredConfig {
	rootPk: string;
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

function loadBAP(): { bap: BAP; config: StoredConfig } {
	const config = loadConfig();
	if (!config) {
		console.error("No identity found. Run 'bap create' first.");
		process.exit(1);
	}
	const bap = createBAP(config.rootPk);
	if (config.ids) {
		bap.importIds(config.ids);
	}
	return { bap, config };
}

function saveConfig(
	bap: BAP,
	rootPk: string,
	labels: Record<string, string>,
	createdAt?: string,
): void {
	ensureConfigDir();
	const config: StoredConfig = {
		rootPk,
		ids: bap.exportIds(),
		labels,
		createdAt: createdAt ?? new Date().toISOString(),
	};
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
	return { identity, bapId, label: config.labels[bapId] };
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
	.action((opts) => {
		let config = loadConfig();
		let rootPk: string;
		let labels: Record<string, string>;
		let createdAt: string | undefined;
		let bap: BAP;

		if (config) {
			// Existing master — add a new identity
			rootPk = config.rootPk;
			labels = config.labels;
			createdAt = config.createdAt;
			bap = createBAP(rootPk);
			bap.importIds(config.ids);
		} else {
			// New master
			rootPk = opts.wif ?? PrivateKey.fromRandom().toWif();
			labels = {};
			bap = createBAP(rootPk);
		}

		const identity = bap.newId();
		const bapId = identity.bapId;

		if (opts.name) {
			labels[bapId] = opts.name;
		}

		saveConfig(bap, rootPk, labels, createdAt);
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
	.action(() => {
		const { bap, config } = loadBAP();
		const ids = bap.listIds();
		const active = getActiveBapId();

		if (ids.length === 0) {
			console.log("No identities. Run 'bap create' to get started.");
			return;
		}

		for (const bapId of ids) {
			const marker = bapId === active ? " *" : "  ";
			const label = config.labels[bapId];
			const suffix = label ? ` (${label})` : "";
			console.log(`${marker} ${bapId}${suffix}`);
		}
	});

program
	.command("use")
	.description("Set active identity")
	.argument("<bapId>", "BAP ID to activate")
	.action((bapId: string) => {
		const { bap } = loadBAP();
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
	.action(() => {
		const { bap, config } = loadBAP();
		const { identity, bapId, label } = getActiveIdentity(bap, config);

		console.log("Active Identity:");
		console.log(`  BAP ID:        ${bapId}`);
		if (label) console.log(`  Label:         ${label}`);
		console.log(`  Root Address:  ${identity.rootAddress}`);
		console.log(`  Root Path:     ${identity.rootPath}`);
		console.log(`  Current Path:  ${identity.currentPath}`);
		console.log(`  Previous Path: ${identity.previousPath}`);
		console.log(`  Account Key:   ${identity.getAccountKey().toPublicKey().toString()}`);
	});

program
	.command("remove")
	.description("Remove an identity")
	.argument("<bapId>", "BAP ID to remove")
	.action((bapId: string) => {
		const { bap, config } = loadBAP();

		if (!bap.getId(bapId)) {
			console.error(`Identity ${bapId} not found.`);
			process.exit(1);
		}

		bap.removeId(bapId);
		delete config.labels[bapId];
		saveConfig(bap, config.rootPk, config.labels, config.createdAt);

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
	.action(() => {
		const { bap } = loadBAP();
		const backup = bap.exportForBackup();
		console.log(JSON.stringify(backup, null, 2));
	});

program
	.command("export-account")
	.description("Export account backup for active or specified identity")
	.option("--id <bapId>", "Specific BAP ID to export")
	.action((opts) => {
		const { bap, config } = loadBAP();

		let identity;
		if (opts.id) {
			identity = bap.getId(opts.id);
			if (!identity) {
				console.error(`Identity ${opts.id} not found.`);
				process.exit(1);
			}
		} else {
			({ identity } = getActiveIdentity(bap, config));
		}

		const backup = identity.exportAccountBackup();
		console.log(JSON.stringify(backup, null, 2));
	});

program
	.command("import")
	.description("Import from backup file")
	.argument("<file>", "Path to backup JSON file")
	.action((file: string) => {
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

		saveConfig(bap, rootPk, labels);

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
	.action((data: string) => {
		const { bap } = loadBAP();
		console.log(bap.encrypt(data));
	});

program
	.command("decrypt")
	.description("Decrypt ciphertext with master key")
	.argument("<ciphertext>", "Base64 ciphertext to decrypt")
	.action((ciphertext: string) => {
		const { bap } = loadBAP();
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
			// Invalid signature format — treat as not valid
		}
		console.log(JSON.stringify({ valid, message, address, signature }, null, 2));
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

program.parse();
