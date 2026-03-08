#!/usr/bin/env bun
/**
 * BAP CLI - Bitcoin Attestation Protocol Command Line Interface
 *
 * Usage:
 *   bap create [--name <name>] [--wif <wif>]  Create new BAP identity
 *   bap sign <message>                        Sign a message
 *   bap verify <message> <sig> <address>      Verify a signature
 *   bap friend-pubkey <friendBapId>           Get friend public key
 *   bap encrypt <data> <friendBapId>          Encrypt for friend
 *   bap decrypt <ciphertext> <friendBapId>    Decrypt from friend
 *   bap export                                Export identity backup
 *   bap import <backup>                       Import identity from backup
 *   bap info                                  Show current identity info
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { PrivateKey, Utils } from "@bsv/sdk";
import { BAP } from "bsv-bap";

const { toHex, toArray } = Utils;

// Default config path
const CONFIG_DIR = join(homedir(), ".bap");
const CONFIG_FILE = join(CONFIG_DIR, "identity.json");

interface StoredIdentity {
	wif: string;
	ids: string;
	label?: string;
	createdAt: string;
}

function ensureConfigDir(): void {
	const { mkdirSync } = require("node:fs");
	if (!existsSync(CONFIG_DIR)) {
		mkdirSync(CONFIG_DIR, { recursive: true });
	}
}

function loadIdentity(): BAP | null {
	if (!existsSync(CONFIG_FILE)) {
		return null;
	}

	try {
		const data = JSON.parse(readFileSync(CONFIG_FILE, "utf-8")) as StoredIdentity;
		const bap = new BAP({ rootPk: data.wif });
		if (data.ids) {
			bap.importIds(data.ids);
		}
		return bap;
	} catch (error) {
		console.error("Failed to load identity:", error);
		return null;
	}
}

function saveIdentity(bap: BAP, wif: string, label?: string): void {
	ensureConfigDir();
	const backup: StoredIdentity = {
		wif,
		ids: bap.exportIds(),
		...(label && { label }),
		createdAt: new Date().toISOString(),
	};
	writeFileSync(CONFIG_FILE, JSON.stringify(backup, null, 2));
}

function printUsage(): void {
	console.log(`
BAP CLI - Bitcoin Attestation Protocol

Commands:
  create [--name <name>] [--wif <wif>]  Create new BAP identity
  sign <message>                        Sign a message with identity
  verify <message> <sig> <address>      Verify a BSM signature
  friend-pubkey <friendBapId>           Get encryption pubkey for friend
  encrypt <data> <friendBapId>          Encrypt data for friend
  decrypt <ciphertext> <friendBapId>    Decrypt data from friend
  export                                Export identity backup (JSON)
  import <file>                         Import identity from backup file
  info                                  Show current identity info
  help                                  Show this help message

Options:
  --name <name>  Identity name (for create)
  --wif <wif>    Use existing WIF key (for create)

Examples:
  bap create --name "My Identity"
  bap sign "Hello World"
  bap verify "Hello World" <signature> <address>
  bap friend-pubkey "abc123..."
  bap encrypt "secret message" "abc123..."
  bap decrypt "<ciphertext>" "abc123..."
  bap export > backup.json
  bap import backup.json
`);
}

function createIdentity(args: string[]): void {
	let name = "Default Identity";
	let wif: string | undefined;

	// Parse arguments
	for (let i = 0; i < args.length; i++) {
		if (args[i] === "--name" && args[i + 1]) {
			name = args[i + 1];
			i++;
		} else if (args[i] === "--wif" && args[i + 1]) {
			wif = args[i + 1];
			i++;
		}
	}

	// Generate or use provided WIF
	if (!wif) {
		const privateKey = PrivateKey.fromRandom();
		wif = privateKey.toWif();
	}

	// Create BAP instance with Type42
	const bap = new BAP({ rootPk: wif });
	const identity = bap.newId(name);

	// Save to config
	saveIdentity(bap, wif);

	console.log("Identity created successfully!");
	console.log(`  Name: ${name}`);
	console.log(`  Identity Key: ${identity.getIdentityKey()}`);
	console.log(`  Root Address: ${identity.rootAddress}`);
	console.log(`  Signing Address: ${identity.getCurrentAddress()}`);
	console.log(`\nStored at: ${CONFIG_FILE}`);
}

function signMessage(message: string): void {
	const bap = loadIdentity();
	if (!bap) {
		console.error("No identity found. Run 'bap create' first.");
		process.exit(1);
	}

	const ids = bap.listIds();
	if (ids.length === 0) {
		console.error("No identities in BAP instance.");
		process.exit(1);
	}

	const identity = bap.getId(ids[0]);
	if (!identity) {
		console.error("Failed to get identity.");
		process.exit(1);
	}

	const { address, signature } = identity.signMessage(toArray(message, "utf8"));

	console.log(JSON.stringify({ message, address, signature }, null, 2));
}

function verifySignature(message: string, signature: string, address: string): void {
	const bap = new BAP({ rootPk: PrivateKey.fromRandom().toWif() }); // Temporary instance
	const isValid = bap.verifySignature(message, address, signature);

	console.log(JSON.stringify({ valid: isValid, message, address, signature }, null, 2));
}

function getFriendPubkey(friendBapId: string): void {
	const bap = loadIdentity();
	if (!bap) {
		console.error("No identity found. Run 'bap create' first.");
		process.exit(1);
	}

	const ids = bap.listIds();
	if (ids.length === 0) {
		console.error("No identities in BAP instance.");
		process.exit(1);
	}

	const identity = bap.getId(ids[0]);
	if (!identity) {
		console.error("Failed to get identity.");
		process.exit(1);
	}

	const publicKey = identity.getEncryptionPublicKeyWithSeed(friendBapId);
	console.log(JSON.stringify({ friendBapId, publicKey }, null, 2));
}

function encryptForFriend(data: string, friendBapId: string): void {
	const bap = loadIdentity();
	if (!bap) {
		console.error("No identity found. Run 'bap create' first.");
		process.exit(1);
	}

	const ids = bap.listIds();
	if (ids.length === 0) {
		console.error("No identities in BAP instance.");
		process.exit(1);
	}

	const identity = bap.getId(ids[0]);
	if (!identity) {
		console.error("Failed to get identity.");
		process.exit(1);
	}

	const ciphertext = identity.encryptWithSeed(data, friendBapId);
	console.log(JSON.stringify({ ciphertext, friendBapId }, null, 2));
}

function decryptFromFriend(ciphertext: string, friendBapId: string): void {
	const bap = loadIdentity();
	if (!bap) {
		console.error("No identity found. Run 'bap create' first.");
		process.exit(1);
	}

	const ids = bap.listIds();
	if (ids.length === 0) {
		console.error("No identities in BAP instance.");
		process.exit(1);
	}

	const identity = bap.getId(ids[0]);
	if (!identity) {
		console.error("Failed to get identity.");
		process.exit(1);
	}

	try {
		const data = identity.decryptWithSeed(ciphertext, friendBapId);
		console.log(JSON.stringify({ data, friendBapId }, null, 2));
	} catch (error) {
		console.error("Decryption failed:", error instanceof Error ? error.message : error);
		process.exit(1);
	}
}

function exportIdentity(): void {
	const bap = loadIdentity();
	if (!bap) {
		console.error("No identity found. Run 'bap create' first.");
		process.exit(1);
	}

	// Read stored WIF
	const stored = JSON.parse(readFileSync(CONFIG_FILE, "utf-8")) as StoredIdentity;
	const backup = bap.exportForBackup(stored.label);

	console.log(JSON.stringify(backup, null, 2));
}

function importIdentity(file: string): void {
	if (!existsSync(file)) {
		console.error(`File not found: ${file}`);
		process.exit(1);
	}

	try {
		const backup = JSON.parse(readFileSync(file, "utf-8"));

		if (!backup.rootPk && !backup.xprv) {
			console.error("Invalid backup format: missing rootPk or xprv");
			process.exit(1);
		}

		let bap: BAP;
		let wif: string;

		if (backup.rootPk) {
			// Type42 format
			bap = new BAP({ rootPk: backup.rootPk });
			wif = backup.rootPk;
		} else {
			// BIP32 format (legacy)
			bap = new BAP(backup.xprv);
			wif = backup.xprv;
		}

		if (backup.ids) {
			bap.importIds(backup.ids);
		}

		saveIdentity(bap, wif, backup.label);

		const ids = bap.listIds();
		console.log("Identity imported successfully!");
		console.log(`  Identities: ${ids.length}`);
		if (backup.label) {
			console.log(`  Label: ${backup.label}`);
		}
		console.log(`\nStored at: ${CONFIG_FILE}`);
	} catch (error) {
		console.error("Failed to import identity:", error);
		process.exit(1);
	}
}

function showInfo(): void {
	const bap = loadIdentity();
	if (!bap) {
		console.error("No identity found. Run 'bap create' first.");
		process.exit(1);
	}

	const ids = bap.listIds();
	console.log("BAP Identity Info");
	console.log(`  Config: ${CONFIG_FILE}`);
	console.log(`  Identities: ${ids.length}`);

	for (const idKey of ids) {
		const identity = bap.getId(idKey);
		if (identity) {
			console.log(`\n  Identity: ${identity.idName}`);
			console.log(`    Key: ${idKey}`);
			console.log(`    Root Address: ${identity.rootAddress}`);
			console.log(`    Current Address: ${identity.getCurrentAddress()}`);
			console.log(`    Encryption Pubkey: ${identity.getEncryptionPublicKey()}`);
		}
	}
}

// Main CLI entry point
const args = process.argv.slice(2);
const command = args[0];

switch (command) {
	case "create":
		createIdentity(args.slice(1));
		break;

	case "sign":
		if (!args[1]) {
			console.error("Usage: bap sign <message>");
			process.exit(1);
		}
		signMessage(args[1]);
		break;

	case "verify":
		if (!args[1] || !args[2] || !args[3]) {
			console.error("Usage: bap verify <message> <signature> <address>");
			process.exit(1);
		}
		verifySignature(args[1], args[2], args[3]);
		break;

	case "friend-pubkey":
		if (!args[1]) {
			console.error("Usage: bap friend-pubkey <friendBapId>");
			process.exit(1);
		}
		getFriendPubkey(args[1]);
		break;

	case "encrypt":
		if (!args[1] || !args[2]) {
			console.error("Usage: bap encrypt <data> <friendBapId>");
			process.exit(1);
		}
		encryptForFriend(args[1], args[2]);
		break;

	case "decrypt":
		if (!args[1] || !args[2]) {
			console.error("Usage: bap decrypt <ciphertext> <friendBapId>");
			process.exit(1);
		}
		decryptFromFriend(args[1], args[2]);
		break;

	case "export":
		exportIdentity();
		break;

	case "import":
		if (!args[1]) {
			console.error("Usage: bap import <backup-file>");
			process.exit(1);
		}
		importIdentity(args[1]);
		break;

	case "info":
		showInfo();
		break;

	case "help":
	case "--help":
	case "-h":
		printUsage();
		break;

	default:
		if (command) {
			console.error(`Unknown command: ${command}`);
		}
		printUsage();
		process.exit(command ? 1 : 0);
}
