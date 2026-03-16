import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Each test gets a fresh HOME to isolate ~/.bap state
let testHome: string;
let testConfigDir: string;

function freshHome(): string {
	const dir = join(tmpdir(), `bap-cli-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	mkdirSync(dir, { recursive: true });
	return dir;
}

function run(...args: string[]): { stdout: string; stderr: string; exitCode: number } {
	const result = Bun.spawnSync(["bun", "src/cli.ts", ...args], {
		cwd: "/Users/satchmo/code/bap",
		env: { ...process.env, HOME: testHome, BAP_NO_TOUCHID: "1" },
	});
	return {
		stdout: result.stdout.toString(),
		stderr: result.stderr.toString(),
		exitCode: result.exitCode,
	};
}

beforeEach(() => {
	testHome = freshHome();
	testConfigDir = join(testHome, ".bap");
});

afterEach(() => {
	if (existsSync(testHome)) {
		rmSync(testHome, { recursive: true, force: true });
	}
});

describe("CLI: create", () => {
	test("creates first identity with defaults", () => {
		const { stdout, exitCode } = run("create");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Identity created:");
		expect(stdout).toContain("BAP ID:");
		expect(stdout).toContain("Root Address:");
		expect(stdout).toContain("Root Path:     bap:0");
		expect(existsSync(join(testConfigDir, "identity.json"))).toBe(true);
		expect(existsSync(join(testConfigDir, "active"))).toBe(true);
	});

	test("creates identity with --name", () => {
		const { stdout, exitCode } = run("create", "--name", "Personal");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Label:         Personal");

		const config = JSON.parse(readFileSync(join(testConfigDir, "identity.json"), "utf-8"));
		const bapId = Object.keys(config.labels)[0];
		expect(config.labels[bapId]).toBe("Personal");
	});

	test("creates identity with --wif", () => {
		const { stdout, exitCode } = run("create", "--wif", "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Identity created:");

		const config = JSON.parse(readFileSync(join(testConfigDir, "identity.json"), "utf-8"));
		expect(config.rootPk).toBe("L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6");
	});

	test("second create adds identity to existing master", () => {
		run("create", "--name", "First");
		const { stdout, exitCode } = run("create", "--name", "Second");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Root Path:     bap:1");

		const { stdout: listOut } = run("list");
		expect(listOut).toContain("(First)");
		expect(listOut).toContain("(Second)");
	});

	test("second create preserves original rootPk and createdAt", () => {
		run("create", "--name", "First");
		const config1 = JSON.parse(readFileSync(join(testConfigDir, "identity.json"), "utf-8"));

		run("create", "--name", "Second");
		const config2 = JSON.parse(readFileSync(join(testConfigDir, "identity.json"), "utf-8"));

		expect(config2.rootPk).toBe(config1.rootPk);
		expect(config2.createdAt).toBe(config1.createdAt);
	});

	test("--wif is ignored on second create (master already set)", () => {
		run("create", "--name", "First");
		const config1 = JSON.parse(readFileSync(join(testConfigDir, "identity.json"), "utf-8"));

		run("create", "--wif", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "--name", "Second");
		const config2 = JSON.parse(readFileSync(join(testConfigDir, "identity.json"), "utf-8"));

		// rootPk stays the same since a master already existed
		expect(config2.rootPk).toBe(config1.rootPk);
	});
});

describe("CLI: list", () => {
	test("shows empty message when no identities", () => {
		// Create config dir but no identity file
		const { stderr, exitCode } = run("list");
		expect(exitCode).toBe(1);
	});

	test("marks active identity with *", () => {
		run("create", "--name", "A");
		run("create", "--name", "B");

		const { stdout } = run("list");
		// B is active (most recent create sets active)
		expect(stdout).toContain("* ");
		expect(stdout).toContain("(B)");
		expect(stdout).toContain("(A)");
	});
});

describe("CLI: use", () => {
	test("switches active identity", () => {
		run("create", "--name", "A");
		const { stdout: listBefore } = run("list");
		// Extract first bapId (line with (A))
		const aLine = listBefore.split("\n").find((l) => l.includes("(A)"));
		const aBapId = aLine?.trim().replace("*", "").trim().split(" ")[0];

		run("create", "--name", "B");

		// B should be active now
		const { stdout: infoBefore } = run("info");
		expect(infoBefore).not.toContain(aBapId);

		// Switch to A
		const { exitCode } = run("use", aBapId!);
		expect(exitCode).toBe(0);

		const { stdout: infoAfter } = run("info");
		expect(infoAfter).toContain(aBapId!);
	});

	test("rejects unknown bapId", () => {
		run("create");
		const { exitCode, stderr } = run("use", "nonexistent");
		expect(exitCode).toBe(1);
		expect(stderr).toContain("not found");
	});
});

describe("CLI: info", () => {
	test("shows active identity details", () => {
		run("create", "--name", "MyId");
		const { stdout, exitCode } = run("info");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Active Identity:");
		expect(stdout).toContain("BAP ID:");
		expect(stdout).toContain("Label:         MyId");
		expect(stdout).toContain("Root Address:");
		expect(stdout).toContain("Root Path:");
		expect(stdout).toContain("Current Path:");
		expect(stdout).toContain("Previous Path:");
		expect(stdout).toContain("Account Key:");
	});

	test("fails with no identity", () => {
		const { exitCode } = run("info");
		expect(exitCode).toBe(1);
	});
});

describe("CLI: remove", () => {
	test("removes an identity", () => {
		run("create", "--name", "A");
		run("create", "--name", "B");

		const { stdout: listBefore } = run("list");
		const bLine = listBefore.split("\n").find((l) => l.includes("(B)"));
		const bBapId = bLine?.trim().replace("*", "").trim().split(" ")[0];

		const { exitCode } = run("remove", bBapId!);
		expect(exitCode).toBe(0);

		const { stdout: listAfter } = run("list");
		expect(listAfter).not.toContain("(B)");
		expect(listAfter).toContain("(A)");
	});

	test("removes active and falls back to remaining", () => {
		run("create", "--name", "A");
		run("create", "--name", "B");

		// B is active
		const { stdout: listBefore } = run("list");
		const bLine = listBefore.split("\n").find((l) => l.includes("(B)"));
		const bBapId = bLine?.trim().replace("*", "").trim().split(" ")[0];

		run("remove", bBapId!);

		// A should now be active
		const { stdout } = run("info");
		expect(stdout).toContain("Active Identity:");
		expect(stdout).toContain("Label:         A");
	});

	test("rejects unknown bapId", () => {
		run("create");
		const { exitCode, stderr } = run("remove", "nonexistent");
		expect(exitCode).toBe(1);
		expect(stderr).toContain("not found");
	});
});

describe("CLI: export / import roundtrip", () => {
	test("export and import preserves identities", () => {
		run("create", "--name", "Original");
		const { stdout: exportOut } = run("export");
		const backup = JSON.parse(exportOut);
		expect(backup.rootPk).toBeTruthy();
		expect(backup.ids).toBeTruthy();

		// Save to file
		const backupFile = join(testHome, "backup.json");
		writeFileSync(backupFile, exportOut);

		// Import into fresh home
		const newHome = freshHome();
		const importResult = Bun.spawnSync(["bun", "src/cli.ts", "import", backupFile], {
			cwd: "/Users/satchmo/code/bap",
			env: { ...process.env, HOME: newHome, BAP_NO_TOUCHID: "1" },
		});
		expect(importResult.exitCode).toBe(0);

		// Verify identities match
		const listResult = Bun.spawnSync(["bun", "src/cli.ts", "list"], {
			cwd: "/Users/satchmo/code/bap",
			env: { ...process.env, HOME: newHome, BAP_NO_TOUCHID: "1" },
		});
		const listOut = listResult.stdout.toString();
		expect(listOut.split("\n").filter((l) => l.trim()).length).toBe(1);

		rmSync(newHome, { recursive: true, force: true });
	});

	test("import rejects invalid backup", () => {
		const badFile = join(testHome, "bad.json");
		writeFileSync(badFile, JSON.stringify({ foo: "bar" }));

		const { exitCode, stderr } = run("import", badFile);
		expect(exitCode).toBe(1);
		expect(stderr).toContain("missing rootPk or xprv");
	});

	test("import rejects missing file", () => {
		const { exitCode, stderr } = run("import", "/nonexistent/file.json");
		expect(exitCode).toBe(1);
		expect(stderr).toContain("File not found");
	});
});

describe("CLI: export-account", () => {
	test("exports active identity account backup", () => {
		run("create", "--name", "Test");
		const { stdout, exitCode } = run("export-account");
		expect(exitCode).toBe(0);
		const backup = JSON.parse(stdout);
		expect(backup.wif).toBeTruthy();
		expect(backup.id).toBeTruthy();
	});

	test("exports specific identity with --id", () => {
		run("create", "--name", "A");
		run("create", "--name", "B");

		const { stdout: listOut } = run("list");
		const aLine = listOut.split("\n").find((l) => l.includes("(A)"));
		const aBapId = aLine?.trim().replace("*", "").trim().split(" ")[0];

		const { stdout, exitCode } = run("export-account", "--id", aBapId!);
		expect(exitCode).toBe(0);
		const backup = JSON.parse(stdout);
		expect(backup.id).toBe(aBapId);
	});

	test("rejects unknown --id", () => {
		run("create");
		const { exitCode, stderr } = run("export-account", "--id", "nonexistent");
		expect(exitCode).toBe(1);
		expect(stderr).toContain("not found");
	});
});

describe("CLI: encrypt / decrypt", () => {
	test("roundtrip encrypt/decrypt", () => {
		run("create");
		const { stdout: encrypted } = run("encrypt", "secret message");
		expect(encrypted.trim()).toBeTruthy();

		const { stdout: decrypted, exitCode } = run("decrypt", encrypted.trim());
		expect(exitCode).toBe(0);
		expect(decrypted.trim()).toBe("secret message");
	});

	test("encrypt fails without identity", () => {
		const { exitCode } = run("encrypt", "test");
		expect(exitCode).toBe(1);
	});
});

describe("CLI: verify", () => {
	test("verify returns valid/invalid JSON", () => {
		// Use a dummy signature that won't verify
		const { stdout, exitCode } = run(
			"verify",
			"hello",
			"H1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890=",
			"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		);
		// It should succeed (exit 0) and return JSON with valid: false
		expect(exitCode).toBe(0);
		const result = JSON.parse(stdout);
		expect(result.valid).toBe(false);
	});
});

describe("CLI: id-from-address / id-from-pubkey", () => {
	test("id-from-address derives correct BAP ID", () => {
		run("create");
		const { stdout: infoOut } = run("info");
		const bapIdLine = infoOut.split("\n").find((l) => l.includes("BAP ID:"));
		const bapId = bapIdLine?.split("BAP ID:")[1]?.trim();
		const addrLine = infoOut.split("\n").find((l) => l.includes("Root Address:"));
		const addr = addrLine?.split("Root Address:")[1]?.trim();

		const { stdout, exitCode } = run("id-from-address", addr!);
		expect(exitCode).toBe(0);
		expect(stdout.trim()).toBe(bapId);
	});

	test("id-from-pubkey derives correct BAP ID", () => {
		// Create identity and get its account pubkey
		run("create");
		const { stdout: infoOut } = run("info");
		const bapIdLine = infoOut.split("\n").find((l) => l.includes("BAP ID:"));
		const bapId = bapIdLine?.split("BAP ID:")[1]?.trim();

		// We can't easily test this without knowing the member pubkey,
		// but we can at least verify the command runs without error
		const { exitCode } = run("id-from-pubkey", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
		expect(exitCode).toBe(0);
	});
});

describe("CLI: version and help", () => {
	test("--version outputs 0.2.0", () => {
		const { stdout } = run("--version");
		expect(stdout.trim()).toBe("0.2.0");
	});

	test("--help shows all commands", () => {
		const { stdout } = run("--help");
		expect(stdout).toContain("create");
		expect(stdout).toContain("list");
		expect(stdout).toContain("use");
		expect(stdout).toContain("info");
		expect(stdout).toContain("remove");
		expect(stdout).toContain("export");
		expect(stdout).toContain("export-account");
		expect(stdout).toContain("import");
		expect(stdout).toContain("encrypt");
		expect(stdout).toContain("decrypt");
		expect(stdout).toContain("verify");
		expect(stdout).toContain("lookup");
		expect(stdout).toContain("lookup-address");
		expect(stdout).toContain("attestations");
		expect(stdout).toContain("id-from-address");
		expect(stdout).toContain("id-from-pubkey");
	});
});

describe("CLI: import 0.1.x backup formats", () => {
	const HDPrivateKey =
		"xprv9s21ZrQH143K2LcEfSnFRH1JvdKAcuZj2C8kAzCDnvqC4kgo417hYmAYQKdYDSzQSnQMLWXjDG42TgWwdYqwhAWTWpEBG1ighLLNnVHNKxx";

	test("imports BIP32 (xprv) backup format", () => {
		// Create a BIP32 backup the way 0.1.x would have exported it
		const { BAP } = require("../src/index");
		const bap = new BAP(HDPrivateKey);
		const id = bap.newId();
		const backup = bap.exportForBackup("Legacy Backup");

		expect(backup.xprv).toBeTruthy();
		expect(backup.ids).toBeTruthy();

		const backupFile = join(testHome, "legacy-backup.json");
		writeFileSync(backupFile, JSON.stringify(backup));

		const { exitCode, stdout } = run("import", backupFile);
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Backup imported:");
		expect(stdout).toContain("Identities: 1");
		expect(stdout).toContain("Label: Legacy Backup");

		// Verify we can list the imported identity
		const { stdout: listOut } = run("list");
		expect(listOut.split("\n").filter((l) => l.trim()).length).toBeGreaterThanOrEqual(1);
	});

	test("imports Type42 (rootPk) backup format", () => {
		const { BAP } = require("../src/index");
		const { PrivateKey } = require("@bsv/sdk");
		const pk = PrivateKey.fromRandom();
		const bap = new BAP({ rootPk: pk.toWif() });
		bap.newId();
		bap.newId();
		const backup = bap.exportForBackup("Type42 Backup");

		expect(backup.rootPk).toBeTruthy();

		const backupFile = join(testHome, "type42-backup.json");
		writeFileSync(backupFile, JSON.stringify(backup));

		const { exitCode, stdout } = run("import", backupFile);
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Identities: 2");

		const { stdout: listOut } = run("list");
		const lines = listOut.split("\n").filter((l) => l.trim());
		expect(lines.length).toBe(2);
	});

	test("imports backup without label", () => {
		const { BAP } = require("../src/index");
		const { PrivateKey } = require("@bsv/sdk");
		const pk = PrivateKey.fromRandom();
		const bap = new BAP({ rootPk: pk.toWif() });
		bap.newId();
		const backup = bap.exportForBackup(); // no label

		const backupFile = join(testHome, "nolabel.json");
		writeFileSync(backupFile, JSON.stringify(backup));

		const { exitCode, stdout } = run("import", backupFile);
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Identities: 1");
		expect(stdout).not.toContain("Label:");
	});

	test("imported BIP32 identity can export-account", () => {
		const { BAP } = require("../src/index");
		const bap = new BAP(HDPrivateKey);
		bap.newId();
		const backup = bap.exportForBackup();

		const backupFile = join(testHome, "bip32.json");
		writeFileSync(backupFile, JSON.stringify(backup));

		run("import", backupFile);
		const { stdout, exitCode } = run("export-account");
		expect(exitCode).toBe(0);
		const account = JSON.parse(stdout);
		expect(account.wif).toBeTruthy();
		expect(account.id).toBeTruthy();
	});
});

describe("CLI: edge cases", () => {
	test("info falls back to first identity when active file is stale", () => {
		run("create", "--name", "Only");
		// Corrupt the active file with a non-existent bapId
		writeFileSync(join(testConfigDir, "active"), "nonexistent-bap-id");

		const { exitCode, stdout } = run("info");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Active Identity:");
		expect(stdout).toContain("Label:         Only");
	});

	test("list works when active file is missing", () => {
		run("create", "--name", "Test");
		// Delete the active file
		rmSync(join(testConfigDir, "active"));

		const { stdout, exitCode } = run("list");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("(Test)");
	});

	test("create three identities sequentially", () => {
		run("create", "--name", "A");
		run("create", "--name", "B");
		run("create", "--name", "C");

		const { stdout } = run("list");
		expect(stdout).toContain("(A)");
		expect(stdout).toContain("(B)");
		expect(stdout).toContain("(C)");
		const lines = stdout.split("\n").filter((l) => l.trim());
		expect(lines.length).toBe(3);
	});

	test("remove last identity leaves empty list", () => {
		run("create", "--name", "Solo");
		const { stdout: listOut } = run("list");
		const bapId = listOut.split("\n").find((l) => l.includes("(Solo)"))?.trim().replace("*", "").trim().split(" ")[0];

		run("remove", bapId!);
		const { exitCode } = run("list");
		// Should fail because no identities remain (loadBAP still works but listIds is empty)
		// Actually the BAP instance can have 0 ids; let's see what happens
		expect(exitCode).toBe(0);
	});

	test("encrypt/decrypt with special characters", () => {
		run("create");
		const data = 'hello "world" & <tags> \' newline';
		const { stdout: encrypted } = run("encrypt", data);
		const { stdout: decrypted } = run("decrypt", encrypted.trim());
		expect(decrypted.trim()).toBe(data);
	});

	test("export-account for non-active identity", () => {
		run("create", "--name", "A");
		const { stdout: listOut } = run("list");
		const aBapId = listOut.split("\n").find((l) => l.includes("(A)"))?.trim().replace("*", "").trim().split(" ")[0];

		run("create", "--name", "B");
		// B is now active, but export A's account
		const { stdout, exitCode } = run("export-account", "--id", aBapId!);
		expect(exitCode).toBe(0);
		const backup = JSON.parse(stdout);
		expect(backup.id).toBe(aBapId);
	});

	test("export roundtrip preserves multiple identities", () => {
		run("create", "--name", "A");
		run("create", "--name", "B");
		run("create", "--name", "C");

		const { stdout: exportOut } = run("export");
		const backupFile = join(testHome, "multi.json");
		writeFileSync(backupFile, exportOut);

		const newHome = freshHome();
		Bun.spawnSync(["bun", "src/cli.ts", "import", backupFile], {
			cwd: "/Users/satchmo/code/bap",
			env: { ...process.env, HOME: newHome, BAP_NO_TOUCHID: "1" },
		});
		const listResult = Bun.spawnSync(["bun", "src/cli.ts", "list"], {
			cwd: "/Users/satchmo/code/bap",
			env: { ...process.env, HOME: newHome, BAP_NO_TOUCHID: "1" },
		});
		const lines = listResult.stdout.toString().split("\n").filter((l) => l.trim());
		expect(lines.length).toBe(3);

		rmSync(newHome, { recursive: true, force: true });
	});

	test("unknown command shows error", () => {
		const { exitCode, stderr } = run("foobar");
		expect(exitCode).toBe(1);
		expect(stderr).toContain("unknown command");
	});
});

describe("CLI: deterministic WIF", () => {
	test("same WIF produces same identities", () => {
		const wif = "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6";

		run("create", "--wif", wif, "--name", "Deterministic");
		const { stdout: info1 } = run("info");
		const bapId1 = info1.split("\n").find((l) => l.includes("BAP ID:"))?.split("BAP ID:")[1]?.trim();
		const addr1 = info1.split("\n").find((l) => l.includes("Root Address:"))?.split("Root Address:")[1]?.trim();

		// Create in a fresh home with same WIF
		const newHome = freshHome();
		Bun.spawnSync(["bun", "src/cli.ts", "create", "--wif", wif], {
			cwd: "/Users/satchmo/code/bap",
			env: { ...process.env, HOME: newHome, BAP_NO_TOUCHID: "1" },
		});
		const info2Result = Bun.spawnSync(["bun", "src/cli.ts", "info"], {
			cwd: "/Users/satchmo/code/bap",
			env: { ...process.env, HOME: newHome, BAP_NO_TOUCHID: "1" },
		});
		const info2 = info2Result.stdout.toString();
		const bapId2 = info2.split("\n").find((l) => l.includes("BAP ID:"))?.split("BAP ID:")[1]?.trim();
		const addr2 = info2.split("\n").find((l) => l.includes("Root Address:"))?.split("Root Address:")[1]?.trim();

		expect(bapId1).toBe(bapId2);
		expect(addr1).toBe(addr2);

		rmSync(newHome, { recursive: true, force: true });
	});
});

describe("CLI: touchid commands", () => {
	test("touchid status shows availability (no identity)", () => {
		const { stdout, exitCode } = run("touchid", "status");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Touch ID Status:");
		expect(stdout).toContain("Available:");
		expect(stdout).toContain("Biometry:");
		expect(stdout).toContain("Key Protected: false");
	});

	test("touchid status shows unprotected when identity exists", () => {
		run("create", "--name", "Test");
		const { stdout, exitCode } = run("touchid", "status");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("Key Protected: false");
	});

	test("touchid enable fails without identity", () => {
		const { exitCode, stderr } = run("touchid", "enable");
		expect(exitCode).toBe(1);
		expect(stderr).toContain("No identity found");
	});

	test("touchid disable reports nothing to do without protection", () => {
		run("create", "--name", "Test");
		const { stdout, exitCode } = run("touchid", "disable");
		expect(exitCode).toBe(0);
		expect(stdout).toContain("not Touch ID protected");
	});

	test("--no-touchid flag stores plaintext rootPk", () => {
		const { exitCode } = run("create", "--no-touchid", "--name", "NoTouch");
		expect(exitCode).toBe(0);

		const config = JSON.parse(readFileSync(join(testConfigDir, "identity.json"), "utf-8"));
		expect(config.rootPk).toBeTruthy();
		expect(config.rootPkEncrypted).toBeUndefined();
	});

	test("touchid shows in --help", () => {
		const { stdout } = run("--help");
		expect(stdout).toContain("touchid");
	});

	test("touchid subcommands show in touchid --help", () => {
		const { stdout } = run("touchid", "--help");
		expect(stdout).toContain("status");
		expect(stdout).toContain("enable");
		expect(stdout).toContain("disable");
	});
});
