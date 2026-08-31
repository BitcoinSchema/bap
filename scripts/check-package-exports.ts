import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

type PackageManifest = {
  exports?: Record<string, Record<string, string>>;
  main?: string;
  module?: string;
  types?: string;
};

function run(command: string[]): string {
  const result = Bun.spawnSync(command, {
    cwd: process.cwd(),
    stderr: "pipe",
    stdout: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `${command.join(" ")} failed: ${result.stderr.toString().trim()}`
    );
  }
  return result.stdout.toString();
}

function exportTargets(manifest: PackageManifest): string[] {
  const targets = new Set<string>();
  for (const target of [manifest.main, manifest.module, manifest.types]) {
    if (target) targets.add(target.replace(/^\.\//, ""));
  }
  for (const conditions of Object.values(manifest.exports ?? {})) {
    for (const target of Object.values(conditions)) {
      targets.add(target.replace(/^\.\//, ""));
    }
  }
  return [...targets];
}

const temporary = mkdtempSync(join(process.cwd(), ".package-check-"));
try {
  run(["bun", "pm", "pack", "--destination", temporary]);
  const archiveName = readdirSync(temporary).find((name) =>
    name.endsWith(".tgz")
  );
  if (!archiveName) throw new Error("package archive was not created");

  run(["tar", "-xzf", join(temporary, archiveName), "-C", temporary]);
  const packageRoot = join(temporary, "package");
  const manifest = JSON.parse(
    readFileSync(join(packageRoot, "package.json"), "utf8")
  ) as PackageManifest;

  for (const target of exportTargets(manifest)) {
    if (!existsSync(join(packageRoot, target))) {
      throw new Error(`declared package export is missing: ${target}`);
    }
  }

  const commonJsTarget = manifest.exports?.["."]?.require ?? manifest.main;
  const esmTarget = manifest.exports?.["."]?.import ?? manifest.module;
  if (!(commonJsTarget && esmTarget)) {
    throw new Error("package must declare CommonJS and ESM entry points");
  }
  run([
    "node",
    "-e",
    "const api = require(process.argv[1]); if (typeof api.BAP !== 'function' || typeof api.MasterID !== 'function') throw new Error('CommonJS public API is missing')",
    resolve(packageRoot, commonJsTarget),
  ]);
  run([
    "node",
    "--input-type=module",
    "-e",
    "const api = await import(process.argv[1]); if (typeof api.BAP !== 'function' || typeof api.MasterID !== 'function') throw new Error('ESM public API is missing')",
    pathToFileURL(resolve(packageRoot, esmTarget)).href,
  ]);

  console.log("Packed CommonJS and ESM exports verified.");
} finally {
  rmSync(temporary, { force: true, recursive: true });
}
