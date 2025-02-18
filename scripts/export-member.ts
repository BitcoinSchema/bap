#!/usr/bin/env bun

import { BAP } from "../src";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

// Get xpriv from command line argument
const xpriv = process.argv[2];
if (!xpriv) {
  console.error("Please provide an xpriv as argument");
  process.exit(1);
}

try {
  // Create BAP instance with xpriv
  const bap = new BAP(xpriv);
  
  // Create first member ID
  const masterId = bap.newId();
  
  // Export member backup
  const backup = masterId.exportMemberBackup();
  
  // Create export directory if it doesn't exist
  const exportDir = join(process.cwd(), "export");
  await mkdir(exportDir, { recursive: true });
  
  // Create filename using member address
  const filename = `member-${backup.address}.json`;
  const filepath = join(exportDir, filename);
  
  // Write backup to file
  await writeFile(filepath, JSON.stringify(backup, null, 2));
  
  console.log(`Member backup exported to: ${filepath}`);
} catch (error) {
  console.error("Error:", error.message);
  process.exit(1);
} 