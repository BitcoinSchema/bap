/**
 * Touch ID vault integration for BAP identity protection.
 *
 * Architecture:
 *   - P-256 key generated INSIDE the macOS Secure Enclave (never leaves the chip)
 *   - Encryption uses ECIES (ECDH + AES-256-GCM) via the SE public key
 *   - Decryption requires Touch ID — SE performs ECDH internally
 *   - Encrypted data stored at ~/.secure-enclave-vault/bap-master.vault.json
 *   - Config stores sentinel "se:bap-master" in rootPkEncrypted
 *   - Plaintext WIF never touches disk when Touch ID is active
 *
 * Powered by the provider-based @1sat/vault (>=0.0.6): the platform-agnostic
 * vault interface plus the macOS SecureEnclaveProvider from @1sat/wallet-mac.
 */

import { homedir } from "node:os";
import { resolve } from "node:path";
import { createVault, FileVaultStorage, type Vault } from "@1sat/vault";
import { SecureEnclaveProvider } from "@1sat/wallet-mac";

const LABEL = "bap-master";

/** Directory where the Secure Enclave ciphertext entries are stored. */
const VAULT_DIR = resolve(homedir(), ".secure-enclave-vault");

let providerInstance: SecureEnclaveProvider | undefined;

/** The macOS Secure Enclave provider (Touch ID prompt branded as "bap"). */
function getProvider(): SecureEnclaveProvider {
  if (!providerInstance) {
    providerInstance = new SecureEnclaveProvider({ name: "bap" });
  }
  return providerInstance;
}

let vaultInstance: Vault | undefined;

/** Build the Secure Enclave vault from the provider and on-disk storage. */
function getVault(): Vault {
  if (!vaultInstance) {
    vaultInstance = createVault(getProvider(), new FileVaultStorage(VAULT_DIR));
  }
  return vaultInstance;
}

/**
 * Encrypt a WIF private key with the Secure Enclave.
 *
 * Touch ID is NOT required for encryption — only for decryption.
 * Returns the sentinel string "se:bap-master" to store in config.
 */
export async function protectRootKey(wif: string): Promise<string> {
  await getVault().protectSecret(LABEL, wif, { type: "bap-root" });
  return `se:${LABEL}`;
}

/**
 * Decrypt the protected root key using Touch ID + Secure Enclave.
 *
 * The ECDH key agreement happens INSIDE the Secure Enclave hardware.
 * The P-256 private key never leaves the chip.
 */
export async function unlockRootKey(sentinel: string): Promise<string> {
  if (!sentinel.startsWith("se:")) {
    throw new Error(
      `Unrecognized vault format: "${sentinel.slice(0, 20)}...". ` +
        'Old Keychain format is no longer supported. Re-import your backup with "bap import <file>".'
    );
  }
  const label = sentinel.slice(3);
  const { plaintext } = await getVault().unlockSecret(label);
  return plaintext;
}

/**
 * Remove the Secure Enclave key and vault file.
 * After this, the encrypted rootPk becomes permanently undecryptable.
 * The caller must replace rootPkEncrypted with rootPk before calling this.
 */
export async function removeProtection(): Promise<void> {
  await getVault().removeSecret(LABEL);
}

/**
 * Check Touch ID availability and whether the identity is currently protected.
 */
export async function getTouchIDStatus(hasEncryptedKey: boolean): Promise<{
  available: boolean;
  biometryType: string;
  protected: boolean;
}> {
  const provider = getProvider();
  if (!provider.isSupported()) {
    return { available: false, biometryType: "None", protected: false };
  }
  const status = await provider.checkAvailability();
  return {
    available: status.supported && status.biometryAvailable,
    biometryType: status.biometryType,
    protected: hasEncryptedKey,
  };
}

/**
 * Synchronous check for Secure Enclave support (macOS arm64).
 */
export function isTouchIDSupported(): boolean {
  return getProvider().isSupported();
}
