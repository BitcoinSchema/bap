export type IdentityAttribute = Record<
  "value" | "nonce",
  string | Record<string, string>
>;

export interface IdentityAttributes {
  [key: string]: IdentityAttribute;
}

// Identity as stored in the master backup's ids blob
export interface Identity {
  bapId: string;
  rootPath: string;
  rootAddress: string;
  currentPath: string;
  previousPath: string;
  lastIdPath: string;
  idSeed: string;
}

// Old format for backward compatibility during import
export interface OldIdentity {
  name?: string;
  description?: string;
  identityKey: string;
  rootPath: string;
  rootAddress: string;
  currentPath: string;
  previousPath: string;
  idSeed?: string;
  identityAttributes?: IdentityAttributes;
}

export interface Identities {
  lastIdPath: string;
  ids: Identity[];
}

/**
 * Result of recomputing one legacy (pre-0.3) identity under the current
 * BRC-100 identity-0 derivation. The underlying keys are unchanged; only
 * the derived rootAddress/bapId differ.
 */
export interface LegacyIdRecompute {
  /** bapId recorded in the legacy export (pre-0.3 derivation). */
  oldBapId: string;
  /** bapId for the same key material under the current derivation. */
  newBapId: string;
  /** Derivation path the identity was re-created at. */
  rootPath: string;
}

export type PathPrefix =
  | `/${number}/${number}/${number}`
  | `/${number}'/${number}'/${number}'`;

// Account-level backup — compatible with bitcoin-backup's BapAccountBackup
export interface BapAccountBackup {
  wif: string; // Account private key in WIF format
  id: string; // BAP ID for this account
}

export interface Attestation {
  type: string;
  hash: string;
  sequence: string;
  signingProtocol: string;
  signingAddress: string;
  signature: string;
  data?: string;
  verified?: boolean;
}
