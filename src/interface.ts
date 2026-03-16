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
