export type IdentityAttribute = Record<"value" | "nonce", string | Record<string, string>>

export interface IdentityAttributes {
  [key: string]: IdentityAttribute;
}
// Base identity properties shared between old and new formats
export interface BaseIdentity {
  name: string;
  description: string;
  identityKey: string;
  rootPath: string;
  rootAddress: string;
  currentPath: string;
  previousPath: string;
  identityAttributes: IdentityAttributes;
}

// Old format - array of identities with no container
export interface OldIdentity extends BaseIdentity {
  idSeed?: string;  // Optional in old format
}

// New format - identity objects within container.
export interface Identity extends BaseIdentity {
  lastIdPath: string;
  idSeed: string;
}

export interface MemberIdentity {
  name: string;
  description: string;
  derivedPrivateKey: string;
  address: string;
  identityKey: string;
  identityAttributes?: IdentityAttributes;
}

// New format container structure
export interface Identities {
  lastIdPath: string;
  ids: Identity[];
}

export type PathPrefix =
  | `/${number}/${number}/${number}`
  | `/${number}'/${number}'/${number}'`;

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
