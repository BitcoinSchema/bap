export type IdentityAttribute = {
  value: string;
  nonce: string;
}

export interface IdentityAttributes {
  [key: string]: IdentityAttribute;
}
// Base identity properties shared between old and new formats
export interface BaseIdentity {
  name: string;
  description: string;
  identityKey: string;
  rootAddress: string;
  identityAttributes: IdentityAttributes;
  idSeed?: string;
}

// Old format - array of identities with no container
export interface OldIdentity extends BaseIdentity {
  currentPath?: string;
}

// HD Key based identity
export interface HDIdentity extends BaseIdentity {
  rootPath: string;
  currentPath: string;
  previousPath: string;
  lastIdPath: string;
}

// Single key based identity
export interface SingleKeyIdentity extends BaseIdentity {
  derivedPrivateKey: string;
}

export type Identity = HDIdentity | SingleKeyIdentity;

// Container for storing identities
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
