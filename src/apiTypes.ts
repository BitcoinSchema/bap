import type { Organization, Person, WithContext } from "schema-dts";

// Base API Response type
export interface APIResponse<T> {
  status: "success" | "error";
  result?: T;
  message?: string;
}

// Attestation types
export interface Signer {
  idKey: string;
  signingAddress: string;
  sequence: number;
  block: number;
  txId: string;
  timestamp: number;
  revoked: boolean;
}

export interface Attestation {
  hash: string;
  attribute?: string;
  value?: string;
  nonce?: string;
  urn?: string;
  signers: Signer[];
}

export interface SigningKey {
  idKey: string;
  signingAddress: string;
  sequence: number;
  block: number;
  txId: string;
  timestamp: number;
  revoked: boolean;
}

export type GetSigningKeysResponse = APIResponse<Signer[]>;

// Identity types
export interface APIIdentityAddress {
  address: string;
  txId: string;
  block: number;
}

// Replace our custom schema with schema-dts types
export type APISchemaIdentity = WithContext<Person | Organization>;

export interface APIIdentity {
  idKey: string;
  firstSeen: number;
  rootAddress: string;
  currentAddress: string;
  addresses: APIIdentityAddress[];
  identity?: APISchemaIdentity;
}

// Validity types
export interface ValidityRecord {
  valid: boolean;
  block: number;
  timestamp: number;
}

export interface Profile {
  _id: string;
  data: WithContext<Person | Organization>;
}

export interface IdentityValidResponse extends APIIdentity, ValidityRecord {
  profile?: Profile;
}

// Response types
export type GetAttestationResponse = APIResponse<Attestation>;
export type GetIdentityResponse = APIResponse<APIIdentity>;
export type GetIdentityByAddressResponse = APIResponse<APIIdentity>;
export type AttestationValidResponse = APIResponse<ValidityRecord>;
