import type { Attestation, Identity } from "./interface";

// General Response type
export interface APIResponse<T = Attestation | Identity> {
  status: string;
  result?: T;
  message?: string;
}

// POST /v1/attestation/get
export type GetAttestationResponse = APIResponse<Attestation>;

// POST /v1/identity/get
export type GetIdentityResponse = APIResponse<Identity>;

// POST /v1/identity/getByAddress
export type GetIdentityByAddressResponse = APIResponse<Identity>;

// POST /v1/identity/did
export type GetIdentityDIDResponse = string;

// POST /identity/didByAddress
export type GetIdentityDIDByAddressResponse = string;

// Additional types from models.go
export interface AttestationValidParams {
  address: string;
  idKey: string;
  attribute: string;
  value: string;
  nonce: string;
  urn: string;
  hash: string;
  block: number;
  timestamp: number;
}

export interface IdentityValidByAddressParams {
  address: string;
  block: number;
  timestamp: number;
}

export interface ValidityRecord {
  valid: boolean;
  block: number;
  timestamp: number;
}

export interface AttestationValidResponse extends ValidityRecord {}

export interface IdentityValidResponse extends Identity, ValidityRecord {}