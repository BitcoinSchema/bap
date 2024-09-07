export type IdentityAttribute = Record<"value" | "nonce", string>

export interface IdentityAttributes {
	[key: string]: IdentityAttribute;
}
export interface Identity {
	name: string;
	description: string;
	identityKey: string;
	lastIdPath?: string;
	rootPath: string;
	rootAddress: string;
	currentPath: string;
	previousPath: string;
	idSeed?: string;
	identityAttributes: IdentityAttributes;
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
