import { Utils } from "@bsv/sdk";
const { toHex, toArray } = Utils;

export const BAP_BITCOM_ADDRESS = "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT";
export const BAP_BITCOM_ADDRESS_HEX = toHex(toArray(BAP_BITCOM_ADDRESS));
export const AIP_BITCOM_ADDRESS = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";
export const AIP_BITCOM_ADDRESS_HEX = toHex(toArray(AIP_BITCOM_ADDRESS));
export const BAP_SERVER = "https://api.1sat.app/1sat/bap";
export const MAX_INT = 2147483648 - 1; // 0x80000000

export const SIGNING_PATH_PREFIX = "m/424150'/0'/0'"; // BAP in hex

// BRC-100 derivation that defines the canonical BAP identity-0 key.
// Mirrors @1sat/actions: ctx.wallet.getPublicKey({ protocolID: BAP_PROTOCOL_ID,
// keyID: `${BAP_KEY_ID}-0`, counterparty: 'self' }). bapId is derived from the
// resulting address — not from the BRC-100 wallet root itself, since BRC-100
// wallets don't expose root-key signing.
export const BAP_PROTOCOL_ID: [1, "sigma"] = [1, "sigma"];
export const BAP_KEY_ID = "identity";

// Used by the BAP class for encrypting the identity list in the master backup
export const ENCRYPTION_PATH = `m/424150'/${MAX_INT}'/${MAX_INT}'`;
