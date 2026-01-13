import { Utils } from "@bsv/sdk";
const { toHex, toArray } = Utils;

export const BAP_BITCOM_ADDRESS = "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT";
export const BAP_BITCOM_ADDRESS_HEX = toHex(toArray(BAP_BITCOM_ADDRESS));
export const AIP_BITCOM_ADDRESS = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";
export const AIP_BITCOM_ADDRESS_HEX = toHex(toArray(AIP_BITCOM_ADDRESS));
export const BAP_SERVER = "https://api.sigmaidentity.com/v1";
export const MAX_INT = 2147483648 - 1; // 0x80000000

// This is just a choice for this library and could be anything else if so needed/wanted
// but it is advisable to use the same derivation between libraries for compatibility
export const SIGNING_PATH_PREFIX = "m/424150'/0'/0'"; // BAP in hex
export const ENCRYPTION_PATH = `m/424150'/${MAX_INT}'/${MAX_INT}'`;

// BAP identity signing key derivation constants
// Uses Type 42 (BRC-42) derivation pattern: invoiceNumber = `${securityLevel}-${protocolName}-${keyID}`
export const BAP_PROTOCOL_ID: [1, string] = [1, "bap"];
export const BAP_KEY_ID = "identity";
export const BAP_INVOICE_NUMBER = "1-bap-identity"; // Pre-computed for Type42 deriveChild
