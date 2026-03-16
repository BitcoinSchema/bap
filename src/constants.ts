import { Utils } from "@bsv/sdk";
const { toHex, toArray } = Utils;

export const BAP_BITCOM_ADDRESS = "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT";
export const BAP_BITCOM_ADDRESS_HEX = toHex(toArray(BAP_BITCOM_ADDRESS));
export const AIP_BITCOM_ADDRESS = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";
export const AIP_BITCOM_ADDRESS_HEX = toHex(toArray(AIP_BITCOM_ADDRESS));
export const BAP_SERVER = "https://api.1sat.app/1sat/bap";
export const MAX_INT = 2147483648 - 1; // 0x80000000

export const SIGNING_PATH_PREFIX = "m/424150'/0'/0'"; // BAP in hex

// Used by the BAP class for encrypting the identity list in the master backup
export const ENCRYPTION_PATH = `m/424150'/${MAX_INT}'/${MAX_INT}'`;
