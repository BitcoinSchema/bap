import type { PathPrefix } from "./interface.js";

export const Utils = {
  /**
   * Helper function to generate cryptographically secure random bytes
   * 
   * This follows the pattern used by BSV SDK and other Bitcoin libraries.
   * Uses crypto.getRandomValues() which is available in browsers and modern Node.js.
   *
   * @param {number} byteLength - Number of random bytes to generate (default: 32)
   * @returns {Uint8Array} Array of cryptographically secure random bytes
   */
  getRandomBytes(byteLength = 32): Uint8Array {
    // Use crypto.getRandomValues() - available in browsers and Node.js 15+
    if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
      const array = new Uint8Array(byteLength);
      globalThis.crypto.getRandomValues(array);
      return array;
    }

    // Fallback error - crypto operations require secure randomness
    throw new Error(
      'Secure random number generation not available. ' +
      'crypto.getRandomValues() is required for cryptographic operations. ' +
      'This environment may not be suitable for secure key generation.'
    );
  },

  /**
   * Helper function to generate a random hex string
   *
   * @param {number} byteLength - Number of random bytes to generate (default: 32)
   * @returns {string} Hex string of random bytes
   */
  getRandomString(byteLength = 32): string {
    const bytes = this.getRandomBytes(byteLength);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Get a signing path from a hex number
   *
   * @param hexString {string}
   * @param hardened {boolean} Whether to return a hardened path
   * @returns {string}
   */
  getSigningPathFromHex(hexString: string, hardened = true) {
    // "m/0/0/1"
    let signingPath = "m";
    const signingHex = hexString.match(/.{1,8}/g);
    if (!signingHex) {
      throw new Error("Invalid hex string");
    }
    const maxNumber = 2147483648 - 1; // 0x80000000
    for (const hexNumber of signingHex) {
      let number = Number(`0x${hexNumber}`);
      if (number > maxNumber) number -= maxNumber;
      signingPath += `/${number}${hardened ? "'" : ""}`;
    }

    return signingPath;
  },

  /**
   * Increment that second to last part from the given part, set the last part to 0
   *
   * @param path string
   * @returns {*}
   */
  getNextIdentityPath(path: string): PathPrefix {
    const pathValues = path.split("/");
    const secondToLastPart = pathValues[pathValues.length - 2];

    let hardened = false;
    if (secondToLastPart.match("'")) {
      hardened = true;
    }

    const nextPath = (
      Number(secondToLastPart.replace(/[^0-9]/g, "")) + 1
    ).toString();
    pathValues[pathValues.length - 2] = nextPath + (hardened ? "'" : "");
    pathValues[pathValues.length - 1] = `0${hardened ? "'" : ""}`;

    return pathValues.join("/") as PathPrefix;
  },

  /**
   * Increment that last part of the given path
   *
   * @param path string
   * @returns {*}
   */
  getNextPath(path: string) {
    const pathValues = path.split("/");
    const lastPart = pathValues[pathValues.length - 1];
    let hardened = false;
    if (lastPart.match("'")) {
      hardened = true;
    }
    const nextPath = (Number(lastPart.replace(/[^0-9]/g, "")) + 1).toString();
    pathValues[pathValues.length - 1] = nextPath + (hardened ? "'" : "");
    return pathValues.join("/");
  },
};
