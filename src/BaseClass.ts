import { OP, Utils } from "@bsv/sdk";
import { AIP_BITCOM_ADDRESS } from "./constants";
const { toArray, toHex } = Utils;

abstract class BaseClass {
  /**
   * Abstract method that must be implemented by derived classes to sign messages
   * @param message - The message to sign
   * @param signingPath - Optional signing path for HD wallets
   * @returns Object containing address and signature
   */
  abstract signMessage(message: number[], signingPath?: string): { address: string; signature: string };

  /**
   * Construct an AIP buffer from the op return data
   * @param opReturn
   * @returns {number[]} Array of numbers representing the buffer
   */
  getAIPMessageBuffer(opReturn: number[][]): number[] {
    const buffers: number[] = [];
    if (opReturn[0][0] !== OP.OP_RETURN) {
      // include OP_RETURN in constructing the signature buffer
      buffers.push(OP.OP_RETURN);
    }
    for (const op of opReturn) {
      buffers.push(...op);
    }
    // add a trailing "|" - this is the AIP way
    return buffers.concat(toArray("|"));
  }

  /**
   * Sign an op_return hex array with AIP
   * Each implementation must handle its own signing path logic
   * @param opReturn {array}
   * @param signingPath {string}
   * @return {number[]}
   */
  abstract signOpReturnWithAIP(
    opReturn: number[][],
    signingPath?: string,
  ): number[][];

  /**
   * Helper method to format AIP output
   * @param opReturn Original OP_RETURN data
   * @param address Signing address
   * @param signature Base64 signature
   * @returns Formatted AIP output as number[]
   */
  protected formatAIPOutput(
    opReturnBuffers: number[][],
    address: string,
    signature: string,
  ): number[][] {    
    // Add AIP protocol elements
    const aipElements = [
      toArray("|"),
      toArray(AIP_BITCOM_ADDRESS),
      toArray("BITCOIN_ECDSA"),
      toArray(address),
      toArray(signature, "base64"),
    ];

    // Concatenate all buffers
    return [
      ...opReturnBuffers,
      ...aipElements
    ];
  }
}

export { BaseClass };