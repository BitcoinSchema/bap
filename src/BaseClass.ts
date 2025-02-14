import { OP, Utils as BSVUtils } from "@bsv/sdk";
import { AIP_BITCOM_ADDRESS } from "./constants";
import type { IdentityAttribute, IdentityAttributes } from "./interface";
import { Utils } from "./utils";
const { toArray } = BSVUtils;

abstract class BaseClass {
  protected identityAttributes: IdentityAttributes = {};

  /**
   * Abstract method that must be implemented by derived classes to sign messages
   * @param message - The message to sign
   * @param signingPath - Optional signing path for HD wallets
   * @returns Object containing address and signature
   */
  abstract signMessage(message: number[], signingPath?: string): { address: string; signature: string };

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
   * Returns all the attributes in the identity
   * @returns {IdentityAttributes}
   */
  getAttributes(): IdentityAttributes {
    return this.identityAttributes;
  }

  /**
   * Get the value of the given attribute
   * @param attributeName
   * @returns {IdentityAttribute | null}
   */
  getAttribute(attributeName: string): IdentityAttribute | null {
    if (this.identityAttributes[attributeName]) {
      return this.identityAttributes[attributeName];
    }
    return null;
  }

  /**
   * Set the value of the given attribute
   * If an empty value ('' || null || false) is given, the attribute is removed from the ID
   * @param attributeName string
   * @param attributeValue any
   */
  setAttribute(attributeName: string, attributeValue: string | Record<string, string>): void {
    if (!attributeValue) {
      return;
    }

    if (this.identityAttributes[attributeName]) {
      this.updateExistingAttribute(attributeName, attributeValue);
    } else {
      this.createNewAttribute(attributeName, attributeValue);
    }
  }

  /**
   * Unset the given attribute from the ID
   * @param attributeName
   */
  unsetAttribute(attributeName: string): void {
    delete this.identityAttributes[attributeName];
  }

  /**
   * Add an attribute to this identity
   * @param attributeName
   * @param value
   * @param nonce
   */
  addAttribute(attributeName: string, value: string, nonce = ""): void {
    let nonceToUse = nonce;
    if (!nonce) {
      nonceToUse = Utils.getRandomString();
    }

    this.identityAttributes[attributeName] = {
      value,
      nonce: nonceToUse,
    };
  }

  /**
   * Get all attribute URNs for this ID
   * @returns {string}
   */
  getAttributeUrns(): string {
    let urns = "";
    for (const key in this.identityAttributes) {
      const urn = this.getAttributeUrn(key);
      if (urn) {
        urns += `${urn}\n`;
      }
    }
    return urns;
  }

  /**
   * Create and return the attribute URN for the given attribute
   * @param attributeName
   * @returns {string|null}
   */
  getAttributeUrn(attributeName: string): string | null {
    const attribute = this.identityAttributes[attributeName];
    if (attribute) {
      return `urn:bap:id:${attributeName}:${attribute.value}:${attribute.nonce}`;
    }
    return null;
  }

  /**
   * Parse a text of URN string into identity attributes
   * @param urnIdentityAttributes
   */
  protected parseStringUrns(urnIdentityAttributes: string): IdentityAttributes {
    const identityAttributes: IdentityAttributes = {};
    const attributesRaw = urnIdentityAttributes
      .replace(/^\s+/g, "")
      .replace(/\r/gm, "")
      .split("\n");

    for (const line of attributesRaw) {
      const attribute = line.replace(/^\s+/g, "").replace(/\s+$/g, "");
      const urn = attribute.split(":");
      if (
        urn[0] === "urn" &&
        urn[1] === "bap" &&
        urn[2] === "id" &&
        urn[3] &&
        urn[4] &&
        urn[5]
      ) {
        identityAttributes[urn[3]] = {
          value: urn[4],
          nonce: urn[5],
        };
      }
    }

    return identityAttributes;
  }

  /**
   * Helper function to parse identity attributes
   * @param identityAttributes
   * @returns {IdentityAttributes}
   */
  protected parseAttributes(
    identityAttributes: IdentityAttributes | string,
  ): IdentityAttributes {
    if (typeof identityAttributes === "string") {
      return this.parseStringUrns(identityAttributes);
    }

    for (const key in identityAttributes) {
      if (!identityAttributes[key].value || !identityAttributes[key].nonce) {
        throw new Error("Invalid identity attribute");
      }
    }

    return identityAttributes || {};
  }

  /**
   * Helper method to update an existing attribute
   */
  protected updateExistingAttribute(
    attributeName: string,
    attributeValue: string | Record<string, string>
  ): void {
    if (typeof attributeValue === 'string') {
      this.identityAttributes[attributeName].value = attributeValue;
      return;
    }

    this.identityAttributes[attributeName].value = attributeValue.value || '';
    if (attributeValue.nonce) {
      this.identityAttributes[attributeName].nonce = attributeValue.nonce;
    }
  }

  /**
   * Helper method to create a new attribute
   */
  protected createNewAttribute(
    attributeName: string,
    attributeValue: string | Record<string, string>
  ): void {
    if (typeof attributeValue === 'string') {
      this.addAttribute(attributeName, attributeValue);
      return;
    }

    this.addAttribute(
      attributeName,
      attributeValue.value || '',
      attributeValue.nonce
    );
  }

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