import { Utils as BSVUtils, OP, BSM, BigNumber } from "@bsv/sdk";
import type { PrivateKey, Signature } from "@bsv/sdk";
import { AIP_BITCOM_ADDRESS } from "./constants";
const { toArray, toBase64 } = BSVUtils;

abstract class BaseClass {
  abstract signMessage(
    message: number[],
  ): { address: string; signature: string };

  protected signWithBSM(
    message: number[],
    signingKey: PrivateKey
  ): { address: string; signature: string } {
    const address = signingKey.toPublicKey().toAddress();
    const dummySig = BSM.sign(message, signingKey, "raw") as Signature;
    const h = new BigNumber(BSM.magicHash(message));
    const r = dummySig.CalculateRecoveryFactor(signingKey.toPublicKey(), h);
    const signature = (
      BSM.sign(message, signingKey, "raw") as Signature
    ).toCompact(r, true, "base64") as string;

    return { address, signature };
  }

  signOpReturnWithAIP(opReturn: number[][]): number[][] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(
      aipMessageBuffer.flat(),
    );
    return this.formatAIPOutput(aipMessageBuffer, address, signature);
  }

  protected getAIPMessageBuffer(
    opReturn: number[][],
    indicies?: number[]
  ): number[][] {
    let opReturnIndex = opReturn.findIndex((op) => op[0] === OP.OP_RETURN);
    const buffers: number[][] = [];

    if (opReturnIndex === -1) {
      buffers.push([OP.OP_RETURN]);
      opReturnIndex = 0;
    }

    if (indicies) {
      for (const index of indicies) {
        buffers.push(opReturn[opReturnIndex + index]);
      }
    } else {
      for (const op of opReturn) {
        buffers.push(op);
      }
    }

    return buffers;
  }

  protected formatAIPOutput(
    opReturnBuffers: number[][],
    address: string,
    signature: string
  ): number[][] {
    const aipElements = [
      toArray("|"),
      toArray(AIP_BITCOM_ADDRESS),
      toArray("BITCOIN_ECDSA"),
      toArray(address),
      toArray(signature, "base64"),
    ];

    return [...opReturnBuffers, ...aipElements];
  }
}

export { BaseClass };
