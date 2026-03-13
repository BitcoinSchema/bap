import {
  PrivateKey,
  Hash,
  Utils as BSVUtils,
  OP,
} from "@bsv/sdk";
import { BaseClass } from "./BaseClass";
import { BAP_BITCOM_ADDRESS } from "./constants";
const { toArray } = BSVUtils;

export class AccountID extends BaseClass {
  private key: PrivateKey;

  constructor(key: PrivateKey) {
    super();
    this.key = key;
  }

  getBapId(): string {
    const addressBytes = toArray(this.getRootAddress());
    const sha = Hash.sha256(addressBytes);
    const ripe = Hash.ripemd160(sha);
    return BSVUtils.toBase58(ripe);
  }

  getRootAddress(): string {
    return this.key.toPublicKey().toAddress();
  }

  getRootPublicKey(): string {
    return this.key.toPublicKey().toString();
  }

  signMessage(message: number[]): { address: string; signature: string } {
    return this.signWithBSM(message, this.key);
  }

  getInitialIdTransaction(firstSigningAddress: string): number[][] {
    const opReturn = [
      [OP.OP_RETURN],
      toArray(BAP_BITCOM_ADDRESS),
      toArray("ID"),
      toArray(this.getBapId()),
      toArray(firstSigningAddress),
    ];

    return this.signOpReturnWithAIP(opReturn);
  }

  getRevocationTransaction(): number[][] {
    const opReturn = [
      [OP.OP_RETURN],
      toArray(BAP_BITCOM_ADDRESS),
      toArray("ID"),
      toArray(this.getBapId()),
      toArray("0"),
    ];

    return this.signOpReturnWithAIP(opReturn);
  }
}
