import type { HD } from "@bsv/sdk";

export const BAP_POA = class {
  #HDPrivateKey: HD;

  constructor(HDPrivateKey: HD) {
    this.#HDPrivateKey = HDPrivateKey;
  }
};
