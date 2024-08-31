import {
  describe,
  expect,
  it,
} from '@jest/globals';
import { BAP } from '../src';

import testVectors from './data/test-vectors.json';

describe('test-vectors', () => {
  it('regression', () => {
    for (const v of testVectors) {
      const bap = new BAP(v.HDPrivateKey);
      const id = bap.newId();
      expect(id.rootAddress).toBe(v.rootAddress);
      expect(id.getIdentityKey()).toBe(v.idKey);
      expect(id.rootPath).toBe(v.rootPath);
      const tx = id.getInitialIdTransaction();
      expect(typeof tx[8]).toBe('string')
      expect(typeof v.tx[8]).toBe('string')
      // biome-ignore lint/performance/noDelete: <explanation>
      delete tx[8]; // remove the signature, will be different
      // biome-ignore lint/performance/noDelete: <explanation>
      delete v.tx[8]; // remove the signature, will be different
      expect(tx).toStrictEqual(v.tx);
    }
  });
});
