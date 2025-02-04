# Bitcoin Attestation Protocol - BAP

> A simple protocol to create a chain of trust for any kind of information on the Bitcoin blockchain

Javascript classes for working with identities and attestations.

**NOTE: This is work in progress and more documentation will follow.**

# BAP

The BAP class is a wrapper around all BAP functions, including managing IDs and attestations.

```shell
npm install bitcoin-bap --save
```

Example creating a new ID:

```javascript
const HDPrivateKey = "xprv...";
const bap = new BAP(HDPrivateKey);

// Create a new identity
const newId = bap.newId();
// set the name of the ID
newId.name = "Social media identity";
// set a description for this ID
newId.description = "Pseudonymous identity to use on social media sites";
// set identity attributes
newId.addAttribute("name", "John Doe");
newId.addAttribute("email", "john@doe.com");

// export all identities for storage (encrypted by default)
const encryptedExport = bap.exportIds();

// export specific identities
const idKey = newId.getIdentityKey();
const singleIdExport = bap.exportIds(true, [idKey]);

// export multiple specific identities
const multipleIdExport = bap.exportIds(true, [idKey1, idKey2]);

// export unencrypted
const unencryptedExport = bap.exportIds(false);
```

Signing:

```javascript
const HDPrivateKey = "xprv...";
const bap = new BAP(HDPrivateKey);
const identity = bap.getId("<identityKey>");

// B protocol data
const opReturn = [
  Buffer.from("19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut").toString("hex"),
  Buffer.from("Hello World!").toString("hex"),
  Buffer.from("text/plain").toString("hex"),
  Buffer.from("utf8").toString("hex"),
];
// signOpReturnWithAIP expects and returns hex values
const signedOpReturn = identity.signOpReturnWithAIP(opReturn);
```

Encryption, every identity has a separate encryption/decryption key:

```javascript
const HDPrivateKey = "xprv...";
const bap = new BAP(HDPrivateKey);
const identity = bap.getId("<identityKey>");

const publicKey = identity.getEncryptionPublicKey();

const cipherText = identity.encrypt("Hello World!");

const text = identity.decrypt(cipherText);
```

The encryption uses `ECIES` from the `@bsv/sdk` library:

```javascript
import { ECIES, Utils } from "@bsv/sdk";
const { toArray, toBase64 } = Utils;

return toBase64(bitcoreEncrypt(toArray(stringData)));
```

Other examples:

```javascript
// List the identity keys of all id's
const idKeys = bap.listIds();

// get a certain id
const id = bap.getId(idKeys[0]);
```
