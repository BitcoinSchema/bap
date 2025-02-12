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
const singleIdExport = bap.exportIds([idKey]);

// export multiple specific identities
const multipleIdExport = bap.exportIds([idKey1, idKey2]);

// export unencrypted
const unencryptedExport = bap.exportIds(undefined, false);
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


## Key Derivations and Identity Classes

### Encryption Key Derivation
Each identity's encryption key is derived from its HD private key as follows:
1. The identity's HD key is first derived using its **rootPath**.
2. From the derived key, an additional derivation using the constant **ENCRYPTION_PATH** is performed.
3. The resulting private key is then used to compute the corresponding public key, which serves as the encryption key for ECIES operations.

This process ensures that every identity has a unique encryption key for secure data encryption and decryption.

### Member Key Derivation
For individual (non-HD) identities managed by the `MemberID` class, the identity key is derived from the member's Bitcoin address using the following method:

1. Obtain the Bitcoin address from the private key (via `this.key.toAddress()`).
2. Hash the address (encoded in UTF-8) using SHA-256.
3. Process the resulting hash with RIPEMD-160.
4. Encode the final hash in base58.

This derivation can be summarized as:

```
identityKey = base58( ripemd160( sha256( address ) ) )
```

This method ties the member's identity key directly to its Bitcoin address, ensuring uniqueness and security.

### Identity Classes

- **MasterID**: This class replaces the old `BAP_ID` class. It is used for identities derived from an HD private key and supports hierarchical deterministic key derivation. All references to the older `BAP_ID` should now refer to `MasterID`.

- **MemberID**: The new `MemberID` class is designed for individual member identities that do not rely on HD key derivation. It supports functions like message signing and exporting identity information. 

In summary, the library now distinguishes between HD-based identities (`MasterID`) and standalone member identities (`MemberID`), with clear key derivation schemes for each type.
