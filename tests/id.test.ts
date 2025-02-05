import { describe, expect, beforeEach, test } from "bun:test";
import { MasterID } from "../src";
import { HDPrivateKey } from "./data/keys";
import { HD, PrivateKey } from "@bsv/sdk";
import {
	BAP_BITCOM_ADDRESS_HEX,
	AIP_BITCOM_ADDRESS_HEX,
	SIGNING_PATH_PREFIX,
} from "../src/constants";
import type { IdentityAttributes } from "../src/interface";

const identityAttributes: IdentityAttributes = {
	name: {
		value: "John Doe",
		nonce: "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa",
	},
	email: {
		value: "john.doe@example.com",
		nonce: "2864fd138ab1e9ddaaea763c77a45898dac64a26229f9f3d0f2280e4bfa915de",
	},
};
const identityAttributeStrings = `
    urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
    urn:bap:id:email:john.doe@example.com:2864fd138ab1e9ddaaea763c77a45898dac64a26229f9f3d0f2280e4bfa915de
`;

let bap: InstanceType<typeof MasterID>;
describe("bap-id", () => {
	beforeEach(() => {
		bap = new MasterID(HDPrivateKey);
	});

	test("new id", () => {
		const bapId = bap.newId();

		const identityKey = bapId.getIdentityKey();
		expect(typeof identityKey).toBe("string");
		expect(identityKey).toHaveLength(27);
		expect(bapId.getAttributes()).toMatchObject({});
	});

	test("new id with known key", () => {
		const userId = new MasterID(HD.fromString(HDPrivateKey));
		const rootAddress = userId.rootAddress;
		const identityKey = userId.getIdentityKey();
		expect(rootAddress).toBe("1CSJiMMYzfW8gbhXXNYyEJ1NsWJohLXyet");
		expect(identityKey).toBe("2cWvSXKfFQScCgDFssRPKvDLjNYx");
	});

	test("new id with seeded keys", () => {
		const userId = new MasterID(HD.fromString(HDPrivateKey), {}, "test");
		const rootAddress = userId.rootAddress;
		const identityKey = userId.getIdentityKey();
		expect(rootAddress).toBe("189oxMiD6wFA4nD38CkoWBKragxXUfw26J");
		expect(identityKey).toBe("ffw3VszEVByph2DuHUiswEMNjRm");

		const userId2 = new MasterID(HD.fromString(HDPrivateKey), {}, "testing 123");
		const rootAddress2 = userId2.rootAddress;
		const identityKey2 = userId2.getIdentityKey();
		expect(rootAddress2).toBe("18zrzzv2Nieve7QAj2AwGDcPYyBziz8vWk");
		expect(identityKey2).toBe("2UKj9321g9pDExCjL7dPhXMtM326");
	});

	test("set BAP_SERVER", () => {
		const bap = new MasterID(HDPrivateKey);
		const id = bap.newId();
		expect(id.BAP_SERVER).toBe("https://api.sigmaidentity.com/v1");

		const newServer = "https://some.newserverdomain.com/";
		id.BAP_SERVER = newServer;
		expect(id.BAP_SERVER).toBe(newServer);
	});

	test("identity attributes", () => {
		// Test creating new ID with attributes
		const bapId = bap.newId(identityAttributeStrings);
		expect(bapId.getAttributes()).toStrictEqual(identityAttributes);

		// Test adding attributes
		const bapId2 = bap.newId();
		bapId2.addAttribute("birthday", "1990-05-22"); // nonce will be automatically generated
		bapId2.addAttribute(
			"over18",
			"1",
			"ca17ccaacd671b28dc811332525f2f2cd594d8e8e7825de515ce5d52d30e8",
		);

		expect(bapId2.getAttribute("birthday")?.value).toBe("1990-05-22");
		expect(typeof bapId2.getAttribute("birthday")?.nonce).toBe("string");
		expect(bapId2.getAttribute("birthday")?.nonce).toHaveLength(64);

		expect(bapId2.getAttribute("over18")?.value).toBe("1");
		expect(bapId2.getAttribute("over18")?.nonce).toBe(
			"ca17ccaacd671b28dc811332525f2f2cd594d8e8e7825de515ce5d52d30e8",
		);

		expect(bapId2.getAttribute("over21")).toBe(null);
	});

	test("getAttributeUrns", () => {
		const bapId = bap.newId(identityAttributeStrings);

		const expectedName =
			"urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa";
		expect(bapId.getAttributeUrn("name")).toBe(expectedName);
		expect(bapId.getAttributeUrn("over21")).toBe(null);

		const attributeStrings = bapId.getAttributeUrns();
		const expectedAtt = `urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
urn:bap:id:email:john.doe@example.com:2864fd138ab1e9ddaaea763c77a45898dac64a26229f9f3d0f2280e4bfa915de
`;
		expect(attributeStrings).toBe(expectedAtt);
	});

	test("incrementPath", () => {
		const randomHDPrivateKey = HD.fromRandom();
		const bapId = new MasterID(randomHDPrivateKey);

		expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/1`);
		bapId.incrementPath();
		expect(bapId.previousPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/1`);
		expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/2`);
		bapId.incrementPath();
		expect(bapId.previousPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/2`);
		expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/3`);
		bapId.incrementPath();
		expect(bapId.previousPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/3`);
		expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/4`);
	});

	test("signingPath", () => {
		const bapId = bap.newId();
		expect(bapId.rootPath).toBe("m/424150'/0'/0'/0'/0'/0'");
		expect(bapId.currentPath).toBe("m/424150'/0'/0'/0'/0'/1'");

		bapId.currentPath = "/0/0/2";
		expect(bapId.currentPath).toBe("m/424150'/0'/0'/0/0/2");

		expect(() => {
			bapId.rootPath = "test";
		}).toThrow();
		expect(() => {
			bapId.currentPath = "test";
		}).toThrow();
	});

	test("getAttestation / Hash", () => {
		const bapId = bap.newId(identityAttributes);
		const urn = bapId.getAttributeUrn("name");
		expect(urn).not.toBeNull();
		expect(urn).toBe(
			"urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa",
		);
		const attestation = bapId.getAttestation(urn || "");
		const expectedAttestation =
			"bap:attest:b17c8e606afcf0d8dca65bdf8f33d275239438116557980203c82b0fae259838:GbPKb7tQpfZDut9mJnBm5BMtGqu";
		expect(attestation).toBe(expectedAttestation);

		const hash = bapId.getAttestationHash("name");
		expect(hash).toBe(
			"bc91964394e81cb0fc0a0cad53894456711e2f7e4626ce3977de0a92abdded70",
		);
	});

	test("getInitialIdTransaction", () => {
		const bapId = bap.newId(identityAttributes);
		const tx = bapId.getInitialIdTransaction();
		expect(`0x${tx[0]}`).toBe(BAP_BITCOM_ADDRESS_HEX);
		expect(tx[1]).toBe(Buffer.from("ID").toString("hex"));
		expect(tx[2]).toBe(Buffer.from(bapId.getIdentityKey()).toString("hex"));
		expect(tx[3]).toBe(
			Buffer.from(bapId.getAddress(bapId.currentPath)).toString("hex"),
		);
		expect(tx[4]).toBe(Buffer.from("|").toString("hex"));
		expect(`0x${tx[5]}`).toBe(AIP_BITCOM_ADDRESS_HEX);
		expect(tx[6]).toBe(Buffer.from("BITCOIN_ECDSA").toString("hex"));
		expect(tx[7]).toBe(
			Buffer.from(bapId.getAddress(bapId.rootPath)).toString("hex"),
		);
		expect(typeof tx[8]).toBe("string");
	});

	test("encryption public keys", () => {
		const bapId = bap.newId(identityAttributes);
		const pubKey = bapId.getEncryptionPublicKey();
		expect(pubKey).toBe(
			"02a257adfbba04a25a7c37600209a0926aa264428b2d3d2b17fa97cf9c31b87cdf",
		);

		const pubKeySeed = bapId.getEncryptionPublicKeyWithSeed("test-seed");
		expect(pubKeySeed).toBe(
			"0344786ed9e861b40b1157e841d6f0f7667548f03adff2709ebd74061068f8376a",
		);
	});

	test("encryption", () => {
		const bapId = bap.newId(identityAttributes);
		const pubKey = bapId.getEncryptionPublicKey();
		expect(pubKey).toBe(
			"02a257adfbba04a25a7c37600209a0926aa264428b2d3d2b17fa97cf9c31b87cdf",
		);

		const testData = "This is a test we are going to encrypt";
		const ciphertext = bapId.encrypt(testData);
		expect(typeof ciphertext).toBe("string");
		expect(testData === ciphertext).toBe(false);

		const decrypted = bapId.decrypt(ciphertext);
		expect(testData === decrypted).toBe(true);
	});

	test("encryption with seed", () => {
		const bapId = bap.newId(identityAttributes);
		const pubKey = bapId.getEncryptionPublicKey();
		expect(pubKey).toBe(
			"02a257adfbba04a25a7c37600209a0926aa264428b2d3d2b17fa97cf9c31b87cdf",
		);

		const seed = "test-seed";

		const testData = "This is a test we are going to encrypt";
		const ciphertext = bapId.encryptWithSeed(testData, seed);
		expect(typeof ciphertext).toBe("string");
		expect(testData === ciphertext).toBe(false);

		const decrypted = bapId.decryptWithSeed(ciphertext, seed);
		expect(testData === decrypted).toBe(true);
	});

	test("encryption with seed with counterparty", () => {
		const bapId = bap.newId(identityAttributes);
		const pubKey = bapId.getEncryptionPublicKey();
		expect(pubKey).toBe(
			"02a257adfbba04a25a7c37600209a0926aa264428b2d3d2b17fa97cf9c31b87cdf",
		);

		const seed = "test-seed";

		const testData = "This is a test we are going to encrypt";
		const ciphertext = bapId.encryptWithSeed(testData, seed);
		expect(typeof ciphertext).toBe("string");
		expect(testData === ciphertext).toBe(false);

		const decrypted = bapId.decryptWithSeed(ciphertext, seed);
		expect(testData === decrypted).toBe(true);
	});
});
