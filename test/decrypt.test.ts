import { describe, it, expect } from "vitest";
import { constants, generateKeyPairSync, publicEncrypt } from "node:crypto";
import {
  OfficeFile,
  OOXMLFile,
  isEncrypted,
  DecryptionError,
  FileFormatError,
  InvalidKeyError,
} from "../src/index.js";
import { OleFileIO } from "../src/olefile.js";
import { ECMA376Agile } from "../src/method/ecma376_agile.js";
import { ECMA376Encrypted } from "../src/method/container/ecma376_encrypted.js";
import { ByteWriter } from "../src/utils.js";
import { PASSWORD, expected, input } from "./fixtures.js";

describe("OOXML agile decryption", () => {
  it("decrypts example_password.docx (Agile / SHA-512 / AES-256)", () => {
    const file = OfficeFile(input("example_password.docx"));
    expect(file.format).toBe("ooxml");
    expect((file as OOXMLFile).type).toBe("agile");
    file.loadKey({ password: PASSWORD, verifyPassword: true });
    expect(file.decrypt()).toEqual(expected("example_password.docx"));
  });

  it("decrypts example_password.xlsx (Agile)", () => {
    const file = OfficeFile(input("example_password.xlsx"));
    file.loadKey({ password: PASSWORD });
    expect(file.decrypt()).toEqual(expected("example_password.xlsx"));
  });

  it("rejects an incorrect password (verifyPassword=true)", () => {
    const file = OfficeFile(input("example_password.docx"));
    expect(() =>
      file.loadKey({ password: "wrong-password", verifyPassword: true }),
    ).toThrow(InvalidKeyError);
    // A failed verification must not leave a (wrong) key behind.
    expect(() => file.decrypt()).toThrow(/loadKey/);
  });

  it("rejects an incorrect password by zip-magic check (verifyPassword=false)", () => {
    const file = OfficeFile(input("example_password.docx"));
    file.loadKey({ password: "wrong-password" });
    expect(() => file.decrypt()).toThrow(InvalidKeyError);
  });

  it("verifies HMAC integrity when requested", () => {
    const file = OfficeFile(input("example_password.docx"));
    file.loadKey({ password: PASSWORD });
    expect(file.decrypt({ verifyIntegrity: true })).toEqual(
      expected("example_password.docx"),
    );
  });

  it("throws a DecryptionError when decrypt is called before loadKey", () => {
    const file = OfficeFile(input("example_password.docx"));
    expect(() => file.decrypt()).toThrow(DecryptionError);
  });
});

describe("OOXML standard decryption", () => {
  it("decrypts ecma376standard_password.docx (Standard / SHA-1 / AES-128 ECB)", () => {
    const file = OfficeFile(input("ecma376standard_password.docx"));
    expect((file as OOXMLFile).type).toBe("standard");
    file.loadKey({ password: PASSWORD, verifyPassword: true });
    expect(file.decrypt()).toEqual(expected("ecma376standard_password.docx"));
  });
});

/**
 * Build an Agile-encrypted OOXML container whose descriptor lists a
 * certificate key encryptor *before* the password one, the way Office does
 * for documents protected with both.
 */
function buildAgileWithCertificate(
  plain: Uint8Array,
  password: string,
  publicKeyPem: string,
): Uint8Array {
  const spinCount = 1000;
  const { info, secretKey, keyData } = ECMA376Agile.generateEncryptionParameters(
    password,
    null,
    spinCount,
  );
  const pkg = ECMA376Agile.encryptPayload(
    plain,
    secretKey,
    keyData.saltValue!,
    keyData.hashName,
    keyData.saltSize,
    keyData.blockSize,
  );
  const hmac = ECMA376Agile.generateIntegrityParameter(pkg, keyData, secretKey);
  const certKey = publicEncrypt(
    { key: publicKeyPem, padding: constants.RSA_PKCS1_PADDING },
    secretKey,
  );
  const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
  const cipher = `saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512"`;
  const xml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n` +
    `<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">` +
    `<keyData ${cipher} saltValue="${b64(keyData.saltValue!)}"/>` +
    `<dataIntegrity encryptedHmacKey="${b64(hmac.encryptedHmacKey)}" encryptedHmacValue="${b64(hmac.encryptedHmacValue)}"/>` +
    `<keyEncryptors>` +
    `<keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">` +
    `<c:encryptedKey encryptedKeyValue="${b64(certKey)}" X509Certificate="" certVerifier=""/>` +
    `</keyEncryptor>` +
    `<keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">` +
    `<p:encryptedKey spinCount="${spinCount}" ${cipher} saltValue="${b64(info.passwordSalt)}" ` +
    `encryptedVerifierHashInput="${b64(info.encryptedVerifierHashInput)}" ` +
    `encryptedVerifierHashValue="${b64(info.encryptedVerifierHashValue)}" ` +
    `encryptedKeyValue="${b64(info.encryptedKeyValue)}"/>` +
    `</keyEncryptor>` +
    `</keyEncryptors></encryption>`;
  const encryptionInfo = new ByteWriter()
    .u16(4)
    .u16(4)
    .u32(0x40)
    .bytes(new TextEncoder().encode(xml))
    .build();
  return new ECMA376Encrypted(pkg, encryptionInfo).build();
}

describe("OOXML agile with multiple key encryptors", () => {
  const plain = expected("example_password.docx");
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const encrypted = buildAgileWithCertificate(plain, "secret", publicKey);

  it("picks the password encryptor by uri, not by position", () => {
    const file = OfficeFile(encrypted);
    file.loadKey({ password: "secret", verifyPassword: true });
    expect(file.decrypt({ verifyIntegrity: true })).toEqual(plain);
  });

  it("decrypts with the private key via the certificate encryptor", () => {
    const file = OfficeFile(encrypted);
    file.loadKey({ privateKey });
    expect(file.decrypt({ verifyIntegrity: true })).toEqual(plain);
  });
});

describe("OfficeFile", () => {
  it("rejects non-Office input", () => {
    expect(() => OfficeFile(new TextEncoder().encode("hello"))).toThrow(
      FileFormatError,
    );
  });
});

describe("isEncrypted helper", () => {
  it("returns true for a protected OOXML container", () => {
    expect(isEncrypted(input("example_password.docx"))).toBe(true);
  });

  it("returns false for plain files", () => {
    expect(isEncrypted(input("plain.xls"))).toBe(false);
    expect(isEncrypted(input("plain.doc"))).toBe(false);
    expect(isEncrypted(input("plain.ppt"))).toBe(false);
    expect(isEncrypted(expected("example_password.docx"))).toBe(false);
  });
});

describe("OleFileIO", () => {
  it("lists EncryptionInfo and EncryptedPackage streams", () => {
    const ole = new OleFileIO(input("example_password.docx"));
    expect(ole.exists("EncryptionInfo")).toBe(true);
    expect(ole.exists("EncryptedPackage")).toBe(true);
    const list = ole.listdir().map((p) => p.join("/"));
    expect(list).toContain("EncryptionInfo");
    expect(list).toContain("EncryptedPackage");
  });
});
