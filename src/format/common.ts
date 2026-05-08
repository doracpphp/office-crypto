/**
 * EncryptionInfo structure helpers shared by OOXML, XLS97, DOC97, PPT97.
 *
 * Direct port of `msoffcrypto/format/common.py`.
 */

import {
  BytesIO,
  readU32,
  utf16leDecode,
  type Readable,
} from "../utils.js";

export type { Readable };

export interface EncryptionHeader {
  flags: number;
  sizeExtra: number;
  algId: number;
  algIdHash: number;
  keySize: number;
  providerType: number;
  reserved1: number;
  reserved2: number;
  cspName: string;
}

export interface EncryptionVerifier {
  saltSize: number;
  salt: Uint8Array;
  encryptedVerifier: Uint8Array;
  verifierHashSize: number;
  encryptedVerifierHash: Uint8Array;
}

export function parseEncryptionHeader(blob: Readable): EncryptionHeader {
  return {
    flags: readU32(blob),
    sizeExtra: readU32(blob),
    algId: readU32(blob),
    algIdHash: readU32(blob),
    keySize: readU32(blob),
    providerType: readU32(blob),
    reserved1: readU32(blob),
    reserved2: readU32(blob),
    cspName: utf16leDecode(blob.read()),
  };
}

export function parseEncryptionVerifier(
  blob: Readable,
  algorithm: "AES" | "RC4",
): EncryptionVerifier {
  const saltSize = readU32(blob);
  const salt = new Uint8Array(blob.read(16));
  const encryptedVerifier = new Uint8Array(blob.read(16));
  const verifierHashSize = readU32(blob);
  const encryptedVerifierHash = new Uint8Array(
    blob.read(algorithm === "RC4" ? 20 : 32),
  );
  return {
    saltSize,
    salt,
    encryptedVerifier,
    verifierHashSize,
    encryptedVerifierHash,
  };
}

export interface RC4CryptoAPIInfo {
  salt: Uint8Array;
  keySize: number;
  encryptedVerifier: Uint8Array;
  encryptedVerifierHash: Uint8Array;
}

export function parseHeaderRC4CryptoAPI(
  encryptionHeader: Readable,
): RC4CryptoAPIInfo {
  encryptionHeader.read(4); // flags (we don't surface them yet)
  const headerSize = readU32(encryptionHeader);
  const headerBlob = new BytesIO(
    new Uint8Array(encryptionHeader.read(headerSize)),
  );
  const header = parseEncryptionHeader(headerBlob);
  const keySize = header.keySize === 0 ? 0x28 : header.keySize;
  const verifierBlob = new BytesIO(new Uint8Array(encryptionHeader.read()));
  const verifier = parseEncryptionVerifier(verifierBlob, "RC4");
  return {
    salt: verifier.salt,
    keySize,
    encryptedVerifier: verifier.encryptedVerifier,
    encryptedVerifierHash: verifier.encryptedVerifierHash,
  };
}

export interface RC4Info {
  salt: Uint8Array;
  encryptedVerifier: Uint8Array;
  encryptedVerifierHash: Uint8Array;
}

/**
 * RC4 (non-CryptoAPI) header used by older XLS / DOC files: three back-to-back
 * 16-byte chunks (salt, encryptedVerifier, encryptedVerifierHash).
 */
export function parseHeaderRC4(blob: Readable): RC4Info {
  return {
    salt: new Uint8Array(blob.read(16)),
    encryptedVerifier: new Uint8Array(blob.read(16)),
    encryptedVerifierHash: new Uint8Array(blob.read(16)),
  };
}
