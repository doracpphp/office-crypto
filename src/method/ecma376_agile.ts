/**
 * ECMA-376 Agile encryption (the most common encryption flavor used by
 * password-protected DOCX/XLSX/PPTX files).
 *
 * Spec: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/
 *
 * Direct port of `msoffcrypto/method/ecma376_agile.py`.
 */

import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  hash,
  hashSize,
  hmac,
  randomBytes,
  rsaDecryptPkcs1v15,
  type HashAlgorithm,
} from "../crypto.js";
import {
  bytesEqual,
  concatBytes,
  packU32LE,
  packU64LE,
  readU64LE,
  utf16leEncode,
} from "../utils.js";
import type { BytesIO } from "../utils.js";

/** Block keys defined by [MS-OFFCRYPTO] §2.3.4.13. */
export const BLK_VERIFIER_HASH_INPUT = new Uint8Array([
  0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79,
]);
export const BLK_ENCRYPTED_VERIFIER_HASH_VALUE = new Uint8Array([
  0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e,
]);
export const BLK_ENCRYPTED_KEY_VALUE = new Uint8Array([
  0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6,
]);
export const BLK_DATA_INTEGRITY1 = new Uint8Array([
  0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6,
]);
export const BLK_DATA_INTEGRITY2 = new Uint8Array([
  0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33,
]);

function resizeBuffer(
  buf: Uint8Array,
  n: number,
  pad: number = 0x00,
): Uint8Array {
  if (buf.length === n) return buf;
  if (buf.length > n) return buf.subarray(0, n);
  const out = new Uint8Array(n);
  out.set(buf, 0);
  out.fill(pad, buf.length);
  return out;
}

function normalizeKey(key: Uint8Array, n: number): Uint8Array {
  // Per spec: pad short keys with 0x36, truncate long keys.
  return resizeBuffer(key, n, 0x36);
}

function roundUp(sz: number, block: number): number {
  return Math.floor((sz + block - 1) / block) * block;
}

export interface AgileEncryptionInfo {
  keyDataSalt: Uint8Array;
  keyDataHashAlgorithm: HashAlgorithm;
  keyDataBlockSize: number;
  encryptedHmacKey: Uint8Array;
  encryptedHmacValue: Uint8Array;
  encryptedVerifierHashInput: Uint8Array;
  encryptedVerifierHashValue: Uint8Array;
  encryptedKeyValue: Uint8Array;
  spinValue: number;
  passwordSalt: Uint8Array;
  passwordHashAlgorithm: HashAlgorithm;
  passwordKeyBits: number;
}

/**
 * Hash chain used by both verify_password and makekey: H₀ = sha(salt || pw),
 * Hₙ = sha(uint32_le(n-1) || Hₙ₋₁) — repeated `spinValue` times.
 *
 * Expensive (default spinCount is 100 000); callers should reuse the result.
 */
function deriveIteratedHashFromPassword(
  password: string,
  saltValue: Uint8Array,
  hashAlgorithm: HashAlgorithm,
  spinValue: number,
): Uint8Array {
  let h = hash(hashAlgorithm, saltValue, utf16leEncode(password));
  for (let i = 0; i < spinValue; i++) {
    h = hash(hashAlgorithm, packU32LE(i), h);
  }
  return h;
}

/** Final block-key hashing step used to derive each per-purpose AES key. */
function deriveEncryptionKey(
  h: Uint8Array,
  blockKey: Uint8Array,
  hashAlgorithm: HashAlgorithm,
  keyBits: number,
): Uint8Array {
  const finalHash = hash(hashAlgorithm, h, blockKey);
  return finalHash.subarray(0, keyBits / 8);
}

export class ECMA376Agile {
  /**
   * Decrypt the EncryptedPackage stream using a derived secret key.
   *
   * The payload format is `<u64 totalSize>` followed by AES-CBC blocks, each
   * 4096-byte segment using `IV = sha(keyDataSalt || u32_le(blockIndex))`
   * truncated to 16 bytes.
   */
  static decrypt(
    key: Uint8Array,
    keyDataSalt: Uint8Array,
    hashAlgorithm: HashAlgorithm,
    ibuf: BytesIO,
  ): Uint8Array {
    const SEGMENT_LENGTH = 4096;

    ibuf.seek(0);
    const head = ibuf.read(8);
    const totalSize = Number(readU64LE(head, 0));

    const out: Uint8Array[] = [];
    let written = 0;
    let i = 0;
    while (true) {
      const buf = ibuf.read(SEGMENT_LENGTH);
      if (buf.length === 0) break;
      // Avoid an extra allocation: `hash()` accepts multiple parts.
      const iv = hash(hashAlgorithm, keyDataSalt, packU32LE(i)).subarray(0, 16);
      let dec = aesCbcDecrypt(buf, key, iv);
      const remaining = totalSize - written;
      if (remaining < dec.length) dec = dec.subarray(0, remaining);
      out.push(dec);
      written += dec.length;
      if (written >= totalSize) break;
      i++;
    }

    return concatBytes(...out);
  }

  /**
   * Encrypt arbitrary payload bytes using the same agile scheme used for
   * decryption. Returns an EncryptedPackage stream (the OLE container is
   * built separately by `ECMA376Encrypted`).
   */
  static encryptPayload(
    ibuf: Uint8Array,
    secretKey: Uint8Array,
    saltValue: Uint8Array,
    hashAlgorithm: HashAlgorithm,
    saltSize: number,
    blockSize: number,
  ): Uint8Array {
    const SEGMENT_LENGTH = 4096;

    const totalSize = ibuf.length;
    const segments: Uint8Array[] = [];
    segments.push(packU64LE(totalSize));

    let i = 0;
    let off = 0;
    while (off < ibuf.length) {
      const chunk = ibuf.subarray(off, off + SEGMENT_LENGTH);
      const ivSeed = hash(hashAlgorithm, saltValue, packU32LE(i));
      const iv = normalizeKey(ivSeed, saltSize);
      let buf = chunk;
      if (buf.length % blockSize) {
        buf = resizeBuffer(buf, roundUp(buf.length, blockSize));
      }
      segments.push(aesCbcEncrypt(buf, secretKey, iv));
      off += SEGMENT_LENGTH;
      i++;
    }

    return concatBytes(...segments);
  }

  /**
   * Verify password by decrypting the stored verifier hash inputs and
   * comparing to the stored hash. Mirrors the spec's password-verifier flow.
   */
  static verifyPassword(
    password: string,
    saltValue: Uint8Array,
    hashAlgorithm: HashAlgorithm,
    encryptedVerifierHashInput: Uint8Array,
    encryptedVerifierHashValue: Uint8Array,
    spinValue: number,
    keyBits: number,
  ): boolean {
    const h = deriveIteratedHashFromPassword(
      password,
      saltValue,
      hashAlgorithm,
      spinValue,
    );

    const key1 = deriveEncryptionKey(
      h,
      BLK_VERIFIER_HASH_INPUT,
      hashAlgorithm,
      keyBits,
    );
    const key2 = deriveEncryptionKey(
      h,
      BLK_ENCRYPTED_VERIFIER_HASH_VALUE,
      hashAlgorithm,
      keyBits,
    );

    const hashInput = aesCbcDecrypt(encryptedVerifierHashInput, key1, saltValue);
    const actualHash = hash(hashAlgorithm, hashInput);
    const expectedFull = aesCbcDecrypt(
      encryptedVerifierHashValue,
      key2,
      saltValue,
    );
    const expected = expectedFull.subarray(0, hashSize(hashAlgorithm));

    return bytesEqual(actualHash, expected);
  }

  /**
   * HMAC-verify the encrypted payload. Used for tamper detection (the spec
   * recommends running this before decrypting).
   */
  static verifyIntegrity(
    secretKey: Uint8Array,
    keyDataSalt: Uint8Array,
    keyDataHashAlgorithm: HashAlgorithm,
    keyDataBlockSize: number,
    encryptedHmacKey: Uint8Array,
    encryptedHmacValue: Uint8Array,
    streamBytes: Uint8Array,
  ): boolean {
    const iv1 = hash(
      keyDataHashAlgorithm,
      keyDataSalt,
      BLK_DATA_INTEGRITY1,
    ).subarray(0, keyDataBlockSize);
    const iv2 = hash(
      keyDataHashAlgorithm,
      keyDataSalt,
      BLK_DATA_INTEGRITY2,
    ).subarray(0, keyDataBlockSize);

    const hmacKey = aesCbcDecrypt(encryptedHmacKey, secretKey, iv1);
    const hmacValue = aesCbcDecrypt(encryptedHmacValue, secretKey, iv2);

    const expectedSize = hashSize(keyDataHashAlgorithm);
    const actual = hmac(keyDataHashAlgorithm, hmacKey, streamBytes);
    return bytesEqual(hmacValue.subarray(0, expectedSize), actual);
  }

  /**
   * Recover the document secret key from a password.
   */
  static makekeyFromPassword(
    password: string,
    saltValue: Uint8Array,
    hashAlgorithm: HashAlgorithm,
    encryptedKeyValue: Uint8Array,
    spinValue: number,
    keyBits: number,
  ): Uint8Array {
    const h = deriveIteratedHashFromPassword(
      password,
      saltValue,
      hashAlgorithm,
      spinValue,
    );
    const encryptionKey = deriveEncryptionKey(
      h,
      BLK_ENCRYPTED_KEY_VALUE,
      hashAlgorithm,
      keyBits,
    );
    return aesCbcDecrypt(encryptedKeyValue, encryptionKey, saltValue);
  }

  /**
   * Recover the document secret key from a private key (PEM bytes or string).
   * Matches the legacy private-key key-encryptor flow used by certificate
   * protected files.
   */
  static makekeyFromPrivkey(
    privkeyPem: Uint8Array | string,
    encryptedKeyValue: Uint8Array,
  ): Uint8Array {
    return rsaDecryptPkcs1v15(privkeyPem, encryptedKeyValue);
  }

  /**
   * Generate a fresh secret key + parameter set suitable for encrypting a
   * brand-new file. Used by the encryption path.
   */
  static generateEncryptionParameters(
    password: string,
    saltValue: Uint8Array | null,
    spinCount: number,
  ): {
    info: AgileEncryptionInfo;
    secretKey: Uint8Array;
    encryptedKey: AgileCipherParams;
    keyData: AgileCipherParams;
  } {
    const encryptedKey: AgileCipherParams = {
      cipherName: "AES",
      hashName: "SHA512",
      saltSize: 16,
      blockSize: 16,
      keyBits: 256,
      hashSize: 64,
      saltValue: saltValue ?? randomBytes(16),
    };
    const keyData: AgileCipherParams = {
      cipherName: "AES",
      hashName: "SHA512",
      saltSize: 16,
      blockSize: 16,
      keyBits: 256,
      hashSize: 64,
      saltValue: randomBytes(16),
    };

    const h = deriveIteratedHashFromPassword(
      password,
      encryptedKey.saltValue!,
      encryptedKey.hashName,
      spinCount,
    );

    const key1 = deriveEncryptionKey(
      h,
      BLK_VERIFIER_HASH_INPUT,
      encryptedKey.hashName,
      encryptedKey.keyBits,
    );
    const key2 = deriveEncryptionKey(
      h,
      BLK_ENCRYPTED_VERIFIER_HASH_VALUE,
      encryptedKey.hashName,
      encryptedKey.keyBits,
    );
    const key3 = deriveEncryptionKey(
      h,
      BLK_ENCRYPTED_KEY_VALUE,
      encryptedKey.hashName,
      encryptedKey.keyBits,
    );

    let verifierHashInput = randomBytes(encryptedKey.saltSize);
    verifierHashInput = resizeBuffer(
      verifierHashInput,
      roundUp(verifierHashInput.length, encryptedKey.blockSize),
    );
    const encryptedVerifierHashInput = aesCbcEncrypt(
      verifierHashInput,
      key1,
      encryptedKey.saltValue!,
    );

    let hashedVerifier = hash(encryptedKey.hashName, verifierHashInput);
    hashedVerifier = resizeBuffer(
      hashedVerifier,
      roundUp(hashedVerifier.length, encryptedKey.blockSize),
    );
    const encryptedVerifierHashValue = aesCbcEncrypt(
      hashedVerifier,
      key2,
      encryptedKey.saltValue!,
    );

    let secretKey = randomBytes(encryptedKey.saltSize);
    secretKey = normalizeKey(secretKey, encryptedKey.keyBits / 8);

    const encryptedKeyValue = aesCbcEncrypt(
      secretKey,
      key3,
      encryptedKey.saltValue!,
    );

    const info: AgileEncryptionInfo = {
      keyDataSalt: keyData.saltValue!,
      keyDataHashAlgorithm: keyData.hashName,
      keyDataBlockSize: keyData.blockSize,
      encryptedHmacKey: new Uint8Array(0),
      encryptedHmacValue: new Uint8Array(0),
      encryptedVerifierHashInput,
      encryptedVerifierHashValue,
      encryptedKeyValue,
      spinValue: spinCount,
      passwordSalt: encryptedKey.saltValue!,
      passwordHashAlgorithm: encryptedKey.hashName,
      passwordKeyBits: encryptedKey.keyBits,
    };

    return { info, secretKey, encryptedKey, keyData };
  }

  /**
   * Compute and return the encrypted HMAC key + value for the given payload.
   */
  static generateIntegrityParameter(
    encryptedData: Uint8Array,
    keyData: AgileCipherParams,
    secretKey: Uint8Array,
  ): { encryptedHmacKey: Uint8Array; encryptedHmacValue: Uint8Array } {
    const salt = randomBytes(keyData.hashSize);
    const iv1 = generateIv(keyData, BLK_DATA_INTEGRITY1, keyData.saltValue!);
    const iv2 = generateIv(keyData, BLK_DATA_INTEGRITY2, keyData.saltValue!);

    const encryptedHmacKey = aesCbcEncrypt(salt, secretKey, iv1);
    const value = hmac(keyData.hashName, salt, encryptedData);

    // Pad to AES block size before encrypting
    const padded = resizeBuffer(value, roundUp(value.length, keyData.blockSize));
    const encryptedHmacValue = aesCbcEncrypt(padded, secretKey, iv2);

    return { encryptedHmacKey, encryptedHmacValue };
  }
}

export interface AgileCipherParams {
  cipherName: "AES";
  hashName: HashAlgorithm;
  saltSize: number;
  blockSize: number;
  keyBits: number;
  hashSize: number;
  saltValue: Uint8Array | null;
}

function generateIv(
  params: AgileCipherParams,
  blkKey: Uint8Array | null,
  saltValue: Uint8Array,
): Uint8Array {
  if (!blkKey) return normalizeKey(saltValue, params.blockSize);
  return normalizeKey(
    hash(params.hashName, saltValue, blkKey),
    params.blockSize,
  );
}
