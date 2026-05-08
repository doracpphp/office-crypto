/**
 * ECMA-376 Standard encryption: SHA-1 + AES-128 ECB key derivation, used by
 * older Office 2007/2010 password protection.
 *
 * Direct port of `msoffcrypto/method/ecma376_standard.py`.
 */

import { aesEcbDecrypt, hash } from "../crypto.js";
import {
  bytesEqual,
  concatBytes,
  packU32LE,
  readU32LE,
  utf16leEncode,
} from "../utils.js";
import type { BytesIO } from "../utils.js";

export class ECMA376Standard {
  static decrypt(key: Uint8Array, ibuf: BytesIO): Uint8Array {
    ibuf.seek(0);
    const head = ibuf.read(4);
    const totalSize = readU32LE(head, 0);
    ibuf.seek(8);
    const payload = ibuf.read();
    const dec = aesEcbDecrypt(payload, key);
    return dec.subarray(0, totalSize);
  }

  /**
   * Verify a derived key by comparing the encrypted verifier hash and the
   * SHA-1 of the decrypted verifier.
   */
  static verifyKey(
    key: Uint8Array,
    encryptedVerifier: Uint8Array,
    encryptedVerifierHash: Uint8Array,
  ): boolean {
    const verifier = aesEcbDecrypt(encryptedVerifier, key);
    const expectedHash = hash("SHA1", verifier);
    const verifierHash = aesEcbDecrypt(encryptedVerifierHash, key).subarray(
      0,
      20,
    );
    return bytesEqual(expectedHash, verifierHash);
  }

  /**
   * Standard SHA-1 based PBKDF used by ECMA-376 v2/v3 (50 000 iterations).
   * Truncates to `keySize` bits.
   */
  static makekeyFromPassword(
    password: string,
    _algId: number,
    _algIdHash: number,
    _providerType: number,
    keySize: number,
    _saltSize: number,
    salt: Uint8Array,
  ): Uint8Array {
    const ITER_COUNT = 50000;
    const pwBytes = utf16leEncode(password);
    let h = hash("SHA1", salt, pwBytes);
    for (let i = 0; i < ITER_COUNT; i++) {
      h = hash("SHA1", packU32LE(i), h);
    }
    // Final block
    const hfinal = hash("SHA1", h, packU32LE(0));

    const cbHash = 20;
    const cbRequiredKeyLength = keySize / 8;

    const buf1 = new Uint8Array(64);
    buf1.fill(0x36);
    for (let i = 0; i < cbHash; i++) buf1[i] ^= hfinal[i];
    const x1 = hash("SHA1", buf1);

    const buf2 = new Uint8Array(64);
    buf2.fill(0x5c);
    for (let i = 0; i < cbHash; i++) buf2[i] ^= hfinal[i];
    const x2 = hash("SHA1", buf2);

    const x3 = concatBytes(x1, x2);
    return x3.subarray(0, cbRequiredKeyLength);
  }
}
