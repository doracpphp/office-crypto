/**
 * Office 97 RC4 encryption (MD5-based key derivation). Used by older Excel,
 * Word, and PowerPoint password protection via the legacy
 * "Office Binary Document RC4" provider.
 *
 * Direct port of `msoffcrypto/method/rc4.py`.
 */

import { hash } from "../crypto.js";
import { packU32LE, utf16leEncode } from "../utils.js";
import type { Readable } from "../format/common.js";
import { blockwiseRc4Decrypt, rc4VerifyByHash } from "./rc4_common.js";

function makekey(
  password: string,
  salt: Uint8Array,
  block: number,
): Uint8Array {
  // [MS-OFFCRYPTO] §2.3.6.1.
  const pwBytes = utf16leEncode(password);
  const truncated = hash("MD5", pwBytes).subarray(0, 5);
  // Build (truncated || salt) repeated 16 times — same as the Python original.
  const segLen = truncated.length + salt.length;
  const intermediate = new Uint8Array(segLen * 16);
  for (let i = 0; i < 16; i++) {
    intermediate.set(truncated, i * segLen);
    intermediate.set(salt, i * segLen + truncated.length);
  }
  const truncatedHash = hash("MD5", intermediate).subarray(0, 5);
  return hash("MD5", truncatedHash, packU32LE(block)).subarray(0, 16);
}

export class DocumentRC4 {
  static verifyPassword(
    password: string,
    salt: Uint8Array,
    encryptedVerifier: Uint8Array,
    encryptedVerifierHash: Uint8Array,
  ): boolean {
    const key = makekey(password, salt, 0);
    return rc4VerifyByHash("MD5", key, encryptedVerifier, encryptedVerifierHash);
  }

  static decrypt(
    password: string,
    salt: Uint8Array,
    ibuf: Readable,
    blockSize = 0x200,
  ): Uint8Array {
    return blockwiseRc4Decrypt(
      ibuf,
      (b) => makekey(password, salt, b),
      blockSize,
    );
  }
}
