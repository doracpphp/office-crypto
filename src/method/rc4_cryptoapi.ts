/**
 * RC4 CryptoAPI encryption (Office 97-2003 SP3 / 2007 SP1+ legacy XLS, DOC,
 * PPT). Uses SHA-1 + RC4 with per-block re-keying.
 *
 * Direct port of `msoffcrypto/method/rc4_cryptoapi.py`.
 */

import { hash } from "../crypto.js";
import { packU32LE, utf16leEncode } from "../utils.js";
import type { Readable } from "../format/common.js";
import { blockwiseRc4Decrypt, rc4VerifyByHash } from "./rc4_common.js";

function makekey(
  password: string,
  salt: Uint8Array,
  keyLength: number,
  block: number,
): Uint8Array {
  // [MS-OFFCRYPTO] §2.3.5.2.
  const pwBytes = utf16leEncode(password);
  const hfinal = hash("SHA1", hash("SHA1", salt, pwBytes), packU32LE(block));
  if (keyLength === 40) {
    // 40-bit export-grade key: 5 bytes from the hash, padded to 16 with zeros.
    const out = new Uint8Array(16);
    out.set(hfinal.subarray(0, 5), 0);
    return out;
  }
  return hfinal.subarray(0, keyLength / 8);
}

export class DocumentRC4CryptoAPI {
  static verifyPassword(
    password: string,
    salt: Uint8Array,
    keySize: number,
    encryptedVerifier: Uint8Array,
    encryptedVerifierHash: Uint8Array,
    block = 0,
  ): boolean {
    const key = makekey(password, salt, keySize, block);
    return rc4VerifyByHash(
      "SHA1",
      key,
      encryptedVerifier,
      encryptedVerifierHash,
    );
  }

  static decrypt(
    password: string,
    salt: Uint8Array,
    keySize: number,
    ibuf: Readable,
    blockSize = 0x200,
    startBlock = 0,
  ): Uint8Array {
    return blockwiseRc4Decrypt(
      ibuf,
      (b) => makekey(password, salt, keySize, b),
      blockSize,
      startBlock,
    );
  }
}
