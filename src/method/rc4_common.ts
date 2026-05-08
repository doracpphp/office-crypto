/**
 * Shared building blocks for the RC4-based Office encryption schemes
 * (`DocumentRC4` for Office 97 RC4 and `DocumentRC4CryptoAPI` for the later
 * RC4 CryptoAPI provider). Both share the same per-block re-keying loop and
 * the same verify-by-hash flow; only the key-derivation function differs.
 */

import { hash, rc4, type HashAlgorithm } from "../crypto.js";
import { bytesEqual, concatBytes } from "../utils.js";
import type { Readable } from "../format/common.js";

/**
 * Verify a password by RC4-decrypting the verifier + verifier hash with the
 * key derived for block 0, then comparing `H(verifier) == verifierHash`.
 *
 * The two ciphertexts share an RC4 keystream — concatenate, decrypt, split.
 */
export function rc4VerifyByHash(
  hashAlgo: HashAlgorithm,
  key: Uint8Array,
  encryptedVerifier: Uint8Array,
  encryptedVerifierHash: Uint8Array,
): boolean {
  const ct = concatBytes(encryptedVerifier, encryptedVerifierHash);
  const pt = rc4(key, ct);
  const verifier = pt.subarray(0, encryptedVerifier.length);
  const verifierHash = pt.subarray(encryptedVerifier.length);
  const expected = hash(hashAlgo, verifier);
  return bytesEqual(expected, verifierHash);
}

/**
 * Walk an input stream in `blockSize` chunks and decrypt each chunk under a
 * freshly derived key. Used by both DocumentRC4 (per-block MD5 rekey) and
 * DocumentRC4CryptoAPI (per-block SHA-1 rekey).
 *
 * @param ibuf       input stream — read until EOF
 * @param makeKey    derive the RC4 key for block index `b`
 * @param blockSize  chunk size in bytes
 * @param startBlock first block index (defaults to 0; PPT uses persistId here)
 */
export function blockwiseRc4Decrypt(
  ibuf: Readable,
  makeKey: (block: number) => Uint8Array,
  blockSize: number,
  startBlock = 0,
): Uint8Array {
  const out: Uint8Array[] = [];
  let block = startBlock;
  let key = makeKey(block);
  while (true) {
    const buf = ibuf.read(blockSize);
    if (buf.length === 0) break;
    out.push(rc4(key, buf));
    block += 1;
    key = makeKey(block);
  }
  return concatBytes(...out);
}
