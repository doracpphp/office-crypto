/**
 * Cryptography helpers backed by Node.js `node:crypto`.
 *
 * Algorithms used by the Office encryption schemes:
 *   - SHA-1 / SHA-256 / SHA-384 / SHA-512
 *   - MD5 (used by RC4 / XOR obfuscation)
 *   - HMAC-{SHA1,256,384,512}
 *   - AES-CBC / AES-ECB (128, 192, 256 bit keys)
 *   - RC4 (a.k.a. ARC4) — implemented in pure TS to avoid OpenSSL legacy provider
 *   - RSA-PKCS1 v1.5 decrypt (for private-key based unwrap)
 */

import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  privateDecrypt,
  constants as cryptoConstants,
} from "node:crypto";

export type HashAlgorithm = "SHA1" | "SHA256" | "SHA384" | "SHA512" | "MD5";

function nodeAlgo(a: HashAlgorithm): string {
  switch (a) {
    case "SHA1":
      return "sha1";
    case "SHA256":
      return "sha256";
    case "SHA384":
      return "sha384";
    case "SHA512":
      return "sha512";
    case "MD5":
      return "md5";
  }
}

export function hash(algorithm: HashAlgorithm, ...parts: Uint8Array[]): Uint8Array {
  const h = createHash(nodeAlgo(algorithm));
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function hashSize(algorithm: HashAlgorithm): number {
  switch (algorithm) {
    case "SHA1":
      return 20;
    case "SHA256":
      return 32;
    case "SHA384":
      return 48;
    case "SHA512":
      return 64;
    case "MD5":
      return 16;
  }
}

export function hmac(
  algorithm: HashAlgorithm,
  key: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  const h = createHmac(nodeAlgo(algorithm), key);
  h.update(message);
  return new Uint8Array(h.digest());
}

function aesCbcCipher(key: Uint8Array): string {
  switch (key.length) {
    case 16:
      return "aes-128-cbc";
    case 24:
      return "aes-192-cbc";
    case 32:
      return "aes-256-cbc";
    default:
      throw new Error(`Unsupported AES key length: ${key.length}`);
  }
}

function aesEcbCipher(key: Uint8Array): string {
  switch (key.length) {
    case 16:
      return "aes-128-ecb";
    case 24:
      return "aes-192-ecb";
    case 32:
      return "aes-256-ecb";
    default:
      throw new Error(`Unsupported AES key length: ${key.length}`);
  }
}

export function aesCbcDecrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const decipher = createDecipheriv(aesCbcCipher(key), key, iv);
  decipher.setAutoPadding(false);
  const a = decipher.update(data);
  const b = decipher.final();
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function aesCbcEncrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const cipher = createCipheriv(aesCbcCipher(key), key, iv);
  cipher.setAutoPadding(false);
  const a = cipher.update(data);
  const b = cipher.final();
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function aesEcbDecrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
  const decipher = createDecipheriv(aesEcbCipher(key), key, null);
  decipher.setAutoPadding(false);
  const a = decipher.update(data);
  const b = decipher.final();
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function aesEcbEncrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
  const cipher = createCipheriv(aesEcbCipher(key), key, null);
  cipher.setAutoPadding(false);
  const a = cipher.update(data);
  const b = cipher.final();
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Pure-TS RC4 (ARC4) — Node's native rc4 cipher requires the OpenSSL legacy
 * provider on modern builds, which pulls in environment-specific flags. A
 * direct port keeps the library deployable everywhere.
 */
export function rc4(key: Uint8Array, data: Uint8Array): Uint8Array {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  const klen = key.length;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % klen]) & 0xff;
    const t = S[i];
    S[i] = S[j];
    S[j] = t;
  }

  const out = new Uint8Array(data.length);
  let i = 0;
  j = 0;
  for (let n = 0; n < data.length; n++) {
    i = (i + 1) & 0xff;
    j = (j + S[i]) & 0xff;
    const t = S[i];
    S[i] = S[j];
    S[j] = t;
    const k = S[(S[i] + S[j]) & 0xff];
    out[n] = data[n] ^ k;
  }
  return out;
}

/**
 * Decrypt RSA PKCS#1 v1.5 with a PEM-encoded private key.
 */
export function rsaDecryptPkcs1v15(
  privateKeyPem: Uint8Array | string,
  ciphertext: Uint8Array,
): Uint8Array {
  const keyObj = createPrivateKey({
    key: typeof privateKeyPem === "string" ? privateKeyPem : Buffer.from(privateKeyPem),
    format: "pem",
  });
  const out = privateDecrypt(
    {
      key: keyObj,
      padding: cryptoConstants.RSA_PKCS1_PADDING,
    },
    Buffer.from(ciphertext),
  );
  return new Uint8Array(out);
}

/**
 * Cryptographically secure random bytes.
 */
export function randomBytes(n: number): Uint8Array {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { randomFillSync } = require("node:crypto") as typeof import("node:crypto");
  const out = new Uint8Array(n);
  randomFillSync(out);
  return out;
}
