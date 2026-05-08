/**
 * XOR Obfuscation (a.k.a. "Method 1") used by old XLS files. Algorithm copied
 * verbatim from [MS-OFFCRYPTO] §2.3.6.
 *
 * Direct port of `msoffcrypto/method/xor_obfuscation.py`.
 */

import type { BytesIO } from "../utils.js";

const PAD_ARRAY = [
  0xbb, 0xff, 0xff, 0xba, 0xff, 0xff, 0xb9, 0x80, 0x00, 0xbe, 0x0f, 0x00, 0xbf,
  0x0f, 0x00,
];

const INITIAL_CODE = [
  0xe1f0, 0x1d0f, 0xcc9c, 0x84c0, 0x110c, 0x0e10, 0xf1ce, 0x313e, 0x1872,
  0xe139, 0xd40f, 0x84f9, 0x280c, 0xa96a, 0x4ec3,
];

const XOR_MATRIX = [
  0xaefc, 0x4dd9, 0x9bb2, 0x2745, 0x4e8a, 0x9d14, 0x2a09, 0x7b61, 0xf6c2,
  0xfda5, 0xeb6b, 0xc6f7, 0x9dcf, 0x2bbf, 0x4563, 0x8ac6, 0x05ad, 0x0b5a,
  0x16b4, 0x2d68, 0x5ad0, 0x0375, 0x06ea, 0x0dd4, 0x1ba8, 0x3750, 0x6ea0,
  0xdd40, 0xd849, 0xa0b3, 0x5147, 0xa28e, 0x553d, 0xaa7a, 0x44d5, 0x6f45,
  0xde8a, 0xad35, 0x4a4b, 0x9496, 0x390d, 0x721a, 0xeb23, 0xc667, 0x9cef,
  0x29ff, 0x53fe, 0xa7fc, 0x5fd9, 0x47d3, 0x8fa6, 0x0f6d, 0x1eda, 0x3db4,
  0x7b68, 0xf6d0, 0xb861, 0x60e3, 0xc1c6, 0x93ad, 0x377b, 0x6ef6, 0xddec,
  0x45a0, 0x8b40, 0x06a1, 0x0d42, 0x1a84, 0x3508, 0x6a10, 0xaa51, 0x4483,
  0x8906, 0x022d, 0x045a, 0x08b4, 0x1168, 0x76b4, 0xed68, 0xcaf1, 0x85c3,
  0x1ba7, 0x374e, 0x6e9c, 0x3730, 0x6e60, 0xdcc0, 0xa9a1, 0x4363, 0x86c6,
  0x1dad, 0x3331, 0x6662, 0xccc4, 0x89a9, 0x0373, 0x06e6, 0x0dcc, 0x1021,
  0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48c4,
];

function ror(n: number, rotations: number, width: number): number {
  return ((1 << width) - 1) & ((n >>> rotations) | (n << (width - rotations)));
}

function xorRor(byte1: number, byte2: number): number {
  return ror(byte1 ^ byte2, 1, 8);
}

export class DocumentXOR {
  /**
   * Verify password by computing the obfuscation verifier and comparing to
   * the on-disk verificationBytes. Spec: [MS-OFFCRYPTO] §2.3.7.
   */
  static verifyPassword(password: string, verificationBytes: number): boolean {
    let verifier = 0;
    const arr: number[] = [];
    arr.push(password.length);
    for (const ch of password) arr.push(ch.charCodeAt(0));
    arr.reverse();
    for (const passwordByte of arr) {
      const intermediate1 = (verifier & 0x4000) === 0 ? 0 : 1;
      const intermediate2 = (verifier * 2) & 0x7fff;
      const intermediate3 = intermediate1 ^ intermediate2;
      verifier = intermediate3 ^ passwordByte;
    }
    return (verifier ^ 0xce4b) === verificationBytes;
  }

  /** Build the 16-byte XOR pad described by [MS-OFFCRYPTO] §2.3.6.2. */
  static createXorArrayMethod1(password: string): number[] {
    const xorKey = (() => {
      let k = INITIAL_CODE[password.length - 1];
      let currentElement = 0x68;
      const data: number[] = [];
      for (let i = password.length - 1; i >= 0; i--) {
        data.push(password.charCodeAt(i));
      }
      for (let ch of data) {
        for (let i = 0; i < 7; i++) {
          if ((ch & 0x40) !== 0) k = (k ^ XOR_MATRIX[currentElement]) % 65536;
          ch = (ch << 1) % 256;
          currentElement -= 1;
        }
      }
      return k;
    })();

    let index = password.length;
    const obfuscationArray = new Array<number>(16).fill(0);

    if (index % 2 === 1) {
      let temp = (xorKey & 0xff00) >>> 8;
      obfuscationArray[index] = xorRor(PAD_ARRAY[0], temp);

      index -= 1;
      temp = xorKey & 0x00ff;
      const passwordLastChar = password.charCodeAt(password.length - 1);
      obfuscationArray[index] = xorRor(passwordLastChar, temp);
    }

    while (index > 0) {
      index -= 1;
      let temp = (xorKey & 0xff00) >>> 8;
      obfuscationArray[index] = xorRor(password.charCodeAt(index), temp);

      index -= 1;
      temp = xorKey & 0x00ff;
      obfuscationArray[index] = xorRor(password.charCodeAt(index), temp);
    }

    let i = 15;
    let padIndex = 15 - password.length;
    while (padIndex > 0) {
      let temp = (xorKey & 0xff00) >>> 8;
      obfuscationArray[i] = xorRor(PAD_ARRAY[padIndex], temp);

      i -= 1;
      padIndex -= 1;

      temp = xorKey & 0x00ff;
      obfuscationArray[i] = xorRor(PAD_ARRAY[padIndex], temp);

      i -= 1;
      padIndex -= 1;
    }

    return obfuscationArray;
  }

  /**
   * Decrypt records using the Method 1 XOR scheme. The plaintext array marks
   * which bytes are actually encrypted (-1, -2) vs. plaintext-as-is (>=0).
   */
  static decrypt(
    password: string,
    ibuf: BytesIO,
    plaintext: number[],
    _records: unknown,
    _base: unknown,
  ): Uint8Array {
    const xorArray = DocumentXOR.createXorArrayMethod1(password);
    const out: number[] = [];

    let dataIndex = 0;
    while (dataIndex < plaintext.length) {
      let count = 1;
      if (plaintext[dataIndex] === -1 || plaintext[dataIndex] === -2) {
        for (let j = dataIndex + 1; j < plaintext.length; j++) {
          if (plaintext[j] >= 0) break;
          count += 1;
        }

        let xorArrayIndex =
          plaintext[dataIndex] === -2
            ? (dataIndex + count + 4) % 16
            : (dataIndex + count) % 16;

        for (let item = 0; item < count; item++) {
          const dataByte = ibuf.read(1)[0];
          let tempRes = dataByte ^ xorArray[xorArrayIndex];
          tempRes = ror(tempRes, 5, 8);
          out.push(tempRes);
          xorArrayIndex = (xorArrayIndex + 1) % 16;
        }
      } else {
        out.push(ibuf.read(1)[0]);
      }
      dataIndex += count;
    }

    return new Uint8Array(out);
  }
}
