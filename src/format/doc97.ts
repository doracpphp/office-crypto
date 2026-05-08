/**
 * Word 97-2003 (BIFF / FIB) format handler.
 *
 * Word's encryption affects three streams:
 *   - WordDocument: starts with a 0x44-byte FibBase header. The first 0x44
 *     bytes (with `fEncrypted=0` and `fObfuscation=0` cleared) MUST be
 *     written plaintext; the rest of the stream is decrypted.
 *   - 0Table or 1Table (selected by FibBase.fWhichTblStm): fully decrypted.
 *   - Data: optional, fully decrypted if present.
 *
 * Direct port of `msoffcrypto/format/doc97.py`.
 */

import { OleFileIO } from "../olefile.js";
import {
  DecryptionError,
  FileFormatError,
  InvalidKeyError,
} from "../exceptions.js";
import { DocumentRC4 } from "../method/rc4.js";
import { DocumentRC4CryptoAPI } from "../method/rc4_cryptoapi.js";
import { parseHeaderRC4, parseHeaderRC4CryptoAPI } from "./common.js";
import {
  ByteWriter,
  BytesIO,
  getBit,
  getBitSlice,
  readU16,
  readU32,
  setBit,
  setBitSlice,
  type Readable,
} from "../utils.js";
import type {
  BaseOfficeFile,
  DecryptOptions,
  LoadKeyOptions,
} from "./base.js";

interface FibBase {
  wIdent: number;
  nFib: number;
  unused: number;
  lid: number;
  pnNext: number;
  // Bit fields packed into one u16
  fDot: number;
  fGlsy: number;
  fComplex: number;
  fHasPic: number;
  cQuickSaves: number;
  fEncrypted: number;
  fWhichTblStm: number;
  fReadOnlyRecommended: number;
  fWriteReservation: number;
  fExtChar: number;
  fLoadOverride: number;
  fFarEast: number;
  fObfuscation: number;
  // ---
  nFibBack: number;
  IKey: number;
  envr: number;
  // Bit field byte
  fMac: number;
  fEmptySpecial: number;
  fLoadOverridePage: number;
  reserved1: number;
  reserved2: number;
  fSpare0: number;
  // ---
  reserved3: number;
  reserved4: number;
  reserved5: number;
  reserved6: number;
}

function parseFibBase(blob: Readable): FibBase {
  const wIdent = readU16(blob);
  const nFib = readU16(blob);
  const unused = readU16(blob);
  const lid = readU16(blob);
  const pnNext = readU16(blob);

  const flagsA = readU16(blob);
  const fDot = getBit(flagsA, 0);
  const fGlsy = getBit(flagsA, 1);
  const fComplex = getBit(flagsA, 2);
  const fHasPic = getBit(flagsA, 3);
  const cQuickSaves = getBitSlice(flagsA, 4, 4);
  const fEncrypted = getBit(flagsA, 8);
  const fWhichTblStm = getBit(flagsA, 9);
  const fReadOnlyRecommended = getBit(flagsA, 10);
  const fWriteReservation = getBit(flagsA, 11);
  const fExtChar = getBit(flagsA, 12);
  const fLoadOverride = getBit(flagsA, 13);
  const fFarEast = getBit(flagsA, 14);
  const fObfuscation = getBit(flagsA, 15);

  const nFibBack = readU16(blob);
  const IKey = readU32(blob);
  const envr = blob.read(1)[0];

  const flagsB = blob.read(1)[0];
  const fMac = getBit(flagsB, 0);
  const fEmptySpecial = getBit(flagsB, 1);
  const fLoadOverridePage = getBit(flagsB, 2);
  const reserved1 = getBit(flagsB, 3);
  const reserved2 = getBit(flagsB, 4);
  const fSpare0 = getBitSlice(flagsB, 5, 3);

  const reserved3 = readU16(blob);
  const reserved4 = readU16(blob);
  const reserved5 = readU32(blob);
  const reserved6 = readU32(blob);

  return {
    wIdent,
    nFib,
    unused,
    lid,
    pnNext,
    fDot,
    fGlsy,
    fComplex,
    fHasPic,
    cQuickSaves,
    fEncrypted,
    fWhichTblStm,
    fReadOnlyRecommended,
    fWriteReservation,
    fExtChar,
    fLoadOverride,
    fFarEast,
    fObfuscation,
    nFibBack,
    IKey,
    envr,
    fMac,
    fEmptySpecial,
    fLoadOverridePage,
    reserved1,
    reserved2,
    fSpare0,
    reserved3,
    reserved4,
    reserved5,
    reserved6,
  };
}

function packFibBase(fib: FibBase): Uint8Array {
  let flagsA = 0xffff;
  flagsA = setBit(flagsA, 0, fib.fDot);
  flagsA = setBit(flagsA, 1, fib.fGlsy);
  flagsA = setBit(flagsA, 2, fib.fComplex);
  flagsA = setBit(flagsA, 3, fib.fHasPic);
  flagsA = setBitSlice(flagsA, 4, 4, fib.cQuickSaves);
  flagsA = setBit(flagsA, 8, fib.fEncrypted);
  flagsA = setBit(flagsA, 9, fib.fWhichTblStm);
  flagsA = setBit(flagsA, 10, fib.fReadOnlyRecommended);
  flagsA = setBit(flagsA, 11, fib.fWriteReservation);
  flagsA = setBit(flagsA, 12, fib.fExtChar);
  flagsA = setBit(flagsA, 13, fib.fLoadOverride);
  flagsA = setBit(flagsA, 14, fib.fFarEast);
  flagsA = setBit(flagsA, 15, fib.fObfuscation);

  let flagsB = 0xff;
  flagsB = setBit(flagsB, 0, fib.fMac);
  flagsB = setBit(flagsB, 1, fib.fEmptySpecial);
  flagsB = setBit(flagsB, 2, fib.fLoadOverridePage);
  flagsB = setBit(flagsB, 3, fib.reserved1);
  flagsB = setBit(flagsB, 4, fib.reserved2);
  flagsB = setBitSlice(flagsB, 5, 3, fib.fSpare0);

  return new ByteWriter()
    .u16(fib.wIdent)
    .u16(fib.nFib)
    .u16(fib.unused)
    .u16(fib.lid)
    .u16(fib.pnNext)
    .u16(flagsA & 0xffff)
    .u16(fib.nFibBack)
    .u32(fib.IKey >>> 0)
    .u8(fib.envr)
    .u8(flagsB & 0xff)
    .u16(fib.reserved3)
    .u16(fib.reserved4)
    .u32(fib.reserved5 >>> 0)
    .u32(fib.reserved6 >>> 0)
    .build();
}

type EncType = "rc4" | "rc4_cryptoapi";

export class Doc97File implements BaseOfficeFile {
  format = "doc97";
  keyTypes: readonly string[] = ["password"];

  private fib: FibBase;
  private tableName: "0Table" | "1Table";

  private type?: EncType;
  private password?: string;
  private salt?: Uint8Array;
  private keySize?: number;

  constructor(public ole: OleFileIO) {
    const wd = ole.exists("WordDocument")
      ? "WordDocument"
      : ole.exists("wordDocument")
        ? "wordDocument"
        : null;
    if (!wd) {
      throw new FileFormatError("Not a Word 97-2003 file (no WordDocument stream)");
    }
    this.fib = parseFibBase(new BytesIO(ole.openstream(wd).getValue()));
    this.tableName = this.fib.fWhichTblStm === 1 ? "1Table" : "0Table";
  }

  loadKey(opts: LoadKeyOptions): void {
    const password = opts.password;
    if (password === undefined) {
      throw new DecryptionError("doc97 requires a password");
    }
    if (!this.fib.fEncrypted) {
      throw new DecryptionError("File is not encrypted");
    }
    if (this.fib.fObfuscation === 1) {
      throw new DecryptionError(
        "XOR-obfuscated DOC files are not supported (the format is rare)",
      );
    }

    if (!this.ole.exists(this.tableName)) {
      throw new FileFormatError(`Table stream not found: ${this.tableName}`);
    }
    const table = this.ole.openstream(this.tableName);
    const vMajor = readU16(table);
    const vMinor = readU16(table);

    if (vMajor === 1 && vMinor === 1) {
      const info = parseHeaderRC4(table);
      if (
        !DocumentRC4.verifyPassword(
          password,
          info.salt,
          info.encryptedVerifier,
          info.encryptedVerifierHash,
        )
      ) {
        throw new InvalidKeyError("Failed to verify password");
      }
      this.type = "rc4";
      this.password = password;
      this.salt = info.salt;
      return;
    }

    if ((vMajor === 2 || vMajor === 3 || vMajor === 4) && vMinor === 2) {
      const info = parseHeaderRC4CryptoAPI(table);
      if (
        !DocumentRC4CryptoAPI.verifyPassword(
          password,
          info.salt,
          info.keySize,
          info.encryptedVerifier,
          info.encryptedVerifierHash,
        )
      ) {
        throw new InvalidKeyError("Failed to verify password");
      }
      this.type = "rc4_cryptoapi";
      this.password = password;
      this.salt = info.salt;
      this.keySize = info.keySize;
      return;
    }

    throw new DecryptionError(
      `Unsupported encryption version: ${vMajor}.${vMinor}`,
    );
  }

  decrypt(_opts: DecryptOptions = {}): Uint8Array {
    if (!this.type || !this.password) {
      throw new DecryptionError("Must call loadKey before decrypt");
    }

    // Build the new WordDocument: 0x44 plaintext header (with fEncrypted=0,
    // fObfuscation=0, IKey=0) followed by decrypted data starting at 0x44.
    const FIB_LENGTH = 0x44;
    const newFib: FibBase = {
      ...this.fib,
      fEncrypted: 0,
      fObfuscation: 0,
      IKey: 0,
    };

    const wordDocBytes = this.ole.openstream("WordDocument").getValue();
    const fibBytes = packFibBase(newFib);
    const newWordDoc = new Uint8Array(wordDocBytes.length);
    newWordDoc.set(fibBytes, 0);
    // Bytes between fibBytes.length and FIB_LENGTH come from the original
    // WordDocument plaintext (FibRgW, FibRgLw, etc.).
    const remainingHeader = wordDocBytes.subarray(fibBytes.length, FIB_LENGTH);
    newWordDoc.set(remainingHeader, fibBytes.length);

    const decFull = this.cipherDecrypt(wordDocBytes);
    newWordDoc.set(decFull.subarray(FIB_LENGTH), FIB_LENGTH);

    // Decrypt the table stream wholesale.
    const tableBytes = this.ole.openstream(this.tableName).getValue();
    const tableDec = this.cipherDecrypt(tableBytes);

    // Optional Data stream
    let dataDec: Uint8Array | null = null;
    if (this.ole.exists("Data")) {
      const dataBytes = this.ole.openstream("Data").getValue();
      dataDec = this.cipherDecrypt(dataBytes);
    }

    this.ole.writeStream("WordDocument", newWordDoc);
    this.ole.writeStream(this.tableName, tableDec);
    if (dataDec) this.ole.writeStream("Data", dataDec);

    return this.ole.getBuffer();
  }

  private cipherDecrypt(buf: Uint8Array): Uint8Array {
    if (this.type === "rc4") {
      return DocumentRC4.decrypt(this.password!, this.salt!, new BytesIO(buf));
    }
    return DocumentRC4CryptoAPI.decrypt(
      this.password!,
      this.salt!,
      this.keySize!,
      new BytesIO(buf),
    );
  }

  isEncrypted(): boolean {
    return this.fib.fEncrypted === 1;
  }
}

