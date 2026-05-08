/**
 * Excel 97-2003 (BIFF8) format handler.
 *
 * The Workbook stream is decrypted in place — encryption is applied per
 * record, but a handful of records (BOF, FilePass, BoundSheet8.lbPlyPos, …)
 * MUST stay plaintext. We mirror the Python implementation's two-pass plan:
 *   1. Walk all records; build a per-byte plan ("keep plain" / "decrypt").
 *   2. Build a contiguous "encrypted-only" buffer (zeros where plain bytes
 *      should land), feed it to the cipher, then merge back per the plan.
 *
 * Direct port of `msoffcrypto/format/xls97.py`.
 */

import { OleFileIO } from "../olefile.js";
import {
  DecryptionError,
  FileFormatError,
  InvalidKeyError,
  ParseError,
} from "../exceptions.js";
import { DocumentRC4 } from "../method/rc4.js";
import { DocumentRC4CryptoAPI } from "../method/rc4_cryptoapi.js";
import { DocumentXOR } from "../method/xor_obfuscation.js";
import { parseHeaderRC4, parseHeaderRC4CryptoAPI } from "./common.js";
import { BytesIO, packU16LE, readU16, readU16LE } from "../utils.js";
import type {
  BaseOfficeFile,
  DecryptOptions,
  LoadKeyOptions,
} from "./base.js";

/** A subset of BIFF record IDs the decryptor cares about. */
const RECORD = {
  Formula: 6,
  EOF: 10,
  FilePass: 47,
  WriteAccess: 92,
  BoundSheet8: 133,
  Country: 140,
  InterfaceHdr: 225,
  RRDInfo: 406,
  RRDHead: 312,
  UsrExcl: 404,
  FileLock: 405,
  BOF: 2057,
} as const;

/**
 * Iterator-style helper for stepping over BIFF records. Each record is a
 * 4-byte header (`<HH`: id, size) followed by `size` bytes of payload.
 */
class BIFFStream {
  constructor(public data: BytesIO) {}

  /**
   * Read the 4-byte (id, size) record header at the current position.
   * Returns null at EOF (no header bytes available).
   */
  private readHeader(): { num: number; size: number } | null {
    const h = this.data.read(4);
    if (h.length === 0) return null;
    return { num: readU16LE(h, 0), size: readU16LE(h, 2) };
  }

  hasRecord(target: number): boolean {
    const pos = this.data.tell();
    while (true) {
      const h = this.readHeader();
      if (!h) {
        this.data.seek(pos);
        return false;
      }
      if (h.num === target) {
        this.data.seek(pos);
        return true;
      }
      this.data.read(h.size);
    }
  }

  skipTo(target: number): { num: number; size: number } {
    while (true) {
      const h = this.readHeader();
      if (!h) throw new ParseError("Record not found");
      if (h.num === target) return h;
      this.data.read(h.size);
    }
  }

  *iterRecord(): Generator<{ num: number; size: number; record: BytesIO }> {
    while (true) {
      const h = this.readHeader();
      if (!h) break;
      const record = new BytesIO(new Uint8Array(this.data.read(h.size)));
      yield { num: h.num, size: h.size, record };
    }
  }
}

type EncType = "rc4" | "rc4_cryptoapi" | "xor";

export class Xls97File implements BaseOfficeFile {
  format = "xls97";
  keyTypes: readonly string[] = ["password"];

  private workbookData: Uint8Array;
  private type?: EncType;
  private password?: string;
  private salt?: Uint8Array;
  private keySize?: number;

  constructor(public ole: OleFileIO) {
    if (!ole.exists("Workbook")) {
      throw new FileFormatError("Not an Excel 97-2003 file (no Workbook stream)");
    }
    this.workbookData = ole.openstream("Workbook").getValue();
  }

  loadKey(opts: LoadKeyOptions): void {
    const password = opts.password;
    if (password === undefined) {
      throw new DecryptionError("xls97 requires a password");
    }

    const wb = new BIFFStream(new BytesIO(this.workbookData));
    // First record must be BOF (id 2057).
    const bofId = readU16(wb.data);
    if (bofId !== RECORD.BOF) {
      throw new ParseError("Workbook stream does not start with BOF");
    }
    const bofSize = readU16(wb.data);
    wb.data.read(bofSize);

    const filePass = wb.skipTo(RECORD.FilePass);
    const wEncryptionType = readU16(wb.data);
    const encryptionInfo = new BytesIO(
      new Uint8Array(wb.data.read(filePass.size - 2)),
    );

    if (wEncryptionType === 0x0000) {
      // XOR obfuscation: <key:u16><verificationBytes:u16>; key is unused here.
      readU16(encryptionInfo); // key
      const verificationBytes = readU16(encryptionInfo);
      if (!DocumentXOR.verifyPassword(password, verificationBytes)) {
        throw new InvalidKeyError("Failed to verify password");
      }
      this.type = "xor";
      this.password = password;
      return;
    }

    if (wEncryptionType !== 0x0001) {
      throw new DecryptionError(
        `Unsupported wEncryptionType: 0x${wEncryptionType.toString(16)}`,
      );
    }

    // RC4 family — branch on the version major/minor that follows.
    const vMajor = readU16(encryptionInfo);
    const vMinor = readU16(encryptionInfo);

    if (vMajor === 1 && vMinor === 1) {
      const info = parseHeaderRC4(encryptionInfo);
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
      const info = parseHeaderRC4CryptoAPI(encryptionInfo);
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

    // Pass 1: classify each byte of the workbook into "preserve plain" or
    // "decrypt". We accumulate a parallel "encrypted-only" buffer (zero-filled
    // where plain bytes will land) so the cipher's per-block re-keying lines
    // up with the actual stream offsets — both buffers share the same length.
    const plain: number[] = []; // values >=0 land verbatim; -1 / -2 are decrypted
    const encrypted: number[] = []; // bytes fed to the cipher (0 at plain spots)

    const wb = new BIFFStream(new BytesIO(this.workbookData));
    for (const { num, size, record } of wb.iterRecord()) {
      const header = packU16LE(num);
      const sizeHeader = packU16LE(size);
      if (num === RECORD.FilePass) {
        // Zero out the FilePass record so the output is no longer marked as
        // encrypted. Header bytes [0, 0] then [size_lo, size_hi] preserves
        // the record framing.
        plain.push(0, 0, sizeHeader[0], sizeHeader[1]);
        for (let i = 0; i < size; i++) plain.push(0);
        for (let i = 0; i < 4 + size; i++) encrypted.push(0);
        continue;
      }
      if (
        num === RECORD.BOF ||
        num === RECORD.UsrExcl ||
        num === RECORD.FileLock ||
        num === RECORD.InterfaceHdr ||
        num === RECORD.RRDInfo ||
        num === RECORD.RRDHead
      ) {
        // Records that MUST NOT be encrypted — preserve verbatim.
        plain.push(header[0], header[1], sizeHeader[0], sizeHeader[1]);
        const rec = record.read();
        for (const b of rec) plain.push(b);
        for (let i = 0; i < 4 + size; i++) encrypted.push(0);
        continue;
      }
      if (num === RECORD.BoundSheet8) {
        // Per spec, BoundSheet8.lbPlyPos (first 4 bytes after header) must
        // stay plain; the remainder is encrypted.
        plain.push(header[0], header[1], sizeHeader[0], sizeHeader[1]);
        const lbPlyPos = record.read(4);
        for (const b of lbPlyPos) plain.push(b);
        for (let i = 0; i < size - 4; i++) plain.push(-2);
        for (let i = 0; i < 8; i++) encrypted.push(0);
        const rest = record.read();
        for (const b of rest) encrypted.push(b);
        continue;
      }
      // Default: 4-byte header stays plain, body gets decrypted.
      plain.push(header[0], header[1], sizeHeader[0], sizeHeader[1]);
      for (let i = 0; i < size; i++) plain.push(-1);
      for (let i = 0; i < 4; i++) encrypted.push(0);
      const body = record.read();
      for (const b of body) encrypted.push(b);
    }

    if (plain.length !== encrypted.length) {
      throw new DecryptionError(
        "Internal error: plain/encrypted length mismatch",
      );
    }

    // Pass 2: decrypt the parallel encrypted-only buffer.
    const encryptedBuf = new Uint8Array(encrypted);
    let dec: Uint8Array;
    if (this.type === "rc4") {
      dec = DocumentRC4.decrypt(
        this.password,
        this.salt!,
        new BytesIO(encryptedBuf),
        1024,
      );
    } else if (this.type === "rc4_cryptoapi") {
      dec = DocumentRC4CryptoAPI.decrypt(
        this.password,
        this.salt!,
        this.keySize!,
        new BytesIO(encryptedBuf),
        1024,
      );
    } else {
      // XOR's per-byte rotation depends on position within the stream and
      // uses the marker array to know which bytes are real.
      dec = DocumentXOR.decrypt(
        this.password,
        new BytesIO(encryptedBuf),
        plain,
        null,
        10,
      );
    }

    // Pass 3: merge — decrypted byte at -1/-2 positions, plain byte elsewhere.
    const out = new Uint8Array(plain.length);
    for (let i = 0; i < plain.length; i++) {
      const c = plain[i];
      out[i] = c === -1 || c === -2 ? dec[i] : c;
    }

    // Write the decrypted Workbook back into a copy of the OLE container,
    // matching the Python implementation's behaviour.
    this.ole.writeStream("Workbook", out);
    return this.ole.getBuffer();
  }

  isEncrypted(): boolean {
    try {
      const wb = new BIFFStream(new BytesIO(this.workbookData));
      if (readU16(wb.data) !== RECORD.BOF) return false;
      const bofSize = readU16(wb.data);
      wb.data.read(bofSize);
      if (!wb.hasRecord(RECORD.FilePass)) return false;
      wb.skipTo(RECORD.FilePass);
      const t = readU16(wb.data);
      return t === 0x0000 || t === 0x0001;
    } catch {
      return false;
    }
  }
}

