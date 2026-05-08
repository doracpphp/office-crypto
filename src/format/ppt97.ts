/**
 * PowerPoint 97-2003 format handler.
 *
 * PPT's encryption story is the most involved of the legacy formats:
 *
 *   1. The Current User Stream contains a CurrentUserAtom whose
 *      `offsetToCurrentEdit` points into the PowerPoint Document stream.
 *   2. Following that pointer lands on a UserEditAtom; its
 *      `encryptSessionPersistIdRef` resolves (via the persist object
 *      directory built from the chain of UserEditAtoms +
 *      PersistDirectoryAtoms) to a CryptSession10Container record holding
 *      the EncryptionInfo header.
 *   3. Each persist object in the directory is independently RC4-CryptoAPI
 *      encrypted, using its `persistId` as the cipher block index.
 *   4. UserEditAtom, PersistDirectoryAtom, and CryptSession10Container
 *      records themselves MUST NOT be encrypted.
 *
 * We mirror the Python implementation: build the persist directory, decrypt
 * each persist object in place, zero out the CryptSession10Container, drop
 * the encryptSessionPersistIdRef, and rewrite Current User Stream's header
 * token to "not encrypted".
 *
 * Direct port of `msoffcrypto/format/ppt97.py`.
 */

import { OleFileIO } from "../olefile.js";
import {
  DecryptionError,
  FileFormatError,
  InvalidKeyError,
  ParseError,
} from "../exceptions.js";
import { DocumentRC4CryptoAPI } from "../method/rc4_cryptoapi.js";
import { parseHeaderRC4CryptoAPI } from "./common.js";
import {
  ByteWriter,
  BytesIO,
  readU16,
  readU16LE,
  readU32LE,
  setBitSlice,
} from "../utils.js";
import type {
  BaseOfficeFile,
  DecryptOptions,
  LoadKeyOptions,
} from "./base.js";

interface RecordHeader {
  recVer: number;
  recInstance: number;
  recType: number;
  recLen: number;
}

function parseRecordHeader(b: Uint8Array, off: number): RecordHeader {
  const w0 = readU16LE(b, off);
  const recVer = w0 & 0xf;
  const recInstance = (w0 >>> 4) & 0xfff;
  const recType = readU16LE(b, off + 2);
  const recLen = readU32LE(b, off + 4);
  return { recVer, recInstance, recType, recLen };
}

function packRecordHeader(rh: RecordHeader): Uint8Array {
  const w0 = (rh.recVer & 0xf) | ((rh.recInstance & 0xfff) << 4);
  return new ByteWriter().u16(w0).u16(rh.recType).u32(rh.recLen).build();
}

interface CurrentUserAtom {
  rh: RecordHeader;
  size: number;
  headerToken: number;
  offsetToCurrentEdit: number;
  lenUserName: number;
  docFileVersion: number;
  majorVersion: number;
  minorVersion: number;
  unused: Uint8Array;
  ansiUserName: Uint8Array;
  relVersion: number;
  unicodeUserName: Uint8Array;
}

function parseCurrentUserAtom(buf: Uint8Array): CurrentUserAtom {
  const rh = parseRecordHeader(buf, 0);
  if (rh.recVer !== 0 || rh.recInstance !== 0 || rh.recType !== 0x0ff6) {
    throw new ParseError("Invalid CurrentUserAtom record header");
  }
  let off = 8;
  const size = readU32LE(buf, off); off += 4;
  if (size !== 0x14) throw new ParseError("CurrentUserAtom.size != 0x14");
  const headerToken = readU32LE(buf, off); off += 4;
  const offsetToCurrentEdit = readU32LE(buf, off); off += 4;
  const lenUserName = readU16LE(buf, off); off += 2;
  const docFileVersion = readU16LE(buf, off); off += 2;
  const majorVersion = buf[off++];
  const minorVersion = buf[off++];
  const unused = buf.subarray(off, off + 2); off += 2;
  const ansiUserName = buf.subarray(off, off + lenUserName); off += lenUserName;
  const relVersion = readU32LE(buf, off); off += 4;
  const unicodeUserName = buf.subarray(off, off + 2 * lenUserName);
  return {
    rh,
    size,
    headerToken,
    offsetToCurrentEdit,
    lenUserName,
    docFileVersion,
    majorVersion,
    minorVersion,
    unused: new Uint8Array(unused),
    ansiUserName: new Uint8Array(ansiUserName),
    relVersion,
    unicodeUserName: new Uint8Array(unicodeUserName),
  };
}

function packCurrentUserAtom(c: CurrentUserAtom): Uint8Array {
  return new ByteWriter()
    .bytes(packRecordHeader(c.rh))
    .u32(c.size)
    .u32(c.headerToken >>> 0)
    .u32(c.offsetToCurrentEdit)
    .u16(c.lenUserName)
    .u16(c.docFileVersion)
    .u8(c.majorVersion)
    .u8(c.minorVersion)
    .bytes(c.unused)
    .bytes(c.ansiUserName)
    .u32(c.relVersion)
    .bytes(c.unicodeUserName)
    .build();
}

interface UserEditAtom {
  rh: RecordHeader;
  lastSlideIdRef: number;
  version: number;
  minorVersion: number;
  majorVersion: number;
  offsetLastEdit: number;
  offsetPersistDirectory: number;
  docPersistIdRef: number;
  persistIdSeed: number;
  lastView: number;
  unused: Uint8Array;
  encryptSessionPersistIdRef: number | null;
}

function parseUserEditAtom(buf: Uint8Array, baseOff: number): UserEditAtom {
  const rh = parseRecordHeader(buf, baseOff);
  if (rh.recVer !== 0 || rh.recInstance !== 0 || rh.recType !== 0x0ff5) {
    throw new ParseError("Invalid UserEditAtom record header");
  }
  if (rh.recLen !== 0x1c && rh.recLen !== 0x20) {
    throw new ParseError(`Unexpected UserEditAtom recLen: ${rh.recLen}`);
  }
  let off = baseOff + 8;
  const lastSlideIdRef = readU32LE(buf, off); off += 4;
  const version = readU16LE(buf, off); off += 2;
  const minorVersion = buf[off++];
  const majorVersion = buf[off++];
  const offsetLastEdit = readU32LE(buf, off); off += 4;
  const offsetPersistDirectory = readU32LE(buf, off); off += 4;
  const docPersistIdRef = readU32LE(buf, off); off += 4;
  const persistIdSeed = readU32LE(buf, off); off += 4;
  const lastView = readU16LE(buf, off); off += 2;
  const unused = buf.subarray(off, off + 2); off += 2;
  let encryptSessionPersistIdRef: number | null = null;
  if (rh.recLen === 0x20) {
    encryptSessionPersistIdRef = readU32LE(buf, off);
  }
  return {
    rh,
    lastSlideIdRef,
    version,
    minorVersion,
    majorVersion,
    offsetLastEdit,
    offsetPersistDirectory,
    docPersistIdRef,
    persistIdSeed,
    lastView,
    unused: new Uint8Array(unused),
    encryptSessionPersistIdRef,
  };
}

function packUserEditAtom(u: UserEditAtom): Uint8Array {
  const w = new ByteWriter()
    .bytes(packRecordHeader(u.rh))
    .u32(u.lastSlideIdRef)
    .u16(u.version)
    .u8(u.minorVersion)
    .u8(u.majorVersion)
    .u32(u.offsetLastEdit)
    .u32(u.offsetPersistDirectory)
    .u32(u.docPersistIdRef)
    .u32(u.persistIdSeed)
    .u16(u.lastView)
    .bytes(u.unused);
  if (u.encryptSessionPersistIdRef !== null) {
    w.u32(u.encryptSessionPersistIdRef);
  }
  return w.build();
}

interface PersistDirectoryEntry {
  persistId: number;
  cPersist: number;
  rgPersistOffset: number[];
}

interface PersistDirectoryAtom {
  rh: RecordHeader;
  rgPersistDirEntry: PersistDirectoryEntry[];
}

function parsePersistDirectoryAtom(
  buf: Uint8Array,
  baseOff: number,
): PersistDirectoryAtom {
  const rh = parseRecordHeader(buf, baseOff);
  if (rh.recVer !== 0 || rh.recInstance !== 0 || rh.recType !== 0x1772) {
    throw new ParseError("Invalid PersistDirectoryAtom record header");
  }
  const entries: PersistDirectoryEntry[] = [];
  let pos = 0;
  let off = baseOff + 8;
  while (pos < rh.recLen) {
    const w = readU32LE(buf, off);
    off += 4;
    const persistId = w & 0xfffff;
    const cPersist = (w >>> 20) & 0xfff;
    const rgPersistOffset: number[] = [];
    for (let i = 0; i < cPersist; i++) {
      rgPersistOffset.push(readU32LE(buf, off));
      off += 4;
    }
    const entrySize = 4 + 4 * cPersist;
    entries.push({ persistId, cPersist, rgPersistOffset });
    pos += entrySize;
  }
  return { rh, rgPersistDirEntry: entries };
}

function packPersistDirectoryAtom(pda: PersistDirectoryAtom): Uint8Array {
  const w = new ByteWriter().bytes(packRecordHeader(pda.rh));
  for (const e of pda.rgPersistDirEntry) {
    // Pack {persistId: u20, cPersist: u12} into one u32 (LE).
    let bits = 0xffffffff >>> 0;
    bits = setBitSlice(bits, 0, 20, e.persistId);
    bits = setBitSlice(bits, 20, 12, e.cPersist);
    w.u32(bits >>> 0);
    for (const o of e.rgPersistOffset) w.u32(o);
  }
  return w.build();
}

/**
 * Build the persist object directory: persistId → byte offset within the
 * PowerPoint Document stream. Walks the UserEditAtom chain via offsetLastEdit.
 */
function constructPersistObjectDirectory(
  currentUserBytes: Uint8Array,
  pptBytes: Uint8Array,
): Map<number, number> {
  const cu = parseCurrentUserAtom(currentUserBytes);
  const stack: PersistDirectoryAtom[] = [];

  let off = cu.offsetToCurrentEdit;
  // Spec says exactly one UserEditAtom — but we walk the chain in case of
  // multiple revisions, mirroring the Python implementation.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const ue = parseUserEditAtom(pptBytes, off);
    const pda = parsePersistDirectoryAtom(pptBytes, ue.offsetPersistDirectory);
    stack.push(pda);
    if (ue.offsetLastEdit === 0) break;
    off = ue.offsetLastEdit;
    // Defensive break: real-world PPT has 1 entry
    if (stack.length > 1) break;
  }

  const dir = new Map<number, number>();
  while (stack.length > 0) {
    const pda = stack.pop()!;
    for (const e of pda.rgPersistDirEntry) {
      for (let i = 0; i < e.rgPersistOffset.length; i++) {
        dir.set(e.persistId + i, e.rgPersistOffset[i]);
      }
    }
  }
  return dir;
}

export class Ppt97File implements BaseOfficeFile {
  format = "ppt97";
  keyTypes: readonly string[] = ["password"];

  private currentUserBytes: Uint8Array;
  private pptBytes: Uint8Array;

  private password?: string;
  private salt?: Uint8Array;
  private keySize?: number;

  constructor(public ole: OleFileIO) {
    if (!ole.exists("Current User") || !ole.exists("PowerPoint Document")) {
      throw new FileFormatError(
        "Not a PowerPoint 97-2003 file (missing Current User or PowerPoint Document stream)",
      );
    }
    this.currentUserBytes = ole.openstream("Current User").getValue();
    this.pptBytes = ole.openstream("PowerPoint Document").getValue();
  }

  loadKey(opts: LoadKeyOptions): void {
    const password = opts.password;
    if (password === undefined) {
      throw new DecryptionError("ppt97 requires a password");
    }

    const cu = parseCurrentUserAtom(this.currentUserBytes);
    const ue = parseUserEditAtom(this.pptBytes, cu.offsetToCurrentEdit);
    if (ue.encryptSessionPersistIdRef === null) {
      throw new DecryptionError("File does not contain an encryption session");
    }

    const dir = constructPersistObjectDirectory(
      this.currentUserBytes,
      this.pptBytes,
    );
    const cryptOff = dir.get(ue.encryptSessionPersistIdRef);
    if (cryptOff === undefined) {
      throw new ParseError(
        "encryptSessionPersistIdRef not in persist object directory",
      );
    }

    // CryptSession10Container: 8-byte rh + recLen bytes of EncryptionInfo.
    const containerRh = parseRecordHeader(this.pptBytes, cryptOff);
    if (containerRh.recType !== 0x2f14) {
      throw new ParseError(
        `Expected CryptSession10Container, got recType=0x${containerRh.recType.toString(16)}`,
      );
    }
    const cryptData = this.pptBytes.subarray(
      cryptOff + 8,
      cryptOff + 8 + containerRh.recLen,
    );
    const blob = new BytesIO(new Uint8Array(cryptData));

    const vMajor = readU16(blob);
    const vMinor = readU16(blob);
    if (
      !(vMajor === 2 || vMajor === 3 || vMajor === 4) ||
      vMinor !== 2
    ) {
      throw new DecryptionError(
        `PPT only supports RC4 CryptoAPI encryption (got ${vMajor}.${vMinor})`,
      );
    }

    const info = parseHeaderRC4CryptoAPI(blob);
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

    this.password = password;
    this.salt = info.salt;
    this.keySize = info.keySize;
  }

  decrypt(_opts: DecryptOptions = {}): Uint8Array {
    if (this.password === undefined) {
      throw new DecryptionError("Must call loadKey before decrypt");
    }

    // ---- Current User Stream rewrite ----
    const cu = parseCurrentUserAtom(this.currentUserBytes);
    const cuNew: CurrentUserAtom = {
      ...cu,
      // 0xE391C05F: spec value indicating "this file SHOULD NOT be encrypted".
      headerToken: 0xe391c05f,
    };
    const newCurrentUser = packCurrentUserAtom(cuNew);
    if (newCurrentUser.length !== this.currentUserBytes.length) {
      throw new DecryptionError(
        "Internal: Current User stream size changed unexpectedly",
      );
    }

    // ---- PowerPoint Document Stream rewrite ----
    const dec = new Uint8Array(this.pptBytes.length);
    dec.set(this.pptBytes, 0);

    // Patch UserEditAtom: clear encryptSessionPersistIdRef + drop 4 bytes
    // from recLen.
    const ueOff = cu.offsetToCurrentEdit;
    const ue = parseUserEditAtom(this.pptBytes, ueOff);
    const ueNew: UserEditAtom = {
      ...ue,
      rh: { ...ue.rh, recLen: ue.rh.recLen - 4 },
      encryptSessionPersistIdRef: 0x00000000,
    };
    const ueBytes = packUserEditAtom(ueNew);
    dec.set(ueBytes, ueOff);

    // Patch PersistDirectoryAtom: drop 1 from cPersist (we'll zero out the
    // CryptSession10Container record below).
    const pda = parsePersistDirectoryAtom(this.pptBytes, ue.offsetPersistDirectory);
    const firstEntry = pda.rgPersistDirEntry[0];
    const pdaNew: PersistDirectoryAtom = {
      rh: pda.rh,
      rgPersistDirEntry: [
        {
          persistId: firstEntry.persistId,
          cPersist: firstEntry.cPersist - 1,
          rgPersistOffset: firstEntry.rgPersistOffset,
        },
      ],
    };
    const pdaBytes = packPersistDirectoryAtom(pdaNew);
    dec.set(pdaBytes, ue.offsetPersistDirectory);

    // ---- Decrypt each persist object ----
    const dir = constructPersistObjectDirectory(
      this.currentUserBytes,
      this.pptBytes,
    );
    // Convert to ordered array (Map preserves insertion order, matching the
    // Python dict iteration semantics on Python 3.7+).
    const items = Array.from(dir.entries());

    for (let i = 0; i < items.length; i++) {
      const [persistId, off] = items[i];
      const rh = parseRecordHeader(this.pptBytes, off);

      // CryptSession10Container — zero out the entire record.
      if (rh.recType === 0x2f14) {
        const total = 8 + rh.recLen;
        for (let k = 0; k < total; k++) dec[off + k] = 0;
        continue;
      }

      // UserEditAtom / PersistDirectoryAtom — already handled above; skip.
      if (rh.recType === 0x0ff5 || rh.recType === 0x1772) continue;

      // Compute the encrypted-region length: from this offset to the next
      // persist object's offset, minus the 8-byte record header. The Python
      // code has the same rule.
      if (i + 1 >= items.length) continue;
      const nextOff = items[i + 1][1];
      const recLen = nextOff - off - 8;
      if (recLen < 0) continue;

      const encBuf = this.pptBytes.subarray(off, off + 8 + recLen);
      // The Python source uses an "undocumented" blocksize that's a multiple
      // of keySize big enough to cover (8 + recLen) plus one extra round.
      const blockSize =
        this.keySize! * (Math.floor((8 + recLen) / this.keySize!) + 1);
      const decoded = DocumentRC4CryptoAPI.decrypt(
        this.password!,
        this.salt!,
        this.keySize!,
        new BytesIO(new Uint8Array(encBuf)),
        blockSize,
        persistId,
      );
      dec.set(decoded.subarray(0, encBuf.length), off);
    }

    this.ole.writeStream("Current User", newCurrentUser);
    this.ole.writeStream("PowerPoint Document", dec);
    return this.ole.getBuffer();
  }

  isEncrypted(): boolean {
    try {
      const cu = parseCurrentUserAtom(this.currentUserBytes);
      const ue = parseUserEditAtom(this.pptBytes, cu.offsetToCurrentEdit);
      return ue.rh.recLen === 0x20;
    } catch {
      return false;
    }
  }
}
