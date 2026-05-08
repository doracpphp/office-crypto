/**
 * Minimal OLE2 / Microsoft Compound File Binary (CFB) reader.
 *
 * Direct TypeScript port of the read-only subset of `olefile.py` (Philippe
 * Lagadec) needed by msoffcrypto: header parsing, FAT/MiniFAT/DIFAT loading,
 * directory tree walking, and stream extraction. Encrypted OOXML containers,
 * and legacy XLS/DOC/PPT files, expose their data through this layer.
 *
 * Original Python: https://www.decalage.info/olefile (BSD-2-Clause-like)
 */

import { readU16LE, readU32LE, utf16leDecode } from "./utils.js";

export const MAGIC = new Uint8Array([
  0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
]);

export const MAXREGSECT = 0xfffffffa;
export const DIFSECT = 0xfffffffc;
export const FATSECT = 0xfffffffd;
export const ENDOFCHAIN = 0xfffffffe;
export const FREESECT = 0xffffffff;

export const NOSTREAM = 0xffffffff;
export const UNKNOWN_SIZE = 0x7fffffff;

export const STGTY_EMPTY = 0;
export const STGTY_STORAGE = 1;
export const STGTY_STREAM = 2;
export const STGTY_LOCKBYTES = 3;
export const STGTY_PROPERTY = 4;
export const STGTY_ROOT = 5;

export const MINIMAL_OLEFILE_SIZE = 1536;

export class OleFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OleFileError";
  }
}

export class NotOleFileError extends OleFileError {
  constructor(message: string) {
    super(message);
    this.name = "NotOleFileError";
  }
}

/**
 * Test if `data` looks like an OLE2 compound file by checking the magic bytes
 * at the start. Mirrors `olefile.isOleFile`.
 */
export function isOleFile(data: Uint8Array): boolean {
  if (data.length < MAGIC.length) return false;
  for (let i = 0; i < MAGIC.length; i++) {
    if (data[i] !== MAGIC[i]) return false;
  }
  return true;
}

/**
 * Directory entry as parsed from the 128-byte directory record.
 * Field names match the AAF/MS-CFB specification.
 */
export interface OleDirectoryEntry {
  sid: number;
  name: string;
  entryType: number;
  color: number;
  sidLeft: number;
  sidRight: number;
  sidChild: number;
  clsid: string;
  stateBits: number;
  createTime: bigint;
  modifyTime: bigint;
  isectStart: number;
  size: number;
  isMinifat: boolean;
  kids: OleDirectoryEntry[];
  used: boolean;
}

/**
 * Read-only view of a single OLE stream. Returns the materialized bytes once;
 * the .py implementation eagerly assembles the sector chain into a BytesIO,
 * and we mirror that.
 */
export class OleStream {
  private _buf: Uint8Array;
  private _pos = 0;

  constructor(buf: Uint8Array) {
    this._buf = buf;
  }

  get size(): number {
    return this._buf.length;
  }

  tell(): number {
    return this._pos;
  }

  seek(offset: number, whence: 0 | 1 | 2 = 0): number {
    if (whence === 0) this._pos = offset;
    else if (whence === 1) this._pos += offset;
    else this._pos = this._buf.length + offset;
    if (this._pos < 0) this._pos = 0;
    return this._pos;
  }

  read(size?: number): Uint8Array {
    const remaining = this._buf.length - this._pos;
    const n = size === undefined ? remaining : Math.min(size, remaining);
    const out = this._buf.subarray(this._pos, this._pos + n);
    this._pos += n;
    return out;
  }

  /** Whole stream contents (does not move position). */
  getValue(): Uint8Array {
    return this._buf;
  }
}

type ParsedDirEntry = OleDirectoryEntry;

/**
 * Read-only OLE/CFB compound file accessor.
 *
 * Constructed from a raw `Uint8Array`. After construction, use `openstream`
 * to read named streams or `listdir` to enumerate them.
 */
export class OleFileIO {
  // Header values
  private dllVersion = 0;
  private byteOrder = 0;
  private sectorShift = 0;
  private miniSectorShift = 0;
  private firstDirSector = 0;
  private miniStreamCutoffSize = 0;
  private firstMiniFatSector = 0;
  private numMiniFatSectors = 0;
  private firstDifatSector = 0;
  private numDifatSectors = 0;

  private sectorSize = 0;
  private miniSectorSize = 0;
  private nbSect = 0;
  private filesize = 0;

  private fp: Uint8Array;
  private fat: number[] = [];
  private minifat: number[] | null = null;
  private ministream: Uint8Array | null = null;
  private writable = false;

  private direntries: ParsedDirEntry[] = [];
  public root!: ParsedDirEntry;

  constructor(input: Uint8Array | ArrayBuffer) {
    const buf = input instanceof ArrayBuffer ? new Uint8Array(input) : input;
    this.fp = buf;
    this.filesize = buf.length;
    this.parseHeader();
    this.loadFat();
    this.loadDirectory();
  }

  /**
   * Return the underlying file bytes. After `writeStream` calls, this reflects
   * the modified container.
   */
  getBuffer(): Uint8Array {
    return this.fp;
  }

  /**
   * Make sure `this.fp` is a private writable copy. Called before any
   * `writeStream` mutation.
   */
  private ensureWritable(): void {
    if (this.writable) return;
    const copy = new Uint8Array(this.fp.length);
    copy.set(this.fp, 0);
    this.fp = copy;
    this.writable = true;
  }

  // ---- Header parsing ----

  private parseHeader(): void {
    if (this.filesize < MINIMAL_OLEFILE_SIZE) {
      throw new NotOleFileError("File too small to be an OLE file");
    }
    const header = this.fp.subarray(0, 512);
    for (let i = 0; i < MAGIC.length; i++) {
      if (header[i] !== MAGIC[i]) {
        throw new NotOleFileError("Not an OLE2 structured storage file");
      }
    }

    this.dllVersion = readU16LE(header, 0x1a);
    this.byteOrder = readU16LE(header, 0x1c);
    this.sectorShift = readU16LE(header, 0x1e);
    this.miniSectorShift = readU16LE(header, 0x20);
    // 0x22..0x27: reserved (6 bytes)
    // 0x28: numDirSectors (only used for 4K sector files; we don't validate)
    // 0x2c: numFatSectors (validation only — DIFAT walk handles overflow)
    this.firstDirSector = readU32LE(header, 0x30);
    // 0x34: transactionSignatureNumber
    this.miniStreamCutoffSize = readU32LE(header, 0x38);
    this.firstMiniFatSector = readU32LE(header, 0x3c);
    this.numMiniFatSectors = readU32LE(header, 0x40);
    this.firstDifatSector = readU32LE(header, 0x44);
    this.numDifatSectors = readU32LE(header, 0x48);

    if (this.byteOrder !== 0xfffe) {
      throw new OleFileError("Unsupported byte order in OLE header");
    }
    if (this.dllVersion !== 3 && this.dllVersion !== 4) {
      throw new OleFileError("Unsupported DLL version in OLE header");
    }
    this.sectorSize = 1 << this.sectorShift;
    this.miniSectorSize = 1 << this.miniSectorShift;
    if (this.sectorSize !== 512 && this.sectorSize !== 4096) {
      throw new OleFileError(
        `Unsupported sector size: ${this.sectorSize}`,
      );
    }
    if (this.miniSectorSize !== 64) {
      throw new OleFileError(
        `Unsupported mini sector size: ${this.miniSectorSize}`,
      );
    }
    this.nbSect =
      Math.floor((this.filesize + this.sectorSize - 1) / this.sectorSize) - 1;
  }

  // ---- Sector access ----

  /** Read a full sector by index (from the file allocation space). */
  private getSect(sect: number): Uint8Array {
    const off = this.sectorSize * (sect + 1);
    if (off + this.sectorSize > this.fp.length) {
      // Some OLE files terminate without a fully padded final sector. Return
      // whatever bytes remain (the caller already trims to declared size).
      return this.fp.subarray(off, this.fp.length);
    }
    return this.fp.subarray(off, off + this.sectorSize);
  }

  // ---- FAT / DIFAT loading ----

  private sectorToU32Array(sect: Uint8Array): number[] {
    const n = sect.length >> 2;
    const out = new Array<number>(n);
    for (let i = 0; i < n; i++) {
      out[i] = readU32LE(sect, i * 4);
    }
    return out;
  }

  /**
   * Walk through one DIFAT-style array of FAT sector pointers and append the
   * referenced FAT sectors to `this.fat`.
   */
  private loadFatSect(values: number[]): number {
    let isect = ENDOFCHAIN;
    for (const raw of values) {
      isect = raw >>> 0;
      if (isect === ENDOFCHAIN || isect === FREESECT) break;
      const sectorBytes = this.getSect(isect);
      const next = this.sectorToU32Array(sectorBytes);
      for (const v of next) this.fat.push(v >>> 0);
    }
    return isect;
  }

  private loadFat(): void {
    // The first 109 FAT sector pointers live in the header itself,
    // starting at offset 0x4C (76).
    const headerSlice = this.fp.subarray(76, 512);
    const headerFatRefs = this.sectorToU32Array(headerSlice);
    this.loadFatSect(headerFatRefs);

    if (this.numDifatSectors !== 0) {
      const slotsPerSector = (this.sectorSize >> 2) - 1;
      let isect = this.firstDifatSector >>> 0;
      for (let i = 0; i < this.numDifatSectors; i++) {
        const sectorBytes = this.getSect(isect);
        const difat = this.sectorToU32Array(sectorBytes);
        this.loadFatSect(difat.slice(0, slotsPerSector));
        isect = difat[slotsPerSector] >>> 0;
        if (isect === ENDOFCHAIN || isect === FREESECT) break;
      }
    }

    if (this.fat.length > this.nbSect) {
      this.fat.length = this.nbSect;
    }
  }

  private loadMinifat(): void {
    if (this.minifat !== null) return;
    const streamSize = this.numMiniFatSectors * this.sectorSize;
    const data = this.openByChain(
      this.firstMiniFatSector,
      streamSize,
      /*forceFat=*/ true,
    );
    const arr = this.sectorToU32Array(data);
    const nbMinisectors = Math.floor(
      (this.root.size + this.miniSectorSize - 1) / this.miniSectorSize,
    );
    this.minifat = arr.slice(0, nbMinisectors).map((v) => v >>> 0);
  }

  private getMinistream(): Uint8Array {
    if (this.ministream !== null) return this.ministream;
    this.ministream = this.openByChain(
      this.root.isectStart,
      this.root.size,
      /*forceFat=*/ true,
    );
    return this.ministream;
  }

  /**
   * Read a full sector chain and return the joined bytes (truncated to size,
   * if known). This is the workhorse used by both stream loading and FAT
   * sub-stream extraction.
   */
  private openByChain(
    start: number,
    size: number,
    forceFat: boolean,
  ): Uint8Array {
    const useMinifat = !forceFat && size < this.miniStreamCutoffSize;
    let sectorSize: number;
    let fat: number[];
    let storage: Uint8Array;
    let offset: number;

    if (useMinifat) {
      this.loadMinifat();
      const ministream = this.getMinistream();
      sectorSize = this.miniSectorSize;
      fat = this.minifat!;
      storage = ministream;
      offset = 0;
    } else {
      sectorSize = this.sectorSize;
      fat = this.fat;
      storage = this.fp;
      offset = this.sectorSize; // FAT sectors are 1-indexed relative to file start
    }

    let unknownSize = false;
    if (size === UNKNOWN_SIZE) {
      size = fat.length * sectorSize;
      unknownSize = true;
    }

    const nbSectors = Math.floor((size + (sectorSize - 1)) / sectorSize);
    const parts: Uint8Array[] = [];
    let sect = start >>> 0;

    for (let i = 0; i < nbSectors; i++) {
      if (sect === ENDOFCHAIN) {
        if (unknownSize) break;
        throw new OleFileError("Incomplete OLE stream (early ENDOFCHAIN)");
      }
      if (sect >= fat.length) {
        throw new OleFileError(
          `Incorrect OLE FAT sector index ${sect.toString(16)}`,
        );
      }
      const sliceStart = offset + sectorSize * sect;
      const sliceEnd = Math.min(sliceStart + sectorSize, storage.length);
      parts.push(storage.subarray(sliceStart, sliceEnd));
      sect = fat[sect] >>> 0;
    }

    let total = 0;
    for (const p of parts) total += p.length;
    const joined = new Uint8Array(total);
    {
      let off = 0;
      for (const p of parts) {
        joined.set(p, off);
        off += p.length;
      }
    }
    if (joined.length >= size) return joined.subarray(0, size);
    return joined;
  }

  // ---- Directory parsing ----

  private parseDirEntry(buf: Uint8Array, sid: number): ParsedDirEntry {
    // 64s name_raw + H namelength + B type + B color + I left + I right + I child
    // + 16s clsid + I stateBits + Q createTime + Q modifyTime + I isectStart
    // + I sizeLow + I sizeHigh
    const nameRaw = buf.subarray(0, 64);
    const nameLength = readU16LE(buf, 64);
    const entryType = buf[66];
    const color = buf[67];
    const sidLeft = readU32LE(buf, 68);
    const sidRight = readU32LE(buf, 72);
    const sidChild = readU32LE(buf, 76);

    const clsidBytes = buf.subarray(80, 96);
    const stateBits = readU32LE(buf, 96);
    const createTime = bytesToBigUint64LE(buf, 100);
    const modifyTime = bytesToBigUint64LE(buf, 108);
    const isectStart = readU32LE(buf, 116);
    const sizeLow = readU32LE(buf, 120);
    const sizeHigh = readU32LE(buf, 124);

    const safeNameLen = Math.max(0, Math.min(nameLength, 64) - 2);
    const name = utf16leDecode(nameRaw.subarray(0, safeNameLen));

    let size: number;
    if (this.sectorSize === 512) {
      size = sizeLow;
    } else {
      // Up to 2^53 — JS number is fine here, real-world streams aren't anywhere near that.
      size = sizeLow + sizeHigh * 0x100000000;
    }

    const isMinifat =
      entryType === STGTY_STREAM &&
      size > 0 &&
      size < this.miniStreamCutoffSize;

    return {
      sid,
      name,
      entryType,
      color,
      sidLeft,
      sidRight,
      sidChild,
      clsid: formatClsid(clsidBytes),
      stateBits,
      createTime,
      modifyTime,
      isectStart,
      size,
      isMinifat,
      kids: [],
      used: false,
    };
  }

  private loadDirectory(): void {
    const dirData = this.openByChain(
      this.firstDirSector,
      UNKNOWN_SIZE,
      /*forceFat=*/ true,
    );
    const maxEntries = Math.floor(dirData.length / 128);
    this.direntries = new Array(maxEntries);

    // Lazily fault entries in as the storage tree is walked.
    const loadEntry = (sid: number): ParsedDirEntry => {
      if (sid < 0 || sid >= maxEntries) {
        throw new OleFileError(
          `OLE directory index out of range: ${sid}`,
        );
      }
      const cached = this.direntries[sid];
      if (cached) return cached;
      const entry = this.parseDirEntry(
        dirData.subarray(sid * 128, (sid + 1) * 128),
        sid,
      );
      this.direntries[sid] = entry;
      return entry;
    };

    const root = loadEntry(0);
    if (root.entryType !== STGTY_ROOT) {
      throw new OleFileError("First directory entry is not the root entry");
    }
    this.root = root;

    // Walk the red-black tree in-order to collect children. Per the spec, the
    // tree contains storage and stream entries; visit left, self, right and
    // recurse into storages.
    const appendKids = (parent: ParsedDirEntry, childSid: number): void => {
      if (childSid === NOSTREAM) return;
      const child = loadEntry(childSid);
      if (child.used) {
        throw new OleFileError("OLE entry referenced more than once");
      }
      child.used = true;
      appendKids(parent, child.sidLeft);
      parent.kids.push(child);
      appendKids(parent, child.sidRight);
      if (child.sidChild !== NOSTREAM) {
        appendKids(child, child.sidChild);
        child.kids.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      }
    };

    if (root.sidChild !== NOSTREAM) {
      appendKids(root, root.sidChild);
      root.kids.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    }
  }

  // ---- Public API ----

  /**
   * Find a directory entry by case-insensitive path. Path may be a string with
   * '/' separators or an array of names.
   */
  private find(filename: string | string[]): ParsedDirEntry {
    const parts =
      typeof filename === "string" ? filename.split("/") : filename;
    let node: ParsedDirEntry = this.root;
    for (const name of parts) {
      const lower = name.toLowerCase();
      const next = node.kids.find((k) => k.name.toLowerCase() === lower);
      if (!next) {
        throw new OleFileError(`Stream not found: ${parts.join("/")}`);
      }
      node = next;
    }
    return node;
  }

  /** Return true if the named stream/storage exists in the file. */
  exists(filename: string | string[]): boolean {
    try {
      this.find(filename);
      return true;
    } catch {
      return false;
    }
  }

  /** Get the size of a named stream. */
  getSize(filename: string | string[]): number {
    return this.find(filename).size;
  }

  /**
   * Open a named stream and return a read-only `OleStream` that exposes
   * `seek/tell/read`. Mirrors `olefile.openstream`.
   */
  openstream(filename: string | string[]): OleStream {
    const entry = this.find(filename);
    if (entry.entryType !== STGTY_STREAM) {
      throw new OleFileError(`Not a stream: ${filename}`);
    }
    if (entry.size === 0) return new OleStream(new Uint8Array(0));
    const data =
      entry.isMinifat && entry.size < this.miniStreamCutoffSize
        ? this.openByChain(entry.isectStart, entry.size, false)
        : this.openByChain(entry.isectStart, entry.size, true);
    return new OleStream(data);
  }

  /**
   * Overwrite the contents of an existing stream with `data`. The new data
   * MUST be exactly the same size as the original — this keeps the FAT chain
   * untouched, which is all we need for the legacy decrypt-in-place flow.
   *
   * Handles both FAT and MiniFAT-allocated streams.
   */
  writeStream(filename: string | string[], data: Uint8Array): void {
    const entry = this.find(filename);
    if (entry.entryType !== STGTY_STREAM) {
      throw new OleFileError(`Not a stream: ${filename}`);
    }
    if (data.length !== entry.size) {
      throw new OleFileError(
        `writeStream requires same-sized data (expected ${entry.size}, got ${data.length})`,
      );
    }
    this.ensureWritable();

    if (entry.isMinifat && entry.size < this.miniStreamCutoffSize) {
      this.writeStreamMiniFat(entry, data);
    } else {
      this.writeStreamFat(entry, data);
    }
  }

  /** Walk the FAT chain for a stream and overwrite each sector. */
  private writeStreamFat(entry: OleDirectoryEntry, data: Uint8Array): void {
    let sect = entry.isectStart >>> 0;
    let off = 0;
    const sectorSize = this.sectorSize;
    while (off < data.length) {
      if (sect === ENDOFCHAIN || sect >= this.fat.length) {
        throw new OleFileError("FAT chain ended unexpectedly during write");
      }
      const fileOffset = this.sectorSize + sect * sectorSize;
      const remaining = data.length - off;
      const chunk = data.subarray(off, off + Math.min(sectorSize, remaining));
      this.fp.set(chunk, fileOffset);
      off += chunk.length;
      sect = this.fat[sect] >>> 0;
    }
  }

  /**
   * Mini-streams live inside the root entry's stream (which itself follows the
   * regular FAT). Walk the MiniFAT chain to compute mini-sector positions, map
   * those into FAT positions, and write.
   */
  private writeStreamMiniFat(
    entry: OleDirectoryEntry,
    data: Uint8Array,
  ): void {
    this.loadMinifat();
    const minifat = this.minifat!;
    const ministreamSize = this.root.size;

    // The ministream itself is allocated on the FAT — collect its sectors.
    const ministreamFatSectors: number[] = [];
    let sect = this.root.isectStart >>> 0;
    const fatSectorCount = Math.ceil(ministreamSize / this.sectorSize);
    for (let i = 0; i < fatSectorCount; i++) {
      if (sect === ENDOFCHAIN || sect >= this.fat.length) break;
      ministreamFatSectors.push(sect);
      sect = this.fat[sect] >>> 0;
    }

    // For each mini-sector, find its position inside the ministream, then map
    // that to (fatSectorIndex, offsetInsideFatSector).
    let miniSect = entry.isectStart >>> 0;
    let off = 0;
    while (off < data.length) {
      if (miniSect === ENDOFCHAIN || miniSect >= minifat.length) {
        throw new OleFileError("MiniFAT chain ended unexpectedly during write");
      }
      const ministreamOffset = miniSect * this.miniSectorSize;
      const fatSectorIdx = Math.floor(ministreamOffset / this.sectorSize);
      const offsetInFatSector = ministreamOffset % this.sectorSize;
      const fileOffset =
        this.sectorSize +
        ministreamFatSectors[fatSectorIdx] * this.sectorSize +
        offsetInFatSector;
      const remaining = data.length - off;
      const chunk = data.subarray(
        off,
        off + Math.min(this.miniSectorSize, remaining),
      );
      this.fp.set(chunk, fileOffset);
      off += chunk.length;
      miniSect = minifat[miniSect] >>> 0;
    }

    // Invalidate the cached ministream so next reads pick up fresh data.
    this.ministream = null;
  }

  /** List all stream paths in the file (depth-first walk). */
  listdir(streams = true, storages = false): string[][] {
    const out: string[][] = [];
    const walk = (node: ParsedDirEntry, prefix: string[]) => {
      for (const kid of node.kids) {
        const path = [...prefix, kid.name];
        if (kid.entryType === STGTY_STORAGE) {
          if (storages) out.push(path);
          walk(kid, path);
        } else if (kid.entryType === STGTY_STREAM) {
          if (streams) out.push(path);
        }
      }
    };
    walk(this.root, []);
    return out;
  }
}

function bytesToBigUint64LE(b: Uint8Array, o = 0): bigint {
  const lo = BigInt(readU32LE(b, o));
  const hi = BigInt(readU32LE(b, o + 4));
  return (hi << 32n) | lo;
}

function formatClsid(b: Uint8Array): string {
  let allZero = true;
  for (const byte of b) if (byte !== 0) { allZero = false; break; }
  if (allZero) return "";
  const hex2 = (n: number) => n.toString(16).padStart(2, "0").toUpperCase();
  const hex4 = (n: number) => n.toString(16).padStart(4, "0").toUpperCase();
  const hex8 = (n: number) => n.toString(16).padStart(8, "0").toUpperCase();
  const a = hex8(readU32LE(b, 0));
  const c = hex4(readU16LE(b, 4));
  const d = hex4(readU16LE(b, 6));
  let tail = "";
  for (let i = 8; i < 16; i++) tail += hex2(b[i]);
  return `${a}-${c}-${d}-${tail.slice(0, 4)}-${tail.slice(4)}`;
}
