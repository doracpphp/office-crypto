/**
 * Minimal CFB / OLE2 writer for producing encrypted OOXML containers.
 *
 * Direct port of `msoffcrypto/method/container/ecma376_encrypted.py` (which
 * itself was lifted from herumi/msoffice). Generates an OLE compound file
 * with the fixed set of streams expected by ECMA-376 strong encryption:
 * EncryptedPackage, EncryptionInfo, plus the DataSpaces metadata streams.
 */

import { MAGIC } from "../../olefile.js";
import { ByteWriter, packU32LE, utf16leEncode } from "../../utils.js";

const SECTOR_TYPES = {
  MAXREGSECT: 0xfffffffa,
  DIFSECT: 0xfffffffc,
  FATSECT: 0xfffffffd,
  ENDOFCHAIN: 0xfffffffe,
  FREESECT: 0xffffffff,
  NOSTREAM: 0xffffffff,
} as const;

const ENTRY_TYPE = {
  EMPTY: 0,
  STORAGE: 1,
  STREAM: 2,
  ROOT_STORAGE: 5,
} as const;

const COLOR = { RED: 0, BLACK: 1 } as const;

const FIRSTNUMDIFAT = 109;
const HEADER_BUFFER_SIZE = 512;

// Indices into the directories array; must match the order used when creating them.
const DSP = {
  iRoot: 0,
  iEncryptionPackage: 1,
  iDataSpaces: 2,
  iVersion: 3,
  iDataSpaceMap: 4,
  iDataSpaceInfo: 5,
  iStrongEncryptionDataSpace: 6,
  iTransformInfo: 7,
  iStrongEncryptionTransform: 8,
  iPrimary: 9,
  iEncryptionInfo: 10,
} as const;

// Pre-computed UTF-16LE blobs lifted from herumi/msoffice.
const DEFAULT_VERSION = new Uint8Array([
  0x3c, 0x00, 0x00, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6f,
  0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x43, 0x00,
  0x6f, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x65,
  0x00, 0x72, 0x00, 0x2e, 0x00, 0x44, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00,
  0x53, 0x00, 0x70, 0x00, 0x61, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
]);

const DEFAULT_PRIMARY = new Uint8Array([
  0x58, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x7b,
  0x00, 0x46, 0x00, 0x46, 0x00, 0x39, 0x00, 0x41, 0x00, 0x33, 0x00, 0x46, 0x00,
  0x30, 0x00, 0x33, 0x00, 0x2d, 0x00, 0x35, 0x00, 0x36, 0x00, 0x45, 0x00, 0x46,
  0x00, 0x2d, 0x00, 0x34, 0x00, 0x36, 0x00, 0x31, 0x00, 0x33, 0x00, 0x2d, 0x00,
  0x42, 0x00, 0x44, 0x00, 0x44, 0x00, 0x35, 0x00, 0x2d, 0x00, 0x35, 0x00, 0x41,
  0x00, 0x34, 0x00, 0x31, 0x00, 0x43, 0x00, 0x31, 0x00, 0x44, 0x00, 0x30, 0x00,
  0x37, 0x00, 0x32, 0x00, 0x34, 0x00, 0x36, 0x00, 0x7d, 0x00, 0x4e, 0x00, 0x00,
  0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x73, 0x00,
  0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x43, 0x00, 0x6f, 0x00, 0x6e,
  0x00, 0x74, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x72, 0x00,
  0x2e, 0x00, 0x45, 0x00, 0x6e, 0x00, 0x63, 0x00, 0x72, 0x00, 0x79, 0x00, 0x70,
  0x00, 0x74, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x54, 0x00, 0x72, 0x00,
  0x61, 0x00, 0x6e, 0x00, 0x73, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6d,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x04, 0x00, 0x00, 0x00,
]);

const DEFAULT_DATASPACE_MAP = new Uint8Array([
  0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x45, 0x00,
  0x6e, 0x00, 0x63, 0x00, 0x72, 0x00, 0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x65,
  0x00, 0x64, 0x00, 0x50, 0x00, 0x61, 0x00, 0x63, 0x00, 0x6b, 0x00, 0x61, 0x00,
  0x67, 0x00, 0x65, 0x00, 0x32, 0x00, 0x00, 0x00, 0x53, 0x00, 0x74, 0x00, 0x72,
  0x00, 0x6f, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x45, 0x00, 0x6e, 0x00, 0x63, 0x00,
  0x72, 0x00, 0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e,
  0x00, 0x44, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x53, 0x00, 0x70, 0x00,
  0x61, 0x00, 0x63, 0x00, 0x65, 0x00, 0x00, 0x00,
]);

const DEFAULT_STRONG_ENCRYPTION_DATASPACE = new Uint8Array([
  0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x53,
  0x00, 0x74, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x45, 0x00,
  0x6e, 0x00, 0x63, 0x00, 0x72, 0x00, 0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x69,
  0x00, 0x6f, 0x00, 0x6e, 0x00, 0x54, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6e, 0x00,
  0x73, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x00, 0x00,
]);

interface DirectoryEntry {
  name: string;
  type: number;
  color: number;
  leftId: number;
  rightId: number;
  childId: number;
  startingSectorLocation: number;
  content: Uint8Array;
}

function dirEntry(
  name: string,
  type: number,
  color: number,
  opts: Partial<{
    leftId: number;
    rightId: number;
    childId: number;
    content: Uint8Array;
  }> = {},
): DirectoryEntry {
  return {
    name,
    type,
    color,
    leftId: opts.leftId ?? SECTOR_TYPES.NOSTREAM,
    rightId: opts.rightId ?? SECTOR_TYPES.NOSTREAM,
    childId: opts.childId ?? SECTOR_TYPES.NOSTREAM,
    startingSectorLocation: 0,
    content: opts.content ?? new Uint8Array(0),
  };
}

function getBlockNum(x: number, block: number): number {
  return Math.floor((x + block - 1) / block);
}

interface Layout {
  sectorSize: number;
  miniFatNum: number;
  miniFatDataSectorNum: number;
  miniFatSectors: number[];
  numMiniFatSectors: number;
  difatSectorNum: number;
  fatSectorNum: number;
  difatPos: number;
  directoryEntrySectorNum: number;
  encryptionPackageSectorNum: number;
}

class WriteBuf {
  private buf: Uint8Array;
  private pos = 0;

  constructor(size: number) {
    this.buf = new Uint8Array(size);
  }

  seek(p: number): void {
    this.pos = p;
  }
  tell(): number {
    return this.pos;
  }
  write(data: Uint8Array): void {
    this.buf.set(data, this.pos);
    this.pos += data.length;
  }

  bytes(): Uint8Array {
    return this.buf;
  }
}

export class ECMA376Encrypted {
  private dirs: DirectoryEntry[];
  private encryptedPackage: Uint8Array;
  private encryptionInfo: Uint8Array;

  // Header values
  private minorVersion = 0x003e;
  private majorVersion = 3;
  private sectorShift = 9;
  private sectorSize = 1 << 9;
  private firstDirectorySectorLocation: number = SECTOR_TYPES.ENDOFCHAIN;
  private firstMiniFatSectorLocation: number = SECTOR_TYPES.ENDOFCHAIN;
  private numMiniFatSectors = 0;
  private firstDifatSectorLocation: number = SECTOR_TYPES.ENDOFCHAIN;
  private numDifatSectors = 0;
  private numFatSectors = 0;
  private difat: number[] = [];

  constructor(encryptedPackage: Uint8Array, encryptionInfo: Uint8Array) {
    this.encryptedPackage = encryptedPackage;
    this.encryptionInfo = encryptionInfo;
    this.dirs = this.buildDirectoryEntries();
    this.dirs[DSP.iEncryptionPackage].content = encryptedPackage;
    this.dirs[DSP.iEncryptionInfo].content = encryptionInfo;
  }

  /** Serialise the OLE compound file. */
  build(): Uint8Array {
    const layout: Layout = {
      sectorSize: this.sectorSize,
      miniFatNum: 0,
      miniFatDataSectorNum: 0,
      miniFatSectors: [],
      numMiniFatSectors: 1,
      difatSectorNum: 0,
      fatSectorNum: 0,
      difatPos: 0,
      directoryEntrySectorNum: 0,
      encryptionPackageSectorNum: 0,
    };

    this.computeStreamLocations(layout);
    this.detectSectorNum(layout);

    const fatPos = layout.difatPos + layout.difatSectorNum;
    const miniFatPos = fatPos + layout.fatSectorNum;
    const directoryEntryPos = miniFatPos + layout.numMiniFatSectors;
    const miniFatDataPos = directoryEntryPos + layout.directoryEntrySectorNum;
    const encryptionPackagePos = miniFatDataPos + layout.miniFatDataSectorNum;

    const totalSectors =
      layout.difatSectorNum +
      layout.fatSectorNum +
      layout.numMiniFatSectors +
      layout.directoryEntrySectorNum +
      layout.miniFatDataSectorNum +
      layout.encryptionPackageSectorNum;
    const totalSize = HEADER_BUFFER_SIZE + totalSectors * layout.sectorSize;

    this.firstDirectorySectorLocation = directoryEntryPos;
    this.firstMiniFatSectorLocation = miniFatPos;
    this.numMiniFatSectors = layout.numMiniFatSectors;

    this.dirs[DSP.iRoot].startingSectorLocation = miniFatDataPos;
    this.dirs[DSP.iRoot].content = new Uint8Array(64 * layout.miniFatNum);
    this.dirs[DSP.iEncryptionPackage].startingSectorLocation =
      encryptionPackagePos;

    for (let i = 0; i < Math.min(layout.fatSectorNum, FIRSTNUMDIFAT); i++) {
      this.difat.push(fatPos + i);
    }
    this.numFatSectors = layout.fatSectorNum;
    this.numDifatSectors = layout.difatSectorNum;
    if (layout.difatSectorNum > 0) {
      this.firstDifatSectorLocation = layout.difatPos;
    }

    const obuf = new WriteBuf(totalSize);

    this.writeHeader(obuf);

    this.writeDifat(obuf, layout);
    this.writeFatStart(obuf, layout, fatPos);
    this.writeMiniFat(obuf, layout, miniFatPos);
    this.writeDirectoryEntries(obuf, layout, directoryEntryPos);
    this.writeContent(obuf, layout, miniFatDataPos);

    return obuf.bytes();
  }

  // ---- Streams layout ----

  private computeStreamLocations(layout: Layout): void {
    // All streams that go into the MiniFAT (everything except EncryptedPackage).
    const streams = this.dirs.filter(
      (d) => d.type === ENTRY_TYPE.STREAM && d.name !== "EncryptedPackage",
    );

    let pos = 0;
    const miniFatSectors: number[] = [];
    for (const s of streams) {
      const n = getBlockNum(s.content.length, 64);
      miniFatSectors.push(n);
      s.startingSectorLocation = pos;
      pos += n;
    }
    layout.miniFatNum = pos;
    layout.miniFatSectors = miniFatSectors;
    layout.miniFatDataSectorNum = getBlockNum(
      layout.miniFatNum,
      layout.sectorSize / 64,
    );
    if (getBlockNum(layout.miniFatDataSectorNum, 128) > 1) {
      throw new Error("Unexpected layout size; too large");
    }
    layout.directoryEntrySectorNum = getBlockNum(this.dirs.length, 4);
    layout.encryptionPackageSectorNum = getBlockNum(
      this.dirs[DSP.iEncryptionPackage].content.length,
      layout.sectorSize,
    );
  }

  private detectSectorNum(layout: Layout): void {
    const numInFat = layout.sectorSize / 4;
    let difatSectorNum = 0;
    let fatSectorNum = 0;
    const contentSectorNum = (l: Layout) =>
      l.numMiniFatSectors +
      l.directoryEntrySectorNum +
      l.miniFatDataSectorNum +
      l.encryptionPackageSectorNum;

    for (let i = 0; i < 10; i++) {
      const a = getBlockNum(
        difatSectorNum + fatSectorNum + contentSectorNum(layout),
        numInFat,
      );
      const b =
        a <= FIRSTNUMDIFAT ? 0 : getBlockNum(a - FIRSTNUMDIFAT, numInFat - 1);
      if (b === difatSectorNum && a === fatSectorNum) {
        layout.fatSectorNum = fatSectorNum;
        layout.difatSectorNum = difatSectorNum;
        return;
      }
      difatSectorNum = b;
      fatSectorNum = a;
    }
    throw new RangeError("Unable to detect sector number");
  }

  // ---- Writing helpers ----

  private writeHeader(obuf: WriteBuf): void {
    const reserved = 0;
    const byteOrder = 0xfffe;
    const miniSectorShift = 6;
    const miniStreamCutoffSize = 0x1000;

    const w = new ByteWriter()
      .bytes(MAGIC)
      .zeros(16) // CLSID
      .u16(this.minorVersion)
      .u16(this.majorVersion)
      .u16(byteOrder)
      .u16(this.sectorShift)
      .u16(miniSectorShift)
      .u16(reserved)
      .u16(reserved)
      .u16(reserved) // 6 bytes total reserved
      .u32(0) // numDirectorySectors
      .u32(this.numFatSectors)
      .u32(this.firstDirectorySectorLocation)
      .u32(0) // transactionSignatureNumber
      .u32(miniStreamCutoffSize)
      .u32(this.firstMiniFatSectorLocation)
      .u32(this.numMiniFatSectors)
      .u32(this.firstDifatSectorLocation)
      .u32(this.numDifatSectors);

    const difatLen = this.difat.length;
    for (let i = 0; i < Math.min(difatLen, FIRSTNUMDIFAT); i++) {
      w.u32(this.difat[i]);
    }
    for (let i = difatLen; i < FIRSTNUMDIFAT; i++) {
      w.u32(SECTOR_TYPES.NOSTREAM);
    }

    obuf.seek(0);
    obuf.write(w.build());
  }

  private writeDifat(obuf: WriteBuf, layout: Layout): void {
    if (layout.difatSectorNum < 1) return;
    let v = FIRSTNUMDIFAT + layout.difatSectorNum;
    for (let i = 0; i < layout.difatSectorNum; i++) {
      obuf.seek(HEADER_BUFFER_SIZE + (layout.difatPos + i) * layout.sectorSize);
      const slots = layout.sectorSize / 4 - 1;
      for (let j = 0; j < slots; j++) {
        obuf.write(packU32LE(v));
        v += 1;
        if (v > layout.difatSectorNum + layout.fatSectorNum) {
          for (let k = j + 1; k < slots; k++) {
            obuf.write(packU32LE(SECTOR_TYPES.FREESECT));
          }
          obuf.write(packU32LE(SECTOR_TYPES.ENDOFCHAIN));
          return;
        }
      }
      obuf.write(packU32LE(layout.difatPos + i + 1));
    }
  }

  private writeFatStart(
    obuf: WriteBuf,
    layout: Layout,
    fatPos: number,
  ): void {
    const v: number[] = [];
    for (let i = 0; i < layout.difatSectorNum; i++) v.push(SECTOR_TYPES.DIFSECT);
    for (let i = 0; i < layout.fatSectorNum; i++) v.push(SECTOR_TYPES.FATSECT);
    v.push(layout.numMiniFatSectors);
    v.push(layout.directoryEntrySectorNum);
    v.push(layout.miniFatDataSectorNum);
    v.push(layout.encryptionPackageSectorNum);

    obuf.seek(HEADER_BUFFER_SIZE + fatPos * layout.sectorSize);
    this.writeFat(obuf, v, layout.fatSectorNum * layout.sectorSize);
  }

  private writeMiniFat(obuf: WriteBuf, layout: Layout, miniFatPos: number): void {
    obuf.seek(HEADER_BUFFER_SIZE + miniFatPos * layout.sectorSize);
    this.writeFat(
      obuf,
      layout.miniFatSectors,
      layout.numMiniFatSectors * layout.sectorSize,
    );
  }

  private writeFat(
    obuf: WriteBuf,
    entries: number[],
    blockSize: number,
  ): void {
    let v = 0;
    const startPos = obuf.tell();
    const maxN = blockSize / 4;
    for (const e of entries) {
      if (e <= SECTOR_TYPES.MAXREGSECT) {
        for (let j = 1; j < e; j++) {
          v += 1;
          if (v > maxN) throw new Error("Attempting to write beyond block size");
          obuf.write(packU32LE(v));
        }
        if (v === maxN) throw new Error("Attempting to write beyond block size");
        obuf.write(packU32LE(SECTOR_TYPES.ENDOFCHAIN));
      } else {
        if (v === maxN) throw new Error("Attempting to write beyond block size");
        obuf.write(packU32LE(e));
      }
      v += 1;
    }
    for (let i = v; i < maxN; i++) obuf.write(packU32LE(SECTOR_TYPES.FREESECT));
    if (obuf.tell() - startPos !== blockSize) {
      throw new Error("writeFat did not completely fill the block space");
    }
  }

  private writeDirectoryEntries(
    obuf: WriteBuf,
    layout: Layout,
    directoryEntryPos: number,
  ): void {
    obuf.seek(HEADER_BUFFER_SIZE + directoryEntryPos * layout.sectorSize);
    for (const d of this.dirs) this.writeEntryHeader(obuf, d);
  }

  private writeEntryHeader(obuf: WriteBuf, d: DirectoryEntry): void {
    const name16 = utf16leEncode(d.name);
    const directoryNameSize = name16.length + 2;
    if (directoryNameSize > 64) throw new Error("Name too long");

    obuf.write(
      new ByteWriter()
        .bytes(name16)
        .zeros(2) // null terminator
        .zeros(64 - directoryNameSize) // pad to 64
        .u16(directoryNameSize > 2 ? directoryNameSize : 0)
        .u8(d.type)
        .u8(d.color)
        .u32(d.leftId)
        .u32(d.rightId)
        .u32(d.childId)
        .zeros(16) // CLSID
        .u32(0) // stateBits
        .zeros(8) // creationTime
        .zeros(8) // modifiedTime
        .u32(d.startingSectorLocation)
        .u64(BigInt(d.content.length))
        .build(),
    );
  }

  private writeContent(obuf: WriteBuf, layout: Layout, miniFatDataPos: number): void {
    for (const d of this.dirs) {
      const size = d.content.length;
      if (!size) continue;
      if (size <= 4096) {
        obuf.seek(
          HEADER_BUFFER_SIZE +
            miniFatDataPos * layout.sectorSize +
            d.startingSectorLocation * 64,
        );
      } else {
        obuf.seek(
          HEADER_BUFFER_SIZE + d.startingSectorLocation * layout.sectorSize,
        );
      }
      obuf.write(d.content);
    }
  }

  // ---- Directory build ----

  private buildDirectoryEntries(): DirectoryEntry[] {
    return [
      dirEntry("Root Entry", ENTRY_TYPE.ROOT_STORAGE, COLOR.RED, {
        childId: DSP.iEncryptionInfo,
      }),
      dirEntry("EncryptedPackage", ENTRY_TYPE.STREAM, COLOR.RED),
      dirEntry("DataSpaces", ENTRY_TYPE.STORAGE, COLOR.RED, {
        childId: DSP.iDataSpaceMap,
      }),
      dirEntry("Version", ENTRY_TYPE.STREAM, COLOR.BLACK, {
        content: DEFAULT_VERSION,
      }),
      dirEntry("DataSpaceMap", ENTRY_TYPE.STREAM, COLOR.BLACK, {
        leftId: DSP.iVersion,
        rightId: DSP.iDataSpaceInfo,
        content: DEFAULT_DATASPACE_MAP,
      }),
      dirEntry("DataSpaceInfo", ENTRY_TYPE.STORAGE, COLOR.BLACK, {
        rightId: DSP.iTransformInfo,
        childId: DSP.iStrongEncryptionDataSpace,
      }),
      dirEntry(
        "StrongEncryptionDataSpace",
        ENTRY_TYPE.STREAM,
        COLOR.BLACK,
        { content: DEFAULT_STRONG_ENCRYPTION_DATASPACE },
      ),
      dirEntry("TransformInfo", ENTRY_TYPE.STORAGE, COLOR.RED, {
        childId: DSP.iStrongEncryptionTransform,
      }),
      dirEntry(
        "StrongEncryptionTransform",
        ENTRY_TYPE.STORAGE,
        COLOR.BLACK,
        { childId: DSP.iPrimary },
      ),
      dirEntry("Primary", ENTRY_TYPE.STREAM, COLOR.BLACK, {
        content: DEFAULT_PRIMARY,
      }),
      dirEntry("EncryptionInfo", ENTRY_TYPE.STREAM, COLOR.BLACK, {
        leftId: DSP.iDataSpaces,
        rightId: DSP.iEncryptionPackage,
      }),
    ];
  }
}

