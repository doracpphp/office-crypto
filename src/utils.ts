/**
 * Utility helpers: byte/struct manipulation, UTF-16 encoding, BytesIO equivalent.
 */

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function utf16leEncode(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out[i * 2] = c & 0xff;
    out[i * 2 + 1] = (c >>> 8) & 0xff;
  }
  return out;
}

export function utf16leDecode(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i + 1 < b.length; i += 2) {
    const c = b[i] | (b[i + 1] << 8);
    s += String.fromCharCode(c);
  }
  return s;
}

export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function utf8Decode(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function base64Encode(b: Uint8Array): string {
  // Use globalThis.btoa if available, else manual encode.
  let s = "";
  for (let i = 0; i < b.length; i += 3) {
    const a = b[i];
    const c = i + 1 < b.length ? b[i + 1] : 0;
    const d = i + 2 < b.length ? b[i + 2] : 0;
    const n = (a << 16) | (c << 8) | d;
    s +=
      B64_CHARS[(n >> 18) & 63] +
      B64_CHARS[(n >> 12) & 63] +
      (i + 1 < b.length ? B64_CHARS[(n >> 6) & 63] : "=") +
      (i + 2 < b.length ? B64_CHARS[n & 63] : "=");
  }
  return s;
}

export function base64Decode(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, "");
  const raw = clean.replace(/=+$/, "");
  // Output length: every 4 input chars become 3 bytes, plus partial groups
  // (2 chars → 1 byte, 3 chars → 2 bytes).
  const fullGroups = Math.floor(raw.length / 4);
  const remainder = raw.length % 4;
  const outLen =
    fullGroups * 3 + (remainder === 2 ? 1 : remainder === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);
  let oi = 0;
  for (let i = 0; i < raw.length; i += 4) {
    const a = B64_CHARS.indexOf(raw[i]);
    const b = B64_CHARS.indexOf(raw[i + 1]);
    const c = i + 2 < raw.length ? B64_CHARS.indexOf(raw[i + 2]) : 0;
    const d = i + 3 < raw.length ? B64_CHARS.indexOf(raw[i + 3]) : 0;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    out[oi++] = (n >> 16) & 0xff;
    if (i + 2 < raw.length) out[oi++] = (n >> 8) & 0xff;
    if (i + 3 < raw.length) out[oi++] = n & 0xff;
  }
  return out;
}

/**
 * Pack 32-bit unsigned little-endian.
 */
export function packU32LE(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

export function packU16LE(n: number): Uint8Array {
  const b = new Uint8Array(2);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  return b;
}

export function packU64LE(n: bigint | number): Uint8Array {
  const v = typeof n === "bigint" ? n : BigInt(n);
  const b = new Uint8Array(8);
  const lo = Number(v & 0xffffffffn);
  const hi = Number((v >> 32n) & 0xffffffffn);
  b[0] = lo & 0xff;
  b[1] = (lo >>> 8) & 0xff;
  b[2] = (lo >>> 16) & 0xff;
  b[3] = (lo >>> 24) & 0xff;
  b[4] = hi & 0xff;
  b[5] = (hi >>> 8) & 0xff;
  b[6] = (hi >>> 16) & 0xff;
  b[7] = (hi >>> 24) & 0xff;
  return b;
}

/**
 * Read helpers (little-endian).
 */
export function readU16LE(b: Uint8Array, o = 0): number {
  return b[o] | (b[o + 1] << 8);
}
export function readU32LE(b: Uint8Array, o = 0): number {
  return (
    (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0
  );
}
export function readU64LE(b: Uint8Array, o = 0): bigint {
  const lo = BigInt(readU32LE(b, o));
  const hi = BigInt(readU32LE(b, o + 4));
  return (hi << 32n) | lo;
}
export function readI32LE(b: Uint8Array, o = 0): number {
  return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
}

/**
 * Minimal stream-reader interface — both `BytesIO` and the read-only
 * `OleStream` satisfy this. Used by the `read{U16,U32,U64}` stream helpers
 * below so callers don't have to write `readU32LE(s.read(4), 0)` everywhere.
 */
export interface Readable {
  read(size?: number): Uint8Array;
}

export function readU16(s: Readable): number {
  return readU16LE(s.read(2), 0);
}
export function readU32(s: Readable): number {
  return readU32LE(s.read(4), 0);
}
export function readU64(s: Readable): bigint {
  return readU64LE(s.read(8), 0);
}

/**
 * Append-style bytes builder. Replaces the `parts.push(packU32LE(...))` +
 * concat dance used by the various `pack*` helpers in the format/ folder.
 */
export class ByteWriter {
  private chunks: Uint8Array[] = [];
  private len = 0;

  bytes(b: Uint8Array): this {
    this.chunks.push(b);
    this.len += b.length;
    return this;
  }
  u8(v: number): this {
    this.chunks.push(new Uint8Array([v & 0xff]));
    this.len += 1;
    return this;
  }
  u16(v: number): this {
    return this.bytes(packU16LE(v));
  }
  u32(v: number): this {
    return this.bytes(packU32LE(v >>> 0));
  }
  u64(v: bigint | number): this {
    return this.bytes(packU64LE(v));
  }
  zeros(n: number): this {
    return this.bytes(new Uint8Array(n));
  }

  get length(): number {
    return this.len;
  }

  build(): Uint8Array {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

/**
 * Bit-field helpers for the legacy formats (FibBase, RecordHeader, etc.).
 */
export function getBit(bits: number, i: number): number {
  return (bits >>> i) & 1;
}
export function getBitSlice(bits: number, i: number, w: number): number {
  return (bits >>> i) & ((1 << w) - 1);
}
export function setBit(bits: number, i: number, v: number): number {
  return v ? bits | (1 << i) : bits & ~(1 << i);
}
export function setBitSlice(
  bits: number,
  i: number,
  w: number,
  v: number,
): number {
  const mask = ((1 << w) - 1) << i;
  return (bits & ~mask) | ((v & ((1 << w) - 1)) << i);
}

/**
 * Stream-like wrapper around a Uint8Array providing seek/tell/read.
 * Mirrors `io.BytesIO` semantics enough for the rest of the library.
 */
export class BytesIO {
  private _buf: Uint8Array;
  private _pos = 0;

  constructor(initial?: Uint8Array | ArrayBuffer | number) {
    if (initial === undefined) {
      this._buf = new Uint8Array(0);
    } else if (typeof initial === "number") {
      this._buf = new Uint8Array(initial);
    } else if (initial instanceof ArrayBuffer) {
      this._buf = new Uint8Array(initial);
    } else {
      this._buf = initial;
    }
  }

  get length(): number {
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

  /** Returns the entire underlying buffer (does not move position). */
  getValue(): Uint8Array {
    return this._buf;
  }

  /**
   * Writes data at the current position, growing the buffer if needed.
   */
  write(data: Uint8Array): number {
    const needed = this._pos + data.length;
    if (needed > this._buf.length) {
      const next = new Uint8Array(needed);
      next.set(this._buf, 0);
      this._buf = next;
    }
    this._buf.set(data, this._pos);
    this._pos += data.length;
    return data.length;
  }
}

/**
 * Coerce input (Uint8Array | ArrayBuffer | BytesIO) into BytesIO.
 */
export function toBytesIO(
  src: Uint8Array | ArrayBuffer | BytesIO,
): BytesIO {
  if (src instanceof BytesIO) return src;
  return new BytesIO(src);
}
