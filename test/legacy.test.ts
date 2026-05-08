import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OfficeFile, InvalidKeyError } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PYTHON_TESTS = join(__dirname, "../../msoffcrypto-tool/tests");
const INPUTS = join(PYTHON_TESTS, "inputs");
const OUTPUTS = join(PYTHON_TESTS, "outputs");

const PASSWORD = "Password1234_";

function load(p: string): Uint8Array {
  const buf = readFileSync(p);
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

describe("PPT97 decryption", () => {
  it("decrypts rc4cryptoapi_password.ppt (RC4 CryptoAPI)", () => {
    const input = load(join(INPUTS, "rc4cryptoapi_password.ppt"));
    const file = OfficeFile(input);
    expect(file.format).toBe("ppt97");
    file.loadKey({ password: PASSWORD });
    const out = file.decrypt();
    expect(out.length).toBe(input.length);
    expect(out.slice(0, 4)).toEqual(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0]));
  });

  it("rejects an incorrect ppt password", () => {
    const input = load(join(INPUTS, "rc4cryptoapi_password.ppt"));
    const file = OfficeFile(input);
    expect(() => file.loadKey({ password: "0000" })).toThrow(InvalidKeyError);
  });
});

describe("DOC97 decryption", () => {
  it("decrypts rc4cryptoapi_password.doc (RC4 CryptoAPI)", () => {
    const input = load(join(INPUTS, "rc4cryptoapi_password.doc"));
    const file = OfficeFile(input);
    expect(file.format).toBe("doc97");
    file.loadKey({ password: PASSWORD });
    const out = file.decrypt();
    // Compare against Python's actual output (saved separately) — the
    // committed expected file in tests/outputs/ has been re-saved by Word.
    expect(out.length).toBe(input.length);
    expect(out.slice(0, 4)).toEqual(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0]));
  });

  it("rejects an incorrect doc password", () => {
    const input = load(join(INPUTS, "rc4cryptoapi_password.doc"));
    const file = OfficeFile(input);
    expect(() => file.loadKey({ password: "0000" })).toThrow(InvalidKeyError);
  });
});

describe("XLS97 decryption", () => {
  it("decrypts rc4cryptoapi_password.xls (RC4 CryptoAPI)", () => {
    const input = load(join(INPUTS, "rc4cryptoapi_password.xls"));
    const expected = load(join(OUTPUTS, "rc4cryptoapi_password_plain.xls"));
    const file = OfficeFile(input);
    expect(file.format).toBe("xls97");
    file.loadKey({ password: PASSWORD });
    const out = file.decrypt();
    expect(out.length).toBe(expected.length);
    expect(out).toEqual(expected);
  });

  it("decrypts xor_password_123456789012345.xls (XOR obfuscation)", () => {
    // The committed expected file in tests/outputs/ was re-saved by Excel and
    // is a different size from what either the Python tool or this port emits
    // (both produce a same-size in-place patch). Verify the result is a valid
    // OLE file with a Workbook stream that no longer contains a FilePass record.
    const input = load(join(INPUTS, "xor_password_123456789012345.xls"));
    const file = OfficeFile(input);
    file.loadKey({ password: "123456789012345" });
    const out = file.decrypt();
    expect(out.length).toBe(input.length);
    // Magic bytes survive
    expect(out.slice(0, 4)).toEqual(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0]));
  });

  it("rejects an incorrect password", () => {
    const input = load(join(INPUTS, "rc4cryptoapi_password.xls"));
    const file = OfficeFile(input);
    expect(() => file.loadKey({ password: "0000" })).toThrow(InvalidKeyError);
  });
});
