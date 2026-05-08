import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OfficeFile, OOXMLFile, isEncrypted, InvalidKeyError } from "../src/index.js";
import { OleFileIO } from "../src/olefile.js";

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

describe("OOXML agile decryption", () => {
  it("decrypts example_password.docx (Agile / SHA-512 / AES-256)", () => {
    const input = load(join(INPUTS, "example_password.docx"));
    const expected = load(join(OUTPUTS, "example.docx"));

    const file = OfficeFile(input);
    expect(file.format).toBe("ooxml");
    expect((file as OOXMLFile).type).toBe("agile");
    file.loadKey({ password: PASSWORD, verifyPassword: true });
    const out = file.decrypt();
    expect(out.length).toBe(expected.length);
    expect(out).toEqual(expected);
  });

  it("decrypts example_password.xlsx (Agile)", () => {
    const input = load(join(INPUTS, "example_password.xlsx"));
    const expected = load(join(OUTPUTS, "example.xlsx"));
    const file = OfficeFile(input);
    file.loadKey({ password: PASSWORD });
    const out = file.decrypt();
    expect(out.length).toBe(expected.length);
    expect(out).toEqual(expected);
  });

  it("rejects an incorrect password (verifyPassword=true)", () => {
    const input = load(join(INPUTS, "example_password.docx"));
    const file = OfficeFile(input);
    expect(() =>
      file.loadKey({ password: "wrong-password", verifyPassword: true }),
    ).toThrow(InvalidKeyError);
  });

  it("rejects an incorrect password by zip-magic check (verifyPassword=false)", () => {
    const input = load(join(INPUTS, "example_password.docx"));
    const file = OfficeFile(input);
    file.loadKey({ password: "wrong-password" });
    expect(() => file.decrypt()).toThrow(InvalidKeyError);
  });

  it("verifies HMAC integrity when requested", () => {
    const input = load(join(INPUTS, "example_password.docx"));
    const file = OfficeFile(input);
    file.loadKey({ password: PASSWORD });
    const out = file.decrypt({ verifyIntegrity: true });
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("OOXML standard decryption", () => {
  it("decrypts ecma376standard_password.docx (Standard / SHA-1 / AES-128 ECB)", () => {
    const input = load(join(INPUTS, "ecma376standard_password.docx"));
    const expected = load(join(OUTPUTS, "ecma376standard_password_plain.docx"));
    const file = OfficeFile(input);
    expect((file as OOXMLFile).type).toBe("standard");
    file.loadKey({ password: PASSWORD, verifyPassword: true });
    const out = file.decrypt();
    expect(out.length).toBe(expected.length);
    expect(out).toEqual(expected);
  });
});

describe("isEncrypted helper", () => {
  it("returns true for a protected OOXML container", () => {
    const input = load(join(INPUTS, "example_password.docx"));
    expect(isEncrypted(input)).toBe(true);
  });

  it("returns false for a plain XLS file", () => {
    const input = load(join(INPUTS, "plain.xls"));
    expect(isEncrypted(input)).toBe(false);
    const docxPlain = load(join(OUTPUTS, "example.docx"));
    expect(isEncrypted(docxPlain)).toBe(false);
  });
});

describe("OleFileIO", () => {
  it("lists EncryptionInfo and EncryptedPackage streams", () => {
    const input = load(join(INPUTS, "example_password.docx"));
    const ole = new OleFileIO(input);
    expect(ole.exists("EncryptionInfo")).toBe(true);
    expect(ole.exists("EncryptedPackage")).toBe(true);
    const list = ole.listdir().map((p) => p.join("/"));
    expect(list).toContain("EncryptionInfo");
    expect(list).toContain("EncryptedPackage");
  });
});
