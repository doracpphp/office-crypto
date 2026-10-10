import { describe, it, expect } from "vitest";
import { OfficeFile, DecryptionError, InvalidKeyError } from "../src/index.js";
import { blockwiseRc4Decrypt } from "../src/method/rc4_common.js";
import { rc4 } from "../src/crypto.js";
import { BytesIO } from "../src/utils.js";
import { PASSWORD, expected, input } from "./fixtures.js";

// Every legacy case is compared byte for byte against msoffcrypto-tool's
// output (see test/README.md).
const cases = [
  ["rc4cryptoapi_password.ppt", "ppt97", PASSWORD],
  ["rc4cryptoapi_password.doc", "doc97", PASSWORD],
  ["rc4cryptoapi_password.xls", "xls97", PASSWORD],
  ["xor_password_123456789012345.xls", "xls97", "123456789012345"],
] as const;

describe.each(cases)("%s", (name, format, password) => {
  it(`decrypts to the same bytes as msoffcrypto-tool (${format})`, () => {
    const file = OfficeFile(input(name));
    expect(file.format).toBe(format);
    expect(file.isEncrypted()).toBe(true);
    file.loadKey({ password });
    expect(file.decrypt()).toEqual(expected(name));
  });

  it("returns an independent, identical buffer on every decrypt call", () => {
    const file = OfficeFile(input(name));
    file.loadKey({ password });
    const first = file.decrypt();
    const second = file.decrypt();
    expect(second).not.toBe(first);
    expect(second).toEqual(expected(name));
    expect(first).toEqual(expected(name));
  });

  it("rejects an incorrect password", () => {
    const file = OfficeFile(input(name));
    expect(() => file.loadKey({ password: "0000" })).toThrow(InvalidKeyError);
  });
});

describe("unencrypted legacy files", () => {
  it.each(["plain.xls", "plain.doc", "plain.ppt"])(
    "%s: loadKey reports the file is not encrypted",
    (name) => {
      const file = OfficeFile(input(name));
      expect(file.isEncrypted()).toBe(false);
      expect(() => file.loadKey({ password: PASSWORD })).toThrow(
        DecryptionError,
      );
    },
  );
});

describe("blockwiseRc4Decrypt", () => {
  it("handles more blocks than fit in a spread call", () => {
    // Regression: concatenating per-block results with `...spread`
    // overflowed the call stack at ~150k blocks (e.g. a ~75MB .doc).
    const key = new Uint8Array([1, 2, 3, 4, 5]);
    const data = new Uint8Array(300_000).fill(0xab);
    const out = blockwiseRc4Decrypt(new BytesIO(data), () => key, 1);
    expect(out.length).toBe(data.length);
    expect(out[299_999]).toBe(rc4(key, data.subarray(0, 1))[0]);
  });
});
