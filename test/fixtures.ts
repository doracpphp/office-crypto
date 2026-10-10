import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** Encrypted / plain sample files from msoffcrypto-tool's tests/inputs. */
export const INPUTS = join(here, "inputs");
/** msoffcrypto-tool's decrypt output for each file in INPUTS (same name). */
export const EXPECTED = join(here, "expected");

export const PASSWORD = "Password1234_";

export function load(p: string): Uint8Array {
  const buf = readFileSync(p);
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export const input = (name: string) => load(join(INPUTS, name));
export const expected = (name: string) => load(join(EXPECTED, name));
