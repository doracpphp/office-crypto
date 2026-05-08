/**
 * office-crypto — TypeScript port of msoffcrypto-tool.
 *
 * Entry point. Exposes:
 *   - `OfficeFile(buf)`: factory that auto-detects file format.
 *   - `OOXMLFile`: handler for DOCX/XLSX/PPTX.
 *   - `Xls97File` / `Doc97File` / `Ppt97File`: legacy stubs.
 *   - `isEncrypted(buf)`: quick helper.
 *
 * See README for usage and the documented public surface area.
 */

import { isOleFile, OleFileIO } from "./olefile.js";
import { FileFormatError } from "./exceptions.js";
import { OOXMLFile, isOoxml } from "./format/ooxml.js";
import { Xls97File } from "./format/xls97.js";
import { Doc97File } from "./format/doc97.js";
import { Ppt97File } from "./format/ppt97.js";
import type { BaseOfficeFile } from "./format/base.js";

export {
  FileFormatError,
  ParseError,
  DecryptionError,
  EncryptionError,
  InvalidKeyError,
} from "./exceptions.js";

export { OOXMLFile, isOoxml } from "./format/ooxml.js";
export { Xls97File } from "./format/xls97.js";
export { Doc97File } from "./format/doc97.js";
export { Ppt97File } from "./format/ppt97.js";
export { OleFileIO, isOleFile } from "./olefile.js";

export type {
  BaseOfficeFile,
  LoadKeyOptions,
  DecryptOptions,
} from "./format/base.js";

/**
 * Auto-detect the format of `buf` and return the appropriate handler.
 *
 * @example
 *   const buf = await fs.promises.readFile("encrypted.docx");
 *   const file = OfficeFile(buf);
 *   file.loadKey({ password: "secret" });
 *   const decrypted = file.decrypt();
 *   await fs.promises.writeFile("plain.docx", decrypted);
 */
export function OfficeFile(buf: Uint8Array | ArrayBuffer): BaseOfficeFile {
  const view = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;

  if (isOleFile(view)) {
    const ole = new OleFileIO(view);
    if (ole.exists("EncryptionInfo")) return new OOXMLFile(view);
    if (ole.exists("WordDocument") || ole.exists("wordDocument")) {
      return new Doc97File(ole);
    }
    if (ole.exists("Workbook")) return new Xls97File(ole);
    if (ole.exists("PowerPoint Document")) return new Ppt97File(ole);
    throw new FileFormatError("Unrecognized OLE file format");
  }
  if (isOoxml(view)) return new OOXMLFile(view);
  throw new FileFormatError("Unsupported file format");
}

/**
 * Returns true if the input bytes look like an encrypted Office file.
 * Plain OOXML (.docx etc.) returns false; legacy OLE-based protected files
 * return true if a known encryption marker is present.
 */
export function isEncrypted(buf: Uint8Array | ArrayBuffer): boolean {
  const view = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  if (!isOleFile(view)) return false;
  try {
    const file = OfficeFile(view);
    return file.isEncrypted();
  } catch {
    return false;
  }
}
