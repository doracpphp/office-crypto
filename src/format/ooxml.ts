/**
 * OOXML (DOCX/XLSX/PPTX) format handler.
 *
 * Encrypted OOXML is wrapped inside an OLE compound file containing an
 * `EncryptionInfo` stream (header + XML descriptor or binary header) and an
 * `EncryptedPackage` stream (the actual encrypted ZIP).
 *
 * Plain OOXML is a regular ZIP starting with `PK\x03\x04`.
 *
 * Direct port of `msoffcrypto/format/ooxml.py`.
 */

import { DecryptionError, FileFormatError, InvalidKeyError } from "../exceptions.js";
import {
  isOleFile,
  OleFileIO,
  type OleStream,
} from "../olefile.js";
import { ECMA376Agile } from "../method/ecma376_agile.js";
import { ECMA376Standard } from "../method/ecma376_standard.js";
import { base64Decode, BytesIO, readU16, readU32 } from "../utils.js";
import {
  parseEncryptionHeader,
  parseEncryptionVerifier,
  type EncryptionHeader,
  type EncryptionVerifier,
} from "./common.js";
import type {
  BaseOfficeFile,
  DecryptOptions,
  LoadKeyOptions,
} from "./base.js";
import type { HashAlgorithm } from "../crypto.js";

/**
 * Quick zip-magic sniff for plain OOXML detection. We don't decompress; we
 * only need to know whether the file is encrypted (OLE) or not (zip).
 */
export function isZip(buf: Uint8Array): boolean {
  // Local file header magic
  return (
    buf.length >= 4 &&
    buf[0] === 0x50 &&
    buf[1] === 0x4b &&
    (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07) &&
    (buf[3] === 0x04 || buf[3] === 0x06 || buf[3] === 0x08)
  );
}

/** Heuristic: is this a plain (unencrypted) OOXML file? */
export function isOoxml(buf: Uint8Array): boolean {
  if (!isZip(buf)) return false;
  // We could verify [Content_Types].xml exists, but that requires a zip
  // parser. Detecting the magic + later confirming via OLE absence is enough
  // for the routing decision the library needs.
  return true;
}

/** EncryptionInfo with type discriminator. */
type AgileInfo = {
  type: "agile";
  keyDataSalt: Uint8Array;
  keyDataHashAlgorithm: HashAlgorithm;
  keyDataBlockSize: number;
  encryptedHmacKey: Uint8Array;
  encryptedHmacValue: Uint8Array;
  encryptedVerifierHashInput: Uint8Array;
  encryptedVerifierHashValue: Uint8Array;
  encryptedKeyValue: Uint8Array;
  spinValue: number;
  passwordSalt: Uint8Array;
  passwordHashAlgorithm: HashAlgorithm;
  passwordKeyBits: number;
};

type StandardInfo = {
  type: "standard";
  header: EncryptionHeader;
  verifier: EncryptionVerifier;
};

type ParsedInfo = AgileInfo | StandardInfo;

/**
 * Pull a single attribute value out of an XML tag matching `tagPattern`.
 * Used because the Agile descriptor has a fixed schema — full XML parsing
 * would just inflate the dependency footprint.
 */
function readAttr(
  xml: string,
  tagPattern: RegExp,
  attr: string,
): string {
  const tagMatch = xml.match(tagPattern);
  if (!tagMatch) throw new FileFormatError(`Tag not found: ${tagPattern}`);
  const tag = tagMatch[0];
  const re = new RegExp(`${attr}\\s*=\\s*"([^"]*)"`);
  const m = tag.match(re);
  if (!m) throw new FileFormatError(`Attribute not found: ${attr}`);
  return m[1];
}

function parseAgileInfo(xml: string): AgileInfo {
  const keyDataSalt = base64Decode(readAttr(xml, /<keyData\s[^>]*\/?>/, "saltValue"));
  const keyDataHashAlgorithm = readAttr(
    xml,
    /<keyData\s[^>]*\/?>/,
    "hashAlgorithm",
  ) as HashAlgorithm;
  const keyDataBlockSize = parseInt(
    readAttr(xml, /<keyData\s[^>]*\/?>/, "blockSize"),
    10,
  );
  const encryptedHmacKey = base64Decode(
    readAttr(xml, /<dataIntegrity\s[^>]*\/?>/, "encryptedHmacKey"),
  );
  const encryptedHmacValue = base64Decode(
    readAttr(xml, /<dataIntegrity\s[^>]*\/?>/, "encryptedHmacValue"),
  );

  // Look for the password keyEncryptor's <p:encryptedKey> element. The
  // namespace prefix may be "p:" or another prefix bound to the same URI.
  const ekTagRe = /<(?:[A-Za-z0-9_-]+:)?encryptedKey\s[^>]*\/?>/;
  const spinValue = parseInt(readAttr(xml, ekTagRe, "spinCount"), 10);
  const encryptedKeyValue = base64Decode(
    readAttr(xml, ekTagRe, "encryptedKeyValue"),
  );
  const encryptedVerifierHashInput = base64Decode(
    readAttr(xml, ekTagRe, "encryptedVerifierHashInput"),
  );
  const encryptedVerifierHashValue = base64Decode(
    readAttr(xml, ekTagRe, "encryptedVerifierHashValue"),
  );
  const passwordSalt = base64Decode(readAttr(xml, ekTagRe, "saltValue"));
  const passwordHashAlgorithm = readAttr(
    xml,
    ekTagRe,
    "hashAlgorithm",
  ) as HashAlgorithm;
  const passwordKeyBits = parseInt(readAttr(xml, ekTagRe, "keyBits"), 10);

  return {
    type: "agile",
    keyDataSalt,
    keyDataHashAlgorithm,
    keyDataBlockSize,
    encryptedHmacKey,
    encryptedHmacValue,
    encryptedVerifierHashInput,
    encryptedVerifierHashValue,
    encryptedKeyValue,
    spinValue,
    passwordSalt,
    passwordHashAlgorithm,
    passwordKeyBits,
  };
}

function parseStandardInfo(stream: OleStream): StandardInfo {
  // headerFlags + encryptionHeaderSize, then encryptionHeader, then verifier.
  readU32(stream); // headerFlags (unused)
  const encryptionHeaderSize = readU32(stream);
  const headerBytes = new Uint8Array(stream.read(encryptionHeaderSize));
  const header = parseEncryptionHeader(new BytesIO(headerBytes));
  const verifierBytes = new Uint8Array(stream.read());
  const isAes = (header.algId & 0xff00) === 0x6600;
  const verifier = parseEncryptionVerifier(
    new BytesIO(verifierBytes),
    isAes ? "AES" : "RC4",
  );
  return { type: "standard", header, verifier };
}

function parseInfo(stream: OleStream): ParsedInfo {
  const versionMajor = readU16(stream);
  const versionMinor = readU16(stream);
  if (versionMajor === 4 && versionMinor === 4) {
    stream.seek(8);
    const xmlBytes = stream.read();
    const xml = new TextDecoder("utf-8").decode(xmlBytes);
    return parseAgileInfo(xml);
  }
  if (
    (versionMajor === 2 || versionMajor === 3 || versionMajor === 4) &&
    versionMinor === 2
  ) {
    return parseStandardInfo(stream);
  }
  if ((versionMajor === 3 || versionMajor === 4) && versionMinor === 3) {
    throw new DecryptionError(
      "Unsupported EncryptionInfo version (Extensible Encryption)",
    );
  }
  throw new DecryptionError(
    `Unsupported EncryptionInfo version (${versionMajor}:${versionMinor})`,
  );
}

export class OOXMLFile implements BaseOfficeFile {
  format = "ooxml" as const;
  keyTypes: readonly string[];
  type: "agile" | "standard" | "plain";

  private file: OleFileIO | Uint8Array;
  private info?: ParsedInfo;
  private secretKey: Uint8Array | null = null;

  constructor(buf: Uint8Array) {
    if (isOleFile(buf)) {
      const ole = new OleFileIO(buf);
      this.file = ole;
      if (!ole.exists("EncryptionInfo")) {
        throw new FileFormatError(
          "Supposed to be an encrypted OOXML file, but no EncryptionInfo stream found",
        );
      }
      this.info = parseInfo(ole.openstream("EncryptionInfo"));
      this.type = this.info.type;
      this.keyTypes =
        this.type === "agile"
          ? (["password", "private_key", "secret_key"] as const)
          : (["password", "secret_key"] as const);
    } else if (isOoxml(buf)) {
      this.file = buf;
      this.type = "plain";
      this.keyTypes = [];
    } else {
      throw new FileFormatError("Unsupported file format");
    }
  }

  loadKey(opts: LoadKeyOptions): void {
    const { password, privateKey, secretKey, verifyPassword = false } = opts;
    if (password !== undefined) {
      if (this.type === "agile") {
        const info = this.info as AgileInfo;
        this.secretKey = ECMA376Agile.makekeyFromPassword(
          password,
          info.passwordSalt,
          info.passwordHashAlgorithm,
          info.encryptedKeyValue,
          info.spinValue,
          info.passwordKeyBits,
        );
        if (verifyPassword) {
          const ok = ECMA376Agile.verifyPassword(
            password,
            info.passwordSalt,
            info.passwordHashAlgorithm,
            info.encryptedVerifierHashInput,
            info.encryptedVerifierHashValue,
            info.spinValue,
            info.passwordKeyBits,
          );
          if (!ok) throw new InvalidKeyError("Key verification failed");
        }
      } else if (this.type === "standard") {
        const info = this.info as StandardInfo;
        this.secretKey = ECMA376Standard.makekeyFromPassword(
          password,
          info.header.algId,
          info.header.algIdHash,
          info.header.providerType,
          info.header.keySize,
          info.verifier.saltSize,
          info.verifier.salt,
        );
        if (verifyPassword) {
          const ok = ECMA376Standard.verifyKey(
            this.secretKey,
            info.verifier.encryptedVerifier,
            info.verifier.encryptedVerifierHash,
          );
          if (!ok) throw new InvalidKeyError("Key verification failed");
        }
      } else if (this.type === "plain") {
        // Nothing to do; the file is unencrypted.
      }
    } else if (privateKey !== undefined) {
      if (this.type !== "agile") {
        throw new DecryptionError(
          "Unsupported key type for the encryption method",
        );
      }
      const info = this.info as AgileInfo;
      this.secretKey = ECMA376Agile.makekeyFromPrivkey(
        privateKey,
        info.encryptedKeyValue,
      );
    } else if (secretKey !== undefined) {
      this.secretKey = secretKey;
    } else {
      throw new DecryptionError("No key specified");
    }
  }

  decrypt(opts: DecryptOptions = {}): Uint8Array {
    if (this.type === "plain") {
      throw new DecryptionError("Document is not encrypted");
    }
    const ole = this.file as OleFileIO;
    const stream = ole.openstream("EncryptedPackage");
    let result: Uint8Array;

    if (this.type === "agile") {
      const info = this.info as AgileInfo;
      if (opts.verifyIntegrity) {
        const ok = ECMA376Agile.verifyIntegrity(
          this.secretKey!,
          info.keyDataSalt,
          info.keyDataHashAlgorithm,
          info.keyDataBlockSize,
          info.encryptedHmacKey,
          info.encryptedHmacValue,
          stream.getValue(),
        );
        if (!ok) {
          throw new InvalidKeyError("Payload integrity verification failed");
        }
      }
      result = ECMA376Agile.decrypt(
        this.secretKey!,
        info.keyDataSalt,
        info.keyDataHashAlgorithm,
        new BytesIO(stream.getValue()),
      );
    } else if (this.type === "standard") {
      result = ECMA376Standard.decrypt(
        this.secretKey!,
        new BytesIO(stream.getValue()),
      );
    } else {
      throw new DecryptionError("Unsupported encryption method");
    }

    if (!isZip(result)) {
      throw new InvalidKeyError(
        "The file could not be decrypted with this password",
      );
    }
    return result;
  }

  isEncrypted(): boolean {
    return this.type !== "plain";
  }
}
