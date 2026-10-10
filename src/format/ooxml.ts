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
import { parseHashAlgorithm, type HashAlgorithm } from "../crypto.js";

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

/** Fields of the password key encryptor's `<p:encryptedKey>` element. */
type PasswordKeyEncryptor = {
  encryptedVerifierHashInput: Uint8Array;
  encryptedVerifierHashValue: Uint8Array;
  encryptedKeyValue: Uint8Array;
  spinValue: number;
  passwordSalt: Uint8Array;
  passwordHashAlgorithm: HashAlgorithm;
  passwordKeyBits: number;
};

/** EncryptionInfo with type discriminator. */
type AgileInfo = {
  type: "agile";
  keyDataSalt: Uint8Array;
  keyDataHashAlgorithm: HashAlgorithm;
  keyDataBlockSize: number;
  /** null when the descriptor has no `<dataIntegrity>` element. */
  dataIntegrity: {
    encryptedHmacKey: Uint8Array;
    encryptedHmacValue: Uint8Array;
  } | null;
  /** null when the file can't be opened with a password. */
  password: PasswordKeyEncryptor | null;
  /** RSA-wrapped secret key from the certificate key encryptor, if any. */
  certificateEncryptedKeyValue: Uint8Array | null;
};

type StandardInfo = {
  type: "standard";
  header: EncryptionHeader;
  verifier: EncryptionVerifier;
};

type ParsedInfo = AgileInfo | StandardInfo;

const KEY_ENCRYPTOR_PASSWORD =
  "http://schemas.microsoft.com/office/2006/keyEncryptor/password";
const KEY_ENCRYPTOR_CERTIFICATE =
  "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate";

/** [MS-OFFCRYPTO] caps spinCount at 10,000,000; reject anything larger. */
const MAX_SPIN_COUNT = 10_000_000;

/** Optional namespace prefix in front of an element name, e.g. `p:`. */
const NS_PREFIX = "(?:[A-Za-z_][\\w.-]*:)?";

/**
 * Return the first start tag of element `name` (with any namespace prefix)
 * in `xml`, or null. The Agile descriptor has a fixed, shallow schema, so
 * this is enough — full XML parsing would just inflate the dependency
 * footprint.
 */
function findTag(xml: string, name: string): string | null {
  const m = xml.match(new RegExp(`<${NS_PREFIX}${name}(?=[\\s/>])[^>]*>`));
  return m ? m[0] : null;
}

function requireTag(xml: string, name: string): string {
  const tag = findTag(xml, name);
  if (!tag) throw new FileFormatError(`Element not found: ${name}`);
  return tag;
}

/** Read attribute `attr` (single- or double-quoted) from a start tag. */
function readAttr(tag: string, attr: string): string {
  const m = tag.match(
    new RegExp(`\\s${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`),
  );
  if (!m) throw new FileFormatError(`Attribute not found: ${attr}`);
  return m[1] ?? m[2];
}

function readIntAttr(tag: string, attr: string): number {
  const value = readAttr(tag, attr);
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new FileFormatError(`Invalid ${attr}: ${value}`);
  }
  return n;
}

function readHashAttr(tag: string, attr: string): HashAlgorithm {
  const value = readAttr(tag, attr);
  const algorithm = parseHashAlgorithm(value);
  if (!algorithm) {
    throw new DecryptionError(`Unsupported hash algorithm: ${value}`);
  }
  return algorithm;
}

/**
 * Map each `<keyEncryptor uri="...">` to the `<encryptedKey>` start tag it
 * contains. A file may carry several encryptors (password and certificate),
 * in any order, so they must be told apart by `uri` rather than position.
 */
function findKeyEncryptors(xml: string): Map<string, string> {
  const re = new RegExp(
    `<${NS_PREFIX}keyEncryptor(?=[\\s>])[^>]*>([\\s\\S]*?)</${NS_PREFIX}keyEncryptor\\s*>`,
    "g",
  );
  const out = new Map<string, string>();
  for (const m of xml.matchAll(re)) {
    const encryptedKey = findTag(m[1], "encryptedKey");
    if (encryptedKey) out.set(readAttr(m[0], "uri"), encryptedKey);
  }
  return out;
}

function parseAgileInfo(xml: string): AgileInfo {
  const keyData = requireTag(xml, "keyData");
  const dataIntegrity = findTag(xml, "dataIntegrity");
  const encryptors = findKeyEncryptors(xml);
  const passwordTag = encryptors.get(KEY_ENCRYPTOR_PASSWORD);
  const certificateTag = encryptors.get(KEY_ENCRYPTOR_CERTIFICATE);
  if (!passwordTag && !certificateTag) {
    throw new FileFormatError("No supported key encryptor found");
  }

  let password: PasswordKeyEncryptor | null = null;
  if (passwordTag) {
    const spinValue = readIntAttr(passwordTag, "spinCount");
    if (spinValue > MAX_SPIN_COUNT) {
      throw new FileFormatError(`spinCount too large: ${spinValue}`);
    }
    password = {
      encryptedVerifierHashInput: base64Decode(
        readAttr(passwordTag, "encryptedVerifierHashInput"),
      ),
      encryptedVerifierHashValue: base64Decode(
        readAttr(passwordTag, "encryptedVerifierHashValue"),
      ),
      encryptedKeyValue: base64Decode(
        readAttr(passwordTag, "encryptedKeyValue"),
      ),
      spinValue,
      passwordSalt: base64Decode(readAttr(passwordTag, "saltValue")),
      passwordHashAlgorithm: readHashAttr(passwordTag, "hashAlgorithm"),
      passwordKeyBits: readIntAttr(passwordTag, "keyBits"),
    };
  }

  return {
    type: "agile",
    keyDataSalt: base64Decode(readAttr(keyData, "saltValue")),
    keyDataHashAlgorithm: readHashAttr(keyData, "hashAlgorithm"),
    keyDataBlockSize: readIntAttr(keyData, "blockSize"),
    dataIntegrity: dataIntegrity
      ? {
          encryptedHmacKey: base64Decode(
            readAttr(dataIntegrity, "encryptedHmacKey"),
          ),
          encryptedHmacValue: base64Decode(
            readAttr(dataIntegrity, "encryptedHmacValue"),
          ),
        }
      : null,
    password,
    certificateEncryptedKeyValue: certificateTag
      ? base64Decode(readAttr(certificateTag, "encryptedKeyValue"))
      : null,
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
    const info = this.info;
    if (password !== undefined) {
      if (info?.type === "agile") {
        const pw = info.password;
        if (!pw) {
          throw new DecryptionError(
            "This file has no password key encryptor; use a private key",
          );
        }
        if (verifyPassword) {
          const { secretKey: key, verified } =
            ECMA376Agile.makekeyAndVerifyPassword(
              password,
              pw.passwordSalt,
              pw.passwordHashAlgorithm,
              pw.encryptedKeyValue,
              pw.encryptedVerifierHashInput,
              pw.encryptedVerifierHashValue,
              pw.spinValue,
              pw.passwordKeyBits,
            );
          if (!verified) throw new InvalidKeyError("Key verification failed");
          this.secretKey = key;
        } else {
          this.secretKey = ECMA376Agile.makekeyFromPassword(
            password,
            pw.passwordSalt,
            pw.passwordHashAlgorithm,
            pw.encryptedKeyValue,
            pw.spinValue,
            pw.passwordKeyBits,
          );
        }
      } else if (info?.type === "standard") {
        const key = ECMA376Standard.makekeyFromPassword(
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
            key,
            info.verifier.encryptedVerifier,
            info.verifier.encryptedVerifierHash,
          );
          if (!ok) throw new InvalidKeyError("Key verification failed");
        }
        this.secretKey = key;
      } else {
        // Plain file: nothing to do; the file is unencrypted.
      }
    } else if (privateKey !== undefined) {
      if (info?.type !== "agile") {
        throw new DecryptionError(
          "Unsupported key type for the encryption method",
        );
      }
      if (!info.certificateEncryptedKeyValue) {
        throw new DecryptionError(
          "This file has no certificate key encryptor; use a password",
        );
      }
      this.secretKey = ECMA376Agile.makekeyFromPrivkey(
        privateKey,
        info.certificateEncryptedKeyValue,
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
    const key = this.secretKey;
    if (!key) throw new DecryptionError("Must call loadKey before decrypt");
    const ole = this.file as OleFileIO;
    const stream = ole.openstream("EncryptedPackage");
    const info = this.info;
    let result: Uint8Array;

    if (info?.type === "agile") {
      if (opts.verifyIntegrity) {
        if (!info.dataIntegrity) {
          throw new DecryptionError(
            "This file has no dataIntegrity element to verify",
          );
        }
        const ok = ECMA376Agile.verifyIntegrity(
          key,
          info.keyDataSalt,
          info.keyDataHashAlgorithm,
          info.keyDataBlockSize,
          info.dataIntegrity.encryptedHmacKey,
          info.dataIntegrity.encryptedHmacValue,
          stream.getValue(),
        );
        if (!ok) {
          throw new InvalidKeyError("Payload integrity verification failed");
        }
      }
      result = ECMA376Agile.decrypt(
        key,
        info.keyDataSalt,
        info.keyDataHashAlgorithm,
        new BytesIO(stream.getValue()),
      );
    } else if (info?.type === "standard") {
      result = ECMA376Standard.decrypt(key, new BytesIO(stream.getValue()));
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
