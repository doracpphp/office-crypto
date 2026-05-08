# office-crypto

A TypeScript library for decrypting (and encrypting) password-protected Microsoft Office files. Direct port of [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) (Python).

## Status

| Format | Decrypt | Encrypt |
| --- | --- | --- |
| OOXML (DOCX/XLSX/PPTX) — Agile (AES-256 / SHA-512) | ✅ | 🚧 (CFB writer ported, top-level wiring pending) |
| OOXML — Standard (AES-128 / SHA-1) | ✅ | — |
| Excel 97-2003 (XLS) — RC4, RC4 CryptoAPI, XOR | ✅ | — |
| Word 97-2003 (DOC) — RC4, RC4 CryptoAPI | ✅ | — |
| PowerPoint 97-2003 (PPT) — RC4 CryptoAPI | ✅ | — |

## Install

```sh
npm install office-crypto
```

Requires Node.js ≥ 18.

## Library usage

```ts
import { readFileSync, writeFileSync } from "node:fs";
import { OfficeFile } from "office-crypto";

const buf = readFileSync("encrypted.docx");
const file = OfficeFile(buf);

file.loadKey({ password: "Password1234_", verifyPassword: true });
const decrypted = file.decrypt();

writeFileSync("plain.docx", decrypted);
```

### Key types

`OOXMLFile.loadKey()` accepts:

```ts
file.loadKey({ password: "secret" });            // password (most common)
file.loadKey({ privateKey: pemBytes });          // RSA-protected file
file.loadKey({ secretKey: rawBytes });           // pre-derived intermediate key
```

### HMAC integrity check (Agile only)

```ts
const decrypted = file.decrypt({ verifyIntegrity: true });
```

### Lower-level access

```ts
import { OleFileIO, ECMA376Agile } from "office-crypto";

const ole = new OleFileIO(buf);
ole.exists("EncryptionInfo");   // true / false
ole.openstream("EncryptionInfo").getValue();
```

## CLI

```sh
# decrypt (password visible in `ps` — fine for local one-offs only)
npx office-crypto -p PASSWORD encrypted.docx plain.docx

# safer: read password from stdin, or from a file
echo -n "$PASSWORD" | npx office-crypto --password-stdin encrypted.docx plain.docx
npx office-crypto --password-file ~/.config/secret encrypted.docx plain.docx

# interactive prompt (no echo) when no password flag is given
npx office-crypto encrypted.docx plain.docx

# test if a file is encrypted (exit 0 = encrypted, 1 = not)
npx office-crypto -t encrypted.docx
```

## Development

```sh
npm install
npm test         # vitest against the original Python test fixtures
npm run build    # tsup → dist/
```

## License

MIT. Includes derivative work from:

- [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) (MIT) — original Python implementation by nolze
- [olefile](https://www.decalage.info/olefile) (BSD-2-Clause) — OLE/CFB parser by Philippe Lagadec

