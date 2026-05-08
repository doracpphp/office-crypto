export class FileFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FileFormatError";
  }
}

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParseError";
  }
}

export class DecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecryptionError";
  }
}

export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncryptionError";
  }
}

export class InvalidKeyError extends DecryptionError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidKeyError";
  }
}
