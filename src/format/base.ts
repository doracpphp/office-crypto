/**
 * Base interface every OfficeFile implementation conforms to.
 */

export interface LoadKeyOptions {
  password?: string;
  privateKey?: Uint8Array | string;
  secretKey?: Uint8Array;
  verifyPassword?: boolean;
}

export interface DecryptOptions {
  verifyIntegrity?: boolean;
}

export interface BaseOfficeFile {
  format: string;
  keyTypes: readonly string[];
  loadKey(opts: LoadKeyOptions): void;
  decrypt(opts?: DecryptOptions): Uint8Array;
  isEncrypted(): boolean;
}
