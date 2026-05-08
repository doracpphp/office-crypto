#!/usr/bin/env node
/**
 * office-crypto CLI. Mirrors the upstream Python `msoffcrypto-tool` script:
 *
 *   office-crypto -p PASSWORD infile [outfile]   # decrypt
 *   office-crypto -t infile                       # test if encrypted
 */

import { readFileSync, writeFileSync } from "node:fs";
import { OfficeFile, isEncrypted, FileFormatError } from "./index.js";

interface Args {
  password?: string;
  passwordStdin: boolean;
  passwordFile?: string;
  test: boolean;
  encrypt: boolean;
  verbose: boolean;
  infile?: string;
  outfile?: string;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    test: false,
    encrypt: false,
    verbose: false,
    passwordStdin: false,
  };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-p" || a === "--password") {
      // Consume the next token as password unless it starts with '-' or absent.
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        args.password = next;
        i++;
      } else {
        args.password = "";
      }
    } else if (a === "--password-stdin") {
      args.passwordStdin = true;
    } else if (a === "--password-file") {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("-")) {
        console.error("--password-file requires a path argument");
        process.exit(2);
      }
      args.passwordFile = next;
      i++;
    } else if (a === "-t" || a === "--test") {
      args.test = true;
    } else if (a === "-e") {
      args.encrypt = true;
    } else if (a === "-v") {
      args.verbose = true;
    } else if (a === "-h" || a === "--help") {
      printUsage();
      process.exit(0);
    } else if (a === "--") {
      // End of options — remaining args are positional.
      for (let j = i + 1; j < argv.length; j++) positional.push(argv[j]);
      break;
    } else if (a.startsWith("-")) {
      console.error(`Unknown option: ${a}`);
      process.exit(2);
    } else {
      positional.push(a);
    }
  }
  args.infile = positional[0];
  args.outfile = positional[1];
  return args;
}

function printUsage(): void {
  const lines = [
    "Usage: office-crypto [options] infile [outfile]",
    "",
    "Options:",
    "  -p, --password PWD     decrypt with the given password",
    "                         (note: visible in `ps`; prefer the options below)",
    "      --password-stdin   read password from stdin (newline terminates)",
    "      --password-file F  read password from file F (first line)",
    "  -t, --test             test whether the file is encrypted (exit 0=yes, 1=no)",
    "  -v                     verbose output",
    "  -h, --help             show this help",
    "",
    "If outfile is omitted, the decrypted bytes are written to stdout.",
    "If neither -p / --password-stdin / --password-file is given, the user is",
    "prompted on stderr (terminal input).",
  ];
  console.log(lines.join("\n"));
}

/**
 * Prompt the user for a password on the controlling terminal, with echo off
 * when stdin is a TTY. Falls back to a regular line read otherwise.
 */
async function promptPassword(): Promise<string> {
  const readline = await import("node:readline");

  if (!process.stdin.isTTY) {
    // Non-TTY: read a single line without echo handling.
    const rl = readline.createInterface({ input: process.stdin });
    return new Promise<string>((resolve) => {
      rl.once("line", (line: string) => {
        rl.close();
        resolve(line);
      });
    });
  }

  process.stderr.write("Password: ");
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");

  return new Promise<string>((resolve) => {
    let pwd = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener("data", onData);
          process.stderr.write("\n");
          resolve(pwd);
          return;
        }
        if (ch === "\x03") {
          // Ctrl-C
          process.stdin.setRawMode(false);
          process.stderr.write("\n");
          process.exit(130);
        }
        if (ch === "\x7f" || ch === "\b") {
          // Backspace
          pwd = pwd.slice(0, -1);
        } else {
          pwd += ch;
        }
      }
    };
    process.stdin.on("data", onData);
  });
}

/** Read a password from stdin (one line), without prompting. */
async function readPasswordFromStdinPipe(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  // Strip a single trailing newline (CR/LF).
  let s = Buffer.concat(chunks).toString("utf8");
  if (s.endsWith("\r\n")) s = s.slice(0, -2);
  else if (s.endsWith("\n") || s.endsWith("\r")) s = s.slice(0, -1);
  return s;
}

async function resolvePassword(args: Args): Promise<string> {
  if (args.passwordFile) {
    const raw = readFileSync(args.passwordFile, "utf8");
    // Use only the first line; trim a trailing newline.
    const newline = raw.indexOf("\n");
    return (newline === -1 ? raw : raw.slice(0, newline)).replace(/\r$/, "");
  }
  if (args.passwordStdin) return readPasswordFromStdinPipe();
  if (args.password !== undefined && args.password !== "") return args.password;
  return promptPassword();
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (!args.infile) {
    printUsage();
    process.exit(2);
  }

  const buf = readFileSync(args.infile);
  const view = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);

  if (args.test) {
    const enc = isEncrypted(view);
    if (!enc) {
      console.error(`${args.infile}: not encrypted`);
      process.exit(1);
    } else {
      if (args.verbose) console.error(`${args.infile}: encrypted`);
      process.exit(0);
    }
  }

  if (args.encrypt) {
    throw new FileFormatError(
      "Encryption mode (-e) is not yet implemented in this TypeScript port",
    );
  }

  const password = await resolvePassword(args);

  const file = OfficeFile(view);
  file.loadKey({ password });
  const decrypted = file.decrypt();

  if (args.outfile) {
    writeFileSync(args.outfile, decrypted);
  } else {
    process.stdout.write(decrypted);
  }
}

main().catch((err: Error) => {
  process.stderr.write(`error: ${err.message}\n`);
  if (process.env.DEBUG) process.stderr.write(`${err.stack}\n`);
  process.exit(1);
});
