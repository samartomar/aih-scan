#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { closeSync, lstatSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { captureCiscoOciCandidateV2 } from "./cisco/capture-v2.js";
import { canonicalStrictJsonBytesV1, parseStrictJsonObjectV1 } from "./contract/strict-json-v1.js";
import {
  canonicalScanAttestationEnvelopeBytesV2,
  canonicalScanCandidateBytesV2,
  parseScanAttestationEnvelopeV2Json,
  parseScanCandidateV2Json,
  signScanCandidateV2,
  verifyScanAttestationV2,
} from "./observation/scan-attestation-v2.js";

const maxInputBytes = 2 * 1024 * 1024;
function fail(message: string): never {
  throw new TypeError(`aih-scan: ${message}`);
}
function readText(path: string, label: string): string {
  const bytes = readFileSync(resolve(path));
  if (bytes.byteLength === 0 || bytes.byteLength > maxInputBytes) fail(`${label} input size`);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail(`${label} UTF-8`);
  return text;
}
function readPrivateKey(path: string): string {
  const resolved = resolve(path),
    stat = lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > 64 * 1024)
    fail("private key file shape");
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    fail("private key file permissions");
  return readText(resolved, "private key");
}
function readJson(path: string, label: string): Record<string, unknown> {
  return parseStrictJsonObjectV1(readText(path, label), label);
}
function flag(args: readonly string[], name: string): string {
  const index = args.indexOf(name);
  if (index < 0 || index + 1 >= args.length || args[index + 1]?.startsWith("--"))
    fail(`missing ${name}`);
  if (args.filter((value) => value === name).length !== 1) fail(`duplicate ${name}`);
  return args[index + 1] as string;
}
function verify(args: readonly string[]): void {
  const allowed = new Set(["--evidence", "--roots", "--expected", "--seen"]);
  if (args.length % 2 !== 0 || args.some((arg, index) => index % 2 === 0 && !allowed.has(arg)))
    fail("unknown verify argument");
  const evidence = parseScanAttestationEnvelopeV2Json(
    readText(flag(args, "--evidence"), "evidence"),
  );
  const rootsWire = readJson(flag(args, "--roots"), "roots");
  const expected = readJson(flag(args, "--expected"), "expected policy");
  const rootsValue = rootsWire.roots;
  if (!Array.isArray(rootsValue) || rootsValue.length === 0 || rootsValue.length > 64)
    fail("roots shape");
  const roots = rootsValue.map((value) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) fail("root object");
    const root = value as Record<string, unknown>;
    if (
      typeof root.identity !== "string" ||
      (root.class !== "test-ephemeral" && root.class !== "organization") ||
      typeof root.keyId !== "string" ||
      typeof root.publicKeyPem !== "string"
    )
      fail("root fields");
    return {
      identity: root.identity,
      class: root.class,
      keyId: root.keyId,
      publicKey: createPublicKey(root.publicKeyPem),
    };
  });
  const seen = args.includes("--seen")
    ? readJson(flag(args, "--seen"), "replay identities").identities
    : [];
  const result = verifyScanAttestationV2({
    envelope: evidence,
    roots,
    expected,
    seenReplayIdentities: seen,
  });
  process.stdout.write(`${canonicalStrictJsonBytesV1(result.facts).toString("utf8")}\n`);
}
function writeNew(path: string, bytes: Uint8Array): void {
  const descriptor = openSync(resolve(path), "wx", 0o600);
  try {
    writeFileSync(descriptor, bytes);
  } finally {
    closeSync(descriptor);
  }
}
function dockerRunner(
  argv: readonly string[],
  options: {
    readonly env: Readonly<Record<string, string>>;
    readonly timeoutMs: number;
    readonly maxStdoutBytes: number;
    readonly maxStderrBytes: number;
  },
): Promise<unknown> {
  if (argv[0] !== "docker" || argv.length < 2) fail("registered Docker argv");
  return new Promise((resolveResult, reject) => {
    const child = spawn("docker", argv.slice(1), {
      shell: false,
      windowsHide: true,
      env: options.env,
      stdio: "pipe",
    });
    const stdout: Buffer[] = [],
      stderr: Buffer[] = [];
    let stdoutSize = 0,
      stderrSize = 0,
      truncated = false,
      settled = false;
    const finish = (result: unknown) => {
      if (!settled) {
        settled = true;
        resolveResult(result);
      }
    };
    const timer = setTimeout(() => {
      truncated = true;
      child.kill();
    }, options.timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutSize += chunk.byteLength;
      if (stdoutSize > options.maxStdoutBytes) {
        truncated = true;
        child.kill();
      } else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrSize += chunk.byteLength;
      if (stderrSize > options.maxStderrBytes) {
        truncated = true;
        child.kill();
      } else stderr.push(chunk);
    });
    child.once("error", reject);
    child.once("close", (code) => {
      clearTimeout(timer);
      finish({
        code: code ?? 1,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        truncated,
      });
    });
  });
}
async function capture(args: readonly string[]): Promise<void> {
  if (args.length !== 4 || args[0] !== "--request" || args[2] !== "--output") fail("capture usage");
  const requestPath = args[1],
    outputPath = args[3];
  if (typeof requestPath !== "string" || typeof outputPath !== "string") fail("capture arguments");
  const request = readJson(requestPath, "Cisco capture request");
  const candidate = await captureCiscoOciCandidateV2({ ...request, runner: dockerRunner });
  writeNew(outputPath, canonicalScanCandidateBytesV2(candidate));
}
function sign(args: readonly string[]): void {
  if (
    args.length !== 10 ||
    args[0] !== "--candidate" ||
    args[2] !== "--signer" ||
    args[4] !== "--private-key" ||
    args[6] !== "--claims" ||
    args[8] !== "--output"
  )
    fail("sign usage");
  const candidatePath = args[1],
    signerPath = args[3],
    privateKeyPath = args[5],
    claimsPath = args[7],
    outputPath = args[9];
  if (
    [candidatePath, signerPath, privateKeyPath, claimsPath, outputPath].some(
      (entry) => typeof entry !== "string",
    )
  )
    fail("sign arguments");
  const candidate = parseScanCandidateV2Json(readText(candidatePath as string, "candidate"));
  const signerWire = readJson(signerPath as string, "signer");
  const claims = readJson(claimsPath as string, "claims");
  if (
    typeof signerWire.identity !== "string" ||
    typeof signerWire.class !== "string" ||
    typeof signerWire.keyId !== "string" ||
    Object.keys(signerWire).length !== 3
  )
    fail("signer fields");
  const evidence = signScanCandidateV2({
    candidate,
    signer: {
      identity: signerWire.identity,
      class: signerWire.class,
      keyId: signerWire.keyId,
      privateKey: createPrivateKey(readPrivateKey(privateKeyPath as string)),
    },
    claims,
  });
  writeNew(outputPath as string, canonicalScanAttestationEnvelopeBytesV2(evidence));
}
async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === "verify") {
    verify(args);
    return;
  }
  if (command === "capture") return capture(args);
  if (command === "sign") return sign(args);
  if (command === "--help" || command === "-h") {
    process.stdout.write(
      "Usage: aih-scan capture --request <file> --output <new-file> | sign --candidate <file> --signer <file> --private-key <file> --claims <file> --output <new-file> | verify --evidence <file> --roots <file> --expected <file> [--seen <file>]\n",
    );
    return;
  }
  fail("unknown command");
}
main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "invalid input"}\n`);
  process.exitCode = 2;
});
