#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { captureCiscoOciCandidateV2 } from "./cisco/capture-v2.js";
import { canonicalStrictJsonBytesV1, parseStrictJsonObjectV1 } from "./contract/strict-json-v1.js";
import {
  canonicalScanAttestationEnvelopeBytesV2,
  parseScanAttestationEnvelopeV2Json,
  signScanCandidateV2,
  verifyScanAttestationV2,
} from "./observation/scan-attestation-v2.js";
import { readScanCaptureBundleV2, writeScanCaptureBundleV2 } from "./observation/scan-bundle-v2.js";

const maxInputBytes = 2 * 1024 * 1024;
function fail(message: string): never {
  throw new TypeError(`aih-scan: ${message}`);
}
function sameIdentity(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}
function readBoundedRegularFile(path: string, label: string, maximumBytes: number): Buffer {
  const resolved = resolve(path);
  const beforePath = lstatSync(resolved);
  if (
    !beforePath.isFile() ||
    beforePath.isSymbolicLink() ||
    beforePath.nlink !== 1 ||
    beforePath.size <= 0 ||
    beforePath.size > maximumBytes
  )
    fail(`${label} file shape`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameIdentity(beforePath, before))
      fail(`${label} file replacement`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const afterPath = lstatSync(resolved);
    if (
      bytes.byteLength === 0 ||
      bytes.byteLength > maximumBytes ||
      after.nlink !== 1 ||
      !sameIdentity(before, after) ||
      !sameIdentity(before, afterPath)
    )
      fail(`${label} file replacement`);
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
function readText(path: string, label: string): string {
  const bytes = readBoundedRegularFile(path, label, maxInputBytes);
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
  const bytes = readBoundedRegularFile(resolved, "private key", 64 * 1024);
  const after = lstatSync(resolved);
  if (process.platform !== "win32" && (after.mode & 0o077) !== 0)
    fail("private key file permissions");
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail("private key UTF-8");
  return text;
}
function decodeCanonicalBase64(value: string, label: string, maximumBytes: number): Buffer {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    value.length > Math.ceil(maximumBytes / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  )
    fail(`${label} base64`);
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength > maximumBytes || decoded.toString("base64") !== value)
    fail(`${label} base64`);
  return decoded;
}
function exactWire(value: Record<string, unknown>, fields: readonly string[], label: string): void {
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0 ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field)) ||
    fields.some((field) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, field);
      return descriptor === undefined || !("value" in descriptor);
    })
  )
    fail(`${label} fields`);
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
  const allowed = new Set(["--evidence", "--bundle", "--roots", "--expected", "--seen"]);
  if (args.length % 2 !== 0 || args.some((arg, index) => index % 2 === 0 && !allowed.has(arg)))
    fail("unknown verify argument");
  const evidence = parseScanAttestationEnvelopeV2Json(
    readText(flag(args, "--evidence"), "evidence"),
  );
  const bundle = readScanCaptureBundleV2({ bundleDirectory: flag(args, "--bundle") });
  const rootsWire = readJson(flag(args, "--roots"), "roots");
  const expected = readJson(flag(args, "--expected"), "expected policy");
  exactWire(rootsWire, ["roots"], "roots");
  const rootsValue = rootsWire.roots;
  if (!Array.isArray(rootsValue) || rootsValue.length === 0 || rootsValue.length > 64)
    fail("roots shape");
  const roots = rootsValue.map((value) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) fail("root object");
    const root = value as Record<string, unknown>;
    exactWire(root, ["identity", "class", "keyId", "publicKeySpkiBase64"], "root");
    if (
      typeof root.identity !== "string" ||
      (root.class !== "test-ephemeral" && root.class !== "organization") ||
      typeof root.keyId !== "string" ||
      typeof root.publicKeySpkiBase64 !== "string"
    )
      fail("root fields");
    return {
      identity: root.identity,
      class: root.class,
      keyId: root.keyId,
      publicKey: createPublicKey({
        key: decodeCanonicalBase64(root.publicKeySpkiBase64, "root SPKI", 4096),
        format: "der",
        type: "spki",
      }),
    };
  });
  const seen = (() => {
    if (!args.includes("--seen")) return [];
    const seenWire = readJson(flag(args, "--seen"), "replay identities");
    exactWire(seenWire, ["identities"], "replay identities");
    if (!Array.isArray(seenWire.identities)) fail("replay identities");
    return seenWire.identities;
  })();
  const result = verifyScanAttestationV2({
    envelope: evidence,
    roots,
    expected,
    seenReplayIdentities: seen,
    candidate: bundle.candidate,
    annexArtifacts: bundle.annexArtifacts,
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
export function dockerRunner(
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
    const result = () => ({
      code: 1,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
      truncated,
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const settle = (outcome: { readonly result: unknown } | { readonly error: unknown }) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if ("error" in outcome) reject(outcome.error);
      else resolveResult(outcome.result);
    };
    const finish = (code: number | null) => {
      settle({
        result: {
          ...result(),
          code: code ?? 1,
        },
      });
    };
    const terminate = () => {
      if (settled) return;
      truncated = true;
      try {
        child.kill();
      } catch {
        // The bounded runner result below is still authoritative after a failed termination request.
      }
      finish(1);
    };
    timer = setTimeout(terminate, options.timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdoutSize += chunk.byteLength;
      if (stdoutSize > options.maxStdoutBytes) {
        terminate();
      } else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (settled) return;
      stderrSize += chunk.byteLength;
      if (stderrSize > options.maxStderrBytes) {
        terminate();
      } else stderr.push(chunk);
    });
    child.once("error", (error) => settle({ error }));
    child.once("close", (code) => {
      finish(code);
    });
  });
}
async function capture(args: readonly string[]): Promise<void> {
  if (args.length !== 4 || args[0] !== "--request" || args[2] !== "--output") fail("capture usage");
  const requestPath = args[1],
    outputPath = args[3];
  if (typeof requestPath !== "string" || typeof outputPath !== "string") fail("capture arguments");
  const request = readJson(requestPath, "Cisco capture request");
  exactWire(
    request,
    ["layout", "sourceRoot", "selectedClosurePaths", "runtime", "annexFiles", "broker"],
    "Cisco capture request",
  );
  if (!Array.isArray(request.annexFiles) || request.annexFiles.length !== 2)
    fail("Cisco capture annex files");
  const annexPayloads = request.annexFiles.map((entry) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry))
      fail("Cisco capture annex file");
    const wire = entry as Record<string, unknown>;
    exactWire(wire, ["descriptorId", "path"], "Cisco capture annex file");
    if (
      (wire.descriptorId !== "annex.sbom" && wire.descriptorId !== "annex.provenance") ||
      typeof wire.path !== "string"
    )
      fail("Cisco capture annex file");
    return {
      descriptorId: wire.descriptorId,
      bytes: readBoundedRegularFile(wire.path, "Cisco capture annex", 16 * 1024 * 1024),
    };
  });
  if (new Set(annexPayloads.map((entry) => entry.descriptorId)).size !== annexPayloads.length)
    fail("Cisco capture annex file duplicate");
  const captured = await captureCiscoOciCandidateV2({
    layout: request.layout,
    sourceRoot: request.sourceRoot,
    selectedClosurePaths: request.selectedClosurePaths,
    runtime: request.runtime,
    annexPayloads,
    broker: request.broker,
    runner: dockerRunner,
  });
  writeScanCaptureBundleV2({ outputDirectory: outputPath, ...captured });
}
function sign(args: readonly string[]): void {
  if (
    args.length !== 10 ||
    args[0] !== "--bundle" ||
    args[2] !== "--signer" ||
    args[4] !== "--private-key" ||
    args[6] !== "--claims" ||
    args[8] !== "--output"
  )
    fail("sign usage");
  const bundleDirectory = args[1],
    signerPath = args[3],
    privateKeyPath = args[5],
    claimsPath = args[7],
    outputPath = args[9];
  if (
    [bundleDirectory, signerPath, privateKeyPath, claimsPath, outputPath].some(
      (entry) => typeof entry !== "string",
    )
  )
    fail("sign arguments");
  const bundle = readScanCaptureBundleV2({ bundleDirectory: bundleDirectory as string });
  const signerWire = readJson(signerPath as string, "signer");
  const claims = readJson(claimsPath as string, "claims");
  exactWire(signerWire, ["identity", "class", "keyId"], "signer");
  if (
    typeof signerWire.identity !== "string" ||
    typeof signerWire.class !== "string" ||
    typeof signerWire.keyId !== "string" ||
    Object.keys(signerWire).length !== 3
  )
    fail("signer fields");
  const evidence = signScanCandidateV2({
    candidate: bundle.candidate,
    signer: {
      identity: signerWire.identity,
      class: signerWire.class,
      keyId: signerWire.keyId,
      privateKey: createPrivateKey(readPrivateKey(privateKeyPath as string)),
    },
    claims,
    annexArtifacts: bundle.annexArtifacts,
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
      "Usage: aih-scan capture --request <file> --output <new-directory> | sign --bundle <directory> --signer <file> --private-key <file> --claims <file> --output <new-file> | verify --evidence <file> --bundle <directory> --roots <file> --expected <file> [--seen <file>]\n",
    );
    return;
  }
  fail("unknown command");
}
if (
  typeof process.argv[1] === "string" &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : "invalid input"}\n`);
    process.exitCode = 2;
  });
}
