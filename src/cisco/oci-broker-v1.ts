import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  type Stats,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
} from "../contract/strict-json-v1.js";
import {
  describeNativeObservationSourceV1,
  type SourceSealV1,
  sealNativeObservationSourceV1,
} from "../observation/native-observation-v1.js";
import { createCiscoFactsOnlyV1 } from "./facts-only-v1.js";
import { type CiscoOciLayoutV1, isCiscoOciLayoutV1 } from "./oci-layout-v1.js";
import { parseCiscoSarifV1 } from "./sarif-v1.js";

const MAX_STDIO_BYTES = 64 * 1024;
const MAX_SARIF_BYTES = 16 * 1024 * 1024;
const TIMEOUT_MS = 120_000;
const inputFields = [
  "protocol",
  "layout",
  "sourceRoot",
  "selectedClosurePaths",
  "host",
  "runner",
] as const;
type DockerResponse = {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly truncated?: boolean;
};
type DockerRunner = (
  argv: readonly string[],
  options: {
    readonly env: Readonly<Record<string, string>>;
    readonly timeoutMs: number;
    readonly maxStdoutBytes: number;
    readonly maxStderrBytes: number;
  },
) => Promise<unknown>;
type BrokerInput = {
  readonly layout: CiscoOciLayoutV1;
  readonly sourceRoot: string;
  readonly selectedClosurePaths: readonly string[];
  readonly runner: DockerRunner;
};

const fail = (message: string): never => {
  throw new TypeError(`invalid Cisco OCI broker V1: ${message}`);
};
const ownData = (value: object, key: string): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) fail(`input ${key} must be own data`);
  return (descriptor as PropertyDescriptor & { value: unknown }).value;
};
const sameSeal = (left: SourceSealV1, right: SourceSealV1) =>
  left.sourceTreeSha256 === right.sourceTreeSha256 &&
  left.selectedClosureSha256 === right.selectedClosureSha256 &&
  left.sealedSnapshotSha256 === right.sealedSnapshotSha256;

function parseInput(value: unknown): BrokerInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  const raw = value as object;
  if (
    Object.getPrototypeOf(raw) !== Object.prototype ||
    Object.getOwnPropertySymbols(raw).length > 0
  )
    fail("input plain data");
  const keys = Object.keys(raw);
  if (keys.length !== inputFields.length || inputFields.some((key) => !keys.includes(key)))
    fail("input fields");
  const data = raw;
  const runner = ownData(data, "runner");
  if (typeof runner !== "function") fail("injected runner");
  const layout = ownData(data, "layout");
  if (!isCiscoOciLayoutV1(layout)) fail("branded layout");
  const sourceRoot = ownData(data, "sourceRoot");
  const selectedClosurePaths = ownData(data, "selectedClosurePaths");
  const host = ownData(data, "host");
  const protocol = ownData(data, "protocol");
  try {
    assertStrictJsonValueV1(
      { protocol, sourceRoot, selectedClosurePaths, host },
      "Cisco OCI broker input",
    );
  } catch {
    fail("input data");
  }
  if (
    protocol !== "CiscoOciBrokerV1" ||
    typeof sourceRoot !== "string" ||
    !sourceRoot ||
    sourceRoot.length > 4096 ||
    sourceRoot.includes("\0") ||
    sourceRoot.includes("\r") ||
    sourceRoot.includes("\n") ||
    sourceRoot.includes(",") ||
    !Array.isArray(selectedClosurePaths) ||
    selectedClosurePaths.length === 0 ||
    selectedClosurePaths.length > 100_000 ||
    typeof host !== "object" ||
    host === null ||
    Array.isArray(host)
  )
    fail("input");
  const hostData = host as Record<string, unknown>;
  if (
    Object.keys(hostData).length !== 2 ||
    hostData.os !== "linux" ||
    hostData.architecture !== "amd64"
  )
    fail("linux amd64 host");
  const selected = selectedClosurePaths as unknown[];
  for (const path of selected) {
    const selectedPath = typeof path === "string" ? path : fail("selected closure path");
    assertSafeRelativePosixPathV1(selectedPath, "selected closure path");
  }
  if (new Set(selected).size !== selected.length) fail("duplicate selected closure path");
  return {
    layout: layout as CiscoOciLayoutV1,
    sourceRoot: sourceRoot as string,
    selectedClosurePaths: selected as string[],
    runner: runner as DockerRunner,
  };
}

function response(value: unknown, label: string): DockerResponse {
  try {
    assertStrictJsonValueV1(value, `Docker ${label} response`);
  } catch {
    fail(`${label} response`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value))
    fail(`${label} response`);
  const v = value as Record<string, unknown>;
  const allowed = ["code", "stdout", "stderr", "truncated"];
  if (
    !Object.keys(v).every((key) => allowed.includes(key)) ||
    !["code", "stdout", "stderr"].every((key) => key in v) ||
    typeof v.code !== "number" ||
    !Number.isSafeInteger(v.code) ||
    v.code < 0 ||
    typeof v.stdout !== "string" ||
    typeof v.stderr !== "string" ||
    Buffer.byteLength(v.stdout as string, "utf8") > MAX_STDIO_BYTES ||
    Buffer.byteLength(v.stderr as string, "utf8") > MAX_STDIO_BYTES ||
    (v.truncated !== undefined && v.truncated !== true && v.truncated !== false)
  )
    fail(`${label} response`);
  return {
    code: v.code as number,
    stdout: v.stdout as string,
    stderr: v.stderr as string,
    ...(v.truncated === undefined ? {} : { truncated: v.truncated as boolean }),
  };
}

function normalizedTerminalLine(value: string, label: string): string {
  if (Buffer.byteLength(value, "utf8") > MAX_STDIO_BYTES || value.includes("\0")) fail(label);
  const line = value.endsWith("\r\n")
    ? value.slice(0, -2)
    : value.endsWith("\n")
      ? value.slice(0, -1)
      : value;
  if (line.includes("\r") || line.includes("\n")) fail(label);
  return line;
}

function normalizedImageId(stdout: string): string {
  const line = normalizedTerminalLine(stdout, "local image ID mismatch");
  if (!/^sha256:[a-f0-9]{64}$/.test(line)) fail("local image ID mismatch");
  return line;
}

function output(path: string): Buffer {
  const names = readdirSync(path).sort();
  if (names.length !== 1 || names[0] !== "result.sarif") fail("SARIF output stale or extra");
  const stat: Stats = (() => {
    try {
      return lstatSync(join(path, "result.sarif"));
    } catch {
      return fail("SARIF output missing");
    }
  })();
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink > 1 ||
    stat.size < 0 ||
    stat.size > MAX_SARIF_BYTES
  )
    fail("SARIF output invalid");
  const bytes = readFileSync(join(path, "result.sarif"));
  if (bytes.length !== stat.size) fail("SARIF output changed while reading");
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail("SARIF output UTF-8");
  return bytes;
}

function temporaryPath(path: string, label: string): void {
  if (
    !isAbsolute(path) ||
    !path ||
    path.includes("\0") ||
    path.includes("\r") ||
    path.includes("\n") ||
    path.includes(",")
  )
    fail(`${label} path`);
}

function freeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value) || seen.has(value))
    return value;
  seen.add(value);
  for (const child of Object.values(value)) freeze(child, seen);
  return Object.freeze(value);
}

// biome-ignore lint/suspicious/noExplicitAny: this internal broker returns a closed, branded candidate record.
export async function executeCiscoOciBrokerV1(value: unknown): Promise<any> {
  const input = parseInput(value);
  const sourceInput = {
    sourceRoot: input.sourceRoot,
    selectedClosurePaths: input.selectedClosurePaths,
  };
  const snapshot = describeNativeObservationSourceV1(sourceInput);
  const initialSeal = sealNativeObservationSourceV1(sourceInput);
  const selectedFiles = Object.fromEntries(
    snapshot.selectedClosureFiles.map((file) => [file.path, file.sha256]),
  );
  const temporaryBase = tmpdir();
  temporaryPath(temporaryBase, "temporary base");
  const clientRoot = mkdtempSync(join(temporaryBase, "aih-scan-oci-client-"));
  const home = join(clientRoot, "home");
  const dockerConfig = join(clientRoot, "docker-config");
  let outputRoot: string | undefined;
  const env = Object.freeze({ PATH: "/usr/bin:/bin", HOME: home, DOCKER_CONFIG: dockerConfig });
  const options = Object.freeze({
    env,
    timeoutMs: TIMEOUT_MS,
    maxStdoutBytes: MAX_STDIO_BYTES,
    maxStderrBytes: MAX_STDIO_BYTES,
  });
  const containerName = `aih-scan-cisco-${input.layout.configDigestSha256.slice(7, 19)}`;
  const invoke = async (argv: readonly string[], label: string) =>
    response(await input.runner(argv, options), label);
  let created = false;
  let result: unknown;
  let operationError: unknown;
  let cleanupError: unknown;
  try {
    temporaryPath(clientRoot, "client root");
    mkdirSync(home, { recursive: true });
    mkdirSync(dockerConfig, { recursive: true });
    outputRoot = mkdtempSync(join(temporaryBase, "aih-scan-oci-output-"));
    temporaryPath(outputRoot, "output root");
    const inspected = await invoke(
      ["docker", "image", "inspect", "--format", "{{.Id}}", input.layout.configDigestSha256],
      "image inspect",
    );
    if (
      inspected.code !== 0 ||
      inspected.truncated ||
      normalizedImageId(inspected.stdout) !== input.layout.configDigestSha256 ||
      inspected.stderr !== ""
    )
      fail("local image ID mismatch");
    const before = sealNativeObservationSourceV1(sourceInput);
    if (!sameSeal(initialSeal, before)) fail("source drift before run");
    created = true;
    const run = await invoke(
      [
        "docker",
        "run",
        "--name",
        containerName,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--pids-limit",
        "128",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--mount",
        `type=bind,src=${input.sourceRoot},dst=/source,readonly`,
        "--mount",
        `type=bind,src=${outputRoot},dst=/output,rw`,
        "--entrypoint",
        "/runtime/.venv/bin/skill-scanner",
        input.layout.configDigestSha256,
        "scan",
        "/source",
        "--format",
        "sarif",
        "--output-sarif",
        "/output/result.sarif",
      ],
      "run",
    );
    if (run.code !== 0 || run.truncated || run.stdout !== "" || run.stderr !== "")
      fail("scanner run");
    const rawSarif = output(outputRoot);
    const parsedSarif = parseCiscoSarifV1(rawSarif.toString("utf8"), {
      sourceRoot: input.sourceRoot,
    });
    for (const result of parsedSarif.runs[0]?.results ?? [])
      for (const location of result.locations)
        if (!Object.hasOwn(selectedFiles, location.physicalLocation.artifactLocation.uri))
          fail("SARIF path outside selected closure");
    const after = sealNativeObservationSourceV1(sourceInput);
    if (!sameSeal(before, after)) fail("source drift during run");
    const facts = createCiscoFactsOnlyV1({
      protocol: "CiscoFactsOnlyV1",
      sarif: parsedSarif,
      fileSha256ByPath: selectedFiles,
      platform: { os: "linux", architecture: "amd64" },
    });
    result = freeze({
      protocol: "CiscoOciBrokerV1" as const,
      observationScope: "candidate" as const,
      validationState: "cryptographically-unverified" as const,
      manifestDigestSha256: input.layout.manifestDigestSha256,
      configDigestSha256: input.layout.configDigestSha256,
      logicalReference: input.layout.logicalReference,
      platform: { os: "linux" as const, architecture: "amd64" as const },
      sourceSeal: after,
      sarifSha256: createHash("sha256").update(rawSarif).digest("hex"),
      facts: facts.facts,
      coverage: facts.coverage,
      evidenceAnnex: facts.evidenceAnnex,
      annexBytes: Buffer.from(facts.annexBytes),
      cleanup: { kind: "clean" as const },
    });
  } catch (error) {
    operationError = error;
  }
  if (created) {
    try {
      const removed = await invoke(
        ["docker", "container", "rm", "--force", containerName],
        "container rm",
      );
      const absent = await invoke(
        ["docker", "container", "ls", "--all", "--quiet", "--filter", `name=^/${containerName}$`],
        "container absence",
      );
      if (
        removed.code !== 0 ||
        removed.truncated ||
        absent.code !== 0 ||
        absent.truncated ||
        absent.stdout !== "" ||
        absent.stderr !== ""
      )
        fail("container cleanup");
    } catch (error) {
      cleanupError = error;
    }
  }
  for (const temporaryRoot of [outputRoot, clientRoot]) {
    if (temporaryRoot === undefined) continue;
    try {
      rmSync(temporaryRoot, { recursive: true, force: true });
    } catch (error) {
      if (cleanupError === undefined) cleanupError = error;
    }
  }
  if (cleanupError !== undefined) throw cleanupError;
  if (operationError !== undefined) throw operationError;
  return result;
}
