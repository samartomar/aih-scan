import { createHash } from "node:crypto";
import { closeSync, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";

export const schemas = Object.freeze({
  input: "urn:aihq:scan:refresh-input:1.0.0",
  manifest: "urn:aihq:scan:refresh-manifest:1.0.0",
  inventory: "urn:aihq:scan:refresh-inventory:1.0.0",
  candidate: "urn:aihq:scan:refresh-candidate:1.0.0",
});
export const roster = Object.freeze([
  "mattpocock/skills",
  "affaan-m/ECC",
  "anthropics/skills",
  "obra/superpowers",
  "nextlevelbuilder/ui-ux-pro-max-skill",
  "DietrichGebert/ponytail",
  "samartomar/aih-extensions",
]);
export const profile = "independent-linux-v1";
export const unavailableCoverage = Object.freeze([
  "Cisco and SkillSpector: released rule-material identity unavailable; no vendor parity claimed.",
  "Snyk: outside this profile.",
  "MCP: only explicitly configured mcpConfigPaths are discovery inputs; an empty list establishes no MCP server coverage.",
  "Native: source identity evidence; empty findings make no security claim.",
]);
export const ceilings = Object.freeze({
  maxSourceEntries: 100000,
  maxSourceBytes: 268435456,
  maxRequestBytes: 2097152,
  maxReportBytes: 16777216,
  maxAnnexBytes: 16777216,
  maxDecodedArtifactBytes: 67108864,
  maxArtifactBytes: 100663296,
  maxStatementBytes: 131072,
  detectorTimeoutMs: 3600000,
});
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export function object(value, required, optional = []) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("Expected closed JSON object");
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))
  )
    throw new Error("Unknown or missing contract fields");
  return value;
}
export function canonicalBytes(value) {
  const encode = (v, depth = 0) => {
    if (depth > 64) throw new Error("JSON depth exceeded");
    if (v === null || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "string") {
      if (v.normalize("NFC") !== v || !v.isWellFormed()) throw new Error("Invalid JSON string");
      return JSON.stringify(v);
    }
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v) || v < 0 || Object.is(v, -0))
        throw new Error("Invalid JSON number");
      return String(v);
    }
    if (Array.isArray(v)) return `[${v.map((item) => encode(item, depth + 1)).join(",")}]`;
    if (v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype)
      return (
        "{" +
        Object.keys(v)
          .sort()
          .map((key) => `${encode(key, depth + 1)}:${encode(v[key], depth + 1)}`)
          .join(",") +
        "}"
      );
    throw new Error("Not JSON data");
  };
  return Buffer.from(encode(value));
}
// Parse before shape validation, refusing duplicate keys and lossy control numbers.
export function parseJson(bytes, maximum = 2 * 1024 * 1024, canonical = false) {
  if (bytes.byteLength > maximum) throw new Error("JSON bytes exceeded");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let index = 0;
  const space = () => {
    while (/[\t\n\r ]/.test(text[index] ?? "") && index < text.length) index++;
  };
  const string = () => {
    const start = index++;
    while (index < text.length) {
      const c = text[index++];
      if (c === "\\") {
        index++;
        continue;
      }
      if (c === '"') return JSON.parse(text.slice(start, index));
    }
    throw new Error("Unterminated string");
  };
  const read = (depth = 0) => {
    if (depth > 64) throw new Error("JSON depth exceeded");
    space();
    const c = text[index];
    if (c === '"') return string();
    if (c === "{") {
      index++;
      space();
      const value = {};
      const keys = new Set();
      if (text[index] === "}") {
        index++;
        return value;
      }
      while (true) {
        space();
        if (text[index] !== '"') throw new Error("Expected key");
        const key = string();
        if (keys.has(key)) throw new Error("Duplicate key");
        keys.add(key);
        space();
        if (text[index++] !== ":") throw new Error("Expected colon");
        Object.defineProperty(value, key, {
          value: read(depth + 1),
          enumerable: true,
          writable: true,
          configurable: true,
        });
        space();
        const delimiter = text[index++];
        if (delimiter === "}") return value;
        if (delimiter !== ",") throw new Error("Expected delimiter");
      }
    }
    if (c === "[") {
      index++;
      space();
      const value = [];
      if (text[index] === "]") {
        index++;
        return value;
      }
      while (true) {
        value.push(read(depth + 1));
        space();
        const delimiter = text[index++];
        if (delimiter === "]") return value;
        if (delimiter !== ",") throw new Error("Expected delimiter");
      }
    }
    const match = /^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
      text.slice(index),
    );
    if (!match) throw new Error("Invalid JSON token");
    index += match[0].length;
    return JSON.parse(match[0]);
  };
  const result = read();
  space();
  if (index !== text.length) throw new Error("Trailing JSON data");
  const normalized = canonicalBytes(result);
  if (canonical && !Buffer.from(bytes).equals(normalized))
    throw new Error("Expected canonical JSON bytes");
  return result;
}
export function readRegular(path, maximum) {
  const before = lstatSync(path);
  if (!before.isFile() || before.nlink !== 1 || before.size > maximum)
    throw new Error("Expected bounded regular file");
  const fd = openSync(path, "r");
  try {
    const current = fstatSync(fd);
    if (
      current.dev !== before.dev ||
      current.ino !== before.ino ||
      !current.isFile() ||
      current.nlink !== 1 ||
      current.size > maximum
    )
      throw new Error("File changed");
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (
      bytes.length > maximum ||
      after.size !== current.size ||
      after.mtimeMs !== current.mtimeMs ||
      after.ctimeMs !== current.ctimeMs
    )
      throw new Error("File changed");
    return bytes;
  } finally {
    closeSync(fd);
  }
}
export function digest(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error("Invalid SHA256");
  return value;
}
export function commit(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) throw new Error("Invalid commit");
  return value;
}
function paths(value) {
  if (!Array.isArray(value) || value.length > 100000 || new Set(value).size !== value.length)
    throw new Error("Invalid paths");
  for (const path of value)
    if (
      typeof path !== "string" ||
      path.length > 4096 ||
      !path.isWellFormed() ||
      path.normalize("NFC") !== path ||
      // biome-ignore lint/suspicious/noControlCharactersInRegex: Contract paths must refuse control characters.
      /[\\%?#:\x00-\x1f\x7f]/.test(path) ||
      path.startsWith("/") ||
      path.endsWith("/") ||
      path.split("/").some((part) => !part || part === "." || part === "..")
    )
      throw new Error("Invalid relative path");
  return value;
}
function selection(value) {
  object(value, ["paths", "excludedPaths"]);
  if (value.paths !== "all") throw new Error("Whole-tree selection required");
  paths(value.excludedPaths);
  return value;
}
function trustLint(value) {
  object(value, ["internalScopes", "mcpConfigPaths"]);
  paths(value.mcpConfigPaths);
  if (
    !Array.isArray(value.internalScopes) ||
    value.internalScopes.length > 256 ||
    new Set(value.internalScopes).size !== value.internalScopes.length ||
    value.internalScopes.some(
      (scope, index) =>
        typeof scope !== "string" ||
        !/^@[a-z0-9][a-z0-9._~-]*$/.test(scope) ||
        (index > 0 && value.internalScopes[index - 1].localeCompare(scope) > 0),
    )
  )
    throw new Error("Invalid internal scopes");
  return value;
}
export function validateRuntime(value) {
  object(value, ["node", "platform", "architecture"]);
  const version = /^v24\.(\d+)\.(\d+)$/.exec(value.node);
  if (
    !version ||
    Number(version[1]) < 15 ||
    value.platform !== "linux" ||
    value.architecture !== "x64"
  )
    throw new Error("Profile requires Linux x64 Node >=24.15 <25");
  return value;
}
export function detectorsFor(value) {
  return [
    { detectorId: "detector.aih-native", profileId: "in-process-native-v1", configuration: {} },
    {
      detectorId: "detector.aih-trust-lint",
      profileId: "in-process-trust-lint-v1",
      configuration: trustLint(value),
    },
    {
      detectorId: "detector.aih-binding-gate",
      profileId: "in-process-binding-gate-v1",
      configuration: {},
    },
    { detectorId: "detector.semgrep", profileId: "linux-namespace-uv-v1", configuration: {} },
  ];
}
function limits(value) {
  object(value, Object.keys(ceilings));
  for (const [key, maximum] of Object.entries(ceilings))
    if (
      !Number.isSafeInteger(value[key]) ||
      value[key] < (key === "detectorTimeoutMs" ? 100 : key === "maxStatementBytes" ? 1024 : 1) ||
      value[key] > maximum
    )
      throw new Error("Invalid limits");
  return value;
}
export function validateInput(value) {
  object(value, ["schema", "scannerSourceCommit", "runtime", "profile", "limits", "targets"]);
  if (value.schema !== schemas.input || value.profile !== profile)
    throw new Error("Unsupported input/profile");
  commit(value.scannerSourceCommit);
  validateRuntime(value.runtime);
  limits(value.limits);
  if (!Array.isArray(value.targets) || value.targets.length !== roster.length)
    throw new Error("Exact roster required");
  value.targets.forEach((target, index) => {
    object(target, ["repository", "ref", "selection", "trustLint"]);
    if (target.repository !== roster[index]) throw new Error("Exact ordered roster required");
    if (
      typeof target.ref !== "string" ||
      (!/^[0-9a-f]{40}$/.test(target.ref) &&
        !/^refs\/heads\/[a-zA-Z0-9][a-zA-Z0-9._/-]*$/.test(target.ref)) ||
      target.ref.includes("..") ||
      target.ref.endsWith("/") ||
      target.ref.includes("//")
    )
      throw new Error("Invalid reviewed ref");
    selection(target.selection);
    trustLint(target.trustLint);
  });
  canonicalBytes(value);
  return value;
}
export function batchId(manifest) {
  const { batchId: _id, ...body } = manifest;
  return `batch:sha256:${sha256(canonicalBytes(body))}`;
}
export function validateManifest(value) {
  object(value, [
    "schema",
    "batchId",
    "createdAt",
    "scanner",
    "runtime",
    "profile",
    "limits",
    "unavailableCoverage",
    "targets",
  ]);
  if (
    value.schema !== schemas.manifest ||
    value.profile !== profile ||
    value.batchId !== batchId(value)
  )
    throw new Error("Manifest identity mismatch");
  if (
    typeof value.createdAt !== "string" ||
    new Date(value.createdAt).toISOString() !== value.createdAt
  )
    throw new Error("Invalid timestamp");
  object(value.scanner, ["name", "version", "sourceCommit", "tarballSha256", "installationSha256"]);
  if (
    value.scanner.name !== "@aihq/scan" ||
    typeof value.scanner.version !== "string" ||
    !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(value.scanner.version)
  )
    throw new Error("Invalid scanner");
  commit(value.scanner.sourceCommit);
  digest(value.scanner.tarballSha256);
  digest(value.scanner.installationSha256);
  validateRuntime(value.runtime);
  limits(value.limits);
  if (
    JSON.stringify(value.unavailableCoverage) !== JSON.stringify(unavailableCoverage) ||
    !Array.isArray(value.targets) ||
    value.targets.length !== roster.length
  )
    throw new Error("Manifest roster/coverage mismatch");
  value.targets.forEach((target, index) => {
    object(target, [
      "repository",
      "repositoryUrl",
      "reviewedRef",
      "commit",
      "selection",
      "detectors",
    ]);
    if (
      target.repository !== roster[index] ||
      target.repositoryUrl !== `https://github.com/${roster[index]}.git`
    )
      throw new Error("Manifest repository mismatch");
    commit(target.commit);
    if (/^[0-9a-f]{40}$/.test(target.reviewedRef) && target.reviewedRef !== target.commit)
      throw new Error("Pinned reviewed commit changed");
    selection(target.selection);
    if (!Array.isArray(target.detectors) || target.detectors.length !== 4)
      throw new Error("Detector roster mismatch");
    const expected = detectorsFor(target.detectors[1]?.configuration);
    if (!canonicalBytes(target.detectors).equals(canonicalBytes(expected)))
      throw new Error("Detector profile mismatch");
    const synthetic = {
      schema: schemas.input,
      scannerSourceCommit: value.scanner.sourceCommit,
      runtime: value.runtime,
      profile: value.profile,
      limits: value.limits,
      targets: value.targets.map((t) => ({
        repository: t.repository,
        ref: t.reviewedRef,
        selection: t.selection,
        trustLint: t.detectors[1].configuration,
      })),
    };
    validateInput(synthetic);
  });
  return value;
}
export const targetDirectory = (repository) => repository.replace("/", "--");
