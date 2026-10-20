import { createHash } from "node:crypto";
import { closeSync, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";

export const schemas = Object.freeze({
  input: "urn:aihq:scan:refresh-input:1.0.0",
  captureInput: "urn:aihq:scan:catalog-capture-input:1.0.0",
  captureBatchInput: "urn:aihq:scan:catalog-capture-batch-input:1.0.0",
  manifest: "urn:aihq:scan:refresh-manifest:1.0.0",
  captureManifest: "urn:aihq:scan:catalog-capture-manifest:1.0.0",
  captureBatchManifest: "urn:aihq:scan:catalog-capture-batch-manifest:1.0.0",
  captureBatchInventory: "urn:aihq:scan:catalog-capture-batch-inventory:1.0.0",
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
    if (!/^(?:null|true|false)$/.test(match[0])) {
      // Control numbers must name an exact nonnegative safe integer, before a
      // double conversion can round a fraction or underflow it to zero.
      const token = match[0];
      if (token.length > 1100 || token.startsWith("-"))
        throw new Error("Invalid bounded control number");
      const parts = /^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
      let digits = (parts[1] + (parts[2] ?? "")).replace(/^0+/, "");
      if (digits === "") return 0;
      const trailing = /0*$/.exec(digits)[0].length;
      digits = digits.slice(0, digits.length - trailing);
      const scale = BigInt(parts[3] ?? "0") - BigInt((parts[2] ?? "").length) + BigInt(trailing);
      if (scale < 0n || scale > 15n || BigInt(digits.length) + scale > 16n)
        throw new Error("Lossy or out-of-range control number");
      const exact = BigInt(digits) * 10n ** scale;
      if (exact > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Unsafe control number");
      return Number(exact);
    }
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
export function paths(value) {
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
  const independent = value.schema === schemas.captureBatchInput;
  object(value, ["schema", "scannerSourceCommit", "runtime", "profile", "limits", "targets", ...(independent ? ["batchLimits"] : [])]);
  const capture = independent || value.schema === schemas.captureInput;
  if ((!capture && value.schema !== schemas.input) || value.profile !== profile)
    throw new Error("Unsupported input/profile");
  commit(value.scannerSourceCommit);
  validateRuntime(value.runtime);
  limits(value.limits);
  const expectedRoster = capture ? ["samartomar/aih-catalog"] : roster;
  if (!Array.isArray(value.targets) || (independent ? value.targets.length < 1 || value.targets.length > 7 : value.targets.length !== expectedRoster.length))
    throw new Error("Exact roster required");
  value.targets.forEach((target, index) => {
    object(target, ["repository", "ref", "selection", "trustLint", ...(capture ? ["capture"] : []), ...(independent ? ["captureId"] : [])]);
    if (target.repository !== expectedRoster[independent ? 0 : index]) throw new Error("Exact ordered roster required");
    if (independent) captureId(target.captureId);
    if (capture) {
      commit(target.ref);
      validateCaptureSelector(target.capture);
      if (target.selection.excludedPaths.length !== 0) throw new Error("Capture exclusions refused");
    }
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
  if (independent) validateCaptureBatch(value, false);
  canonicalBytes(value);
  return value;
}
export function batchId(manifest) {
  const { batchId: _id, ...body } = manifest;
  return `batch:sha256:${sha256(canonicalBytes(body))}`;
}
export function validateManifest(value) {
  const independent = value.schema === schemas.captureBatchManifest;
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
    ...(independent ? ["batchLimits"] : []),
  ]);
  const capture = independent || value.schema === schemas.captureManifest;
  if (capture && canonicalBytes(value).length > 2097152) throw new Error("Frozen capture manifest exceeds bound");
  const expectedRoster = capture ? ["samartomar/aih-catalog"] : roster;
  if (
    (!capture && value.schema !== schemas.manifest) ||
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
    (independent ? value.targets.length < 1 || value.targets.length > 7 : value.targets.length !== expectedRoster.length)
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
      ...(capture ? ["capture"] : []),
      ...(independent ? ["captureId"] : []),
    ]);
    if (
      target.repository !== expectedRoster[independent ? 0 : index] ||
      target.repositoryUrl !== `https://github.com/${expectedRoster[independent ? 0 : index]}.git`
    )
      throw new Error("Manifest repository mismatch");
    commit(target.commit);
    if (independent) captureId(target.captureId);
    if (capture) validateFrozenCapture(target.capture, value.limits);
    if (/^[0-9a-f]{40}$/.test(target.reviewedRef) && target.reviewedRef !== target.commit)
      throw new Error("Pinned reviewed commit changed");
    selection(target.selection);
    if (!Array.isArray(target.detectors) || target.detectors.length !== 4)
      throw new Error("Detector roster mismatch");
    const expected = detectorsFor(target.detectors[1]?.configuration);
    if (!canonicalBytes(target.detectors).equals(canonicalBytes(expected)))
      throw new Error("Detector profile mismatch");
    const synthetic = {
      schema: independent ? schemas.captureBatchInput : capture ? schemas.captureInput : schemas.input,
      scannerSourceCommit: value.scanner.sourceCommit,
      runtime: value.runtime,
      profile: value.profile,
      limits: value.limits,
      ...(independent ? {batchLimits: value.batchLimits} : {}),
      targets: value.targets.map((t) => ({
        repository: t.repository,
        ref: t.reviewedRef,
        selection: t.selection,
        trustLint: t.detectors[1].configuration,
        ...(capture ? { capture: captureSelector(t.capture) } : {}),
        ...(independent ? {captureId: t.captureId} : {}),
      })),
    };
    validateInput(synthetic);
  });
  if (independent) validateCaptureBatch(value, true);
  return value;
}
export const targetKey = target => target.captureId ?? target.repository;
export const targetDirectory = (target) => typeof target === "string" ? target.replace("/", "--") :
  target.captureId ? `catalog--${captureId(target.captureId)}` : target.repository.replace("/", "--");
export const targetIdentity = target => target.captureId === undefined ? {} : {captureId: captureId(target.captureId)};
export function captureId(value) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(value)) throw new Error("Invalid capture target ID");
  return value;
}
export const batchCeilings = Object.freeze({maxInputBytes:268435456,maxSourceBytes:268435456,maxSourceEntries:100000,maxDurationMs:5400000});
export function validateCaptureBatch(value, frozen) {
  object(value.batchLimits, Object.keys(batchCeilings));
  for (const [key, ceiling] of Object.entries(batchCeilings))
    if (!Number.isSafeInteger(value.batchLimits[key]) || value.batchLimits[key] < (key === "maxDurationMs" ? 100 : 1) || value.batchLimits[key] > ceiling)
      throw new Error("Invalid aggregate capture limit");
  const ids = new Set(), assets = new Set(), hashes = new Set();
  let inputBytes=0,sourceBytes=0,sourceEntries=0;
  for (const target of value.targets) {
    const key=captureId(target.captureId);
    if(ids.has(key) || assets.has(target.capture.assetId) || hashes.has(target.capture.sha256)) throw new Error("Duplicate capture target/input");
    ids.add(key); assets.add(target.capture.assetId); hashes.add(target.capture.sha256);
    inputBytes+=target.capture.byteLength;
    if(inputBytes>value.batchLimits.maxInputBytes) throw new Error("Aggregate capture budget exceeded");
    if (frozen) {
      const directories=new Set();
      sourceEntries+=target.capture.files.length;
      if(sourceEntries>value.batchLimits.maxSourceEntries) throw new Error("Aggregate capture budget exceeded");
      for(const file of target.capture.files) {
        sourceBytes+=file.byteLength;
        if(sourceBytes>value.batchLimits.maxSourceBytes) throw new Error("Aggregate capture budget exceeded");
        const parts=file.path.split("/");parts.pop();
        while(parts.length){
          const path=parts.join("/");
          if(!directories.has(path)){
            if(++sourceEntries>value.batchLimits.maxSourceEntries) throw new Error("Aggregate capture budget exceeded");
            directories.add(path);
          }
          parts.pop();
        }
      }
    }
    if (inputBytes>value.batchLimits.maxInputBytes || sourceBytes>value.batchLimits.maxSourceBytes || sourceEntries>value.batchLimits.maxSourceEntries)
      throw new Error("Aggregate capture budget exceeded");
  }
  return value;
}

export const captureCeiling = 64 * 1024 * 1024;
export function descriptor(value) {
  object(value, ["path", "sha256", "byteLength"]);
  paths([value.path]);
  // The data transport supports portable regular files only, including on Windows.
  if (value.path.split("/").some(part => part.toLowerCase() === ".git" ||
    /[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part)))
    throw new Error("Nonportable capture path");
  digest(value.sha256);
  if (!Number.isSafeInteger(value.byteLength) || value.byteLength < 0 || value.byteLength > captureCeiling)
    throw new Error("Invalid capture file length");
  return value;
}
export function validateCaptureSelector(value) {
  object(value, ["releaseId", "assetId", "sha256", "byteLength", "inventory"]);
  for (const key of ["releaseId", "assetId"])
    if (typeof value[key] !== "string" || !/^[1-9][0-9]{0,15}$/.test(value[key]) ||
      !Number.isSafeInteger(Number(value[key]))) throw new Error("Invalid capture immutable ID");
  digest(value.sha256);
  if (!Number.isSafeInteger(value.byteLength) || value.byteLength < 1 || value.byteLength > captureCeiling)
    throw new Error("Capture transport bound exceeded");
  descriptor(value.inventory);
  if (value.inventory.byteLength < 1 || value.inventory.byteLength > 16 * 1024 * 1024)
    throw new Error("Inventory length bound exceeded");
  return value;
}
export function captureSelector(value) {
  const { files: _files, ...selector } = value;
  return validateCaptureSelector(selector);
}
export function validateFrozenCapture(value, limits) {
  object(value, ["releaseId", "assetId", "sha256", "byteLength", "inventory", "files"]);
  captureSelector(value);
  if (!Array.isArray(value.files) || value.files.length < 1 || value.files.length > limits.maxSourceEntries)
    throw new Error("Capture file bound exceeded");
  const seen = new Set(), directories = new Set(), spellings = new Map();
  let total = 0, previous = "";
  for (const file of value.files) {
    descriptor(file);
    total += file.byteLength;
    if (total > limits.maxSourceBytes) throw new Error("Capture source byte bound exceeded");
    if (file.path <= previous || seen.has(file.path.toLowerCase())) throw new Error("Ambiguous capture files");
    previous = file.path;
    seen.add(file.path.toLowerCase());
    const components = file.path.split("/");
    for (let i = 1; i <= components.length; i++) {
      const path = components.slice(0, i).join("/"), key = path.toLowerCase();
      if (spellings.has(key) && spellings.get(key) !== path) throw new Error("Case-ambiguous capture namespace");
      if (!spellings.has(key) && spellings.size >= limits.maxSourceEntries)
        throw new Error("Capture entry bound exceeded");
      spellings.set(key, path);
    }
    const pieces = file.path.split("/");
    pieces.pop();
    while (pieces.length) { directories.add(pieces.join("/").toLowerCase()); pieces.pop(); }
  }
  if ([...directories].some(path => seen.has(path)) || directories.size + seen.size > limits.maxSourceEntries ||
    total > limits.maxSourceBytes || !value.files.some(file => canonicalBytes(file).equals(canonicalBytes(value.inventory))))
    throw new Error("Capture closure or resource bound mismatch");
  return value;
}
export function matchesTargetSource(source, target) {
  if (!target.capture) return source.kind === "git" && source.repository === target.repositoryUrl && source.commit === target.commit;
  if (source.kind !== "local") return false;
  const expected = [...target.capture.files.map(file => ({kind: "file", ...file}))];
  const directories = new Set();
  for (const file of target.capture.files) {
    const pieces = file.path.split("/"); pieces.pop();
    while (pieces.length) { directories.add(pieces.join("/")); pieces.pop(); }
  }
  for (const path of directories) expected.push({kind: "directory", path});
  expected.sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return canonicalBytes(expected).equals(canonicalBytes(source.capture.entries));
}
