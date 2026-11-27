// Tooling-only prepared-content handoff. Caller labels and local execution receipts are unsigned.
import { execFileSync, fork } from "node:child_process";
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { availableParallelism, freemem, hostname, totalmem } from "node:os";
import { isIP } from "node:net";
import { dirname, join, relative, resolve, sep, win32, posix } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { digest, extractArchive, MAX_ARCHIVE_BYTES, need, plainText, readArchive, safePath, writeArchive } from "./prepared-archive.mjs";
import { startPreparedBatching } from "./provider-batching.mjs";

const maintenanceArtifact = JSON.parse(readFileSync(new URL("../analyzers/skillspector/maintenance/artifact.json", import.meta.url), "utf8"));
const staticArtifactPath = "tools/analyzers/skillspector/maintenance/static/artifact.json";
const staticArtifactUrl = new URL(`../../${staticArtifactPath}`, import.meta.url);
const staticWheelVariable = "AIH_SCAN_SKILLSPECTOR_STATIC_WHEEL";
// The maintenance build is versioned `<standard release>+aih.1.<build id>`; the pin test binds that prefix to SKILLSPECTOR_VERSION.
const standardSkillSpectorVersion = maintenanceArtifact.version.split("+")[0];
// Effort levels the Claude CLI accepts; Scan applies one through AIH_SCAN_AI_EFFORT. A test
// keeps this list equal to the scanner's AI_EFFORT_LEVELS.
export const AGENT_EFFORTS = Object.freeze(["low", "medium", "high", "xhigh", "max"]);
// A pinned Claude model id (family plus numeric version, optionally a date snapshot). Aliases
// such as `opus`, `default` or `claude-opus-latest` name whatever the CLI or account resolves.
const AGENT_CLIENTS = Object.freeze({ claude_cli: "claude", kimi_cli: "kimi" });
const KIMI_EFFORTS = Object.freeze(["low", "high", "max"]);
const KIMI_VERSION = "2.7.2";
const isAgentProvider = (provider) => Object.hasOwn(AGENT_CLIENTS, provider);
const PINNED_CLAUDE_MODEL = /^claude-[a-z]+(?:-[0-9]+)+$/;
// An explicit manifest revision, carried into identities and requests only when present.
const revisionOf = (value) => value.revision === undefined ? {} : { revision: value.revision };
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hash = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const loopbackHost = (host) => host === "localhost" || host === "[::1]" || isIP(host) === 4 && host.startsWith("127.");
const canonical = (value) => JSON.stringify(Array.isArray(value) ? value.map((entry) => JSON.parse(canonical(entry))) : object(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, JSON.parse(canonical(value[key]))])) : value);
const fingerprint = (value) => digest(canonical(value));
function keys(value, required, optional = []) {
  need(object(value) && required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => [...required, ...optional].includes(key)), "Unexpected or missing manifest fields");
}
export function regularFiles(root, excluded = new Set()) {
  const result = [];
  const rootStat = lstatSync(root);
  need(rootStat.isDirectory() && !rootStat.isSymbolicLink(), "Expected a real directory");
  const walk = (folder) => {
    for (const entry of readdirSync(folder).sort()) {
      const path = join(folder, entry);
      if (excluded.has(relative(root, path).split(sep).join("/"))) continue;
      const stat = lstatSync(path);
      if (stat.isDirectory() && !stat.isSymbolicLink()) walk(path);
      else { need(stat.isFile() && stat.nlink === 1 && !stat.isSymbolicLink(), "Links and special files are refused"); result.push({ path: relative(root, path).split(sep).join("/"), file: path, stat }); }
    }
  };
  walk(root); return result;
}
const readRegular = (path, max = MAX_ARCHIVE_BYTES) => {
  const stat = lstatSync(path);
  need(stat.isFile() && stat.nlink === 1 && !stat.isSymbolicLink() && stat.size <= max, "Invalid or oversized regular file");
  return readFileSync(path);
};
const json = (bytes) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
const writeJson = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" });
export function writeCheckpointAtomic(path, value) {
  const temp = `${path}.${randomUUID()}.tmp`;
  // Windows FlushFileBuffers requires a writable handle. Flush the descriptor that
  // wrote the bytes rather than reopening the file read-only after writing.
  const fd = openSync(temp, "wx");
  try { writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`); fsyncSync(fd); }
  finally { closeSync(fd); }
  renameSync(temp, path);
}
const atomicJson = writeCheckpointAtomic;
export function validateManifest(bytes, expectedSha256) {
  need(hash(expectedSha256) && digest(bytes) === expectedSha256, "Reviewed manifest digest mismatch");
  const manifest = json(bytes);
  keys(manifest, ["format", "scanner", "assessment", "items"], ["parentManifestSha256", "revision"]);
  // The summary revision the store operator assigns (the signer's nth result per key); default 1.
  if (manifest.revision !== undefined) need(Number.isSafeInteger(manifest.revision) && manifest.revision >= 1, "Invalid summary revision; expected a positive safe integer");
  need(manifest.format === "aih-scan-prepared/1", "Unsupported prepared manifest format");
  if (manifest.parentManifestSha256 !== undefined) need(hash(manifest.parentManifestSha256), "Invalid parent manifest digest");
  keys(manifest.scanner, ["name", "version", "tarballSha256"]);
  need(manifest.scanner.name === "@aihq/scan" && /^\d+\.\d+\.\d+(?:-dev\.\d+)?$/.test(manifest.scanner.version) && hash(manifest.scanner.tarballSha256), "Invalid scanner identity");
  const assessment = manifest.assessment;
  keys(assessment, ["mode", "tools"], ["provider", "baseUrl", "model", "effort", "profile", "reasoningEffort", "structuredOutputMethod", "credentialVariable", "llmConcurrency", "modelTokenLimits", "skillspector"]);
  need(["static", "ai"].includes(assessment.mode) && Array.isArray(assessment.tools) && assessment.tools.length > 0 && assessment.tools.every((tool) => ["skillspector", "aih-trust-lint", "cisco"].includes(tool)) && new Set(assessment.tools).size === assessment.tools.length, "Invalid requested assessment");
  need(assessment.tools.includes("skillspector") && assessment.tools.includes("aih-trust-lint"), "Prepared assessment requires the primary tools");
  if (assessment.profile !== undefined) {
    need(assessment.profile === "adaptive-ssd/1" && assessment.mode === "ai" &&
      assessment.provider === "kimi_cli" && assessment.model === "k3" && assessment.effort === "max",
      "Adaptive SSD requires the Kimi CLI with K3 at max effort");
  }
  if (assessment.mode === "ai" && isAgentProvider(assessment.provider)) {
    // A signed-in agent CLI: the operator's own sign-in, an explicit model and effort, no HTTP controls.
    if (assessment.provider === "kimi_cli") {
      need(assessment.model === "kimi-for-coding" || (assessment.model === "k3" && assessment.effort === "max"), "Prepared Kimi CLI AI requires model kimi-for-coding or k3 at max effort");
      need(KIMI_EFFORTS.includes(assessment.effort), `Prepared Kimi CLI AI requires an explicit effort: ${KIMI_EFFORTS.join(", ")}`);
    } else {
      need(typeof assessment.model === "string" && assessment.model.length <= 128 && PINNED_CLAUDE_MODEL.test(assessment.model), "Prepared agent-CLI AI requires an exact, pinned Claude model id (for example claude-opus-5-5), not an alias or default; no model fallback");
      need(AGENT_EFFORTS.includes(assessment.effort), `Prepared agent-CLI AI requires an explicit effort: ${AGENT_EFFORTS.join(", ")}`);
    }
    need(["baseUrl", "credentialVariable", "reasoningEffort", "structuredOutputMethod", "skillspector"].every((key) => assessment[key] === undefined), "Prepared agent-CLI AI must not name HTTP-provider or maintenance controls");
  } else if (assessment.mode === "ai") {
    need(assessment.provider === "openai_compatible" && typeof assessment.model === "string" && assessment.model.length > 0 && assessment.model.length <= 256 && plainText(assessment.model), "Prepared AI requires an explicitly selected HTTP provider/model or a supported agent CLI; no model fallback");
    need(assessment.effort === undefined, "Agent-CLI effort does not apply to an HTTP provider");
    const endpoint = new URL(assessment.baseUrl);
    const loopback = loopbackHost(endpoint.hostname);
    need(endpoint.protocol === "https:" || endpoint.protocol === "http:" && loopback, "AI endpoint must be HTTPS or loopback HTTP");
    need(!endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash, "AI endpoint must not contain credentials or query parameters");
    need(typeof assessment.reasoningEffort === "string" && /^[a-z0-9_-]{1,64}$/i.test(assessment.reasoningEffort) && ["function_calling", "json_mode", "json_schema"].includes(assessment.structuredOutputMethod), "Invalid explicit AI response controls");
    if (assessment.credentialVariable !== undefined) need(/^[A-Z_][A-Z0-9_]*$/.test(assessment.credentialVariable), "Invalid credential variable name");
    if (assessment.skillspector !== undefined) {
      keys(assessment.skillspector, ["version", "wheelSha256", "tp4"]);
      need(assessment.skillspector.version === maintenanceArtifact.version && assessment.skillspector.wheelSha256 === maintenanceArtifact.wheelSha256, "Unsupported maintenance analyzer identity");
      keys(assessment.skillspector.tp4, ["maxFiles", "maxFindings", "maxBatches"]);
      need(Object.values(assessment.skillspector.tp4).every((value) => Number.isSafeInteger(value) && value > 0 && value <= 4096), "Invalid TP4 capacity; expected integers from 1 to 4096");
    }
  } else {
    need(Object.keys(assessment).every((field) => ["mode", "tools", "skillspector"].includes(field)), "Static assessment must not name AI controls");
    if (assessment.skillspector !== undefined) {
      keys(assessment.skillspector, ["version", "wheelSha256"]);
      const reviewed = json(readRegular(fileURLToPath(staticArtifactUrl)));
      need(/^2\.13\.7\+aih\.static\.1\.[a-f0-9]{64}$/.test(reviewed.version) && hash(reviewed.wheelSha256) &&
        assessment.skillspector.version === reviewed.version && assessment.skillspector.wheelSha256 === reviewed.wheelSha256,
        "Unsupported reviewed static analyzer identity");
    }
  }
  if (assessment.llmConcurrency !== undefined) need(Number.isSafeInteger(assessment.llmConcurrency) && assessment.llmConcurrency > 0, "Invalid AI LLM concurrency; expected a positive safe integer");
  if (assessment.modelTokenLimits !== undefined) {
    const limits = assessment.modelTokenLimits;
    keys(limits, ["contextLength", "maxOutputTokens"]);
    need([limits.contextLength, limits.maxOutputTokens].every((value) => Number.isSafeInteger(value) && value > 0), "Invalid model token limits; expected positive safe integers");
    need(limits.maxOutputTokens <= limits.contextLength, "Model output token limit exceeds its context length");
  }
  need(Array.isArray(manifest.items) && manifest.items.length > 0, "Prepared manifest has no items");
  const roots = new Set();
  for (const item of manifest.items) {
    keys(item, ["path", "scanKey", "files"], ["labels", "source"]);
    safePath(item.path); need(!roots.has(item.path), "Repeated item root"); roots.add(item.path);
    need(/^git-sha(?:1:[0-9a-f]{40}|256:[0-9a-f]{64})$/.test(item.scanKey), "Invalid expected scan key");
    need(Array.isArray(item.files), "Missing file inventory");
    const paths = new Set();
    for (const file of item.files) {
      keys(file, ["path", "mode", "sha256"]); safePath(file.path);
      need(["100644", "100755"].includes(file.mode) && hash(file.sha256) && !paths.has(file.path), "Invalid file inventory"); paths.add(file.path);
    }
    if (item.labels !== undefined) need(object(item.labels) && Object.entries(item.labels).every(([key, value]) => typeof value === "string" && key.length <= 256 && value.length <= 4096 && plainText(key + value)), "Invalid unsigned caller labels");
    if (item.source !== undefined) { keys(item.source, ["locator", "revision"]); need(Object.values(item.source).every((value) => typeof value === "string" && value.length > 0 && value.length <= 4096 && plainText(value)), "Invalid unsigned source pin"); }
  }
  for (const root of roots) need(![...roots].some((other) => other !== root && root.startsWith(`${other}/`)), "Item roots must not overlap");
  return manifest;
}
export async function loadRuntime(consumer, tarball, scanner, assessment) {
  const bytes = readRegular(tarball);
  need(digest(bytes) === scanner.tarballSha256, "Scanner tarball digest mismatch");
  const unpacked = readArchive(gunzipSync(bytes, { maxOutputLength: MAX_ARCHIVE_BYTES }));
  const packageRoot = resolve(consumer, "node_modules/@aihq/scan");
  const expected = [];
  for (const [path, entry] of unpacked) {
    need(path.startsWith("package/"), "Scanner archive has an unexpected root");
    if (entry.type !== "file") continue;
    const local = safePath(path.slice(8)); expected.push(local);
    need(digest(readRegular(join(packageRoot, ...local.split("/")))) === digest(entry.bytes), "Installed scanner differs from reviewed tarball");
  }
  need(canonical(regularFiles(packageRoot).map(({ path }) => path).sort()) === canonical(expected.sort()), "Installed scanner file set differs from tarball");
  const manifest = json(readRegular(join(packageRoot, "package.json")));
  need(manifest.name === scanner.name && manifest.version === scanner.version, "Installed scanner identity mismatch");
  if (assessment?.mode === "static" && assessment.skillspector !== undefined) {
    const artifact = unpacked.get(`package/${staticArtifactPath}`);
    need(artifact?.type === "file" && artifact.bytes.equals(readRegular(fileURLToPath(staticArtifactUrl))),
      "Scanner tarball does not contain the reviewed static analyzer pin");
  }
  const host = await import(pathToFileURL(join(packageRoot, "dist/public/host.js")).href);
  const read = await import(pathToFileURL(join(packageRoot, "dist/public/read.js")).href);
  const contracts = await import(pathToFileURL(join(packageRoot, "dist/public/contracts.js")).href);
  need(contracts.packageIdentity.name === scanner.name && contracts.packageIdentity.version === scanner.version, "Public scanner identity mismatch");
  return { host, read, contracts };
}
export async function validateContent(manifest, root, runtime) {
  const groups = new Map();
  need(lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink(), "Expected a real content directory");
  for (const item of manifest.items) {
    let parent = root;
    for (const segment of item.path.split("/")) { parent = join(parent, segment); need(lstatSync(parent).isDirectory() && !lstatSync(parent).isSymbolicLink(), "Prepared root contains a link"); }
    const actual = regularFiles(parent);
    need(actual.length === item.files.length && actual.every(({ path }) => item.files.some((file) => file.path === path)), "Prepared item has an incomplete or extra inventory");
    need(item.files.length <= runtime.contracts.limits.input.files, "Item exceeds scanner file limit");
    const tree = []; let size = 0;
    for (const file of item.files) {
      const local = `${item.path}/${file.path}`;
      const path = join(root, ...local.split("/"));
      const bytes = readRegular(path, runtime.contracts.limits.input.fileBytes); size += bytes.length;
      need(digest(bytes) === file.sha256, "Prepared file digest mismatch");
      if (process.platform !== "win32") need(((lstatSync(path).mode & 0o111) ? "100755" : "100644") === file.mode, "Prepared file mode mismatch");
      tree.push({ path: file.path, mode: file.mode, bytes: new Uint8Array(bytes) });
    }
    need(size <= runtime.contracts.limits.input.sourceBytes, "Item exceeds scanner source limit");
    const key = await runtime.contracts.scanKeyOf(tree, item.scanKey.startsWith("git-sha256:") ? "sha256" : "sha1");
    need(key.status === "ok" && key.scanKey === item.scanKey, "Prepared scan key mismatch");
    const prior = groups.get(item.scanKey);
    if (prior) need(fingerprint(prior[0].files.slice().sort((a,b) => a.path < b.path ? -1 : 1)) === fingerprint(item.files.slice().sort((a,b) => a.path < b.path ? -1 : 1)), "A key names different byte/mode inventories");
    groups.set(item.scanKey, [...(prior ?? []), item]);
  }
  return groups;
}
function configIdentity(manifest, runtime) {
  // An explicit revision changes every summary's bytes, so it is part of the configuration; omitting it keeps existing identities.
  return { scanner: manifest.scanner, assessment: manifest.assessment, ...revisionOf(manifest), routing: runtime.contracts.routing.format, scoring: runtime.contracts.scoring.format };
}
const toolRan = (tool) => ["pass", "warn", "fail"].includes(tool?.result);
const requestedToolsFinished = (summary, manifest) => manifest.assessment.tools.every((id) => { const tool = summary.tools.find((entry) => entry.tool === id); return toolRan(tool) || tool?.result === "not-applicable"; });
export function aiEligible(summary, manifest) {
  if (manifest.assessment.mode !== "ai" || summary.coverage !== "complete" || summary.origin !== "published") return false;
  const primary = summary.tools.find((tool) => tool.tool === "skillspector");
  if (primary?.version !== (manifest.assessment.skillspector?.version ?? standardSkillSpectorVersion) || primary?.mode !== "ai" || !["pass", "warn", "fail"].includes(primary.result) || primary.ai?.provider !== manifest.assessment.provider || primary.ai.model !== manifest.assessment.model || primary.ai.profile !== manifest.assessment.profile) return false;
  if (isAgentProvider(manifest.assessment.provider)) {
    // Honest agent-CLI provenance: the exact model and effort Scan applied and the client it ran.
    const client = primary.ai.client;
    if (primary.ai.via !== "cli" || primary.ai.effort !== manifest.assessment.effort || !object(client) || client.name !== AGENT_CLIENTS[manifest.assessment.provider] || typeof client.version !== "string" || !client.version || (client.name === "kimi" && client.version !== KIMI_VERSION)) return false;
  } else {
    const endpoint = new URL(manifest.assessment.baseUrl), host = endpoint.hostname;
    if (primary.ai.via !== (loopbackHost(host) ? "local" : "provider")) return false;
  }
  return requestedToolsFinished(summary, manifest);
}
export function staticEligible(summary, manifest) {
  if (manifest.assessment.mode !== "static" || summary.coverage !== "complete" || summary.origin !== "published") return false;
  const primary = summary.tools.find((tool) => tool.tool === "skillspector");
  if (primary?.version !== (manifest.assessment.skillspector?.version ?? standardSkillSpectorVersion) || primary.mode !== "static" || primary.ai !== undefined || !toolRan(primary)) return false;
  return requestedToolsFinished(summary, manifest);
}
export function eligibleEvidence(summary, manifest) {
  return manifest.assessment.mode === "static" ? staticEligible(summary, manifest) : aiEligible(summary, manifest);
}
/** The receipt status of a complete result: `complete-ai` keeps its meaning; static evidence is `complete-static`. */
const completeStatus = (assessment) => assessment.mode === "static" ? "complete-static" : "complete-ai";
const COMPLETE = new Set(["complete-ai", "complete-static"]);

const partialReviewFile = "partial-review.json";
function readPartialReview(bytes, expectedSha256) {
  need(hash(expectedSha256) && digest(bytes) === expectedSha256, "Reviewed partial publication digest mismatch");
  const review = json(bytes);
  keys(review, ["format", "receiptSha256", "results"]);
  need(review.format === "aih-scan-prepared-partial-review/1" && hash(review.receiptSha256) &&
    object(review.results) && Object.keys(review.results).length > 0, "Invalid partial publication review");
  for (const entry of Object.values(review.results)) {
    keys(entry, ["summarySha256", "reason", "limitation", "completePathEvidenceSha256"]);
    need(hash(entry.summarySha256) && hash(entry.completePathEvidenceSha256) &&
      [entry.reason, entry.limitation].every((value) => typeof value === "string" &&
        value.trim().length > 0 && value.length <= 4096 && plainText(value)),
    "Invalid reviewed partial evidence or limitation");
  }
  return review;
}

function readCompletePathEvidence(root, scanKey, expectedSha256) {
  const path = `complete-path-evidence/${expectedSha256}.json`;
  const bytes = readRegular(join(root, ...path.split("/")));
  need(digest(bytes) === expectedSha256, "Complete-path evidence digest mismatch");
  const evidence = json(bytes);
  keys(evidence, ["format", "scanKey", "attempts"]);
  need(evidence.format === "aih-scan-complete-path-evidence/1" && evidence.scanKey === scanKey &&
    Array.isArray(evidence.attempts) && evidence.attempts.length > 0, "Invalid complete-path evidence");
  for (const attempt of evidence.attempts) {
    keys(attempt, ["receiptSha256", "summarySha256", "analyzerVersion", "coverage", "reason"]);
    need(hash(attempt.receiptSha256) && hash(attempt.summarySha256) && attempt.coverage === "partial" &&
      [attempt.analyzerVersion, attempt.reason].every((value) => typeof value === "string" &&
        value.trim().length > 0 && value.length <= 4096 && plainText(value)), "Invalid incomplete assessment attempt");
  }
  return { path, bytes, attempts: evidence.attempts };
}

function verifyPublishable(verified, record, manifest, review, originalReceiptSha256, evidence) {
  if (review === undefined) {
    need(verified.eligible, "Only complete evidence is eligible for prepared publishing");
    return;
  }
  const { summary } = verified;
  const assessment = manifest.assessment;
  const primary = summary.tools.find(({ tool }) => tool === "skillspector");
  const trustLint = summary.tools.find(({ tool }) => tool === "aih-trust-lint");
  need(record.status === "incomplete" && summary.coverage === "partial" &&
    summary.origin === "published" && summary.reason === "failed" && assessment.mode === "static" &&
    primary?.version === (assessment.skillspector?.version ?? standardSkillSpectorVersion) &&
    toolRan(primary) && toolRan(trustLint) && requestedToolsFinished(summary, manifest) &&
    summary.tools.length === assessment.tools.length &&
    summary.tools.every((tool) => tool.mode === "static" && tool.ai === undefined),
  "Reviewed partial publication requires retained static analyzer outputs");
  need(review.summarySha256 === record.summarySha256 && review.reason === summary.reason,
    "Partial publication review does not match the original summary");
  need(evidence.attempts.some((attempt) => attempt.receiptSha256 === originalReceiptSha256 &&
    attempt.summarySha256 === record.summarySha256 && attempt.reason === summary.reason &&
    attempt.analyzerVersion === primary.version), "Complete-path evidence does not match the retained assessment");
}

export async function verifyResult(root, record, items, manifest, content, runtime, requireToolOutputs = false) {
  keys(record, ["status", "summary", "summarySha256", "sarif", "elapsedMs"], ["detail", "notes"]);
  if (record.notes !== undefined) need(Array.isArray(record.notes) && record.notes.length <= 32 && record.notes.every((note) => typeof note === "string" && note.length > 0 && note.length <= 4096 && plainText(note)), "Invalid unsigned diagnostic notes");
  safePath(record.summary); need(hash(record.summarySha256) && Array.isArray(record.sarif) && (record.elapsedMs === null || typeof record.elapsedMs === "number" && Number.isFinite(record.elapsedMs) && record.elapsedMs >= 0), "Invalid result receipt");
  const bytes = readRegular(join(root, ...record.summary.split("/")), runtime.contracts.limits.output.summaryBytes);
  need(digest(bytes) === record.summarySha256, "Summary digest mismatch");
  const read = runtime.read.readSummary(new Uint8Array(bytes)); need(read.status === "ok", "Invalid result summary");
  const summary = read.summary;
  need(summary.scanKey === items[0].scanKey && summary.scanner === `${manifest.scanner.name} ${manifest.scanner.version}`, "Result key or scanner mismatch");
  need(summary.revision === (manifest.revision ?? 1), "Result revision mismatch");
  const inventory = (files) => files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })).sort((a,b)=>a.path < b.path ? -1 : 1);
  need(items.every((item) => canonical(inventory(item.files)) === canonical(inventory(summary.files))), "Summary differs from reviewed path/mode/hash inventory");
  const expectedSarif = summary.sarif.map((entry) => ({ path: `${record.summary.slice(0, -12)}${entry.path}`, sha256: entry.sha256 })).sort((a,b)=>a.path < b.path ? -1 : 1);
  need(canonical(record.sarif.slice().sort((a,b)=>a.path < b.path ? -1 : 1)) === canonical(expectedSarif), "SARIF inventory mismatch");
  const sarifTools = new Set();
  for (const entry of record.sarif) {
    safePath(entry.path);
    const sarif = readRegular(join(root, ...entry.path.split("/")), runtime.contracts.limits.output.sarifBytes);
    need(digest(sarif) === entry.sha256, "SARIF digest mismatch");
    const checked = await runtime.read.readFindings(summary, new Uint8Array(sarif), summary.scanKey);
    need(checked.status === "ok", "SARIF findings mismatch");
    if (requireToolOutputs) {
      const runs = json(sarif).runs;
      const run = runs[0];
      const driver = run?.tool?.driver;
      const tool = summary.tools.find(({ tool }) => tool === driver?.name);
      need(runs.length === 1 && toolRan(tool) && driver.version === tool.version &&
        !sarifTools.has(tool.tool) && run.invocations?.length === 1 &&
        run.invocations[0]?.executionSuccessful === true, "Partial publication requires original per-tool SARIF");
      const counts = {};
      for (const finding of checked.findings) {
        const severity = finding.severity.toLowerCase();
        counts[severity] = (counts[severity] ?? 0) + 1;
      }
      need(canonical(counts) === canonical(tool.counts), "Partial publication SARIF counts differ from the summary");
      sarifTools.add(tool.tool);
    }
  }
  if (requireToolOutputs) need(summary.tools.every((tool) => sarifTools.has(tool.tool) === toolRan(tool)),
    "Partial publication requires every completed tool's SARIF");
  for (const item of content ? items : []) {
    const folder = join(content, ...item.path.split("/")), actual = regularFiles(folder);
    need(actual.length === item.files.length && actual.every(({ path }) => item.files.some((file) => file.path === path)), "Prepared inventory changed before matching");
    const files = item.files.map((file) => {
      const path = join(folder, ...file.path.split("/"));
      if (process.platform !== "win32") need(((lstatSync(path).mode & 0o111) ? "100755" : "100644") === file.mode, "Prepared mode changed before matching");
      return { path: file.path, mode: file.mode, bytes: new Uint8Array(readRegular(path, runtime.contracts.limits.input.fileBytes)) };
    });
    const match = await runtime.read.matchScan(summary, files);
    need(match.status === "ok" && match.matches === true, "Result does not match the complete prepared inventory");
  }
  const eligible = eligibleEvidence(summary, manifest);
  need(record.status === (eligible ? completeStatus(manifest.assessment) : "incomplete"), "Result eligibility was misreported");
  return { summary, eligible };
}
function diagnosticNotes(item, assessment) {
  const credential = assessment.mode === "ai" && assessment.provider === "openai_compatible" ? process.env.SKILLSPECTOR_COMPAT_API_KEY : undefined;
  // Python's str.strip also removes NEL and the four ASCII information separators.
  const whitespace = (character) => character.trim() === "" || character === "\u0085" || character.codePointAt(0) >= 28 && character.codePointAt(0) <= 31;
  const characters = [...(credential ?? "")];
  let start = 0, end = characters.length;
  while (start < end && whitespace(characters[start])) start++;
  while (end > start && whitespace(characters[end - 1])) end--;
  const strippedCredential = characters.slice(start, end).join("");
  const credentials = [...new Set([credential, strippedCredential].filter(Boolean))];
  const notes = [...(item?.notes ?? []), ...(item?.status !== "ok" && item?.reason ? [`${item.reason}${item.detail ? `: ${item.detail}` : ""}`] : [])];
  // Redact before normalizing or bounding text, so neither truncation nor a control
  // character in a credential can leave part of its value in an unsigned receipt.
  return [...new Set(notes.filter((note) => typeof note === "string").map((note) => [...credentials.reduce((text, secret) => text.split(secret).join("[REDACTED]"), note)].map((character) => plainText(character) ? character : " ").join("").slice(0, 4096)).filter(Boolean))].slice(0, 32);
}
async function worker(requestPath) {
  const controller = new AbortController();
  const batching = process.connected && await new Promise((resolveBatching) => {
    process.once("disconnect", () => { controller.abort(); resolveBatching(undefined); });
    process.on("message", (message) => {
      if (message?.cancel === true) controller.abort();
      if (message?.start === true) resolveBatching(message.batching);
    });
  });
  const job = json(readRegular(requestPath));
  const runtime = await loadRuntime(job.consumer, job.tarball, job.scanner, job.assessment);
  const started = Date.now();
  const request = { format: "aih-scan-request/1", origin: "published", mode: job.assessment.mode, tools: job.assessment.tools, ...revisionOf(job), items: [{ path: job.folder, executable: job.item.files.filter((file) => file.mode === "100755").map((file) => file.path) }] };
  const options = { outDir: job.out, signal: controller.signal };
  let result;
  if (batching) {
    need(Number.isSafeInteger(batching.port) && batching.port > 0 && batching.port <= 65535 && hash(batching.token), "Invalid prepared batching handoff");
    const adapter = resolve(job.consumer, "node_modules/@aihq/scan/dist/host/scan.js");
    const { scanWith } = await import(pathToFileURL(adapter).href);
    result = await scanWith(request, options, { preparedBatching: batching });
  } else result = await runtime.host.scan(request, options);
  const item = result.results[0];
  let record;
  if (item?.status !== "ok") record = { status: "failed", detail: result.status, elapsedMs: Date.now() - started };
  else {
    const summary = runtime.read.readSummary(new Uint8Array(readRegular(item.summaryPath)));
    need(summary.status === "ok", "Worker returned an invalid summary");
    record = { status: eligibleEvidence(summary.summary, { assessment: job.assessment }) ? completeStatus(job.assessment) : "incomplete", summary: item.summaryPath, summarySha256: digest(readRegular(item.summaryPath)), sarif: summary.summary.sarif.map((entry) => ({ path: join(dirname(item.summaryPath), ...entry.path.split("/")), sha256: entry.sha256 })), elapsedMs: Date.now() - started };
  }
  const notes = COMPLETE.has(record.status) ? [] : diagnosticNotes(item, job.assessment);
  if (notes.length) record.notes = notes;
  const stateRoot = resolve(dirname(requestPath), "../..");
  const durable = record.summary ? { ...record, summary: relative(stateRoot, record.summary).split(sep).join("/"), sarif: record.sarif.map((entry) => ({ ...entry, path: relative(stateRoot, entry.path).split(sep).join("/") })) } : record;
  const receiptPath = join(dirname(requestPath), "result.json");
  need(!existsSync(receiptPath), "Attempt result already exists");
  writeCheckpointAtomic(receiptPath, { format: "aih-scan-prepared-attempt/1", configSha256: fingerprint(configIdentity({ scanner: job.scanner, assessment: job.assessment, revision: job.revision }, runtime)), scanKey: job.item.scanKey, record: durable });
  return record;
}
function childEnvironment(assessment, scratch, ssdSocket) {
  const allowed = new Set(["PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "LANG", "LC_ALL", "LC_CTYPE", "AIH_SCAN_SKILLSPECTOR", "AIH_SCAN_SKILL_SCANNER"]);
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (allowed.has(key.toUpperCase())) env[key] = value;
  Object.assign(env, { HOME: scratch, USERPROFILE: scratch, APPDATA: scratch, LOCALAPPDATA: scratch, TEMP: scratch, TMP: scratch, TMPDIR: scratch });
  if (assessment.mode === "static" && assessment.skillspector !== undefined)
    env[staticWheelVariable] = process.env[staticWheelVariable];
  if (assessment.mode === "ai" && isAgentProvider(assessment.provider)) {
    // The signed-in CLI reads the operator's own sign-in from their HOME; no credential value is handled.
    need(process.platform !== "win32", "Prepared agent-CLI AI needs a POSIX host");
    need(typeof process.env.HOME === "string" && process.env.HOME.startsWith("/"), "HOME is not set; the signed-in AI CLI cannot be used");
    // PYTHONNOUSERSITE keeps the operator's user site-packages out of the analyzer child.
    Object.assign(env, { HOME: process.env.HOME, PYTHONNOUSERSITE: "1", SKILLSPECTOR_PROVIDER: assessment.provider, SKILLSPECTOR_MODEL: assessment.model, AIH_SCAN_AI_EFFORT: assessment.effort });
    if (assessment.profile === "adaptive-ssd/1") {
      need(typeof ssdSocket === "string" && posix.isAbsolute(ssdSocket), "Adaptive SSD coordinator unavailable");
      env.AIH_SCAN_AI_PROFILE = assessment.profile;
      env.AIH_SCAN_SSD_SOCKET = ssdSocket;
    }
    if (assessment.provider === "kimi_cli") {
      if (process.env.KIMI_CODE_HOME !== undefined) env.KIMI_CODE_HOME = process.env.KIMI_CODE_HOME;
      if (process.env.AIH_SCAN_KIMI_REGION !== undefined) env.AIH_SCAN_KIMI_REGION = process.env.AIH_SCAN_KIMI_REGION;
    }
  } else if (assessment.mode === "ai") {
    const variable = assessment.credentialVariable ?? "SKILLSPECTOR_COMPAT_API_KEY";
    need(typeof process.env[variable] === "string" && process.env[variable].trim(), `${variable} is not set; no AI request started`);
    Object.assign(env, { SKILLSPECTOR_PROVIDER: assessment.provider, SKILLSPECTOR_COMPAT_BASE_URL: assessment.baseUrl, SKILLSPECTOR_COMPAT_API_KEY: process.env[variable], SKILLSPECTOR_MODEL: assessment.model, SKILLSPECTOR_REASONING_EFFORT: assessment.reasoningEffort, SKILLSPECTOR_STRUCTURED_OUTPUT_METHOD: assessment.structuredOutputMethod });
    if (assessment.skillspector !== undefined) {
      const { maxFiles, maxFindings, maxBatches } = assessment.skillspector.tp4;
      Object.assign(env, { SKILLSPECTOR_TP4_MAX_FILES: String(maxFiles), SKILLSPECTOR_TP4_MAX_FINDINGS: String(maxFindings), SKILLSPECTOR_TP4_MAX_BATCHES: String(maxBatches) });
    }
  }
  if (assessment.llmConcurrency !== undefined) env.SKILLSPECTOR_MAX_LLM_CONCURRENCY = String(assessment.llmConcurrency);
  if (assessment.modelTokenLimits !== undefined) {
    const registryPath = resolve(scratch, "model-registry.json");
    writeJson(registryPath, { models: { [assessment.model]: { context_length: assessment.modelTokenLimits.contextLength, max_output_tokens: assessment.modelTokenLimits.maxOutputTokens } } });
    env.SKILLSPECTOR_MODEL_REGISTRY = registryPath;
  }
  return env;
}
function launch(jobPath, assessment, signal, ssdSocket, batching) {
  return new Promise((resolveResult, reject) => {
    const child = fork(new URL(import.meta.url), ["worker", jobPath], { env: childEnvironment(assessment, dirname(jobPath), ssdSocket), windowsHide: true, silent: true, execArgv: [] });
    let result; let stderrBytes = 0;
    const cancel = () => { if (child.connected) child.send({ cancel: true }); };
    signal.addEventListener("abort", cancel, { once: true });
    child.stdout.resume(); child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes > 1024 * 1024) cancel(); });
    child.once("message", (value) => { result = value; });
    child.once("error", reject);
    child.once("exit", (code) => { signal.removeEventListener("abort", cancel); if (code === 0 && result) resolveResult(result); else resolveResult({ status: "failed", detail: "worker-failed", elapsedMs: 0 }); });
    child.send({ start: true, ...(batching ? { batching: { port: batching.port, token: batching.token } } : {}) });
  });
}
function acquireLock(folder) {
  const path = join(folder, "run.lock"), token = randomUUID();
  if (existsSync(path)) {
    const owner = json(readRegular(path));
    need(owner.host === hostname() && Number.isInteger(owner.pid), "Another host owns this checkpoint");
    let alive = true; try { process.kill(owner.pid, 0); } catch (error) { if (error.code === "ESRCH") alive = false; }
    need(!alive, "Another prepared scan owns this checkpoint");
    need(json(readRegular(path)).token === owner.token, "Checkpoint lock changed");
    renameSync(path, `${path}.abandoned-${randomUUID()}`);
  }
  writeJson(path, { host: hostname(), pid: process.pid, token });
  const owned = () => need(existsSync(path) && json(readRegular(path)).token === token, "Checkpoint ownership changed");
  return { owned, release() { owned(); rmSync(path); } };
}
async function recoverTemporaryCheckpoints(root, checkpoint, groups, manifest, content, runtime) {
  let recovered = 0, ignored = 0;
  const adopt = async (key, record) => {
    if (!groups.has(key) || !COMPLETE.has(record.status)) return;
    await verifyResult(root, record, groups.get(key), manifest, content, runtime);
    const prior = checkpoint.results[key];
    if (COMPLETE.has(prior?.status)) {
      await verifyResult(root, prior, groups.get(key), manifest, content, runtime);
      need(prior.summarySha256 === record.summarySha256, "Conflicting completed checkpoint records; retain both for review");
    } else { checkpoint.results[key] = record; recovered++; }
  };
  for (const name of readdirSync(root).sort()) {
    if (!name.startsWith("checkpoint.json.") || !name.endsWith(".tmp")) continue;
    let temporary;
    try { temporary = json(readRegular(join(root, name))); } catch { ignored++; continue; }
    if (temporary.format !== "aih-scan-prepared-checkpoint/1" || temporary.configSha256 !== checkpoint.configSha256 || !object(temporary.results)) { ignored++; continue; }
    for (const [key, record] of Object.entries(temporary.results)) {
      await adopt(key, record);
    }
  }
  const attempts = join(root, "attempts");
  if (existsSync(attempts)) for (const name of readdirSync(attempts).sort()) {
    safePath(name);
    const attempt = join(attempts, name), stat = lstatSync(attempt);
    need(stat.isDirectory() && !stat.isSymbolicLink(), "Attempt directory is not a real directory");
    let foundDurable = false;
    for (const resultName of readdirSync(attempt).sort()) {
      if (resultName !== "result.json" && !(resultName.startsWith("result.json.") && resultName.endsWith(".tmp"))) continue;
      let value;
      try { value = json(readRegular(join(attempt, resultName))); } catch { ignored++; continue; }
      keys(value, ["format", "configSha256", "scanKey", "record"]);
      need(value.format === "aih-scan-prepared-attempt/1" && value.configSha256 === checkpoint.configSha256, "Attempt receipt configuration mismatch");
      await adopt(value.scanKey, value.record); foundDurable = true;
    }
    if (foundDurable || !existsSync(join(attempt, "request.json"))) continue;
    // Older or interrupted workers may have written complete output before their
    // durable receipt. Validate original configuration, actual bytes and complete
    // analyzer outcomes; file presence or requested AI alone never establishes success.
    const job = json(readRegular(join(attempt, "request.json"))), key = job.item?.scanKey;
    if (!groups.has(key)) continue;
    need(fingerprint(configIdentity({ scanner: job.scanner, assessment: job.assessment, revision: job.revision }, runtime)) === checkpoint.configSha256, "Orphan attempt configuration mismatch");
    const summaryPath = join(attempt, "output", runtime.contracts.keyFolderName(key), "summary.json");
    if (!existsSync(summaryPath)) continue;
    const bytes = readRegular(summaryPath), read = runtime.read.readSummary(new Uint8Array(bytes));
    need(read.status === "ok", "Orphan attempt has an invalid summary");
    const record = { status: eligibleEvidence(read.summary, manifest) ? completeStatus(manifest.assessment) : "incomplete", summary: relative(root, summaryPath).split(sep).join("/"), summarySha256: digest(bytes), sarif: read.summary.sarif.map((entry) => ({ path: relative(root, join(dirname(summaryPath), ...entry.path.split("/"))).split(sep).join("/"), sha256: entry.sha256 })), elapsedMs: null, detail: "Recovered completed output; original worker elapsed time is unavailable" };
    await adopt(key, record);
  }
  if (recovered) atomicJson(join(root, "checkpoint.json"), checkpoint);
  return { recovered, ignored };
}
export async function recoverPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out }) {
  const manifest = validateManifest(readRegular(manifestPath), manifestSha256), runtime = await loadRuntime(consumer, tarball, manifest.scanner, manifest.assessment);
  const groups = await validateContent(manifest, content, runtime), configSha256 = fingerprint(configIdentity(manifest, runtime));
  const root = join(resolve(out), "configs", configSha256); mkdirSync(root, { recursive: true });
  const lock = acquireLock(root);
  try {
    const path = join(root, "checkpoint.json");
    const checkpoint = existsSync(path) ? json(readRegular(path)) : { format: "aih-scan-prepared-checkpoint/1", configSha256, results: {} };
    need(checkpoint.format === "aih-scan-prepared-checkpoint/1" && checkpoint.configSha256 === configSha256 && object(checkpoint.results), "Invalid checkpoint configuration");
    const recovery = await recoverTemporaryCheckpoints(root, checkpoint, groups, manifest, content, runtime);
    for (const [key, items] of groups) if (COMPLETE.has(checkpoint.results[key]?.status)) await verifyResult(root, checkpoint.results[key], items, manifest, content, runtime);
    return { root, ...recovery, completedKeys: [...groups.keys()].filter((key) => COMPLETE.has(checkpoint.results[key]?.status)) };
  } finally { lock.release(); }
}
/** Outstanding estimates persist across refill waves; resident usage is not subtracted twice. */
export function workerLaunchBudget(freeMiB, reserveMiB, poolCapacityMiB, reservedMiB) {
  return Math.max(0, Math.min(freeMiB - reserveMiB, poolCapacityMiB - reservedMiB));
}
export function maintenancePythonPath(executable, platform = process.platform) {
  const path = platform === "win32" ? win32 : posix;
  return path.join(path.dirname(executable), platform === "win32" ? "python.exe" : "python");
}
function verifyMaintenanceRuntime(assessment) {
  if (assessment.skillspector === undefined) return;
  const staticBuild = assessment.mode === "static";
  const wheelVariable = staticBuild ? staticWheelVariable : "AIH_SCAN_SKILLSPECTOR_WHEEL";
  const executable = process.env.AIH_SCAN_SKILLSPECTOR, wheel = process.env[wheelVariable];
  need(typeof executable === "string" && typeof wheel === "string", "Maintenance executable and reviewed wheel paths are required");
  const binary = resolve(executable);
  need(binary === executable && (!staticBuild || resolve(wheel) === wheel) &&
    digest(readRegular(wheel, staticBuild ? 32 * 1024 * 1024 : undefined)) === assessment.skillspector.wheelSha256, "Maintenance wheel digest mismatch");
  const python = maintenancePythonPath(binary);
  const env = {};
  for (const name of ["PATH", "SYSTEMROOT", "WINDIR"]) if (process.env[name] !== undefined) env[name] = process.env[name];
  execFileSync(python, ["-I", fileURLToPath(new URL("../analyzers/skillspector/maintenance/verify.py", import.meta.url)), resolve(wheel), assessment.skillspector.wheelSha256, assessment.skillspector.version, ...(staticBuild ? ["--static-probe"] : [])], { env, windowsHide: true, timeout: 30000, stdio: "pipe" });
}
export async function scanPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out, concurrency = availableParallelism(), workerMemoryMiB = 512, reserveMemoryMiB = Math.ceil(Math.max(1024 ** 3, totalmem() / 10) / 1024 ** 2), signal = new AbortController().signal }) {
  const bytes = readRegular(manifestPath); const manifest = validateManifest(bytes, manifestSha256);
  const runtime = await loadRuntime(consumer, tarball, manifest.scanner, manifest.assessment);
  const groups = await validateContent(manifest, content, runtime);
  need(Number.isSafeInteger(concurrency) && concurrency > 0 && Number.isFinite(workerMemoryMiB) && workerMemoryMiB > 0 && Number.isFinite(reserveMemoryMiB) && reserveMemoryMiB >= 0, "Invalid concurrency or memory settings");
  verifyMaintenanceRuntime(manifest.assessment);
  const config = configIdentity(manifest, runtime), configSha256 = fingerprint(config);
  const root = join(resolve(out), "configs", configSha256); mkdirSync(root, { recursive: true });
  const lock = acquireLock(root), checkpointPath = join(root, "checkpoint.json");
  let checkpoint;
  try {
    checkpoint = existsSync(checkpointPath) ? json(readRegular(checkpointPath)) : { format: "aih-scan-prepared-checkpoint/1", configSha256, results: {} };
    need(checkpoint.format === "aih-scan-prepared-checkpoint/1" && checkpoint.configSha256 === configSha256 && object(checkpoint.results), "Invalid checkpoint configuration");
  } catch (error) { lock.release(); throw error; }
  let reused = 0, completed = 0; const pending = [], active = new Set();
  const controller = new AbortController();
  const cancel = () => controller.abort(); signal.addEventListener("abort", cancel, { once: true });
  if (signal.aborted) controller.abort();
  let broker, batching;
  try {
    const recovery = await recoverTemporaryCheckpoints(root, checkpoint, groups, manifest, content, runtime);
    for (const [key, items] of groups) {
      const record = checkpoint.results[key];
      if (COMPLETE.has(record?.status)) {
        await verifyResult(root, record, items, manifest, content, runtime); reused++;
      } else pending.push([key, items]);
    }
    if (pending.length > 1 && concurrency > 1 && !controller.signal.aborted && manifest.assessment.mode === "ai")
      batching = await startPreparedBatching(controller.signal);
    if (pending.length && !controller.signal.aborted && manifest.assessment.profile === "adaptive-ssd/1") {
      const { startAdaptiveSsd } = await import("./adaptive-ssd.mjs");
      const adapter = resolve(consumer, "node_modules/@aihq/scan/dist/host/kimi-inference.js");
      const { inferAdaptiveSsd } = await import(pathToFileURL(adapter).href);
      const contextTokens = manifest.assessment.modelTokenLimits?.contextLength ?? 262_144;
      const outputTokens = Math.min(Math.floor(contextTokens / 4), manifest.assessment.modelTokenLimits?.maxOutputTokens ?? 32_768);
      broker = await startAdaptiveSsd({
        signal: controller.signal,
        infer: (prompt, signal) => inferAdaptiveSsd(prompt, signal, root),
        contextTokens,
        outputTokens,
      });
    }
    let poolCapacityMiB = Math.max(0, freemem() / 1024 ** 2 - reserveMemoryMiB);
    while ((pending.length || active.size) && !signal.aborted) {
      // Reserve each launch estimate immediately: child RSS rises after fork, so a fresh
      // freemem reading for every launch would otherwise overcommit a whole wave.
      const freeMiB = freemem() / 1024 ** 2;
      if (!active.size) poolCapacityMiB = Math.max(0, freeMiB - reserveMemoryMiB);
      let launchBudgetMiB = workerLaunchBudget(freeMiB, reserveMemoryMiB, poolCapacityMiB, active.size * workerMemoryMiB);
      while (pending.length && active.size < concurrency && launchBudgetMiB >= workerMemoryMiB) {
        launchBudgetMiB -= workerMemoryMiB;
        const [key, items] = pending.shift(), item = items[0];
        const id = randomUUID(), work = join(root, "attempts", id); mkdirSync(work, { recursive: true });
        const requestPath = join(work, "request.json");
        writeJson(requestPath, { scanner: manifest.scanner, assessment: manifest.assessment, ...revisionOf(manifest), consumer: resolve(consumer), tarball: resolve(tarball), folder: resolve(content, ...item.path.split("/")), item, out: join(work, "output") });
        const job = launch(requestPath, manifest.assessment, controller.signal, broker?.socketPath, batching).then(async (record) => {
          if (record.summary) {
            record.summary = relative(root, record.summary).split(sep).join("/");
            record.sarif = record.sarif.map((entry) => ({ ...entry, path: relative(root, entry.path).split(sep).join("/") }));
            await verifyResult(root, record, items, manifest, content, runtime);
          }
          lock.owned(); checkpoint.results[key] = record; atomicJson(checkpointPath, checkpoint); completed++;
        }).finally(() => active.delete(job));
        active.add(job);
      }
      if (active.size) await Promise.race(active);
      else if (pending.length && !signal.aborted) break; // Memory pressure leaves explicit pending keys for the next resume.
    }
    await Promise.all(active);
    lock.owned(); atomicJson(checkpointPath, checkpoint);
    const adaptiveStats = broker ? { adaptiveSsd: broker.stats() } : {};
    const receipt = { format: "aih-scan-prepared-receipt/1", execution: "local", manifestSha256, config, configSha256, scheduler: { concurrency, workerMemoryMiB, reserveMemoryMiB }, ...adaptiveStats, results: Object.fromEntries([...groups.keys()].map((key) => [key, checkpoint.results[key] ?? { status: "pending" }])) };
    const receiptPath = join(root, `receipt-${randomUUID()}.json`); writeJson(receiptPath, receipt);
    return { receiptPath, receiptSha256: digest(readRegular(receiptPath)), manifestSha256, root, reused, completed, recovered: recovery.recovered, pending: pending.length, uniqueKeys: groups.size, references: manifest.items.length, cancelled: signal.aborted, ...adaptiveStats };
  } catch (error) { controller.abort(); await Promise.allSettled(active); throw error; }
  finally {
    signal.removeEventListener("abort", cancel);
    try { await Promise.all([broker?.close(), batching?.close()]); } finally { lock.release(); }
  }
}
export async function verifyCandidate(candidate, manifestSha256, receiptSha256, consumer, tarball, partialReviewSha256) {
  const manifestBytes = readRegular(join(candidate, "manifest.json"));
  const manifest = validateManifest(manifestBytes, manifestSha256), receiptBytes = readRegular(join(candidate, "receipt.json"));
  need(hash(receiptSha256) && digest(receiptBytes) === receiptSha256, "Reviewed receipt digest mismatch");
  const receipt = json(receiptBytes), runtime = await loadRuntime(consumer, tarball, manifest.scanner, manifest.assessment);
  keys(receipt, ["format", "execution", "manifestSha256", "config", "configSha256", "results"], ["partialReviewSha256"]);
  need(receipt.format === "aih-scan-prepared-receipt/1" && receipt.execution === "local" && receipt.manifestSha256 === manifestSha256 && receipt.configSha256 === fingerprint(configIdentity(manifest, runtime)) && fingerprint(receipt.config) === receipt.configSha256, "Candidate configuration/provenance mismatch");
  need(receipt.partialReviewSha256 === partialReviewSha256, "Prepared partial publication opt-in mismatch");
  // Hosted intake checks reviewed inventory metadata, not reconstructed source bytes.
  // Actual-byte scanKeyOf/matchScan validation happens locally before export.
  const groups = new Map();
  for (const item of manifest.items) groups.set(item.scanKey, [...(groups.get(item.scanKey) ?? []), item]);
  need(object(receipt.results) && canonical(Object.keys(receipt.results).sort()) === canonical([...groups.keys()].sort()), "Candidate result inventory mismatch");
  const expected = new Set(["manifest.json", "receipt.json", "scanner.tgz"]);
  let partialReview;
  if (partialReviewSha256 !== undefined) {
    partialReview = readPartialReview(readRegular(join(candidate, partialReviewFile)), partialReviewSha256);
    need(canonical(Object.keys(partialReview.results).sort()) === canonical([...groups.keys()].sort()), "Partial publication review key inventory mismatch");
    expected.add(partialReviewFile);
  }
  if (existsSync(join(candidate, "prepared-import.json"))) {
    const imported = json(readRegular(join(candidate, "prepared-import.json")));
    keys(imported, ["execution", "archiveSha256", "manifestSha256", "receiptSha256"], ["producerSha256", "partialReviewSha256"]);
    if (imported.producerSha256 !== undefined) need(hash(imported.producerSha256), "Invalid producer context digest");
    need(imported.execution === "local" && hash(imported.archiveSha256) && imported.manifestSha256 === manifestSha256 && imported.receiptSha256 === receiptSha256 && imported.partialReviewSha256 === partialReviewSha256, "Prepared import receipt mismatch");
    expected.add("prepared-import.json");
  }
  for (const [key, items] of groups) {
    const record = receipt.results[key];
    const verified = await verifyResult(candidate, record, items, manifest, undefined, runtime, partialReview !== undefined);
    const review = partialReview?.results[key];
    const evidence = review && readCompletePathEvidence(candidate, key, review.completePathEvidenceSha256);
    verifyPublishable(verified, record, manifest, review, partialReview?.receiptSha256, evidence);
    if (evidence) expected.add(evidence.path);
    expected.add(record.summary); for (const sarif of record.sarif) expected.add(sarif.path);
  }
  const actual = regularFiles(candidate);
  need(actual.length === expected.size && actual.every(({ path }) => expected.has(path)), "Unexpected candidate files");
  need(digest(readRegular(join(candidate, "scanner.tgz"))) === manifest.scanner.tarballSha256, "Candidate scanner archive mismatch");
  return { manifest, receipt, summaries: [...groups.keys()].map((key) => receipt.results[key].summary) };
}
/** Merge copied immutable worker receipts, never mutable indexes. Every reused key is reverified. */
export async function mergePrepared({ manifestPath, manifestSha256, content, consumer, tarball, out, receipts }) {
  const manifest = validateManifest(readRegular(manifestPath), manifestSha256);
  const runtime = await loadRuntime(consumer, tarball, manifest.scanner, manifest.assessment), groups = await validateContent(manifest, content, runtime);
  const config = configIdentity(manifest, runtime), configSha256 = fingerprint(config);
  const root = join(resolve(out), "configs", configSha256); mkdirSync(root, { recursive: true });
  const lock = acquireLock(root), checkpointPath = join(root, "checkpoint.json");
  const checkpoint = existsSync(checkpointPath) ? json(readRegular(checkpointPath)) : { format: "aih-scan-prepared-checkpoint/1", configSha256, results: {} };
  need(checkpoint.format === "aih-scan-prepared-checkpoint/1" && checkpoint.configSha256 === configSha256 && object(checkpoint.results), "Invalid destination checkpoint");
  let imported = 0;
  try {
    for (const receiptPath of receipts) {
      const source = json(readRegular(receiptPath)), sourceRoot = dirname(receiptPath);
      need(source.format === "aih-scan-prepared-receipt/1" && source.execution === "local" && source.configSha256 === configSha256 && fingerprint(source.config) === configSha256 && object(source.results), "Merge configuration mismatch");
      for (const [key, record] of Object.entries(source.results)) {
        if (!groups.has(key) || !COMPLETE.has(record.status)) continue;
        await verifyResult(sourceRoot, record, groups.get(key), manifest, content, runtime);
        const prior = checkpoint.results[key];
        if (COMPLETE.has(prior?.status)) {
          await verifyResult(root, prior, groups.get(key), manifest, content, runtime);
          need(prior.summarySha256 === record.summarySha256 && canonical(prior.sarif.map(({ sha256 }) => sha256).sort()) === canonical(record.sarif.map(({ sha256 }) => sha256).sort()), "Conflicting completed results for the same key; retain both for review");
          continue;
        }
        const prefix = `attempts/merged-${randomUUID()}/${runtime.contracts.keyFolderName(key)}`;
        const moved = { ...record, summary: `${prefix}/summary.json`, sarif: record.sarif.map((entry) => ({ path: `${prefix}/sarif/${entry.path.split("/").at(-1)}`, sha256: entry.sha256 })) };
        const copies = [{ from: record.summary, to: moved.summary, sha256: record.summarySha256 }, ...record.sarif.map((entry, index) => ({ from: entry.path, to: moved.sarif[index].path, sha256: entry.sha256 }))];
        for (const entry of copies) {
          const bytes = readRegular(join(sourceRoot, ...entry.from.split("/"))); need(digest(bytes) === entry.sha256, "Merge source changed");
          const target = join(root, ...entry.to.split("/")); mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, bytes, { flag: "wx" });
        }
        await verifyResult(root, moved, groups.get(key), manifest, content, runtime);
        lock.owned(); checkpoint.results[key] = moved; atomicJson(checkpointPath, checkpoint); imported++;
      }
    }
    return { root, imported, configSha256 };
  } finally { lock.release(); }
}
export async function exportCandidate({ manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, selection, partialReviewPath, partialReviewSha256 }) {
  const bytes = readRegular(manifestPath), original = validateManifest(bytes, manifestSha256);
  const receiptBytes = readRegular(receiptPath), receipt = json(receiptBytes);
  const runtime = await loadRuntime(consumer, tarball, original.scanner, original.assessment), groups = await validateContent(original, content, runtime);
  need(receipt.configSha256 === fingerprint(configIdentity(original, runtime)) && receipt.manifestSha256 === manifestSha256, "Export receipt configuration mismatch");
  let partialReviewBytes, partialReview;
  if (partialReviewPath !== undefined || partialReviewSha256 !== undefined) {
    need(partialReviewPath && !selection, "Partial publication requires an exclusive reviewed selection");
    partialReviewBytes = readRegular(partialReviewPath);
    partialReview = readPartialReview(partialReviewBytes, partialReviewSha256);
    need(partialReview.receiptSha256 === digest(receiptBytes) && receipt.format === "aih-scan-prepared-receipt/1" &&
      receipt.execution === "local" && fingerprint(receipt.config) === receipt.configSha256 && object(receipt.results),
    "Partial publication review does not match the original receipt");
  }
  const chosen = partialReview ? Object.keys(partialReview.results) : selection ?? [...groups.keys()];
  need(Array.isArray(chosen) && chosen.length && new Set(chosen).size === chosen.length && chosen.every((key) => groups.has(key)), "Invalid explicit key selection");
  const manifest = { ...original, parentManifestSha256: manifestSha256, items: original.items.filter((item) => chosen.includes(item.scanKey)) };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`), batchSha256 = digest(manifestBytes);
  const scannerBytes = readRegular(tarball); need(digest(scannerBytes) === original.scanner.tarballSha256, "Scanner tarball changed during export");
  const root = dirname(receiptPath), results = {}, entries = [{ path: "manifest.json", bytes: manifestBytes }, { path: "scanner.tgz", bytes: scannerBytes }];
  if (partialReviewBytes) {
    entries.push({ path: partialReviewFile, bytes: partialReviewBytes });
    const checkpointPath = join(root, "checkpoint.json");
    if (existsSync(checkpointPath)) {
      const checkpoint = json(readRegular(checkpointPath));
      need(checkpoint.format === "aih-scan-prepared-checkpoint/1" &&
        checkpoint.configSha256 === receipt.configSha256 && object(checkpoint.results), "Invalid partial publication checkpoint");
      need(chosen.every((key) => !COMPLETE.has(checkpoint.results[key]?.status)),
        "Complete evidence already exists in the prepared checkpoint");
    }
  }
  for (const key of chosen) {
    const record = receipt.results[key];
    if (partialReview) need(record?.status === "incomplete", "Selected key has no retained incomplete result");
    else need(record?.status === completeStatus(manifest.assessment), `Selected key has no complete ${manifest.assessment.mode === "static" ? "static" : "AI"} result`);
    const verified = await verifyResult(root, record, groups.get(key), original, content, runtime, partialReview !== undefined);
    const review = partialReview?.results[key];
    const evidence = review && readCompletePathEvidence(dirname(partialReviewPath), key, review.completePathEvidenceSha256);
    verifyPublishable(verified, record, original, review, partialReview?.receiptSha256, evidence);
    if (evidence) entries.push({ path: evidence.path, bytes: evidence.bytes });
    const prefix = `targets/${runtime.contracts.keyFolderName(key)}`;
    const exported = { ...record, summary: `${prefix}/summary.json`, sarif: record.sarif.map((entry) => ({ path: `${prefix}/sarif/${entry.path.split("/").at(-1)}`, sha256: entry.sha256 })) };
    delete exported.notes;
    if (partialReview) delete exported.detail;
    results[key] = exported;
    const summaryBytes = readRegular(join(root, ...record.summary.split("/"))); need(digest(summaryBytes) === record.summarySha256, "Summary changed during export");
    entries.push({ path: exported.summary, bytes: summaryBytes });
    record.sarif.forEach((entry, index) => { const bytes = readRegular(join(root, ...entry.path.split("/"))); need(digest(bytes) === entry.sha256, "SARIF changed during export"); entries.push({ path: exported.sarif[index].path, bytes }); });
  }
  const exportedReceipt = { format: "aih-scan-prepared-receipt/1", execution: "local", manifestSha256: batchSha256, config: configIdentity(manifest, runtime), configSha256: fingerprint(configIdentity(manifest, runtime)), results, ...(partialReview ? { partialReviewSha256 } : {}) };
  const exportedReceiptBytes = Buffer.from(`${JSON.stringify(exportedReceipt, null, 2)}\n`); entries.push({ path: "receipt.json", bytes: exportedReceiptBytes });
  const archive = writeArchive(entries, out);
  return { archiveSha256: archive.sha256, bytes: archive.bytes, manifestSha256: batchSha256, receiptSha256: digest(exportedReceiptBytes), keys: chosen.length, references: manifest.items.length, ...(partialReview ? { partialReviewSha256 } : {}) };
}
export async function importCandidate(archive, archiveSha256, manifestSha256, receiptSha256, consumer, out, partialReviewSha256) {
  const bytes = readRegular(archive); need(hash(archiveSha256) && digest(bytes) === archiveSha256, "Candidate archive digest mismatch");
  extractArchive(bytes, out);
  return verifyCandidate(out, manifestSha256, receiptSha256, consumer, join(out, "scanner.tgz"), partialReviewSha256);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const [command, ...args] = process.argv.slice(2);
  try {
    if (command === "worker" && args.length === 1) { const result = await worker(args[0]); if (process.send) process.send(result); if (process.connected) process.disconnect(); }
    else {
      let result;
      if (command === "validate" && args.length === 5) { const [path, sha, content, consumer, tarball] = args; const manifest = validateManifest(readRegular(path), sha); const runtime = await loadRuntime(consumer, tarball, manifest.scanner, manifest.assessment); const groups = await validateContent(manifest, content, runtime); result = { references: manifest.items.length, uniqueKeys: groups.size }; }
      else if (command === "scan" && args.length >= 6 && args.length <= 9) { const [manifestPath, manifestSha256, content, consumer, tarball, out, concurrency, memory, reserve] = args; const controller = new AbortController(); process.once("SIGINT", () => controller.abort()); process.once("SIGTERM", () => controller.abort()); result = await scanPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out, ...(concurrency ? { concurrency: Number(concurrency) } : {}), ...(memory ? { workerMemoryMiB: Number(memory) } : {}), ...(reserve ? { reserveMemoryMiB: Number(reserve) } : {}), signal: controller.signal }); }
      else if (command === "verify" && [5, 6].includes(args.length)) { const verified = await verifyCandidate(...args); result = { execution: "local", summaries: verified.summaries }; }
      else if (command === "archive" && args.length >= 7 && args.length <= 8) { const [manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, selectionPath] = args; result = await exportCandidate({ manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, ...(selectionPath ? { selection: json(readRegular(selectionPath)) } : {}) }); }
      else if (command === "archive-partial" && args.length === 9) { const [manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, partialReviewPath, partialReviewSha256] = args; result = await exportCandidate({ manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, partialReviewPath, partialReviewSha256 }); }
      else if (command === "merge" && args.length === 7) { const [manifestPath, manifestSha256, content, consumer, tarball, out, receiptList] = args; result = await mergePrepared({ manifestPath, manifestSha256, content, consumer, tarball, out, receipts: json(readRegular(receiptList)) }); }
      else if (command === "recover" && args.length === 6) { const [manifestPath, manifestSha256, content, consumer, tarball, out] = args; result = await recoverPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out }); }
      else if (command === "import" && [6, 7].includes(args.length)) { const verified = await importCandidate(...args); result = { execution: "local", summaries: verified.summaries }; }
      else throw new Error("usage: prepared.mjs validate|scan|verify|archive|archive-partial|import <documented positional arguments>");
      process.stdout.write(`${JSON.stringify(result)}\n`);
    }
  } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : "Prepared operation failed"}\n`); process.exitCode = 1; }
}
