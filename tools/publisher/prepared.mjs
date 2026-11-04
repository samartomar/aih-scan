// Tooling-only prepared-content handoff. Caller labels and local execution receipts are unsigned.
import { fork } from "node:child_process";
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { availableParallelism, freemem, hostname, totalmem } from "node:os";
import { isIP } from "node:net";
import { dirname, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { digest, extractArchive, MAX_ARCHIVE_BYTES, need, plainText, readArchive, safePath, writeArchive } from "./prepared-archive.mjs";

const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hash = (value) => /^[0-9a-f]{64}$/.test(value ?? "");
const loopbackHost = (host) => host === "localhost" || host === "[::1]" || isIP(host) === 4 && host.startsWith("127.");
const canonical = (value) => JSON.stringify(Array.isArray(value) ? value.map((entry) => JSON.parse(canonical(entry))) : object(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, JSON.parse(canonical(value[key]))])) : value);
const fingerprint = (value) => digest(canonical(value));
function keys(value, required, optional = []) {
  need(object(value) && required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => [...required, ...optional].includes(key)), "Unexpected or missing manifest fields");
}
export function regularFiles(root) {
  const result = [];
  const rootStat = lstatSync(root);
  need(rootStat.isDirectory() && !rootStat.isSymbolicLink(), "Expected a real directory");
  const walk = (folder) => {
    for (const entry of readdirSync(folder).sort()) {
      const path = join(folder, entry), stat = lstatSync(path);
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
  keys(manifest, ["format", "scanner", "assessment", "items"], ["parentManifestSha256"]);
  need(manifest.format === "aih-scan-prepared/1", "Unsupported prepared manifest format");
  if (manifest.parentManifestSha256 !== undefined) need(hash(manifest.parentManifestSha256), "Invalid parent manifest digest");
  keys(manifest.scanner, ["name", "version", "tarballSha256"]);
  need(manifest.scanner.name === "@aihq/scan" && /^\d+\.\d+\.\d+$/.test(manifest.scanner.version) && hash(manifest.scanner.tarballSha256), "Invalid scanner identity");
  const assessment = manifest.assessment;
  keys(assessment, ["mode", "tools"], ["provider", "baseUrl", "model", "reasoningEffort", "structuredOutputMethod", "credentialVariable"]);
  need(["static", "ai"].includes(assessment.mode) && Array.isArray(assessment.tools) && assessment.tools.length > 0 && assessment.tools.every((tool) => ["skillspector", "aih-trust-lint", "cisco"].includes(tool)) && new Set(assessment.tools).size === assessment.tools.length, "Invalid requested assessment");
  need(assessment.tools.includes("skillspector") && assessment.tools.includes("aih-trust-lint"), "Prepared assessment requires the primary tools");
  if (assessment.mode === "ai") {
    need(assessment.provider === "openai_compatible" && typeof assessment.model === "string" && assessment.model.length > 0 && assessment.model.length <= 256 && plainText(assessment.model), "Prepared AI requires an explicitly selected HTTP provider/model; no agent CLI or model fallback");
    const endpoint = new URL(assessment.baseUrl);
    const loopback = loopbackHost(endpoint.hostname);
    need(endpoint.protocol === "https:" || endpoint.protocol === "http:" && loopback, "AI endpoint must be HTTPS or loopback HTTP");
    need(!endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash, "AI endpoint must not contain credentials or query parameters");
    need(typeof assessment.reasoningEffort === "string" && /^[a-z0-9_-]{1,64}$/i.test(assessment.reasoningEffort) && ["function_calling", "json_mode", "json_schema"].includes(assessment.structuredOutputMethod), "Invalid explicit AI response controls");
    if (assessment.credentialVariable !== undefined) need(/^[A-Z_][A-Z0-9_]*$/.test(assessment.credentialVariable), "Invalid credential variable name");
  } else need(Object.keys(assessment).length === 2, "Static assessment must not name AI controls");
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
export async function loadRuntime(consumer, tarball, scanner) {
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
  return { scanner: manifest.scanner, assessment: manifest.assessment, routing: runtime.contracts.routing.format, scoring: runtime.contracts.scoring.format };
}
export function aiEligible(summary, manifest) {
  if (manifest.assessment.mode !== "ai" || summary.coverage !== "complete" || summary.origin !== "published") return false;
  const primary = summary.tools.find((tool) => tool.tool === "skillspector");
  const endpoint = new URL(manifest.assessment.baseUrl), host = endpoint.hostname;
  const via = loopbackHost(host) ? "local" : "provider";
  if (primary?.mode !== "ai" || !["pass", "warn", "fail"].includes(primary.result) || primary.ai?.via !== via || primary.ai.provider !== manifest.assessment.provider || primary.ai.model !== manifest.assessment.model) return false;
  return manifest.assessment.tools.every((id) => { const tool = summary.tools.find((entry) => entry.tool === id); return tool && ["pass", "warn", "fail", "not-applicable"].includes(tool.result); });
}
export async function verifyResult(root, record, items, manifest, content, runtime) {
  keys(record, ["status", "summary", "summarySha256", "sarif", "elapsedMs"], ["detail"]);
  safePath(record.summary); need(hash(record.summarySha256) && Array.isArray(record.sarif) && (record.elapsedMs === null || typeof record.elapsedMs === "number" && Number.isFinite(record.elapsedMs) && record.elapsedMs >= 0), "Invalid result receipt");
  const bytes = readRegular(join(root, ...record.summary.split("/")), runtime.contracts.limits.output.summaryBytes);
  need(digest(bytes) === record.summarySha256, "Summary digest mismatch");
  const read = runtime.read.readSummary(new Uint8Array(bytes)); need(read.status === "ok", "Invalid result summary");
  const summary = read.summary;
  need(summary.scanKey === items[0].scanKey && summary.scanner === `${manifest.scanner.name} ${manifest.scanner.version}`, "Result key or scanner mismatch");
  const inventory = (files) => files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })).sort((a,b)=>a.path < b.path ? -1 : 1);
  need(items.every((item) => canonical(inventory(item.files)) === canonical(inventory(summary.files))), "Summary differs from reviewed path/mode/hash inventory");
  const expectedSarif = summary.sarif.map((entry) => ({ path: `${record.summary.slice(0, -12)}${entry.path}`, sha256: entry.sha256 })).sort((a,b)=>a.path < b.path ? -1 : 1);
  need(canonical(record.sarif.slice().sort((a,b)=>a.path < b.path ? -1 : 1)) === canonical(expectedSarif), "SARIF inventory mismatch");
  for (const entry of record.sarif) {
    safePath(entry.path);
    const sarif = readRegular(join(root, ...entry.path.split("/")), runtime.contracts.limits.output.sarifBytes);
    need(digest(sarif) === entry.sha256 && (await runtime.read.readFindings(summary, new Uint8Array(sarif), summary.scanKey)).status === "ok", "SARIF digest or findings mismatch");
  }
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
  const eligible = aiEligible(summary, manifest);
  need(record.status === (eligible ? "complete-ai" : "incomplete"), "Result eligibility was misreported");
  return { summary, eligible };
}
async function worker(requestPath) {
  const job = json(readRegular(requestPath));
  const runtime = await loadRuntime(job.consumer, job.tarball, job.scanner);
  const controller = new AbortController(); process.once("disconnect", () => controller.abort()); process.on("message", () => controller.abort());
  const started = Date.now();
  const result = await runtime.host.scan({ format: "aih-scan-request/1", origin: "published", mode: job.assessment.mode, tools: job.assessment.tools, items: [{ path: job.folder, executable: job.item.files.filter((file) => file.mode === "100755").map((file) => file.path) }] }, { outDir: job.out, signal: controller.signal });
  const item = result.results[0];
  if (item?.status !== "ok") return { status: "failed", detail: result.status, elapsedMs: Date.now() - started };
  const summary = runtime.read.readSummary(new Uint8Array(readRegular(item.summaryPath)));
  need(summary.status === "ok", "Worker returned an invalid summary");
  const record = { status: aiEligible(summary.summary, { assessment: job.assessment }) ? "complete-ai" : "incomplete", summary: item.summaryPath, summarySha256: digest(readRegular(item.summaryPath)), sarif: summary.summary.sarif.map((entry) => ({ path: join(dirname(item.summaryPath), ...entry.path.split("/")), sha256: entry.sha256 })), elapsedMs: Date.now() - started };
  const stateRoot = resolve(dirname(requestPath), "../..");
  const durable = { ...record, summary: relative(stateRoot, record.summary).split(sep).join("/"), sarif: record.sarif.map((entry) => ({ ...entry, path: relative(stateRoot, entry.path).split(sep).join("/") })) };
  const receiptPath = join(dirname(requestPath), "result.json");
  need(!existsSync(receiptPath), "Attempt result already exists");
  writeCheckpointAtomic(receiptPath, { format: "aih-scan-prepared-attempt/1", configSha256: fingerprint(configIdentity({ scanner: job.scanner, assessment: job.assessment }, runtime)), scanKey: job.item.scanKey, record: durable });
  return record;
}
function childEnvironment(assessment, scratch) {
  const allowed = new Set(["PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "LANG", "LC_ALL", "LC_CTYPE", "AIH_SCAN_SKILLSPECTOR", "AIH_SCAN_SKILL_SCANNER"]);
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (allowed.has(key.toUpperCase())) env[key] = value;
  Object.assign(env, { HOME: scratch, USERPROFILE: scratch, APPDATA: scratch, LOCALAPPDATA: scratch, TEMP: scratch, TMP: scratch, TMPDIR: scratch });
  if (assessment.mode === "ai") {
    const variable = assessment.credentialVariable ?? "SKILLSPECTOR_COMPAT_API_KEY";
    need(typeof process.env[variable] === "string" && process.env[variable].trim(), `${variable} is not set; no AI request started`);
    Object.assign(env, { SKILLSPECTOR_PROVIDER: assessment.provider, SKILLSPECTOR_COMPAT_BASE_URL: assessment.baseUrl, SKILLSPECTOR_COMPAT_API_KEY: process.env[variable], SKILLSPECTOR_MODEL: assessment.model, SKILLSPECTOR_REASONING_EFFORT: assessment.reasoningEffort, SKILLSPECTOR_STRUCTURED_OUTPUT_METHOD: assessment.structuredOutputMethod });
  }
  return env;
}
function launch(jobPath, assessment, signal) {
  return new Promise((resolveResult, reject) => {
    const child = fork(new URL(import.meta.url), ["worker", jobPath], { env: childEnvironment(assessment, dirname(jobPath)), windowsHide: true, silent: true, execArgv: [] });
    let result; let stderrBytes = 0;
    const cancel = () => { if (child.connected) child.send({ cancel: true }); };
    signal.addEventListener("abort", cancel, { once: true });
    child.stdout.resume(); child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes > 1024 * 1024) cancel(); });
    child.once("message", (value) => { result = value; });
    child.once("error", reject);
    child.once("exit", (code) => { signal.removeEventListener("abort", cancel); if (code === 0 && result) resolveResult(result); else resolveResult({ status: "failed", detail: "worker-failed", elapsedMs: 0 }); });
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
    if (!groups.has(key) || record.status !== "complete-ai") return;
    await verifyResult(root, record, groups.get(key), manifest, content, runtime);
    const prior = checkpoint.results[key];
    if (prior?.status === "complete-ai") {
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
    need(fingerprint(configIdentity({ scanner: job.scanner, assessment: job.assessment }, runtime)) === checkpoint.configSha256, "Orphan attempt configuration mismatch");
    const summaryPath = join(attempt, "output", runtime.contracts.keyFolderName(key), "summary.json");
    if (!existsSync(summaryPath)) continue;
    const bytes = readRegular(summaryPath), read = runtime.read.readSummary(new Uint8Array(bytes));
    need(read.status === "ok", "Orphan attempt has an invalid summary");
    const record = { status: aiEligible(read.summary, manifest) ? "complete-ai" : "incomplete", summary: relative(root, summaryPath).split(sep).join("/"), summarySha256: digest(bytes), sarif: read.summary.sarif.map((entry) => ({ path: relative(root, join(dirname(summaryPath), ...entry.path.split("/"))).split(sep).join("/"), sha256: entry.sha256 })), elapsedMs: null, detail: "Recovered completed output; original worker elapsed time is unavailable" };
    await adopt(key, record);
  }
  if (recovered) atomicJson(join(root, "checkpoint.json"), checkpoint);
  return { recovered, ignored };
}
export async function recoverPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out }) {
  const manifest = validateManifest(readRegular(manifestPath), manifestSha256), runtime = await loadRuntime(consumer, tarball, manifest.scanner);
  const groups = await validateContent(manifest, content, runtime), configSha256 = fingerprint(configIdentity(manifest, runtime));
  const root = join(resolve(out), "configs", configSha256); mkdirSync(root, { recursive: true });
  const lock = acquireLock(root);
  try {
    const path = join(root, "checkpoint.json");
    const checkpoint = existsSync(path) ? json(readRegular(path)) : { format: "aih-scan-prepared-checkpoint/1", configSha256, results: {} };
    need(checkpoint.format === "aih-scan-prepared-checkpoint/1" && checkpoint.configSha256 === configSha256 && object(checkpoint.results), "Invalid checkpoint configuration");
    const recovery = await recoverTemporaryCheckpoints(root, checkpoint, groups, manifest, content, runtime);
    for (const [key, items] of groups) if (checkpoint.results[key]?.status === "complete-ai") await verifyResult(root, checkpoint.results[key], items, manifest, content, runtime);
    return { root, ...recovery, completedKeys: [...groups.keys()].filter((key) => checkpoint.results[key]?.status === "complete-ai") };
  } finally { lock.release(); }
}
/** Outstanding estimates persist across refill waves; resident usage is not subtracted twice. */
export function workerLaunchBudget(freeMiB, reserveMiB, poolCapacityMiB, reservedMiB) {
  return Math.max(0, Math.min(freeMiB - reserveMiB, poolCapacityMiB - reservedMiB));
}
export async function scanPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out, concurrency = availableParallelism(), workerMemoryMiB = 512, reserveMemoryMiB = Math.ceil(Math.max(1024 ** 3, totalmem() / 10) / 1024 ** 2), signal = new AbortController().signal }) {
  const bytes = readRegular(manifestPath); const manifest = validateManifest(bytes, manifestSha256);
  const runtime = await loadRuntime(consumer, tarball, manifest.scanner);
  const groups = await validateContent(manifest, content, runtime);
  need(Number.isSafeInteger(concurrency) && concurrency > 0 && Number.isFinite(workerMemoryMiB) && workerMemoryMiB > 0 && Number.isFinite(reserveMemoryMiB) && reserveMemoryMiB >= 0, "Invalid concurrency or memory settings");
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
  try {
    const recovery = await recoverTemporaryCheckpoints(root, checkpoint, groups, manifest, content, runtime);
    for (const [key, items] of groups) {
      const record = checkpoint.results[key];
      if (record?.status === "complete-ai") {
        await verifyResult(root, record, items, manifest, content, runtime); reused++;
      } else pending.push([key, items]);
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
        writeJson(requestPath, { scanner: manifest.scanner, assessment: manifest.assessment, consumer: resolve(consumer), tarball: resolve(tarball), folder: resolve(content, ...item.path.split("/")), item, out: join(work, "output") });
        const job = launch(requestPath, manifest.assessment, controller.signal).then(async (record) => {
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
    const receipt = { format: "aih-scan-prepared-receipt/1", execution: "local", manifestSha256, config, configSha256, scheduler: { concurrency, workerMemoryMiB, reserveMemoryMiB }, results: Object.fromEntries([...groups.keys()].map((key) => [key, checkpoint.results[key] ?? { status: "pending" }])) };
    const receiptPath = join(root, `receipt-${randomUUID()}.json`); writeJson(receiptPath, receipt);
    return { receiptPath, receiptSha256: digest(readRegular(receiptPath)), manifestSha256, root, reused, completed, recovered: recovery.recovered, pending: pending.length, uniqueKeys: groups.size, references: manifest.items.length, cancelled: signal.aborted };
  } catch (error) { controller.abort(); await Promise.allSettled(active); throw error; }
  finally { signal.removeEventListener("abort", cancel); lock.release(); }
}
export async function verifyCandidate(candidate, manifestSha256, receiptSha256, consumer, tarball) {
  const manifestBytes = readRegular(join(candidate, "manifest.json"));
  const manifest = validateManifest(manifestBytes, manifestSha256), receiptBytes = readRegular(join(candidate, "receipt.json"));
  need(hash(receiptSha256) && digest(receiptBytes) === receiptSha256, "Reviewed receipt digest mismatch");
  const receipt = json(receiptBytes), runtime = await loadRuntime(consumer, tarball, manifest.scanner);
  keys(receipt, ["format", "execution", "manifestSha256", "config", "configSha256", "results"]);
  need(receipt.format === "aih-scan-prepared-receipt/1" && receipt.execution === "local" && receipt.manifestSha256 === manifestSha256 && receipt.configSha256 === fingerprint(configIdentity(manifest, runtime)) && fingerprint(receipt.config) === receipt.configSha256, "Candidate configuration/provenance mismatch");
  // Hosted intake checks reviewed inventory metadata, not reconstructed source bytes.
  // Actual-byte scanKeyOf/matchScan validation happens locally before export.
  const groups = new Map();
  for (const item of manifest.items) groups.set(item.scanKey, [...(groups.get(item.scanKey) ?? []), item]);
  need(object(receipt.results) && canonical(Object.keys(receipt.results).sort()) === canonical([...groups.keys()].sort()), "Candidate result inventory mismatch");
  const expected = new Set(["manifest.json", "receipt.json", "scanner.tgz"]);
  if (existsSync(join(candidate, "prepared-import.json"))) {
    const imported = json(readRegular(join(candidate, "prepared-import.json")));
    keys(imported, ["execution", "archiveSha256", "manifestSha256", "receiptSha256"]);
    need(imported.execution === "local" && hash(imported.archiveSha256) && imported.manifestSha256 === manifestSha256 && imported.receiptSha256 === receiptSha256, "Prepared import receipt mismatch");
    expected.add("prepared-import.json");
  }
  for (const [key, items] of groups) {
    const record = receipt.results[key];
    need(record.status === "complete-ai", "Only completed AI evidence is eligible for prepared publishing");
    const verified = await verifyResult(candidate, record, items, manifest, undefined, runtime);
    need(verified.eligible, "Prepared AI evidence is incomplete");
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
  const runtime = await loadRuntime(consumer, tarball, manifest.scanner), groups = await validateContent(manifest, content, runtime);
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
        if (!groups.has(key) || record.status !== "complete-ai") continue;
        await verifyResult(sourceRoot, record, groups.get(key), manifest, content, runtime);
        const prior = checkpoint.results[key];
        if (prior?.status === "complete-ai") {
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
export async function exportCandidate({ manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, selection }) {
  const bytes = readRegular(manifestPath), original = validateManifest(bytes, manifestSha256), receipt = json(readRegular(receiptPath));
  const runtime = await loadRuntime(consumer, tarball, original.scanner), groups = await validateContent(original, content, runtime);
  need(receipt.configSha256 === fingerprint(configIdentity(original, runtime)) && receipt.manifestSha256 === manifestSha256, "Export receipt configuration mismatch");
  const chosen = selection ?? [...groups.keys()];
  need(Array.isArray(chosen) && chosen.length && new Set(chosen).size === chosen.length && chosen.every((key) => groups.has(key)), "Invalid explicit key selection");
  const manifest = { ...original, parentManifestSha256: manifestSha256, items: original.items.filter((item) => chosen.includes(item.scanKey)) };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`), batchSha256 = digest(manifestBytes);
  const scannerBytes = readRegular(tarball); need(digest(scannerBytes) === original.scanner.tarballSha256, "Scanner tarball changed during export");
  const root = dirname(receiptPath), results = {}, entries = [{ path: "manifest.json", bytes: manifestBytes }, { path: "scanner.tgz", bytes: scannerBytes }];
  for (const key of chosen) {
    const record = receipt.results[key]; need(record?.status === "complete-ai", "Selected key has no complete AI result");
    await verifyResult(root, record, groups.get(key), original, content, runtime);
    const prefix = `targets/${runtime.contracts.keyFolderName(key)}`;
    const exported = { ...record, summary: `${prefix}/summary.json`, sarif: record.sarif.map((entry) => ({ path: `${prefix}/sarif/${entry.path.split("/").at(-1)}`, sha256: entry.sha256 })) };
    results[key] = exported;
    const summaryBytes = readRegular(join(root, ...record.summary.split("/"))); need(digest(summaryBytes) === record.summarySha256, "Summary changed during export");
    entries.push({ path: exported.summary, bytes: summaryBytes });
    record.sarif.forEach((entry, index) => { const bytes = readRegular(join(root, ...entry.path.split("/"))); need(digest(bytes) === entry.sha256, "SARIF changed during export"); entries.push({ path: exported.sarif[index].path, bytes }); });
  }
  const exportedReceipt = { format: "aih-scan-prepared-receipt/1", execution: "local", manifestSha256: batchSha256, config: configIdentity(manifest, runtime), configSha256: fingerprint(configIdentity(manifest, runtime)), results };
  const receiptBytes = Buffer.from(`${JSON.stringify(exportedReceipt, null, 2)}\n`); entries.push({ path: "receipt.json", bytes: receiptBytes });
  const archive = writeArchive(entries, out);
  return { archiveSha256: archive.sha256, bytes: archive.bytes, manifestSha256: batchSha256, receiptSha256: digest(receiptBytes), keys: chosen.length, references: manifest.items.length };
}
export async function importCandidate(archive, archiveSha256, manifestSha256, receiptSha256, consumer, out) {
  const bytes = readRegular(archive); need(hash(archiveSha256) && digest(bytes) === archiveSha256, "Candidate archive digest mismatch");
  extractArchive(bytes, out);
  return verifyCandidate(out, manifestSha256, receiptSha256, consumer, join(out, "scanner.tgz"));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const [command, ...args] = process.argv.slice(2);
  try {
    if (command === "worker" && args.length === 1) { const result = await worker(args[0]); if (process.send) process.send(result); if (process.connected) process.disconnect(); }
    else {
      let result;
      if (command === "validate" && args.length === 5) { const [path, sha, content, consumer, tarball] = args; const manifest = validateManifest(readRegular(path), sha); const runtime = await loadRuntime(consumer, tarball, manifest.scanner); const groups = await validateContent(manifest, content, runtime); result = { references: manifest.items.length, uniqueKeys: groups.size }; }
      else if (command === "scan" && args.length >= 6 && args.length <= 9) { const [manifestPath, manifestSha256, content, consumer, tarball, out, concurrency, memory, reserve] = args; const controller = new AbortController(); process.once("SIGINT", () => controller.abort()); process.once("SIGTERM", () => controller.abort()); result = await scanPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out, ...(concurrency ? { concurrency: Number(concurrency) } : {}), ...(memory ? { workerMemoryMiB: Number(memory) } : {}), ...(reserve ? { reserveMemoryMiB: Number(reserve) } : {}), signal: controller.signal }); }
      else if (command === "verify" && args.length === 5) { const verified = await verifyCandidate(...args); result = { execution: "local", summaries: verified.summaries }; }
      else if (command === "archive" && args.length >= 7 && args.length <= 8) { const [manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, selectionPath] = args; result = await exportCandidate({ manifestPath, manifestSha256, content, consumer, tarball, receiptPath, out, ...(selectionPath ? { selection: json(readRegular(selectionPath)) } : {}) }); }
      else if (command === "merge" && args.length === 7) { const [manifestPath, manifestSha256, content, consumer, tarball, out, receiptList] = args; result = await mergePrepared({ manifestPath, manifestSha256, content, consumer, tarball, out, receipts: json(readRegular(receiptList)) }); }
      else if (command === "recover" && args.length === 6) { const [manifestPath, manifestSha256, content, consumer, tarball, out] = args; result = await recoverPrepared({ manifestPath, manifestSha256, content, consumer, tarball, out }); }
      else if (command === "import" && args.length === 6) { const verified = await importCandidate(...args); result = { execution: "local", summaries: verified.summaries }; }
      else throw new Error("usage: prepared.mjs validate|scan|verify|archive|import <documented positional arguments>");
      process.stdout.write(`${JSON.stringify(result)}\n`);
    }
  } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : "Prepared operation failed"}\n`); process.exitCode = 1; }
}
