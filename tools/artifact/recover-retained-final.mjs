// Temporary same-original transfer operation. No signing or assessment execution.
import assert from "node:assert/strict";
import { appendFileSync, mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { canonicalBytes, object, parseJson, readRegular, sha256 } from "../refresh/contracts.mjs";
import { checkRefreshRun } from "./check-refresh-run.mjs";
import { extractFinalZip } from "./extract-final-zip.mjs";
import { githubTransport } from "./publish-refresh-release.mjs";
import { measureDirectory } from "./refresh-publication.mjs";

const entered = 0; // Node's monotonic process origin includes module loading for CLI admission.
const base = "https://api.github.com/repos/samartomar/aih-scan";
const uploadedIds = new Map([
  ["consumer-package-lock.json", 623062791],
  ["custody.json", 623392024],
]);
const failedStarter = Object.freeze({
  id: 624741751,
  name: "inventory.json",
  size: 1069648,
  digest: null,
  state: "starter",
  created_at: "2026-10-09T11:14:00Z",
  updated_at: "2026-10-09T11:14:00Z",
});

export const retainedPins = Object.freeze({
  sourceHead: "53dc0cffd2704f0cefd76b53abe850651d1e9505",
  branch: "codex/scan-94-upload-framing",
  runId: "37828958516",
  artifactId: "11573028222",
  archiveBytes: 83224990,
  archiveSha256: "4a64cee9a9e3aaea1c15668c31cfe6b0d9f1f8f2a63171ff6f808beed29ab0d9",
  custodySha256: "577cfbf09915fda2df9ef649970ba0df7a9db41455d8707c0aa8fadd2ebd3cf9",
  receiptSha256: "6ed0a926604c54fd23a7aeb2999127affd2e44cb76909efc39cf7e7597893e33",
  manifestSha256: "d69505e26bfb0516ed43b0f8a96054546779cc6d4b6302442817f69b9f4247ab",
  selectionSha256: "c5193fc57c6ddc0deba91f054009c3cb3287e01507303ae189e643f45cbbe77e",
  batchId: "batch:sha256:636c1710f88f0f0e6f41beecba42252668cf30d2cd6917dadaae73a4c529c5f4",
  releaseId: 407274269,
});
export function checkRecoveryContext(context) {
  assert(
    context && context.actor === "samartomar" && context.actorId === "9993940",
    "Recovery context refused",
  );
  assert(
    context.event === "workflow_dispatch" &&
      context.repository === "samartomar/aih-scan" &&
      context.repositoryId === "1336836161" &&
      context.ownerId === "9993940",
    "Recovery context refused",
  );
  assert(
    context.triggeringActor === "samartomar" && context.attempt === "1",
    "Recovery context refused",
  );
  assert(
    context.ref === `refs/heads/${retainedPins.branch}` &&
      context.workflowRef ===
        `samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/${retainedPins.branch}`,
    "Recovery context refused",
  );
  assert(
    /^[0-9a-f]{40}$/.test(context.head) &&
      context.head === context.recoveryHead &&
      context.head !== retainedPins.sourceHead,
    "Recovery context refused",
  );
  assert(
    /^[1-9][0-9]{0,15}$/.test(context.runId) && Number.isSafeInteger(Number(context.runId)),
    "Recovery context refused",
  );
  assert(
    context.candidateRunId === "37823479906" &&
      context.manifestSha256 === retainedPins.manifestSha256 &&
      context.selectionSha256 === retainedPins.selectionSha256,
    "Recovery context refused",
  );
}
function decodeCustody(value) {
  assert(
    typeof value === "string" &&
      value.length <= 16384 &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),
    "Original custody encoding refused",
  );
  const bytes = Buffer.from(value, "base64");
  assert(
    bytes.toString("base64") === value && sha256(bytes) === retainedPins.custodySha256,
    "Original custody bytes refused",
  );
  const custody = parseJson(bytes, 8192, true);
  assert(canonicalBytes(custody).equals(bytes), "Original custody canonical bytes refused");
  return bytes;
}
function originalAssets(directory, custodyPath) {
  const receiptBytes = readRegular(join(directory, "publication.json"), 2097152);
  const receipt = parseJson(receiptBytes, 2097152, true);
  object(receipt, ["schema", "batchId", "expandedBytes", "assets"]);
  assert(
    receipt.schema === "urn:aihq:scan:publication-assets:1.0.0" &&
      receipt.batchId === retainedPins.batchId &&
      Array.isArray(receipt.assets) &&
      receipt.assets.length === 42,
    "Original receipt refused",
  );
  const assets = new Map(),
    paths = new Set(["publication.json"]);
  let total = 0;
  for (const row of receipt.assets) {
    object(row, ["path", "name", "byteLength", "sha256"]);
    assert(
      typeof row.path === "string" &&
        /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(row.path) &&
        !row.path.split("/").some((part) => part === "." || part === ".."),
      "Original path refused",
    );
    assert(
      row.name === row.path.replaceAll("/", "--") &&
        !assets.has(row.name) &&
        !paths.has(row.path) &&
        row.name !== "publication-custody.json",
      "Original name refused",
    );
    assert(
      Number.isSafeInteger(row.byteLength) &&
        row.byteLength >= 0 &&
        row.byteLength <= 128 * 1024 * 1024 &&
        /^[0-9a-f]{64}$/.test(row.sha256),
      "Original resource refused",
    );
    const bytes = readRegular(join(directory, row.path), 128 * 1024 * 1024);
    assert(
      bytes.length === row.byteLength && sha256(bytes) === row.sha256,
      "Original local bytes refused",
    );
    assets.set(row.name, { ...row, localPath: join(directory, row.path) });
    paths.add(row.path);
    total += bytes.length;
  }
  assert(
    total === receipt.expandedBytes &&
      measureDirectory(directory, paths).bytes === total + receiptBytes.length,
    "Original expanded accounting refused",
  );
  const custodyBytes = readRegular(custodyPath, 8192);
  parseJson(custodyBytes, 8192, true);
  assets.set("publication.json", {
    name: "publication.json",
    byteLength: receiptBytes.length,
    sha256: sha256(receiptBytes),
    localPath: join(directory, "publication.json"),
  });
  assets.set("publication-custody.json", {
    name: "publication-custody.json",
    byteLength: custodyBytes.length,
    sha256: sha256(custodyBytes),
    localPath: custodyPath,
  });
  assert(
    assets.size === 44 &&
      [...uploadedIds.keys()].every((name) => assets.has(name)) &&
      assets.has("inventory.json"),
    "Original closed asset set refused",
  );
  return assets;
}

function operation({
  context,
  token,
  request = fetch,
  now = () => performance.now(),
  startedAt = now(),
  audit = () => {},
}) {
  assert(typeof token === "string" && token.length > 0, "Hosted token required");
  let halted = false,
    sequence = 0,
    deletes = 0,
    uploads = 0,
    deleteReady = false,
    uploadReady = false;
  let assets = new Map();
  const ids = new Map(),
    reservedNames = new Set(),
    redirects = new Map();
  const counts = () => ({
    deletesReserved: deletes,
    uploadsReserved: uploads,
    promotionsReserved: 0,
    creationsReserved: 0,
    retries: 0,
  });
  const check = () => {
    assert(!halted, "Recovery halted");
    const left = Math.floor(25 * 60000 - (now() - startedAt));
    assert(left > 0, "Recovery deadline exhausted");
    return left;
  };
  const guarded = async (input, options = {}) => {
    check();
    const url = new URL(input),
      method = options.method ?? "GET",
      path = url.pathname + url.search;
    let maximum = 2097152,
      timeout = 30000,
      purpose = "metadata",
      uploadName,
      downloadName;
    const api = url.origin === "https://api.github.com",
      assetId = /^\/repos\/samartomar\/aih-scan\/releases\/assets\/([1-9][0-9]*)$/.exec(
        url.pathname,
      )?.[1];
    const id = ++sequence,
      began = now();
    const record = (phase, fields = {}) =>
      audit({
        sequence: id,
        phase,
        method,
        purpose,
        elapsedMs: Math.max(0, Math.round(now() - began)),
        ...counts(),
        ...fields,
      });
    try {
      assert(["GET", "DELETE", "POST"].includes(method), "Promotion/create method forbidden");
      if (method === "GET") {
        assert(options.body === undefined, "Read body forbidden");
        if (redirects.has(url.href)) {
          assert(
            new Headers(options.headers).get("authorization") === null,
            "Redirect credential forwarding forbidden",
          );
          ({ maximum, purpose, name: downloadName } = redirects.get(url.href));
          redirects.delete(url.href);
          timeout = 120000;
        } else {
          assert(api, "Read host refused");
          const suffix = path.slice("/repos/samartomar/aih-scan".length);
          const allowed = [
            "",
            "/git/ref/heads/main",
            `/releases/${retainedPins.releaseId}`,
            `/releases/assets/${failedStarter.id}`,
            `/actions/runs/${context.runId}`,
            `/actions/runs/${retainedPins.runId}`,
            `/actions/runs/${retainedPins.runId}/artifacts?per_page=100`,
          ];
          assert(
            path.startsWith("/repos/samartomar/aih-scan") &&
              (allowed.includes(suffix) ||
                /^\/releases\/407274269\/assets\?per_page=30&page=[1-3]$/.test(suffix) ||
                (assetId && ids.has(Number(assetId))) ||
                suffix === `/actions/artifacts/${retainedPins.artifactId}/zip`),
            "Read scope refused",
          );
          if (suffix === `/actions/artifacts/${retainedPins.artifactId}/zip`) {
            maximum = retainedPins.archiveBytes;
            purpose = "archive";
            timeout = 120000;
          } else if (
            assetId &&
            ids.has(Number(assetId)) &&
            new Headers(options.headers).get("accept") === "application/octet-stream"
          ) {
            downloadName = ids.get(Number(assetId));
            maximum = assets.get(downloadName).byteLength;
            purpose = "original-download";
            timeout = 120000;
          }
        }
      } else if (method === "DELETE") {
        assert(
          api &&
            url.href === `${base}/releases/assets/${failedStarter.id}` &&
            deleteReady &&
            deletes === 0 &&
            options.body === undefined,
          "Exact failed-starter deletion refused",
        );
        deletes = 1;
        purpose = "failed-starter-removal";
      } else {
        assert(
          url.origin === "https://uploads.github.com" &&
            url.pathname ===
              `/repos/samartomar/aih-scan/releases/${retainedPins.releaseId}/assets` &&
            [...url.searchParams.keys()].join(",") === "name",
          "Upload destination refused",
        );
        uploadName = url.searchParams.get("name");
        const original = assets.get(uploadName);
        assert(
          uploadReady &&
            deletes === 1 &&
            original &&
            !uploadedIds.has(uploadName) &&
            !reservedNames.has(uploadName) &&
            uploads < 42,
          "Upload reservation refused",
        );
        assert(
          Buffer.isBuffer(options.body) &&
            options.body.length === original.byteLength &&
            sha256(options.body) === original.sha256 &&
            options.body.equals(readRegular(original.localPath, 128 * 1024 * 1024)),
          "Original upload bytes refused",
        );
        reservedNames.add(uploadName);
        uploads++;
        purpose = "original-upload";
        timeout = 120000;
      }
      record("reserved");
      // Reservation and audit latency are inside the deadline. No retry follows any unknown outcome.
      const actualTimeout = Math.min(timeout, check());
      const signal = AbortSignal.timeout(actualTimeout);
      const response = await request(input, {
        ...options,
        redirect: "manual",
        signal: options.signal ? AbortSignal.any([options.signal, signal]) : signal,
      });
      check();
      const chunks = [];
      let bytesRead = 0;
      for await (const chunk of response.body ?? []) {
        check();
        bytesRead += chunk.length;
        assert(bytesRead <= maximum, "Response bound refused");
        chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks);
      record("completed", {
        httpStatus: response.status,
        responseBytes: bytes.length,
        ...(purpose === "archive" || purpose === "original-download"
          ? { sha256: sha256(bytes) }
          : {}),
      });
      check();
      if (method === "GET" && response.status === 302) {
        assert(
          api && ["archive", "original-download"].includes(purpose),
          "Unexpected redirect refused",
        );
        const location = response.headers.get("location");
        const target = new URL(location);
        assert(
          target.protocol === "https:" &&
            !target.username &&
            !target.password &&
            (purpose === "archive"
              ? /^productionresultssa[0-9]+\.blob\.core\.windows\.net$/.test(target.hostname)
              : target.hostname === "release-assets.githubusercontent.com"),
          "Signed download host refused",
        );
        redirects.set(target.href, { maximum, purpose, name: downloadName });
      } else {
        assert(
          response.status === (method === "DELETE" ? 204 : method === "POST" ? 201 : 200),
          "HTTP outcome refused",
        );
        if (method === "DELETE") assert(bytes.length === 0, "DELETE response body refused");
        if (method === "POST") {
          const remote = parseJson(bytes, 2097152),
            original = assets.get(uploadName);
          assert(
            Number.isSafeInteger(remote.id) &&
              remote.id > 0 &&
              !ids.has(remote.id) &&
              remote.id !== failedStarter.id,
            "New upload identity refused",
          );
          assert(
            remote.name === uploadName &&
              remote.state === "uploaded" &&
              remote.size === original.byteLength &&
              remote.digest === `sha256:${original.sha256}`,
            "Upload metadata refused",
          );
          ids.set(remote.id, uploadName);
        }
        if (purpose === "original-download") {
          const original = assets.get(downloadName);
          assert(
            original &&
              bytes.length === original.byteLength &&
              sha256(bytes) === original.sha256 &&
              bytes.equals(readRegular(original.localPath, 128 * 1024 * 1024)),
            "Downloaded original bytes refused",
          );
        }
      }
      check();
      return {
        status: response.status,
        ok: response.status >= 200 && response.status < 300,
        headers: response.headers,
        body: bytes.length ? [bytes] : [],
      };
    } catch {
      halted = true;
      record("stopped", { outcome: "refused-or-unknown" });
      throw new Error("Retained recovery refused or outcome unknown");
    }
  };
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "aih-scan-retained-recovery",
  };
  const get = async (path) => {
    const response = await guarded(`${base}${path}`, { headers });
    assert(response.status === 200, "Metadata status refused");
    return parseJson(Buffer.concat(response.body), 2097152);
  };
  const downloadArchive = async () => {
    let response = await guarded(`${base}/actions/artifacts/${retainedPins.artifactId}/zip`, {
      headers,
    });
    if (response.status === 302) response = await guarded(response.headers.get("location"), {});
    assert(response.status === 200);
    return Buffer.concat(response.body);
  };
  const scope = async () => {
    const repo = await get("");
    assert(
      repo.id === 1336836161 &&
        repo.full_name === "samartomar/aih-scan" &&
        repo.owner?.id === 9993940,
      "Repository scope refused",
    );
    const main = await get("/git/ref/heads/main");
    assert(
      main.ref === "refs/heads/main" &&
        main.object?.type === "commit" &&
        main.object.sha === retainedPins.sourceHead,
      "Current main differs from original source",
    );
    const run = await get(`/actions/runs/${context.runId}`);
    const actor = (value) => value?.login === "samartomar" && value.id === 9993940;
    const repository = (value) =>
      value?.id === 1336836161 &&
      value.full_name === "samartomar/aih-scan" &&
      value.owner?.id === 9993940;
    assert(
      run.id === Number(context.runId) &&
        run.run_attempt === 1 &&
        run.event === "workflow_dispatch" &&
        run.status === "in_progress" &&
        run.conclusion === null &&
        run.head_sha === context.head &&
        run.head_branch === retainedPins.branch &&
        run.path === ".github/workflows/scan-report-publisher.yml" &&
        repository(run.repository) &&
        repository(run.head_repository) &&
        actor(run.actor) &&
        actor(run.triggering_actor),
      "Hosted run custody refused",
    );
    check();
  };
  const draft = async () => {
    const release = await get(`/releases/${retainedPins.releaseId}`);
    assert(
      release.id === retainedPins.releaseId &&
        release.draft === true &&
        release.immutable === false &&
        release.target_commitish === retainedPins.sourceHead &&
        release.tag_name === `scan-report-batch-${retainedPins.batchId.slice(13)}`,
      "Original draft refused",
    );
    return release;
  };
  return {
    guarded,
    get,
    downloadArchive,
    scope,
    draft,
    check,
    counts,
    ids,
    setAssets(value) {
      assets = value;
      for (const [name, id] of uploadedIds) ids.set(id, name);
    },
    admitDelete() {
      deleteReady = true;
    },
    admitUploads() {
      uploadReady = true;
    },
    remove: () =>
      guarded(`${base}/releases/assets/${failedStarter.id}`, { method: "DELETE", headers }),
  };
}

async function transfer({ directory, custodyPath, context, token, op }) {
  const assets = originalAssets(directory, custodyPath);
  op.check();
  op.setAssets(assets);
  const transport = githubTransport({
    token,
    reviewedHead: retainedPins.sourceHead,
    fetch: op.guarded,
  });
  async function collection(expectedNames, starter = false) {
    const rows = await transport.listAssets(retainedPins.releaseId),
      names = new Set(),
      ids = new Set();
    assert(rows.length === expectedNames.length, "Closed original remote count refused");
    for (const row of rows) {
      assert(
        Number.isSafeInteger(row.id) && row.id > 0 && !ids.has(row.id) && !names.has(row.name),
        "Remote identity refused",
      );
      names.add(row.name);
      ids.add(row.id);
      if (starter && row.id === failedStarter.id) {
        for (const [key, value] of Object.entries(failedStarter))
          assert.equal(row[key], value, "Failed starter changed");
      } else {
        const original = assets.get(row.name);
        assert(
          original &&
            op.ids.get(row.id) === row.name &&
            row.state === "uploaded" &&
            row.size === original.byteLength &&
            row.digest === `sha256:${original.sha256}`,
          "Original remote metadata refused",
        );
      }
    }
    assert.deepEqual([...names].sort(), [...expectedNames].sort(), "Remote name set refused");
    for (const row of rows)
      if (row.id !== failedStarter.id) {
        const original = assets.get(row.name),
          bytes = await transport.download(row.id, original.byteLength);
        assert(
          bytes.length === original.byteLength &&
            sha256(bytes) === original.sha256 &&
            bytes.equals(readRegular(original.localPath, 128 * 1024 * 1024)),
          "Original remote bytes refused",
        );
      }
    op.check();
    return rows;
  }
  await op.scope();
  await op.draft();
  await collection([...uploadedIds.keys(), failedStarter.name], true);
  const failed = await op.get(`/releases/assets/${failedStarter.id}`);
  for (const [key, value] of Object.entries(failedStarter))
    assert.equal(failed[key], value, "Individual failed starter differs");
  assert.equal(failed.url, `${base}/releases/assets/${failedStarter.id}`);
  await op.scope();
  await op.draft();
  op.admitDelete();
  await op.remove();
  await op.draft();
  await collection([...uploadedIds.keys()]);
  await op.scope();
  op.admitUploads();
  for (const [name, asset] of assets)
    if (!uploadedIds.has(name)) {
      await transport.upload(
        retainedPins.releaseId,
        name,
        readRegular(asset.localPath, 128 * 1024 * 1024),
      );
      op.check();
    }
  const remote = await collection([...assets.keys()]);
  await op.scope();
  await op.draft();
  op.check();
  assert(
    op.counts().deletesReserved === 1 && op.counts().uploadsReserved === 42 && op.ids.size === 44,
  );
  return {
    status: "uploaded-draft-originals-not-published",
    phase: "retained-original-transfer",
    releaseId: retainedPins.releaseId,
    sourceHead: retainedPins.sourceHead,
    recoveryHead: context.head,
    assetCount: remote.length,
    assetIds: remote.map((row) => row.id).sort((a, b) => a - b),
    ...op.counts(),
  };
}

// Low-level prepared-byte transfer seam; CLI always uses the fixed retained loader first.
export async function transferRetainedPublication({
  directory,
  custodyPath,
  context,
  token,
  request = fetch,
  now = () => performance.now(),
  startedAt = now(),
  audit = () => {},
}) {
  checkRecoveryContext(context);
  return transfer({
    directory,
    custodyPath,
    context,
    token,
    op: operation({ context, token, request, now, startedAt, audit }),
  });
}

export async function recoverRetainedFinal({
  context,
  custodyBase64,
  output,
  token,
  request = fetch,
  now = () => performance.now(),
  startedAt = now(),
} = {}) {
  checkRecoveryContext(context);
  const custodyBytes = decodeCustody(custodyBase64);
  mkdirSync(output, { mode: 0o700 });
  const auditDirectory = join(output, "audit");
  mkdirSync(auditDirectory, { mode: 0o700 });
  const auditPath = join(auditDirectory, "commands.jsonl");
  writeFileSync(auditPath, "", { flag: "wx", mode: 0o600 });
  const op = operation({
    context,
    token,
    request,
    now,
    startedAt,
    audit: (event) => appendFileSync(auditPath, `${canonicalBytes(event)}\n`),
  });
  let outcomeWritten = false;
  try {
    op.check();
    await op.scope();
    const run = await op.get(`/actions/runs/${retainedPins.runId}`),
      artifacts = await op.get(`/actions/runs/${retainedPins.runId}/artifacts?per_page=100`);
    const custody = checkRefreshRun(
      run,
      artifacts,
      retainedPins.runId,
      retainedPins.sourceHead,
      retainedPins.artifactId,
      `sha256:${retainedPins.archiveSha256}`,
      "scan-refresh-final-publication",
    );
    assert(custody.archiveBytes === retainedPins.archiveBytes);
    const archive = await op.downloadArchive();
    op.check();
    assert(
      archive.length === retainedPins.archiveBytes &&
        sha256(archive) === retainedPins.archiveSha256,
      "Exact original service archive refused",
    );
    const directory = join(output, "publication"),
      measurement = extractFinalZip(archive, directory);
    op.check();
    assert(
      measurement.expandedBytes === 83217614 && measurement.files === 43,
      "Original archive expansion differs",
    );
    assert(
      sha256(readRegular(join(directory, "publication.json"), 2097152)) ===
        retainedPins.receiptSha256 &&
        sha256(readRegular(join(directory, "manifest.json"), 2097152)) ===
          retainedPins.manifestSha256 &&
        sha256(readRegular(join(directory, "selection.json"), 2097152)) ===
          retainedPins.selectionSha256,
      "Original publication selectors differ",
    );
    const custodyPath = join(output, "publication-custody.json");
    writeFileSync(custodyPath, custodyBytes, { flag: "wx", mode: 0o600 });
    op.check();
    const result = await transfer({ directory, custodyPath, context, token, op });
    op.check();
    writeFileSync(join(auditDirectory, "outcome.json"), canonicalBytes(result), {
      flag: "wx",
      mode: 0o600,
    });
    outcomeWritten = true;
    op.check();
    return result;
  } catch {
    if (outcomeWritten) unlinkSync(join(auditDirectory, "outcome.json"));
    writeFileSync(
      join(auditDirectory, "refusal.json"),
      canonicalBytes({
        status: "refused-or-unknown",
        phase: "retained-original-transfer",
        sourceHead: retainedPins.sourceHead,
        recoveryHead: context.head,
        ...op.counts(),
      }),
      { flag: "wx", mode: 0o600 },
    );
    throw new Error("Retained recovery refused or outcome unknown");
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    assert(
      process.argv.length === 3 && !process.env.GH_DEBUG && !process.env.DEBUG,
      "CLI scope refused",
    );
    const event = parseJson(readRegular(process.env.GITHUB_EVENT_PATH, 131072), 131072);
    const env = process.env,
      inputs = event.inputs ?? {};
    const context = {
      event: env.GITHUB_EVENT_NAME,
      repository: env.GITHUB_REPOSITORY,
      repositoryId: env.GITHUB_REPOSITORY_ID,
      ownerId: env.GITHUB_REPOSITORY_OWNER_ID,
      actor: env.GITHUB_ACTOR,
      actorId: env.GITHUB_ACTOR_ID,
      triggeringActor: env.GITHUB_TRIGGERING_ACTOR,
      attempt: env.GITHUB_RUN_ATTEMPT,
      ref: env.GITHUB_REF,
      workflowRef: env.GITHUB_WORKFLOW_REF,
      head: env.GITHUB_SHA,
      recoveryHead: inputs.recovery_head,
      runId: env.GITHUB_RUN_ID,
      candidateRunId: inputs.candidate_run_id,
      manifestSha256: inputs.manifest_sha256,
      selectionSha256: inputs.selection_sha256,
    };
    const result = await recoverRetainedFinal({
      context,
      custodyBase64: inputs.recovery_custody_base64,
      token: env.GH_TOKEN,
      output: process.argv[2],
      startedAt: entered,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write(
      '{"event":"scan-retained-recovery.refused","phase":"retained-original-transfer","reason":"scope-custody-bytes-or-transport-refused"}\n',
    );
    process.exitCode = 2;
  }
}
