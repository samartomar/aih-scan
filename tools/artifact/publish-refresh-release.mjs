// A release is kept draft until its exact complete asset set exists. Retry may
// fill missing draft assets or accept equal bytes; it never replaces any asset.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { object, parseJson, readRegular, sha256 } from "../refresh/contracts.mjs";
import { ghApi } from "./gh-api.mjs";
import { measureDirectory } from "./refresh-publication.mjs";

// Tag lookup sees published releases only. Authenticated bounded listing is
// required to find retained drafts and to rule out competing batch releases.
export async function findRelease(tag, published, page) {
  const matches = new Map();
  const retain = (release) => {
    if (release?.tag_name !== tag) return;
    if (!Number.isSafeInteger(release.id) || release.id < 1 || typeof release.draft !== "boolean")
      throw new Error("Invalid release discovery identity");
    matches.set(release.id, release);
  };
  retain(await published());
  for (let number = 1; number <= 5; number++) {
    const releases = await page(number);
    if (!Array.isArray(releases) || releases.length > 100)
      throw new Error("Invalid bounded release page");
    for (const release of releases) retain(release);
    if (matches.size > 1) throw new Error("Ambiguous draft/published batch release");
    if (releases.length < 100) return matches.values().next().value ?? null;
  }
  throw new Error("Release discovery pagination budget exhausted");
}

export async function publishRelease({ directory, transport, custodyPath }) {
  const receiptBytes = readRegular(resolve(directory, "publication.json"), 2097152);
  const receipt = parseJson(receiptBytes, 2097152, true);
  const inventory = parseJson(
    readRegular(resolve(directory, "inventory.json"), 128 * 1024 * 1024),
    128 * 1024 * 1024,
    true,
  );
  if (
    inventory.schema !== "urn:aihq:scan:publication-inventory:1.0.0" ||
    inventory.batchId !== receipt.batchId ||
    !Array.isArray(inventory.targets) ||
    inventory.targets.length !== 7
  )
    throw new Error("Durable release discovery batch differs");
  object(receipt, ["schema", "batchId", "expandedBytes", "assets"]);
  if (
    receipt.schema !== "urn:aihq:scan:publication-assets:1.0.0" ||
    !/^batch:sha256:[0-9a-f]{64}$/.test(receipt.batchId) ||
    !Array.isArray(receipt.assets) ||
    receipt.assets.length > 64
  )
    throw new Error("Invalid release asset contract");
  const names = new Set(),
    paths = new Set();
  for (const asset of receipt.assets) {
    object(asset, ["path", "name", "byteLength", "sha256"]);
    if (
      typeof asset.path !== "string" ||
      !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(asset.path) ||
      asset.path.split("/").some((part) => part === "." || part === "..") ||
      asset.path === "publication.json" ||
      asset.name !== asset.path.replaceAll("/", "--") ||
      names.has(asset.name) ||
      paths.has(asset.path) ||
      !Number.isSafeInteger(asset.byteLength) ||
      asset.byteLength < 0 ||
      asset.byteLength > 128 * 1024 * 1024 ||
      !/^[0-9a-f]{64}$/.test(asset.sha256)
    )
      throw new Error("Invalid or ambiguous release asset");
    names.add(asset.name);
    paths.add(asset.path);
  }
  const measurement = measureDirectory(directory, new Set([...paths, "publication.json"]));
  if (measurement.bytes - receiptBytes.length !== receipt.expandedBytes)
    throw new Error("Release resource accounting differs");
  const assets = [
    ...receipt.assets,
    {
      path: "publication.json",
      name: "publication.json",
      byteLength: receiptBytes.length,
      sha256: sha256(receiptBytes),
    },
  ];
  if (custodyPath) {
    if (names.has("publication-custody.json"))
      throw new Error("Final custody asset name collision");
    const bytes = readRegular(custodyPath, 2097152);
    parseJson(bytes, 2097152, true);
    assets.push({
      path: null,
      name: "publication-custody.json",
      byteLength: bytes.length,
      sha256: sha256(bytes),
      bytes,
    });
    names.add("publication-custody.json");
  }
  if (assets.length > 64) throw new Error("Release asset count budget exceeded");
  // Verify all local bytes before touching GitHub.
  for (const asset of assets) {
    const bytes = asset.bytes ?? readRegular(resolve(directory, asset.path), 128 * 1024 * 1024);
    if (bytes.length !== asset.byteLength || sha256(bytes) !== asset.sha256)
      throw new Error("Local release bytes differ");
  }
  if ((await transport.immutableEnabled()) !== true)
    throw Object.assign(
      new Error("Repository immutable releases are disabled; no release writes admitted"),
      { code: "immutable-releases-disabled" },
    );
  const tag = `scan-report-batch-${receipt.batchId.slice("batch:sha256:".length)}`;
  let release = await transport.lookup(tag);
  if (!release) {
    try {
      release = await transport.create(tag);
    } catch (error) {
      release = await transport.lookup(tag);
      if (!release) throw error;
    }
  }
  if (release.tag_name !== tag || !Array.isArray(release.assets) || release.assets.length > 64)
    throw new Error("Release identity refused");
  const existing = new Map();
  for (const asset of release.assets) {
    if ((!names.has(asset.name) && asset.name !== "publication.json") || existing.has(asset.name))
      throw new Error("Unexpected release asset collision");
    existing.set(asset.name, asset);
  }
  for (const asset of assets) {
    const prior = existing.get(asset.name);
    if (prior) {
      const bytes = await transport.download(prior.id, asset.byteLength);
      if (
        prior.size !== asset.byteLength ||
        bytes.length !== asset.byteLength ||
        sha256(bytes) !== asset.sha256
      )
        throw new Error("Immutable release asset collision");
    } else {
      if (!release.draft) throw new Error("Published release is missing immutable data");
      await transport.upload(
        release.id,
        asset.name,
        asset.bytes ?? readRegular(resolve(directory, asset.path), 128 * 1024 * 1024),
      );
    }
  }
  if (release.draft) release = await transport.publish(release.id);
  if (release.immutable !== true)
    throw new Error(
      "GitHub immutable releases must be enabled; platform immutability not confirmed",
    );
  if (
    release.draft !== false ||
    release.tag_name !== tag ||
    !Array.isArray(release.assets) ||
    release.assets.length !== assets.length ||
    new Set(release.assets.map((asset) => asset.id)).size !== assets.length ||
    release.assets.some(
      (asset) =>
        !Number.isSafeInteger(asset.id) ||
        asset.id < 1 ||
        !assets.some(
          (expected) => expected.name === asset.name && expected.byteLength === asset.size,
        ),
    )
  )
    throw new Error("Published immutable asset inventory differs");
  return {
    event: "scan-refresh-release.completed",
    phase: "durable-publication",
    batchId: receipt.batchId,
    tag,
    releaseId: release.id,
    assetCount: assets.length,
  };
}

export function githubTransport({ token, reviewedHead, fetch: request = fetch }) {
  if (!token || !/^[0-9a-f]{40}$/.test(reviewedHead)) throw new Error("Missing release authority");
  const base = "https://api.github.com/repos/samartomar/aih-scan";
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "aih-scan-refresh",
  };
  async function responseBytes(response, maximum) {
    let count = 0;
    const parts = [];
    for await (const part of response.body) {
      count += part.length;
      if (count > maximum) throw new Error("GitHub response budget exceeded");
      parts.push(part);
    }
    return Buffer.concat(parts);
  }
  async function json(path, method = "GET", body) {
    const response = await request(`${base}${path}`, {
      method,
      headers: { ...headers, "Content-Type": "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(30000),
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (response.status === 404 && method === "GET") return null;
    if (!response.ok) throw new Error("GitHub release request refused");
    return parseJson(await responseBytes(response, 2097152));
  }
  return {
    async immutableEnabled() {
      return (await json("/immutable-releases"))?.enabled === true;
    },
    lookup: (tag) =>
      findRelease(
        tag,
        () => json(`/releases/tags/${tag}`),
        (page) => json(`/releases?per_page=100&page=${page}`),
      ),
    create: (tag) =>
      json("/releases", "POST", {
        tag_name: tag,
        target_commitish: reviewedHead,
        name: `Scan evidence ${tag.slice("scan-report-batch-".length)}`,
        body: "Frozen Scan evidence batch. inventory.json accounts for all seven sources; assessment authenticity and detector completion are separate fields.",
        draft: true,
        prerelease: false,
        make_latest: "false",
      }),
    async download(id, maximum) {
      if (!Number.isSafeInteger(id) || id < 1) throw new Error("Invalid asset ID");
      // GitHub redirects asset downloads to its signed release-asset endpoint.
      const response = await request(`${base}/releases/assets/${id}`, {
        headers: { ...headers, Accept: "application/octet-stream" },
        redirect: "manual",
        signal: AbortSignal.timeout(30000),
      });
      if (response.status === 302) {
        const url = new URL(response.headers.get("location"));
        if (url.protocol !== "https:" || url.hostname !== "release-assets.githubusercontent.com")
          throw new Error("Unexpected release download endpoint");
        const downloaded = await request(url, {
          redirect: "error",
          signal: AbortSignal.timeout(120000),
        });
        if (!downloaded.ok) throw new Error("Release download refused");
        return responseBytes(downloaded, maximum);
      }
      if (!response.ok) throw new Error("Release download refused");
      return responseBytes(response, maximum);
    },
    async upload(id, name, bytes) {
      const response = await request(
        `https://uploads.github.com/repos/samartomar/aih-scan/releases/${id}/assets?name=${encodeURIComponent(name)}`,
        {
          method: "POST",
          headers: { ...headers, "Content-Type": "application/octet-stream" },
          body: bytes,
          redirect: "error",
          signal: AbortSignal.timeout(120000),
        },
      );
      if (!response.ok) throw new Error("Exclusive asset upload refused");
      await responseBytes(response, 2097152);
    },
    publish: (id) => json(`/releases/${id}`, "PATCH", { draft: false, make_latest: "false" }),
  };
}
export function ghTransport({ reviewedHead, command, api = ghApi({ command }) }) {
  if (!/^[0-9a-f]{40}$/.test(reviewedHead)) throw new Error("Invalid reviewed release head");
  const base = "repos/samartomar/aih-scan";
  return {
    api,
    async verifyScope() {
      const user = api.json("user"),
        repository = api.json(base),
        main = api.json(`${base}/git/ref/heads/main`);
      if (
        user?.login !== "samartomar" ||
        user.id !== 9993940 ||
        repository?.id !== 1336836161 ||
        repository.full_name !== "samartomar/aih-scan" ||
        repository.owner?.id !== 9993940 ||
        main?.ref !== "refs/heads/main" ||
        main.object?.type !== "commit" ||
        main.object.sha !== reviewedHead
      )
        throw new Error("Normal maintainer or current main scope refused");
    },
    async immutableEnabled() {
      return api.json(`${base}/immutable-releases`)?.enabled === true;
    },
    lookup: (tag) =>
      findRelease(
        tag,
        () => api.json(`${base}/releases/tags/${tag}`),
        (page) => api.json(`${base}/releases?per_page=100&page=${page}`),
      ),
    create: (tag) =>
      api.json(`${base}/releases`, {
        method: "POST",
        body: {
          tag_name: tag,
          target_commitish: reviewedHead,
          name: `Scan evidence ${tag.slice("scan-report-batch-".length)}`,
          body: "Frozen Scan evidence; inventory.json retains every source and truthful authenticity/completion.",
          draft: true,
          prerelease: false,
          make_latest: "false",
        },
      }),
    async download(id, maximum) {
      if (!Number.isSafeInteger(id) || id < 1) throw new Error("Invalid release asset ID");
      const response = api.bytes(`${base}/releases/assets/${id}`, {
        accept: "application/octet-stream",
        maximum,
        timeout: 120000,
      });
      if (response.status !== 200) throw new Error("Normal gh asset download refused");
      return response.bytes;
    },
    async upload(id, name, bytes) {
      const response = api.bytes(
        `https://uploads.github.com/${base}/releases/${id}/assets?name=${encodeURIComponent(name)}`,
        { method: "POST", body: bytes, accept: "application/octet-stream", timeout: 120000 },
      );
      if (response.status !== 201) throw new Error("Exclusive normal gh asset upload refused");
    },
    publish: (id) =>
      api.json(`${base}/releases/${id}`, {
        method: "PATCH",
        body: { draft: false, make_latest: "false" },
      }),
  };
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 4)
      throw new Error("Expected checked publication directory and reviewed head");
    // Durable publication is admitted only through publish-final.mjs, which
    // authenticates selected final custody and exact bytes before release writes.
    throw new Error("Use the independently selected maintainer final publication operation");
  } catch (error) {
    process.stderr.write(
      `${JSON.stringify({ event: "scan-refresh-release.refused", phase: "durable-publication", reason: error.code === "immutable-releases-disabled" ? error.code : "release-admission-or-collision-refused" })}\n`,
    );
    process.exitCode = 2;
  }
}
