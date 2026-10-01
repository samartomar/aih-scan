import {
  type BigIntStats,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import { authenticateArtifact } from "../artifact/host.js";
import { readArtifact, validateArtifact } from "../artifact/read.js";
import { selectTrust } from "../artifact/trust.js";
import type { ArtifactAnnex, AuthenticationTrust } from "../artifact/types.js";
import { base64Decode, bound, fail } from "./json.js";
import { locationShape, scanIdShape } from "./shapes.js";
import type { Diagnostic, Limits, ReportBody, ScanId, ScanRequest } from "./types.js";

export interface PriorArtifactCandidate {
  scanId: ScanId;
  report: ReportBody;
  annexes: ArtifactAnnex[];
}
interface PriorArtifactOptions {
  trust?: AuthenticationTrust;
  signal?: AbortSignal;
  limits: Limits;
}
const maxPriorAttempts = 64;
const acquisitionTimeoutMs = 30000;
const readChunkBytes = 64 * 1024;
const sameFile = (a: BigIntStats, b: BigIntStats) =>
  a.dev === b.dev &&
  a.ino === b.ino &&
  a.size === b.size &&
  a.mtimeNs === b.mtimeNs &&
  a.ctimeNs === b.ctimeNs &&
  b.isFile() &&
  b.nlink === 1n;

function readFileSnapshot(
  path: string,
  remaining: number,
  check: () => void,
  charge: (count: number) => void,
): Uint8Array {
  if (!isAbsolute(path)) fail("Prior artifact location is invalid");
  check();
  const expected = lstatSync(path, { bigint: true });
  if (!expected.isFile() || expected.isSymbolicLink() || expected.nlink !== 1n)
    fail("Prior artifact is not a regular file");
  bound(expected.size <= BigInt(remaining), "prior artifact bytes", remaining);
  let descriptor: number | undefined;
  try {
    // Nonblocking open also prevents a raced FIFO substitution from hanging acquisition.
    descriptor = openSync(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    const before = fstatSync(descriptor, { bigint: true });
    if (!sameFile(expected, before)) fail("Prior artifact changed before acquisition");
    const bytes = new Uint8Array(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      check();
      const count = readSync(
        descriptor,
        bytes,
        offset,
        Math.min(readChunkBytes, bytes.length - offset),
        offset,
      );
      if (count <= 0) fail("Prior artifact read ended early");
      charge(count);
      offset += count;
    }
    check();
    if (
      !sameFile(before, fstatSync(descriptor, { bigint: true })) ||
      !sameFile(before, lstatSync(path, { bigint: true }))
    )
      fail("Prior artifact changed during acquisition");
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

async function readHttpsSnapshot(
  url: string,
  remaining: number,
  signal: AbortSignal,
  check: () => void,
  charge: (count: number) => void,
): Promise<Uint8Array> {
  check();
  // Only the explicitly selected HTTPS URL is requested. There is no ambient
  // credential lookup, and redirects cannot forward a request to another origin.
  const response = await fetch(url, { signal, redirect: "error", credentials: "omit" });
  const reader = response.body?.getReader();
  if (!reader) fail("Prior artifact response has no body");
  try {
    if (!response.ok) fail("Prior artifact is unavailable");
    const length = response.headers.get("content-length");
    if (length !== null) {
      if (!/^[0-9]+$/.test(length)) fail("Prior artifact response length is invalid");
      bound(BigInt(length) <= BigInt(remaining), "prior artifact bytes", remaining);
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      check();
      const { done, value } = await reader.read();
      check();
      if (done) break;
      charge(value.byteLength);
      total += value.byteLength;
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Authentication admits an import candidate; current-input relevance is decided by the coordinator. */
export async function readPriorArtifacts(
  priors: NonNullable<ScanRequest["priorArtifacts"]>,
  { trust, signal, limits }: PriorArtifactOptions,
): Promise<{ artifacts: PriorArtifactCandidate[]; diagnostics: Diagnostic[] }> {
  const artifacts: PriorArtifactCandidate[] = [],
    diagnostics: Diagnostic[] = [];
  if (priors.length === 0) return { artifacts, diagnostics };
  const miss = (detail: string) => diagnostics.push({ code: "reuse-miss", detail });
  if (!trust) {
    miss(
      "Prior observations require independently selected authentication trust; current work proceeds.",
    );
    return { artifacts, diagnostics };
  }
  let selected: AuthenticationTrust;
  try {
    selected = selectTrust(trust).trust;
  } catch {
    miss(
      "Prior authentication trust is invalid or exceeds supported bounds; current work proceeds.",
    );
    return { artifacts, diagnostics };
  }
  const deadline = Date.now() + Math.min(acquisitionTimeoutMs, limits.detectorTimeoutMs);
  const acquisitionSignal = AbortSignal.any([
    ...(signal ? [signal] : []),
    AbortSignal.timeout(Math.min(acquisitionTimeoutMs, limits.detectorTimeoutMs)),
  ]);
  const check = () => {
    acquisitionSignal.throwIfAborted();
    if (Date.now() >= deadline) fail("Prior acquisition deadline exceeded");
  };
  let acquiredBytes = 0,
    retainedDecodedBytes = 0;
  const charge = (count: number) => {
    acquiredBytes += count;
    bound(
      acquiredBytes <= limits.maxArtifactBytes,
      "total prior acquisition bytes",
      limits.maxArtifactBytes,
    );
  };
  for (let index = 0; index < Math.min(priors.length, maxPriorAttempts); index++) {
    if (
      acquisitionSignal.aborted ||
      Date.now() >= deadline ||
      acquiredBytes >= limits.maxArtifactBytes
    ) {
      miss(
        "Prior acquisition was cancelled or exhausted its bounded budget; current work proceeds.",
      );
      return { artifacts, diagnostics };
    }
    const prior = priors[index];
    if (!prior) continue;
    try {
      scanIdShape.parse(prior.scanId);
      const location = locationShape.parse(prior.location);
      const remaining = limits.maxArtifactBytes - acquiredBytes;
      const bytes =
        location.kind === "file"
          ? readFileSnapshot(location.path, remaining, check, charge)
          : await readHttpsSnapshot(location.url, remaining, acquisitionSignal, check, charge);
      check();
      // Check the selected and aggregate evidence ceilings before full report
      // parsing. This also exposes exact original annex payloads for admission.
      const { artifact, reportBytes } = await validateArtifact(bytes);
      check();
      const decodedBytes =
        reportBytes.length + artifact.annexes.reduce((sum, annex) => sum + annex.byteLength, 0);
      bound(
        reportBytes.length <= limits.maxReportBytes,
        "prior report bytes",
        limits.maxReportBytes,
      );
      for (const annex of artifact.annexes)
        bound(annex.byteLength <= limits.maxAnnexBytes, "prior annex bytes", limits.maxAnnexBytes);
      if (artifact.attestation)
        base64Decode(artifact.attestation.dsseEnvelope.payload, limits.maxStatementBytes);
      bound(
        retainedDecodedBytes + decodedBytes <= limits.maxDecodedArtifactBytes,
        "retained prior bytes",
        limits.maxDecodedArtifactBytes,
      );
      // All gates consume the same private acquisition snapshot. Narrow
      // authentication alone intentionally supports opaque detailed report schemas.
      const authentication = await authenticateArtifact({
        bytes,
        expectedScanId: prior.scanId,
        trust: selected,
      });
      check();
      if (authentication.status !== "authenticated") {
        miss(
          `Prior artifact authentication failed (${authentication.reason ?? "unavailable"}); current work proceeds.`,
        );
        continue;
      }
      const read = await readArtifact(bytes);
      check();
      if (read.status !== "read" || read.scanId !== prior.scanId) {
        miss(
          "Prior artifact has no supported complete report and annex reading; current work proceeds.",
        );
        continue;
      }
      retainedDecodedBytes += decodedBytes;
      artifacts.push({ scanId: prior.scanId, report: read.report, annexes: artifact.annexes });
    } catch (error) {
      const limited = error instanceof Error && "code" in error && error.code === "resource-limit";
      miss(
        limited
          ? "Prior artifact exceeds the bounded acquisition or retained-evidence budget; current work proceeds."
          : "Prior artifact is unavailable, changed, invalid or cancelled; current work proceeds.",
      );
    }
  }
  if (priors.length > maxPriorAttempts)
    miss("Additional prior artifacts exceed the bounded acquisition count; current work proceeds.");
  return { artifacts, diagnostics };
}
