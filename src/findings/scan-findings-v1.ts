import { createHash } from "node:crypto";
import { z } from "zod";
import {
  assertSafeRelativePosixPathV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import {
  isVerifiedScanAttestationV2,
  type ScanAnnexArtifactV2,
  type VerifiedScanAttestationV2,
} from "../observation/scan-attestation-v2.js";
import type { ScanResultGapKindV1, ScanResultGapV1 } from "../scan-result-record.js";

/**
 * Structured findings read back from digest-verified annex bytes, never guessed.
 *
 * Honesty rules enforced by construction:
 *
 * - a finding is produced only from annex bytes whose digest matches the descriptor
 *   the evidence declares; without those bytes every field except the occurrence
 *   fingerprint and its multiplicity is `unavailable` with a reason;
 * - every annex entry must bind back to exactly one declared occurrence fact by a
 *   recomputed `raw-occurrence-v1` fingerprint, and every declared fact must be bound
 *   exactly once. A non-binding entry is a hard refusal, never a dropped row, so the
 *   annex cannot introduce a finding the evidence never declared;
 * - SARIF is still never parsed here. The vendor severity and the rule name are
 *   dropped by Scan's SARIF projection before the annex is written, so they stay
 *   `unavailable` rather than being reconstructed;
 * - an empty `findings` list is never "nothing was found": the gaps say whether the
 *   list is empty because nothing was declared or because nothing could be read.
 */

const MAX_ANNEX_ENTRIES = 4096;
const MAX_ANNEX_BYTES = 16 * 1024 * 1024;
const RAW_OCCURRENCE = /^raw-occurrence-v1:[0-9a-f]{64}$/;
/**
 * The exact grouping separator `createCiscoFactsOnlyV1` uses when it assigns a
 * canonical ordinal, written without embedding a control character in this source.
 */
const GROUP_SEPARATOR = String.fromCodePoint(0);

export type FindingFieldV1<T> =
  | Readonly<{ state: "present"; value: T }>
  | Readonly<{ state: "unavailable"; reason: ScanResultGapKindV1; detail: string }>;

export interface ScanFindingV1 {
  /** Always present: the occurrence identity the evidence itself declares. */
  readonly rawOccurrenceFingerprint: string;
  /** Always present: how many identical occurrences that identity stands for. */
  readonly multiplicity: number;
  readonly detector: FindingFieldV1<Readonly<{ id: string; analyzerIdentity: string }>>;
  readonly rule: FindingFieldV1<Readonly<{ nativeRuleId: string; name?: string }>>;
  /** The SARIF level only. `vendorSeverity` is never projected into the annex. */
  readonly severity: FindingFieldV1<Readonly<{ level: string; vendorSeverity?: string }>>;
  readonly message: FindingFieldV1<string>;
  readonly location: FindingFieldV1<
    Readonly<{ path: string; fileSha256: string; startLine?: number }>
  >;
  readonly supportingEvidence: FindingFieldV1<
    Readonly<{ annexDescriptorId: string; annexSha256: string; ordinal: number }>
  >;
}

export interface ScanFindingsV1 {
  readonly protocol: "ScanFindingsV1";
  /**
   * Where the reported fields come from:
   *
   * - `annex`: read from digest-verified raw annex bytes;
   * - `attestation-facts-only`: only the occurrence facts the evidence declares;
   * - `analyzer-output-digest-bound`: a single-analyzer run whose output is bound by
   *   digest and deliberately left unparsed;
   * - `analyzer-sarif`: read from the digest-verified, source-relative SARIF annex of one
   *   analyzer observation.
   */
  readonly source:
    | "annex"
    | "attestation-facts-only"
    | "analyzer-output-digest-bound"
    | "analyzer-sarif";
  readonly findings: readonly ScanFindingV1[];
  readonly gaps: readonly ScanResultGapV1[];
}

export type ScanFindingsReadV1 =
  | Readonly<{ status: "available"; findings: ScanFindingsV1 }>
  | Readonly<{ status: "unverified" }>
  | Readonly<{ status: "invalid-input"; reason: string }>;

export interface ReadScanFindingsV1Request {
  /** Only a value minted by `verifyScanAttestationV2` is accepted. */
  readonly verified: unknown;
  /** Optional: when supplied, every annex must match the verified descriptors. */
  readonly annexArtifacts?: readonly ScanAnnexArtifactV2[];
}

const region = z
  .object({
    startLine: z.number().int().min(1).max(10_000_000),
    startColumn: z.number().int().min(1).max(1_000_000).optional(),
    endLine: z.number().int().min(1).max(10_000_000).optional(),
    endColumn: z.number().int().min(1).max(1_000_000).optional(),
  })
  .strict();
const annexEntry = z
  .object({
    detectorClass: z.literal("cisco"),
    nativeRuleId: z.string().min(1).max(256),
    path: z.string().min(1).max(1024),
    fileSha256: z.string().regex(/^[0-9a-f]{64}$/),
    message: z.string().min(1).max(4096),
    level: z.string().max(64),
    locations: z
      .array(
        z
          .object({
            physicalLocation: z
              .object({
                artifactLocation: z.object({ uri: z.string().min(1).max(1024) }).strict(),
                region: region.optional(),
              })
              .strict(),
          })
          .strict(),
      )
      .min(1)
      .max(16),
  })
  .strict();
const annexDocument = z.array(annexEntry).max(MAX_ANNEX_ENTRIES);

type AnnexEntry = z.infer<typeof annexEntry>;

const gap = (kind: ScanResultGapKindV1, detail: string): ScanResultGapV1 =>
  Object.freeze({ kind, detail });

const unavailable = (reason: ScanResultGapKindV1, detail: string) =>
  Object.freeze({ state: "unavailable" as const, reason, detail });

const present = <T>(value: T) => Object.freeze({ state: "present" as const, value });

const NO_ANNEX_BYTES = unavailable(
  "annex-bytes-not-supplied",
  "No digest-verified raw annex bytes were supplied, so this field was not read. Supply the annex artifacts to obtain it.",
);

const VENDOR_SEVERITY_GAP = gap(
  "vendor-severity-not-projected",
  "Scan's SARIF projection drops properties.severity and properties.category before the annex is written, so only the SARIF level survives. Widening the projection changes the annex bytes and therefore appliedFactsSha256 and observationSetSha256, so it needs a separate annex descriptor version.",
);
const SARIF_NOT_INTERPRETED_GAP = gap(
  "sarif-not-interpreted",
  "The detector SARIF document is bound by digest only and is never parsed here, so the rule name and rule metadata are not available.",
);
const NO_AUTHORITY_GAP = gap(
  "no-effect-or-qualification-authority",
  "These findings are evidence only. They grant no qualification, approval, installation, observation or effect authority.",
);

/** `raw-occurrence-v1:<digest>` exactly as `createCiscoFactsOnlyV1` mints it. */
function rawOccurrenceFingerprintV1(entry: {
  readonly nativeRuleId: string;
  readonly path: string;
  readonly fileSha256: string;
  readonly canonicalOrdinal: number;
  /** `cisco` for the Cisco facts; an analyzer observation names its own analyzer. */
  readonly detectorClass?: string;
}): string {
  return `raw-occurrence-v1:${canonicalStrictJsonSha256V1({
    protocol: "RawOccurrenceFingerprintV1",
    detectorClass: entry.detectorClass ?? "cisco",
    nativeRuleId: entry.nativeRuleId,
    path: entry.path,
    fileSha256: entry.fileSha256,
    canonicalOrdinal: entry.canonicalOrdinal,
  })}`;
}

function parseAnnexDocument(bytes: Uint8Array): readonly AnnexEntry[] {
  const buffer = Buffer.from(bytes);
  if (buffer.byteLength === 0 || buffer.byteLength > MAX_ANNEX_BYTES)
    throw new TypeError("raw annex byte bounds");
  const text = buffer.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(buffer)) throw new TypeError("raw annex UTF-8");
  if (!text.startsWith("[")) throw new TypeError("raw annex root must be an array");
  // The strict parser requires an object root, so the array is read inside one and
  // then re-canonicalized and compared byte for byte against the supplied annex.
  const wrapped = parseStrictJsonObjectV1(`{"entries":${text}}`, "raw annex");
  if (!canonicalStrictJsonBytesV1(wrapped.entries).equals(buffer))
    throw new TypeError("raw annex canonical bytes");
  const entries = annexDocument.parse(wrapped.entries);
  for (const entry of entries) {
    assertSafeRelativePosixPathV1(entry.path, "raw annex path");
    for (const location of entry.locations)
      assertSafeRelativePosixPathV1(
        location.physicalLocation.artifactLocation.uri,
        "raw annex location path",
      );
  }
  return entries;
}

export interface BuildScanFindingsV1Input {
  readonly detector: Readonly<{ id: string; analyzerIdentity: string }>;
  readonly facts: readonly Readonly<{ rawOccurrenceFingerprint: string; multiplicity: number }>[];
  readonly annexDescriptors: readonly Readonly<{
    descriptorId: string;
    sha256: string;
    byteLength: number;
  }>[];
  readonly annexArtifacts?: readonly ScanAnnexArtifactV2[];
}

/**
 * Projects declared occurrence facts, plus digest-verified raw annex bytes when they
 * are supplied, into `ScanFindingsV1`. Throws on any binding failure.
 *
 * Internal: `readScanFindingsV1` is the package-level entry point.
 */
export function buildScanFindingsV1(input: BuildScanFindingsV1Input): ScanFindingsV1 {
  const factList = input.facts.map((fact) => {
    if (!RAW_OCCURRENCE.test(fact.rawOccurrenceFingerprint))
      throw new TypeError("declared occurrence fingerprint");
    return fact;
  });
  const rawDescriptor = input.annexDescriptors.find(
    (descriptor) => descriptor.descriptorId === "annex.cisco-raw",
  );
  const rawArtifact = input.annexArtifacts?.find(
    (artifact) => artifact.descriptorId === "annex.cisco-raw",
  );
  if (rawDescriptor === undefined || rawArtifact === undefined) {
    return Object.freeze({
      protocol: "ScanFindingsV1" as const,
      source: "attestation-facts-only" as const,
      findings: Object.freeze(
        factList.map((fact) =>
          Object.freeze({
            rawOccurrenceFingerprint: fact.rawOccurrenceFingerprint,
            multiplicity: fact.multiplicity,
            detector: NO_ANNEX_BYTES,
            rule: NO_ANNEX_BYTES,
            severity: NO_ANNEX_BYTES,
            message: NO_ANNEX_BYTES,
            location: NO_ANNEX_BYTES,
            supportingEvidence: NO_ANNEX_BYTES,
          }),
        ),
      ),
      gaps: Object.freeze([
        gap(
          "annex-bytes-not-supplied",
          rawDescriptor === undefined
            ? "The evidence declares no annex.cisco-raw descriptor, so there are no per-finding bytes to read."
            : "The annex.cisco-raw bytes were not supplied, so only the declared occurrence identities are reported.",
        ),
        gap(
          "finding-message-and-location-not-read-from-annex",
          "Per-finding message and location live in the digest-bound raw annex bytes; supply them to have this reader bind and report them.",
        ),
        gap(
          "severity-not-declared-by-attestation",
          "The evidence declares occurrence fingerprints and multiplicity, not severity. Absent severity is reported as absent, never defaulted.",
        ),
        SARIF_NOT_INTERPRETED_GAP,
        NO_AUTHORITY_GAP,
      ]),
    });
  }

  const bytes = Buffer.from(rawArtifact.bytes);
  if (
    bytes.byteLength !== rawDescriptor.byteLength ||
    createHash("sha256").update(bytes).digest("hex") !== rawDescriptor.sha256
  )
    throw new TypeError("raw annex bytes do not match the declared descriptor");

  const entries = parseAnnexDocument(bytes);
  if (entries.length !== factList.length)
    throw new TypeError(
      `raw annex declares ${entries.length} entries but the evidence declares ${factList.length} occurrence facts`,
    );

  const unbound = new Map<string, { fact: (typeof factList)[number]; used: boolean }>();
  for (const fact of factList) {
    if (unbound.has(fact.rawOccurrenceFingerprint))
      throw new TypeError("duplicate declared occurrence fingerprint");
    unbound.set(fact.rawOccurrenceFingerprint, { fact, used: false });
  }

  const ordinals = new Map<string, number>();
  const findings = entries.map((entry, ordinal) => {
    const group = [entry.nativeRuleId, entry.path, entry.fileSha256].join(GROUP_SEPARATOR);
    const canonicalOrdinal = ordinals.get(group) ?? 0;
    ordinals.set(group, canonicalOrdinal + 1);
    const fingerprint = rawOccurrenceFingerprintV1({ ...entry, canonicalOrdinal });
    const bound = unbound.get(fingerprint);
    if (bound === undefined || bound.used)
      throw new TypeError(
        `raw annex entry ${ordinal} does not bind to exactly one declared occurrence fact`,
      );
    bound.used = true;
    const startLine = entry.locations[0]?.physicalLocation.region?.startLine;
    return Object.freeze({
      rawOccurrenceFingerprint: fingerprint,
      multiplicity: bound.fact.multiplicity,
      detector: present(
        Object.freeze({ id: input.detector.id, analyzerIdentity: input.detector.analyzerIdentity }),
      ),
      rule: present(Object.freeze({ nativeRuleId: entry.nativeRuleId })),
      severity:
        entry.level === ""
          ? unavailable(
              "severity-not-declared-by-attestation",
              "The detector emitted no SARIF level for this result, so no severity is reported for it.",
            )
          : present(Object.freeze({ level: entry.level })),
      message: present(entry.message),
      location: present(
        Object.freeze({
          path: entry.path,
          fileSha256: entry.fileSha256,
          ...(startLine === undefined ? {} : { startLine }),
        }),
      ),
      supportingEvidence: present(
        Object.freeze({
          annexDescriptorId: rawDescriptor.descriptorId,
          annexSha256: rawDescriptor.sha256,
          ordinal,
        }),
      ),
    });
  });
  for (const { used } of unbound.values())
    if (!used) throw new TypeError("a declared occurrence fact has no raw annex entry");

  return Object.freeze({
    protocol: "ScanFindingsV1" as const,
    source: "annex" as const,
    findings: Object.freeze(findings),
    gaps: Object.freeze([VENDOR_SEVERITY_GAP, SARIF_NOT_INTERPRETED_GAP, NO_AUTHORITY_GAP]),
  });
}

/** The findings shape for a run whose analyzer output is bound by digest and not parsed. */
export function digestBoundAnalyzerFindingsV1(detail: string): ScanFindingsV1 {
  return Object.freeze({
    protocol: "ScanFindingsV1" as const,
    source: "analyzer-output-digest-bound" as const,
    findings: Object.freeze([]),
    gaps: Object.freeze([
      gap("sarif-not-interpreted", detail),
      gap(
        "finding-message-and-location-not-read-from-annex",
        "This run's annex bytes are the analyzer's own output. Scan binds them by digest and does not parse them, so no message or location is reported and the empty list is not a claim that nothing was found.",
      ),
      gap(
        "severity-not-declared-by-attestation",
        "A single-analyzer observation declares no occurrence facts, so it declares no severity either. Absent severity is reported as absent, never defaulted.",
      ),
      NO_AUTHORITY_GAP,
    ]),
  });
}

const MAX_SARIF_RESULTS = 10_000;
const ZERO_SHA256 = "0".repeat(64);
const MAX_SARIF_MESSAGE_CHARACTERS = 16 * 1024;

export interface AnalyzerSarifFindingsInputV1 {
  readonly detectorId: string;
  /** The analyzer name; it is the fingerprint's `detectorClass`. */
  readonly analyzer: string;
  readonly analyzerIdentity: string;
  readonly annex: Readonly<{ descriptorId: string; sha256: string; byteLength: number }>;
  /** The observation's annex bytes: canonical, source-relative SARIF 2.1.0. */
  readonly bytes: Uint8Array;
  /** Every sealed source file, by relative path, with its sha256. */
  readonly sealedFiles: ReadonlyMap<string, string>;
  /**
   * `fail` (the default): a result whose first location is not a sealed source file fails
   * the projection. `unavailable`: for engines whose SARIF legitimately names no file (a
   * whole-tree finding, a fallback URI), that result's location is reported unavailable and
   * its fingerprint binds the URI as written with an all-zero file digest.
   */
  readonly unboundLocations?: "fail" | "unavailable";
  /** The most results accepted; defaults to 10 000. */
  readonly maxResults?: number;
}

function sarifFail(reason: string): never {
  throw new TypeError(`invalid analyzer SARIF findings: ${reason}`);
}

function sarifRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * Projects one analyzer observation's SARIF annex into `ScanFindingsV1`.
 *
 * The bytes must match the annex digest; each result must name a rule and a first physical
 * location whose URI is one of the sealed source files, so every finding binds to the exact
 * file bytes that were scanned. The fingerprint is the `raw-occurrence-v1` formula the
 * Cisco facts use, with the analyzer as the detector class. Only the rule id, the SARIF
 * level, the message and the first location are read; nothing is guessed. Throws on any
 * binding failure.
 */
export function projectAnalyzerSarifFindingsV1(
  input: AnalyzerSarifFindingsInputV1,
): ScanFindingsV1 {
  const bytes = Buffer.from(input.bytes);
  if (
    bytes.byteLength !== input.annex.byteLength ||
    createHash("sha256").update(bytes).digest("hex") !== input.annex.sha256
  )
    sarifFail("the SARIF bytes do not match the annex digest");
  let log: Record<string, unknown>;
  try {
    log = parseStrictJsonObjectV1(bytes.toString("utf8"), "analyzer SARIF");
  } catch {
    return sarifFail("the SARIF annex is not strict JSON");
  }
  if (log.version !== "2.1.0" || !Array.isArray(log.runs)) sarifFail("not a SARIF 2.1.0 log");
  // A log with no runs, or a run without a results list, reports no analysis (S2e).
  if (log.runs.length === 0) sarifFail("the SARIF log holds no runs");
  const results: Record<string, unknown>[] = [];
  for (const run of log.runs as unknown[]) {
    const runRecord = sarifRecord(run) ?? sarifFail("a SARIF run is not an object");
    if (!Array.isArray(runRecord.results)) sarifFail("a SARIF results list is not an array");
    for (const result of runRecord.results as unknown[])
      results.push(sarifRecord(result) ?? sarifFail("a SARIF result is not an object"));
  }
  const maxResults = input.maxResults ?? MAX_SARIF_RESULTS;
  if (results.length > maxResults) sarifFail(`more than ${maxResults} results`);
  const tolerant = input.unboundLocations === "unavailable";
  const unbound: string[] = [];
  const ordinals = new Map<string, number>();
  const findings = results.map((result, ordinal) => {
    const ruleId = result.ruleId;
    if (typeof ruleId !== "string" || ruleId.length === 0 || ruleId.length > 256)
      sarifFail(`result ${ordinal} names no rule`);
    const locations = result.locations;
    const physical = Array.isArray(locations)
      ? sarifRecord(sarifRecord(locations[0])?.physicalLocation)
      : undefined;
    const uri = sarifRecord(physical?.artifactLocation)?.uri;
    let bound: string | undefined;
    if (typeof uri !== "string") {
      if (!tolerant) sarifFail(`result ${ordinal} names no file location`);
    } else if (uri.length > 1024) {
      sarifFail(`result ${ordinal} has an over-long location`);
    } else {
      try {
        const safe = assertSafeRelativePosixPathV1(uri, "SARIF location");
        if (input.sealedFiles.has(safe)) bound = safe;
        else if (!tolerant)
          sarifFail(`result ${ordinal} names ${safe}, which is not a sealed source file`);
      } catch (error) {
        if (!tolerant) {
          if (error instanceof TypeError && error.message.startsWith("invalid analyzer SARIF"))
            throw error;
          sarifFail(`result ${ordinal} location ${JSON.stringify(uri)} is not source-relative`);
        }
      }
    }
    if (bound === undefined) unbound.push(typeof uri === "string" ? uri : "");
    const path = bound ?? (typeof uri === "string" ? uri : "");
    const fileSha256 = bound === undefined ? ZERO_SHA256 : (input.sealedFiles.get(bound) as string);
    const region = sarifRecord(physical?.region);
    const startLine = region?.startLine;
    if (startLine !== undefined && (!Number.isSafeInteger(startLine) || (startLine as number) < 1))
      sarifFail(`result ${ordinal} has an invalid start line`);
    const level = result.level;
    if (level !== undefined && (typeof level !== "string" || level.length > 64))
      sarifFail(`result ${ordinal} has an invalid level`);
    const text = sarifRecord(result.message)?.text;
    if (
      text !== undefined &&
      (typeof text !== "string" || text.length > MAX_SARIF_MESSAGE_CHARACTERS)
    )
      sarifFail(`result ${ordinal} has an invalid message`);
    const group = [ruleId, path, fileSha256].join(GROUP_SEPARATOR);
    const canonicalOrdinal = ordinals.get(group) ?? 0;
    ordinals.set(group, canonicalOrdinal + 1);
    return Object.freeze({
      rawOccurrenceFingerprint: rawOccurrenceFingerprintV1({
        detectorClass: input.analyzer,
        nativeRuleId: ruleId as string,
        path,
        fileSha256,
        canonicalOrdinal,
      }),
      multiplicity: 1,
      detector: present(
        Object.freeze({ id: input.detectorId, analyzerIdentity: input.analyzerIdentity }),
      ),
      rule: present(Object.freeze({ nativeRuleId: ruleId as string })),
      severity:
        typeof level === "string" && level.length > 0
          ? present(Object.freeze({ level }))
          : unavailable(
              "severity-not-declared-by-attestation",
              "The analyzer emitted no SARIF level for this result, so no severity is reported for it.",
            ),
      message:
        typeof text === "string"
          ? present(text)
          : unavailable(
              "finding-message-and-location-not-read-from-annex",
              "The analyzer emitted no message text for this result.",
            ),
      location:
        bound === undefined
          ? unavailable(
              "finding-location-not-a-sealed-file",
              typeof uri === "string"
                ? `The analyzer named ${JSON.stringify(uri)}, which is not a sealed source file.`
                : "The analyzer named no file location for this result.",
            )
          : present(
              Object.freeze({
                path,
                fileSha256,
                ...(startLine === undefined ? {} : { startLine: startLine as number }),
              }),
            ),
      supportingEvidence: present(
        Object.freeze({
          annexDescriptorId: input.annex.descriptorId,
          annexSha256: input.annex.sha256,
          ordinal,
        }),
      ),
    });
  });
  return Object.freeze({
    protocol: "ScanFindingsV1" as const,
    source: "analyzer-sarif" as const,
    findings: Object.freeze(findings),
    gaps: Object.freeze([
      ...(unbound.length === 0
        ? []
        : [
            gap(
              "finding-location-not-a-sealed-file",
              `${unbound.length} result${unbound.length === 1 ? " names" : "s name"} no sealed source file (a whole-tree finding or the analyzer's fallback URI), so ${unbound.length === 1 ? "its location is" : "their locations are"} reported unavailable; each fingerprint binds the URI as written with an all-zero file digest.`,
            ),
          ]),
      gap(
        "vendor-severity-not-projected",
        "Only the SARIF rule id, level, message and first location are read. Vendor severities, categories and rule metadata stay in the digest-bound SARIF annex.",
      ),
      gap(
        "no-effect-or-qualification-authority",
        findings.length === 0
          ? "The analyzer's SARIF declared no results for this snapshot. That is the analyzer's own report under its own rules, not a statement that the subject is safe, and it grants no qualification, approval, installation, observation or effect authority."
          : "These findings are evidence only. No finding is not proof of safety, and they grant no qualification, approval, installation, observation or effect authority.",
      ),
    ]),
  });
}

/**
 * Normalizes the findings of one already-verified `ScanAttestationV2`.
 *
 * Returns typed absence for anything that is not verified, and `invalid-input` when
 * supplied annex bytes contradict the verified descriptors or do not bind to the
 * declared occurrence facts.
 */
export function readScanFindingsV1(request: ReadScanFindingsV1Request): ScanFindingsReadV1 {
  if (typeof request !== "object" || request === null)
    return Object.freeze({ status: "unverified" as const });
  const { verified } = request;
  if (!isVerifiedScanAttestationV2(verified))
    return Object.freeze({ status: "unverified" as const });
  const facts = (verified as VerifiedScanAttestationV2).facts;
  if (request.annexArtifacts !== undefined && !Array.isArray(request.annexArtifacts))
    return Object.freeze({ status: "invalid-input" as const, reason: "annex artifacts" });
  const detector = facts.scanner.detector;
  try {
    return Object.freeze({
      status: "available" as const,
      findings: buildScanFindingsV1({
        detector: { id: detector.detectorId, analyzerIdentity: detector.analyzerIdentity },
        facts: detector.observation.facts,
        annexDescriptors: facts.annexDescriptors,
        ...(request.annexArtifacts === undefined
          ? {}
          : { annexArtifacts: [...request.annexArtifacts] }),
      }),
    });
  } catch (error) {
    return Object.freeze({
      status: "invalid-input" as const,
      reason: error instanceof Error ? error.message : "raw annex binding",
    });
  }
}
