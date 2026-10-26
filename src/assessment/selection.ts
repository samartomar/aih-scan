import { z } from "zod";
import { maxContentDescriptors, readContentCoverage } from "./content-coverage.js";
import { bound, canonicalBytes, equalBytes, errorDiagnostic, fail } from "./json.js";
import {
  diagnosticShape,
  digestShape,
  integerShape,
  labelShape,
  pathShape,
  repositoryShape,
  scanIdShape,
  timestampShape,
} from "./shapes.js";
import {
  dataObject,
  detectorIds,
  maxAssessmentBytes,
  readDocument,
  snapshotDocument,
  snapshotJson,
  summarize,
} from "./summary.js";
import type {
  AssessmentSelectionEntry,
  EvidenceAcquisition,
  EvidenceCandidate,
  EvidenceCheck,
  EvidenceSourceFailure,
  SelectAssessmentsInput,
  SelectAssessmentsResult,
} from "./summary-types.js";

export const maxAssessments = 32;
const selectionShape = z
  .object({ paths: z.array(pathShape).max(100000), excludedPaths: z.array(pathShape).max(100000) })
  .strict();
const contextShape = z
  .object({
    sourceIds: z.array(labelShape).min(1).max(32),
    descriptors: z
      .array(z.object({ path: pathShape, sha256: digestShape, byteLength: integerShape }).strict())
      .min(1)
      .max(maxContentDescriptors),
    selection: selectionShape,
    git: z
      .object({ repository: repositoryShape, commit: z.string().regex(/^[0-9a-f]{40}$/) })
      .strict()
      .optional(),
    providers: z
      .array(z.object({ detectorId: labelShape, profileId: labelShape.optional() }).strict())
      .max(10000)
      .optional(),
  })
  .strict();
const checkShape = z
  .object({
    sourceId: labelShape,
    attemptedAt: timestampShape,
    lastSuccessfulAt: timestampShape.optional(),
    status: z.enum(["succeeded", "failed", "offline"]),
    diagnostics: z.array(diagnosticShape).max(1000),
  })
  .strict();
export const associationResultShape = z
  .object({
    scanId: scanIdShape.optional(),
    status: z.enum(["skipped", "authenticated", "unverifiable"]),
    reason: z
      .enum([
        "not-supplied",
        "not-requested",
        "unavailable",
        "unsupported-artifact",
        "malformed",
        "id-mismatch",
        "byte-mismatch",
        "unsigned",
        "unknown-producer",
        "untrusted-key",
        "invalid-signature",
        "resource-limit",
      ])
      .optional(),
    producerIdentity: labelShape.optional(),
    keyId: labelShape.optional(),
    reportRead: z.enum(["supported", "unsupported", "not-requested"]).optional(),
  })
  .strict();
const candidateMetadataShape = z
  .object({
    sourceId: labelShape,
    location: labelShape,
    expectedScanId: scanIdShape.optional(),
    authentication: associationResultShape.optional(),
  })
  .strict();
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const normalized = (paths: string[]) => [...new Set(paths)].sort(compare);
const sameSelection = (
  left: { paths: string[]; excludedPaths: string[] },
  right: { paths: string[]; excludedPaths: string[] },
) => equalBytes(canonicalBytes(left), canonicalBytes(right));

export function snapshotSelectionInput(input: SelectAssessmentsInput, allowEmptySources = false) {
  const raw = dataObject(
    input,
    ["assessments", "context", "evaluationTime", "checks"],
    ["detectorIds"],
  );
  if (!Array.isArray(raw.assessments)) fail("Assessments must be an array");
  bound(raw.assessments.length <= maxAssessments, "assessments", maxAssessments);
  const values: unknown[] = [];
  for (let index = 0; index < raw.assessments.length; index++) {
    const property = Object.getOwnPropertyDescriptor(raw.assessments, String(index));
    if (!property || !("value" in property)) fail("Assessments require own data entries");
    values.push(property.value);
  }
  if (Reflect.ownKeys(raw.assessments).length !== values.length + 1)
    fail("Assessment arrays cannot contain extra fields");
  // Bound aggregate original bytes before allocating any copies or parsing reports.
  const candidates = values.map((value) =>
    dataObject(
      value,
      ["sourceId", "location", "format", "bytes"],
      ["expectedScanId", "authentication"],
    ),
  );
  let bytes = 0;
  for (const candidate of candidates) {
    if (!(candidate.bytes instanceof Uint8Array)) fail("Evidence must be bytes");
    bytes += candidate.bytes.byteLength;
    bound(bytes <= maxAssessmentBytes, "supplied bytes", maxAssessmentBytes);
  }
  const context = (
    allowEmptySources
      ? contextShape.extend({ sourceIds: z.array(labelShape).max(32) })
      : contextShape
  ).parse(snapshotJson(raw.context));
  if (new Set(context.descriptors.map((d) => d.path)).size !== context.descriptors.length)
    fail("Descriptor paths must be unique");
  context.sourceIds = normalized(context.sourceIds);
  context.selection = {
    paths: normalized(context.selection.paths),
    excludedPaths: normalized(context.selection.excludedPaths),
  };
  if (context.selection.excludedPaths.some((path) => !context.selection.paths.includes(path)))
    fail("Exclusions must be in requested paths");
  const evaluationTime = timestampShape.parse(raw.evaluationTime);
  const checks: EvidenceCheck[] = z.array(checkShape).max(32).parse(snapshotJson(raw.checks));
  if (new Set(checks.map((check) => check.sourceId)).size !== checks.length)
    fail("Each source has one latest check");
  for (const check of checks) {
    if (
      !context.sourceIds.includes(check.sourceId) ||
      check.attemptedAt > evaluationTime ||
      (check.lastSuccessfulAt !== undefined && check.lastSuccessfulAt > check.attemptedAt)
    )
      fail("Invalid check source or chronology");
    if (check.status === "succeeded" && check.lastSuccessfulAt !== check.attemptedAt)
      fail("A successful check must name its successful time");
  }
  const assessments: EvidenceCandidate[] = candidates.map((candidate) => {
    const { format, bytes, ...metadata } = candidate;
    const parsed = candidateMetadataShape.parse(snapshotJson(metadata));
    if (!context.sourceIds.includes(parsed.sourceId)) fail("Assessment source is not configured");
    return { ...parsed, ...snapshotDocument({ format, bytes }) };
  });
  return {
    assessments,
    context,
    checks: checks.sort((a, b) => compare(a.sourceId, b.sourceId)),
    evaluationTime,
    ids: detectorIds(raw.detectorIds),
  };
}

/** Selects within an explicit bounded source/content/request group, without acquisition or trust effects. */
export async function selectAssessments(
  input: SelectAssessmentsInput,
): Promise<SelectAssessmentsResult> {
  try {
    const { assessments, context, checks, evaluationTime, ids } = snapshotSelectionInput(input);
    const failures: EvidenceSourceFailure[] = [];
    const entries = new Map<string, AssessmentSelectionEntry>();
    const reportBytes = new Map<string, Uint8Array>();
    const claims = new Map<string, { bytes: Uint8Array; sourceId: string; location: string }[]>();
    for (const candidate of assessments) {
      const read = await readDocument(candidate);
      if (read.status !== "read") {
        failures.push({
          sourceId: candidate.sourceId,
          location: candidate.location,
          diagnostics:
            read.status === "invalid"
              ? read.diagnostics
              : [{ code: "unsupported-report", detail: read.reportSchema }],
        });
        continue;
      }
      const bytes = canonicalBytes(read.report);
      if (candidate.expectedScanId !== undefined && candidate.expectedScanId !== read.scanId) {
        failures.push({
          sourceId: candidate.sourceId,
          location: candidate.location,
          diagnostics: [
            {
              code: "id-mismatch",
              detail: "Expected Scan ID does not identify checked report bytes.",
            },
          ],
        });
        continue;
      }
      const claimed = claims.get(read.scanId) ?? [];
      claimed.push({ bytes, sourceId: candidate.sourceId, location: candidate.location });
      claims.set(read.scanId, claimed);
      if (
        candidate.authentication?.scanId !== undefined &&
        candidate.authentication.scanId !== read.scanId
      ) {
        failures.push({
          sourceId: candidate.sourceId,
          location: candidate.location,
          diagnostics: [
            {
              code: "authentication-id-mismatch",
              detail: "Host authentication names a different assessment.",
            },
          ],
        });
        continue;
      }
      const acquisition: EvidenceAcquisition = {
        sourceId: candidate.sourceId,
        location: candidate.location,
        format: candidate.format,
        authentication: candidate.authentication ?? { status: "skipped", reason: "not-requested" },
        annexBytes: read.annexBytes,
      };
      const existing = entries.get(read.scanId);
      if (existing) {
        existing.acquisitions.push(acquisition);
        // With the current hash identity this branch can only detect a digest collision.
        const previousBytes = reportBytes.get(read.scanId);
        if (!previousBytes || !equalBytes(previousBytes, bytes))
          existing.eligibility = "identity-conflict";
        if (read.annexBytes === "checked") existing.summary.annexBytes = "checked";
        continue;
      }
      const coverage = await readContentCoverage({ read, descriptors: context.descriptors });
      const report = read.report;
      let eligibility: AssessmentSelectionEntry["eligibility"] = "eligible";
      if (coverage.status !== "matched") eligibility = "content-mismatch";
      else if (!sameSelection(report.selection, context.selection)) eligibility = "scope-mismatch";
      else if (
        context.git &&
        (report.source.kind !== "git" ||
          report.source.repository !== context.git.repository ||
          report.source.commit !== context.git.commit)
      )
        eligibility = "git-mismatch";
      else if (
        context.providers?.some(
          (filter) =>
            !report.requestedDetectors.some(
              (request) =>
                request.detectorId === filter.detectorId &&
                (filter.profileId === undefined || filter.profileId === request.profileId),
            ),
        )
      )
        eligibility = "provider-mismatch";
      else if (report.createdAt > evaluationTime) eligibility = "future-dated";
      entries.set(read.scanId, {
        summary: summarize(report, read.scanId, read.annexBytes, ids),
        acquisitions: [acquisition],
        eligibility,
        coverage,
      });
      reportBytes.set(read.scanId, bytes);
    }
    const conflicts: Extract<SelectAssessmentsResult, { status: "selected" }>["conflicts"] = [];
    for (const [scanId, claim] of claims) {
      const first = claim[0];
      if (first && claim.some((item) => !equalBytes(item.bytes, first.bytes))) {
        conflicts.push({
          scanId,
          locations: claim
            .map(({ sourceId, location }) => ({ sourceId, location }))
            .sort((a, b) => compare(a.sourceId, b.sourceId) || compare(a.location, b.location)),
        });
        const entry = entries.get(scanId);
        if (entry) entry.eligibility = "identity-conflict";
      }
    }
    conflicts.sort((a, b) => compare(a.scanId, b.scanId));
    const ordered = [...entries.values()].sort(
      (a, b) =>
        compare(b.summary.createdAt, a.summary.createdAt) ||
        compare(a.summary.scanId, b.summary.scanId),
    );
    for (const entry of ordered)
      entry.acquisitions.sort(
        (a, b) =>
          compare(a.sourceId, b.sourceId) ||
          compare(a.location, b.location) ||
          compare(
            new TextDecoder().decode(canonicalBytes(a)),
            new TextDecoder().decode(canonicalBytes(b)),
          ),
      );
    failures.sort(
      (a, b) =>
        compare(a.sourceId, b.sourceId) ||
        compare(a.location, b.location) ||
        compare(JSON.stringify(a.diagnostics), JSON.stringify(b.diagnostics)),
    );
    const complete =
      failures.length === 0 &&
      conflicts.length === 0 &&
      context.sourceIds.every((id) =>
        checks.some((check) => check.sourceId === id && check.status === "succeeded"),
      );
    return {
      status: "selected",
      selectedScanId:
        ordered.find((entry) => entry.eligibility === "eligible")?.summary.scanId ?? null,
      freshness: complete ? "checked" : "last-known",
      evaluationTime,
      assessments: ordered,
      checks,
      failures,
      conflicts,
    };
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
}
