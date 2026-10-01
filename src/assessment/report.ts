import {
  assertControlJson,
  bound,
  canonicalBytes,
  equalBytes,
  errorDiagnostic,
  fail,
  observationIdFor,
  scanIdFor,
  sha256,
  strictParse,
} from "./json.js";
import { reportShape } from "./shapes.js";
import {
  type CaptureEntry,
  limitCeilings,
  type ReadReportResult,
  type ReportBody,
  schemas,
} from "./types.js";
export function ordered(values: readonly string[], label: string): void {
  for (let i = 1; i < values.length; i++)
    if (values[i - 1]! >= values[i]!) fail(`${label} must be ordered and unique`);
}
const same = (left: unknown, right: unknown) =>
  equalBytes(canonicalBytes(left), canonicalBytes(right));
const subset = (values: readonly string[], allowed: Set<string>, label: string) => {
  ordered(values, label);
  for (const value of values)
    if (!allowed.has(value)) fail(`${label} is outside the declared scope`);
};
export function validateEntries(
  entries: CaptureEntry[],
  maxEntries: number,
  maxBytes: number,
): Map<string, CaptureEntry> {
  bound(entries.length <= maxEntries, "source entries", maxEntries);
  ordered(
    entries.map((entry) => entry.path),
    "source entries",
  );
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  let total = 0;
  for (const entry of entries) {
    if (entry.path === ".git" || entry.path.startsWith(".git/"))
      fail("The capture profile omits root .git metadata");
    const parts = entry.path.split("/");
    parts.pop();
    while (parts.length) {
      if (byPath.get(parts.join("/"))?.kind !== "directory")
        fail("Entry parent must be a captured directory");
      parts.pop();
    }
    if ("target" in entry) {
      const target = byPath.get(entry.target);
      if (target?.kind !== (entry.kind === "file-link" ? "file" : "directory"))
        fail("Link target must resolve to a captured contained regular entry");
      if (
        entry.kind === "file-link" &&
        target.kind === "file" &&
        (entry.sha256 !== target.sha256 || entry.byteLength !== target.byteLength)
      )
        fail("File link must bind target bytes");
    }
    if ("byteLength" in entry) {
      total += entry.byteLength;
      bound(total <= maxBytes, "source bytes", maxBytes);
    }
  }
  return byPath;
}
export async function validateReport(value: unknown): Promise<ReportBody> {
  assertControlJson(value);
  const parsed = reportShape.safeParse(value);
  if (!parsed.success) fail("Report does not match its closed supported schema");
  const report = parsed.data as ReportBody,
    limits = report.effectiveLimits,
    capture = report.source.capture;
  bound(
    canonicalBytes(report).length <= limits.maxReportBytes,
    "report bytes",
    limits.maxReportBytes,
  );
  const entries = validateEntries(capture.entries, limits.maxSourceEntries, limits.maxSourceBytes);
  if (
    capture.captureSha256 !==
    (await sha256(
      canonicalBytes({
        domain: "aih.scan.capture.v1",
        profile: capture.profile,
        entries: capture.entries,
      }),
    ))
  )
    fail("Source capture digest mismatch");
  const files = new Set(
    capture.entries.filter((entry) => "sha256" in entry).map((entry) => entry.path),
  );
  subset(report.selection.paths, files, "selection");
  if (files.size > 0 && report.selection.paths.length === 0)
    fail("Nonempty captured file sets require nonempty selection");
  const selected = new Set(report.selection.paths);
  subset(report.selection.excludedPaths, selected, "exclusions");
  const active = new Set(
    report.selection.paths.filter((path) => !report.selection.excludedPaths.includes(path)),
  );
  ordered(
    report.requestedDetectors.map((d) => d.detectorId),
    "requested detectors",
  );
  ordered(
    report.results.map((d) => d.detectorId),
    "detector results",
  );
  if (
    !same(
      report.requestedDetectors.map((d) => d.detectorId),
      report.results.map((d) => d.detectorId),
    )
  )
    fail("Every requested detector requires exactly one result");
  ordered(
    report.annexes.map((a) => a.id),
    "annexes",
  );
  const annexes = new Map(report.annexes.map((a) => [a.id, a]));
  let decoded = canonicalBytes(report).length;
  for (const annex of report.annexes) {
    bound(annex.byteLength <= limits.maxAnnexBytes, "annex bytes", limits.maxAnnexBytes);
    decoded += annex.byteLength;
  }
  bound(
    decoded <= limits.maxDecodedArtifactBytes,
    "decoded artifact bytes",
    limits.maxDecodedArtifactBytes,
  );
  const observationIds = new Set<string>();
  for (let i = 0; i < report.results.length; i++) {
    const result = report.results[i]!,
      request = report.requestedDetectors[i]!;
    if (request.configurationSha256 !== (await sha256(canonicalBytes(request.configuration))))
      fail("Configuration digest mismatch");
    if (request.profileId === null && result.outcome !== "refused")
      fail("An unresolved profile must be refused");
    if (!same(result.coverage.excludedPaths, report.selection.excludedPaths))
      fail("Detector exclusions must equal explicit exclusions");
    const accounted = new Set<string>();
    for (const paths of [
      result.coverage.coveredPaths,
      result.coverage.excludedPaths,
      result.coverage.uncoveredPaths,
    ]) {
      subset(paths, selected, "coverage");
      for (const path of paths) {
        if (accounted.has(path)) fail("Coverage sets must be disjoint");
        accounted.add(path);
      }
    }
    if (
      accounted.size !== selected.size ||
      result.coverage.complete !== (result.coverage.uncoveredPaths.length === 0)
    )
      fail("Coverage must exactly account for the selected scope");
    ordered(
      result.observations.map((o) => o.observationId),
      "observations",
    );
    const covered = new Set<string>();
    if (result.outcome === "refused" && result.observations.length > 0)
      fail("Refused work has no successful observations");
    if (result.outcome !== "succeeded" && result.diagnostics.length === 0)
      fail("Unsuccessful work requires diagnostics");
    for (const observation of result.observations) {
      if (observationIds.has(observation.observationId)) fail("Duplicate observation identity");
      observationIds.add(observation.observationId);
      if (observation.origin === "fresh" && observation.fromScanId !== undefined)
        fail("Fresh observation cannot name a previous assessment");
      const body = observation.body,
        input = body.input;
      if (observation.observationId !== (await observationIdFor(body)))
        fail("Observation digest mismatch");
      if (body.startedAt > body.completedAt || body.completedAt > report.createdAt)
        fail("Observation times must be ordered before assembly");
      if (
        input.detectorId !== request.detectorId ||
        input.profileId !== request.profileId ||
        input.configurationSha256 !== request.configurationSha256
      )
        fail("Observation analysis input disagrees with requested detector");
      subset(input.targetPaths, active, "observation targets");
      subset(body.coverage.coveredPaths, new Set(input.targetPaths), "observation coverage");
      validateEntries(input.entries, limits.maxSourceEntries, limits.maxSourceBytes);
      for (const entry of input.entries)
        if (!same(entry, entries.get(entry.path) ?? null))
          fail("Observation relevant input differs from capture");
      if (input.scopeKind === "source-tree" && !same(input.entries, capture.entries))
        fail("Whole-tree observation must bind the complete capture");
      const relevant = new Map(input.entries.map((entry) => [entry.path, entry]));
      for (const path of input.targetPaths)
        if (!relevant.has(path)) fail("Observation target is absent from relevant input");
      if (input.platform.os === "independent" || input.platform.architecture === "independent") {
        if (
          input.platform.os !== "independent" ||
          input.platform.architecture !== "independent" ||
          input.platform.relevantFactsSha256 !== (await sha256(canonicalBytes({})))
        )
          fail("Independent platform identity is inconsistent");
      }
      for (const path of body.coverage.coveredPaths) {
        if (covered.has(path)) fail("Observation units must not overlap output coverage");
        covered.add(path);
      }
      ordered(body.annexIds, "observation annex IDs");
      for (const id of body.annexIds)
        if (!annexes.has(id)) fail("Missing observation annex descriptor");
      ordered(
        body.findings.map((f) => f.rawOccurrenceFingerprint),
        "findings",
      );
      for (const finding of body.findings) {
        if (finding.location.state === "present") {
          const location = finding.location.value,
            entry = entries.get(location.path);
          if (
            !entry ||
            !("sha256" in entry) ||
            entry.sha256 !== location.fileSha256 ||
            !body.coverage.coveredPaths.includes(location.path)
          )
            fail("Finding location must bind a covered captured file");
        }
        if (
          finding.supportingEvidence.state === "present" &&
          !body.annexIds.includes(finding.supportingEvidence.value.annexId)
        )
          fail("Finding support must name an observation annex");
      }
    }
    if (!same([...covered].sort(), result.coverage.coveredPaths))
      fail("Covered scope must come from successful observations");
    if (
      result.outcome === "succeeded" &&
      (!result.coverage.complete || result.observations.length === 0)
    )
      fail("Success requires reliable observations with complete coverage");
  }
  if (
    report.completion !==
    (report.results.every((result) => result.outcome === "succeeded" && result.coverage.complete)
      ? "complete"
      : "partial")
  )
    fail("Assessment completion disagrees with detector results");
  return report;
}
export async function readReport(bytes: Uint8Array): Promise<ReadReportResult> {
  try {
    const value = strictParse(bytes, "report", limitCeilings.maxReportBytes);
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      !("schema" in value) ||
      typeof value.schema !== "string" ||
      value.schema.length === 0 ||
      value.schema.length > 256
    )
      fail("Report schema is required");
    const scanId = await scanIdFor(bytes);
    if (value.schema !== schemas.report)
      return { status: "unsupported-report", scanId, reportSchema: value.schema };
    const report = await validateReport(value);
    if (!equalBytes(bytes, canonicalBytes(report)))
      fail("Supported reports require canonical bytes");
    return {
      status: "read",
      scanId,
      report,
      authenticity: "unchecked",
      annexBytes: "not-supplied",
    };
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
}
