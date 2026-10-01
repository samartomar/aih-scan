import type { ReportBody } from "../../src/assessment/types.js";
export function emptyReport(): ReportBody {
  return {
    schema: "urn:aihq:scan:report:1.0.0",
    producer: { name: "@aihq/scan", version: "0.5.0" },
    createdAt: "2026-10-01T00:00:00.000Z",
    source: {
      kind: "local",
      capture: {
        profile: "aih-source-capture-1",
        entries: [],
        captureSha256: "63eabbc6d6f3c6b0fdd7514e763b63a5aaf0ec817f03e8001c51512e5950b584",
      },
    },
    selection: { paths: [], excludedPaths: [] },
    requestedDetectors: [
      {
        detectorId: "detector.unknown",
        profileId: null,
        configuration: {},
        configurationSha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      },
    ],
    results: [
      {
        detectorId: "detector.unknown",
        outcome: "refused",
        observations: [],
        coverage: { coveredPaths: [], excludedPaths: [], uncoveredPaths: [], complete: true },
        diagnostics: [{ code: "unknown-detector", detail: "No definition is available." }],
      },
    ],
    completion: "partial",
    annexes: [],
    effectiveLimits: {
      maxSourceEntries: 100000,
      maxSourceBytes: 268435456,
      maxRequestBytes: 2097152,
      maxReportBytes: 16777216,
      maxAnnexBytes: 16777216,
      maxDecodedArtifactBytes: 67108864,
      maxArtifactBytes: 100663296,
      maxStatementBytes: 131072,
      detectorTimeoutMs: 600000,
    },
    diagnostics: [],
  };
}
