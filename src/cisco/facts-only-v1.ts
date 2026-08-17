import { createHash } from "node:crypto";
import { z } from "zod";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../contract/strict-json-v1.js";
import {
  createEvidenceAnnexV1,
  createObservationKeyV1,
  createObservationSetV1,
} from "../observation/observation-evidence-v1.js";
import { createScannerManifestV1 } from "../observation/scanner-manifest-v1.js";

const MAX_FILE_IDENTITIES = 4096;
const MAX_RESULTS = 4096;
const MAX_LOCATIONS_PER_RESULT = 16;
const MAX_PATH_LENGTH = 1024;
const MAX_RULE_ID_LENGTH = 256;
const MAX_MESSAGE_LENGTH = 4096;
const MAX_LEVEL_LENGTH = 64;
const MAX_ANNEX_BYTES = 16 * 1024 * 1024;

const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const bounded = (maximum: number) => z.string().min(1).max(maximum);
const platformSchema = z.strictObject({
  os: z.literal("linux"),
  architecture: z.literal("amd64"),
});
const regionSchema = z.strictObject({
  startLine: z.number().int().min(1).max(10_000_000),
  startColumn: z.number().int().min(1).max(1_000_000).optional(),
  endLine: z.number().int().min(1).max(10_000_000).optional(),
  endColumn: z.number().int().min(1).max(1_000_000).optional(),
});
const artifactLocationSchema = z.strictObject({ uri: bounded(MAX_PATH_LENGTH) });
const physicalLocationSchema = z.strictObject({
  artifactLocation: artifactLocationSchema,
  region: regionSchema.optional(),
});
const locationSchema = z.strictObject({ physicalLocation: physicalLocationSchema });
const resultSchema = z.strictObject({
  ruleId: bounded(MAX_RULE_ID_LENGTH),
  level: bounded(MAX_LEVEL_LENGTH).optional(),
  message: z.strictObject({ text: bounded(MAX_MESSAGE_LENGTH) }),
  locations: z.array(locationSchema).min(1).max(MAX_LOCATIONS_PER_RESULT),
});
const sarifSchema = z.strictObject({
  version: z.literal("2.1.0"),
  runs: z
    .array(
      z.strictObject({
        tool: z.strictObject({
          driver: z.strictObject({ name: z.literal("cisco-ai-skill-scanner") }),
        }),
        results: z.array(resultSchema).max(MAX_RESULTS),
      }),
    )
    .length(1),
});
const fileSha256ByPathSchema = z
  .record(z.string(), sha256)
  .refine((value) => Object.keys(value).length <= MAX_FILE_IDENTITIES, "too many file identities")
  .superRefine((value, context) => {
    for (const path of Object.keys(value)) {
      try {
        assertSafeRelativePosixPathV1(path, "Cisco file identity path");
      } catch {
        context.addIssue({
          code: "custom",
          message: "invalid Cisco file identity path",
          path: [path],
        });
      }
    }
  });
const sourceSealSchema = z.strictObject({
  protocol: z.literal("SourceSealV1"),
  sourceTreeSha256: sha256,
  selectedClosureSha256: sha256,
  sealedSnapshotSha256: sha256,
});
const coverageSchema = z
  .array(
    z.strictObject({
      coverageKind: z.enum(["selected-closure", "source-tree"]),
      coverageSha256: sha256,
    }),
  )
  .min(1)
  .max(2)
  .refine(
    (coverage) => new Set(coverage.map((entry) => entry.coverageKind)).size === coverage.length,
    "duplicate coverage kind",
  );
const identitiesSchema = z
  .strictObject({
    analyzer: z.strictObject({
      identity: z.string().regex(/^native\.[a-f0-9]{12}$/),
      version: bounded(128),
      lockSha256: sha256,
    }),
    observationConfigurationSha256: sha256,
    sourceSeal: sourceSealSchema,
    coverage: coverageSchema,
    ociImage: z.strictObject({
      reference: z.string().regex(/^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$/),
      sha256,
    }),
    adapter: z.strictObject({
      identity: z.string().regex(/^adapter\.[a-f0-9]{12}$/),
      sha256,
    }),
    executionProfileSha256: sha256,
    supportedPlatforms: z.array(platformSchema).min(1).max(8),
    sbom: z.strictObject({ mediaType: z.literal("application/spdx+json"), sha256 }),
    provenance: z.strictObject({
      mediaType: z.literal("application/vnd.in-toto+json"),
      sha256,
    }),
  })
  .superRefine((identities, context) => {
    if (!identities.ociImage.reference.endsWith(`@sha256:${identities.ociImage.sha256}`))
      context.addIssue({
        code: "custom",
        message: "OCI reference digest mismatch",
        path: ["ociImage"],
      });
    if (
      identities.supportedPlatforms[0]?.os !== "linux" ||
      identities.supportedPlatforms[0]?.architecture !== "amd64"
    )
      context.addIssue({
        code: "custom",
        message: "Cisco linux/amd64 must be first supported platform",
        path: ["supportedPlatforms", 0],
      });
    if (
      new Set(identities.supportedPlatforms.map((entry) => `${entry.os}/${entry.architecture}`))
        .size !== identities.supportedPlatforms.length
    )
      context.addIssue({ code: "custom", message: "duplicate supported platform" });
  });
const inputSchema = z.strictObject({
  protocol: z.literal("CiscoFactsOnlyV1"),
  sarif: sarifSchema,
  fileSha256ByPath: fileSha256ByPathSchema,
  platform: platformSchema,
  identities: identitiesSchema.optional(),
});

type CiscoResult = z.infer<typeof resultSchema>;
type CiscoIdentities = {
  analyzer: { identity: string; version: string; lockSha256: string };
  observationConfigurationSha256: string;
  sourceSeal: {
    protocol: "SourceSealV1";
    sourceTreeSha256: string;
    selectedClosureSha256: string;
    sealedSnapshotSha256: string;
  };
  coverage: { coverageKind: "selected-closure" | "source-tree"; coverageSha256: string }[];
  ociImage: { reference: string; sha256: string };
  adapter: { identity: string; sha256: string };
  executionProfileSha256: string;
  supportedPlatforms: { os: "linux"; architecture: "amd64" }[];
  sbom: { mediaType: "application/spdx+json"; sha256: string };
  provenance: { mediaType: "application/vnd.in-toto+json"; sha256: string };
};
type CiscoInput = {
  protocol: "CiscoFactsOnlyV1";
  sarif: {
    version: "2.1.0";
    runs: [{ tool: { driver: { name: "cisco-ai-skill-scanner" } }; results: CiscoResult[] }];
  };
  fileSha256ByPath: Record<string, string>;
  platform: { os: "linux"; architecture: "amd64" };
  identities?: CiscoIdentities;
};

const fail = (message: string): never => {
  throw new TypeError(`invalid Cisco facts input: ${message}`);
};
const parse = (input: unknown): CiscoInput => {
  // Validate ownership and JSON-only data before a schema can read any property.
  assertStrictJsonValueV1(input, "Cisco facts input");
  const parsed = inputSchema.safeParse(input);
  if (!parsed.success) fail(parsed.error.issues[0]?.message ?? "schema");
  return parsed.data as unknown as CiscoInput;
};
function canonicalResultDetail(result: CiscoResult) {
  return {
    nativeRuleId: result.ruleId,
    message: result.message.text,
    level: result.level ?? "",
    locations: result.locations,
  };
}
function fingerprint(entry: {
  nativeRuleId: string;
  path: string;
  fileSha256: string;
  canonicalOrdinal: number;
}) {
  return `raw-occurrence-v1:${canonicalStrictJsonSha256V1({
    protocol: "RawOccurrenceFingerprintV1",
    detectorClass: "cisco",
    nativeRuleId: entry.nativeRuleId,
    path: entry.path,
    fileSha256: entry.fileSha256,
    canonicalOrdinal: entry.canonicalOrdinal,
  })}`;
}
function effectiveObservationConfigurationSha256(identities: CiscoIdentities): string {
  return canonicalStrictJsonSha256V1({
    domain: "aih.cisco.observation-configuration-v1",
    nativeAnalyzerIdentity: identities.analyzer.identity,
    analyzerVersion: identities.analyzer.version,
    analyzerLockSha256: identities.analyzer.lockSha256,
    declaredObservationConfigurationSha256: identities.observationConfigurationSha256,
  });
}

// biome-ignore lint/suspicious/noExplicitAny: adapter has an intentionally broad internal projection.
export function createCiscoFactsOnlyV1(input: unknown): any {
  const value = parse(input);
  const run = value.sarif.runs[0];
  if (run === undefined) fail("SARIF run");
  const normalized = run.results.map((result) => {
    const locationIdentities = result.locations.map((location) => {
      const path = location.physicalLocation.artifactLocation.uri;
      assertSafeRelativePosixPathV1(path, "Cisco SARIF artifact path");
      if (!Object.hasOwn(value.fileSha256ByPath, path)) fail("file identity");
      return { path, fileSha256: value.fileSha256ByPath[path] ?? fail("file identity") };
    });
    const primaryLocation = locationIdentities[0] ?? fail("SARIF result location");
    return {
      nativeRuleId: result.ruleId,
      path: primaryLocation.path,
      fileSha256: primaryLocation.fileSha256,
      message: result.message.text,
      level: result.level ?? "",
      locations: result.locations,
    };
  });
  normalized.sort((left, right) =>
    canonicalStrictJsonBytesV1({
      detectorClass: "cisco",
      path: left.path,
      fileSha256: left.fileSha256,
      ...canonicalResultDetail({
        ruleId: left.nativeRuleId,
        message: { text: left.message },
        level: left.level || undefined,
        locations: left.locations,
      }),
    }).compare(
      canonicalStrictJsonBytesV1({
        detectorClass: "cisco",
        path: right.path,
        fileSha256: right.fileSha256,
        ...canonicalResultDetail({
          ruleId: right.nativeRuleId,
          message: { text: right.message },
          level: right.level || undefined,
          locations: right.locations,
        }),
      }),
    ),
  );
  const ordinals = new Map<string, number>();
  const facts = normalized.map((item) => {
    const group = `${item.nativeRuleId}\u0000${item.path}\u0000${item.fileSha256}`;
    const canonicalOrdinal = ordinals.get(group) ?? 0;
    ordinals.set(group, canonicalOrdinal + 1);
    return {
      detectorClass: "cisco",
      nativeRuleId: item.nativeRuleId,
      path: item.path,
      fileSha256: item.fileSha256,
      canonicalOrdinal,
      multiplicity: 1,
      rawOccurrenceFingerprint: fingerprint({ ...item, canonicalOrdinal }),
    };
  });
  const annexBytes = canonicalStrictJsonBytesV1(
    normalized.map(({ nativeRuleId, path, fileSha256, message, level, locations }) => ({
      detectorClass: "cisco",
      nativeRuleId,
      path,
      fileSha256,
      message,
      level,
      locations,
    })),
  );
  if (annexBytes.length > MAX_ANNEX_BYTES) fail("annex exceeds bounded evidence size");
  const evidenceAnnex = createEvidenceAnnexV1({
    protocol: "EvidenceAnnexV1",
    descriptors: [
      {
        descriptorId: "annex.cisco-raw",
        mediaType: "application/json",
        sha256: createHash("sha256").update(annexBytes).digest("hex"),
        byteLength: annexBytes.length,
        uri: "annex/cisco-raw.json",
      },
    ],
  });
  const base = {
    protocol: "CiscoFactsOnlyV1" as const,
    facts,
    annexBytes,
    evidenceAnnex,
    coverage: [
      {
        coverageKind: "selected-closure" as const,
        coverageSha256: canonicalStrictJsonSha256V1({
          domain: "aih.cisco.coverage",
          kind: "selected-closure",
          files: Object.entries(value.fileSha256ByPath).sort(),
        }),
      },
    ],
  };
  const identities = value.identities;
  if (identities === undefined) return Object.freeze(base);

  const effectiveConfigurationSha256 = effectiveObservationConfigurationSha256(identities);
  const scannerManifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: [
      {
        detectorId: "detector.cisco",
        analyzerIdentity: identities.analyzer.identity,
        ociImage: identities.ociImage,
        adapter: identities.adapter,
        observationConfigurationSha256: effectiveConfigurationSha256,
        executionProfileSha256: identities.executionProfileSha256,
        supportedPlatforms: identities.supportedPlatforms,
        sbom: identities.sbom,
        provenance: identities.provenance,
      },
    ],
  });
  const detector = scannerManifest.detectors.find((entry) => entry.detectorId === "detector.cisco");
  if (detector === undefined) return fail("Cisco manifest detector");
  const relevantFactsSha256 = canonicalStrictJsonSha256V1({
    domain: "aih.cisco.relevant-facts-v1",
    sourceSeal: identities.sourceSeal,
  });
  const observationKeyInput = {
    protocol: "ObservationKeyV1" as const,
    sourceSeal: identities.sourceSeal,
    nativeAnalyzerIdentity: identities.analyzer.identity,
    observationConfigurationSha256: effectiveConfigurationSha256,
    platform: { ...value.platform, relevantFactsSha256 },
    scannerManifestEntrySha256: detector.scannerManifestEntrySha256,
  };
  const observationKey = createObservationKeyV1(observationKeyInput);
  const coverage = identities.coverage;
  const observationSet = createObservationSetV1({
    protocol: "ObservationSetV1",
    observationKey: observationKeyInput,
    facts: facts.map(({ rawOccurrenceFingerprint, multiplicity }) => ({
      rawOccurrenceFingerprint,
      multiplicity,
    })),
    coverage,
  });
  return Object.freeze({
    ...base,
    observationConfigurationSha256: effectiveConfigurationSha256,
    scannerManifest,
    scannerManifestEntrySha256: detector.scannerManifestEntrySha256,
    observationKey,
    observationSet,
    coverage,
  });
}
