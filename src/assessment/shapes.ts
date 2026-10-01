import { z } from "zod";
import { hasControl } from "./json.js";
import { assertSafeRelativePosixPathV1 } from "./strict-json.js";
import { type defaultLimits, limitCeilings, schemas } from "./types.js";

const utf8 = (limit: number, min = 1) =>
  z
    .string()
    .min(min)
    .max(limit)
    .refine(
      (value) =>
        new TextEncoder().encode(value).length >= min &&
        new TextEncoder().encode(value).length <= limit,
      "UTF-8 string bound",
    );
export const labelShape = utf8(256)
  // biome-ignore lint/suspicious/noControlCharactersInRegex: The public schema intentionally excludes control characters.
  .regex(/^[^\u0000-\u001f\u007f]+$/)
  .refine((value) => !hasControl(value), "label must not contain controls");
export const digestShape = z.string().regex(/^[0-9a-f]{64}$/);
export const scanIdShape = z.string().regex(/^scan:sha256:[0-9a-f]{64}$/);
export const pathShape = utf8(4096)
  // biome-ignore lint/suspicious/noControlCharactersInRegex: Paths must exclude every control character as well as traversal syntax.
  .regex(/^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\/\/)[^\\%?#:\u0000-\u001f\u007f]+(?<!\/)$/)
  .refine((value) => {
    try {
      assertSafeRelativePosixPathV1(value, "path");
      return true;
    } catch {
      return false;
    }
  }, "safe source-relative path");
export const timestampShape = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  .refine(
    (value) => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value,
    "real calendar timestamp",
  );
export const integerShape = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const detailShape = utf8(4096, 0);
export const diagnosticShape = z
  .object({
    code: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/),
    detail: detailShape,
    detectorId: labelShape.optional(),
    path: pathShape.optional(),
  })
  .strict();
export const producerShape = z
  .object({ name: z.literal("@aihq/scan"), version: labelShape })
  .strict();
export const repositoryShape = utf8(2048)
  .regex(/^https:\/\/[^/@\s]+(?:\/[^?#\s]*)?$/)
  .refine((value) => {
    try {
      const url = new URL(value);
      return (
        !hasControl(value, true) &&
        url.protocol === "https:" &&
        !url.username &&
        !url.password &&
        !url.hash &&
        !url.search &&
        !!url.hostname
      );
    } catch {
      return false;
    }
  }, "credential-free HTTPS repository URL");
const absolutePath = utf8(4096)
  .regex(/^(?:[A-Za-z]:[\\/]|\/|\\\\)/)
  .refine(
    (value) => /^(?:[A-Za-z]:[\\/]|\/|\\\\)/.test(value) && !hasControl(value),
    "absolute host path",
  );
export const locationShape = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("file"), path: absolutePath }).strict(),
  z
    .object({
      kind: z.literal("https"),
      url: utf8(2048).refine((value) => {
        try {
          const url = new URL(value);
          return (
            url.protocol === "https:" &&
            !url.username &&
            !url.password &&
            !url.hash &&
            !!url.hostname
          );
        } catch {
          return false;
        }
      }),
    })
    .strict(),
]);
export const entryShape = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("file"),
      path: pathShape,
      sha256: digestShape,
      byteLength: integerShape,
    })
    .strict(),
  z.object({ kind: z.literal("directory"), path: pathShape }).strict(),
  z
    .object({
      kind: z.literal("file-link"),
      path: pathShape,
      target: pathShape,
      sha256: digestShape,
      byteLength: integerShape,
    })
    .strict(),
  z.object({ kind: z.literal("directory-link"), path: pathShape, target: pathShape }).strict(),
]);
export const limitsShape = z
  .object(
    Object.fromEntries(
      Object.entries(limitCeilings).map(([key, value]) => [
        key,
        integerShape.min(key === "detectorTimeoutMs" ? 100 : 1).max(value),
      ]),
    ) as { [K in keyof typeof defaultLimits]: z.ZodNumber },
  )
  .strict();
export const annexDescriptorShape = z
  .object({
    id: z.string().regex(/^annex\.[a-z0-9][a-z0-9._-]{0,249}$/),
    mediaType: utf8(256).refine((value) =>
      /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:;[ -~]+)?$/.test(value),
    ),
    sha256: digestShape,
    byteLength: integerShape,
  })
  .strict();
const field = <T extends z.ZodType>(value: T) =>
  z.discriminatedUnion("state", [
    z.object({ state: z.literal("present"), value }).strict(),
    z.object({ state: z.literal("unavailable"), reason: labelShape, detail: detailShape }).strict(),
  ]);
export const findingShape = z
  .object({
    rawOccurrenceFingerprint: z.string().regex(/^raw-occurrence-v1:[0-9a-f]{64}$/),
    multiplicity: integerShape.min(1),
    rule: field(z.object({ nativeRuleId: labelShape, name: labelShape.optional() }).strict()),
    severity: field(
      z.object({ level: labelShape, vendorSeverity: labelShape.optional() }).strict(),
    ),
    message: field(utf8(16384, 0)),
    location: field(
      z
        .object({
          path: pathShape,
          fileSha256: digestShape,
          startLine: integerShape.min(1).optional(),
        })
        .strict(),
    ),
    supportingEvidence: field(
      z.object({ annexId: annexDescriptorShape.shape.id, ordinal: integerShape }).strict(),
    ),
  })
  .strict();
export const observationInputShape = z
  .object({
    detectorId: labelShape,
    detectorVersion: labelShape,
    adapterSha256: digestShape,
    rulesSha256: digestShape,
    configurationSha256: digestShape,
    profileId: labelShape,
    profileSha256: digestShape,
    platform: z
      .object({ os: labelShape, architecture: labelShape, relevantFactsSha256: digestShape })
      .strict(),
    scopeKind: z.enum(["source-tree", "selected-closure"]),
    targetPaths: z.array(pathShape),
    entries: z.array(entryShape),
  })
  .strict();
export const observationBodyShape = z
  .object({
    format: z.literal("aih-observation-v1"),
    input: observationInputShape,
    startedAt: timestampShape,
    completedAt: timestampShape,
    producer: producerShape,
    coverage: z.object({ coveredPaths: z.array(pathShape) }).strict(),
    findings: z.array(findingShape),
    gaps: z.array(z.object({ reason: labelShape, detail: detailShape }).strict()),
    annexIds: z.array(annexDescriptorShape.shape.id),
  })
  .strict();
export const observationShape = z
  .object({
    observationId: z.string().regex(/^observation:sha256:[0-9a-f]{64}$/),
    body: observationBodyShape,
    origin: z.enum(["fresh", "reused"]),
    fromScanId: scanIdShape.optional(),
  })
  .strict();
export const detectorResultShape = z
  .object({
    detectorId: labelShape,
    outcome: z.enum(["succeeded", "failed", "refused", "cancelled"]),
    observations: z.array(observationShape),
    coverage: z
      .object({
        coveredPaths: z.array(pathShape),
        excludedPaths: z.array(pathShape),
        uncoveredPaths: z.array(pathShape),
        complete: z.boolean(),
      })
      .strict(),
    diagnostics: z.array(diagnosticShape),
  })
  .strict();
export const requestShape = z
  .object({
    schema: z.literal(schemas.request),
    source: z.discriminatedUnion("kind", [
      z.object({ kind: z.literal("local"), path: absolutePath }).strict(),
      z
        .object({
          kind: z.literal("git"),
          repository: repositoryShape,
          commit: z.string().regex(/^[0-9a-f]{40}$/),
        })
        .strict(),
    ]),
    selection: z
      .object({
        paths: z.union([z.literal("all"), z.array(pathShape)]),
        excludedPaths: z.array(pathShape),
      })
      .strict(),
    detectors: z
      .array(
        z
          .object({
            detectorId: labelShape,
            profileId: labelShape.optional(),
            configuration: z.json(),
          })
          .strict(),
      )
      .min(1),
    priorArtifacts: z
      .array(z.object({ scanId: scanIdShape, location: locationShape }).strict())
      .optional(),
    limits: limitsShape.partial().optional(),
  })
  .strict();
export const captureShape = z
  .object({
    profile: z.literal("aih-source-capture-1"),
    entries: z.array(entryShape),
    captureSha256: digestShape,
  })
  .strict();
export const reportShape = z
  .object({
    schema: z.literal(schemas.report),
    producer: producerShape,
    createdAt: timestampShape,
    source: z.discriminatedUnion("kind", [
      z.object({ kind: z.literal("local"), capture: captureShape }).strict(),
      z
        .object({
          kind: z.literal("git"),
          repository: repositoryShape,
          commit: z.string().regex(/^[0-9a-f]{40}$/),
          capture: captureShape,
        })
        .strict(),
    ]),
    selection: z.object({ paths: z.array(pathShape), excludedPaths: z.array(pathShape) }).strict(),
    requestedDetectors: z
      .array(
        z
          .object({
            detectorId: labelShape,
            profileId: labelShape.nullable(),
            configuration: z.json(),
            configurationSha256: digestShape,
          })
          .strict(),
      )
      .min(1),
    results: z.array(detectorResultShape).min(1),
    completion: z.enum(["complete", "partial"]),
    annexes: z.array(annexDescriptorShape),
    effectiveLimits: limitsShape,
    diagnostics: z.array(diagnosticShape),
  })
  .strict();
export const runResultShape = z.discriminatedUnion("status", [
  z
    .object({
      schema: z.literal(schemas.runResult),
      status: z.literal("assessment"),
      scanId: scanIdShape,
      report: reportShape,
      annexes: z.array(
        z.object({ id: annexDescriptorShape.shape.id, bytesBase64: z.string() }).strict(),
      ),
      diagnostics: z.array(diagnosticShape),
    })
    .strict(),
  z
    .object({
      schema: z.literal(schemas.runResult),
      status: z.literal("diagnostic"),
      phase: z.enum(["request", "capture", "assembly"]),
      diagnostics: z.array(diagnosticShape),
    })
    .strict(),
]);
export const evidenceAssociationShape = z
  .object({
    schema: z.literal(schemas.evidenceAssociation),
    scanId: scanIdShape,
    location: locationShape,
  })
  .strict();
