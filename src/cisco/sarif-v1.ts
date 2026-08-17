import { isAbsolute, relative, resolve, win32 } from "node:path";
import { z } from "zod";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";

const MAX_SARIF_BYTES = 16 * 1024 * 1024;
const MAX_RESULTS = 4096;
const MAX_RULES = 4096;
const MAX_LOCATIONS_PER_RESULT = 16;
const MAX_PATH_LENGTH = 1024;
const MAX_RULE_ID_LENGTH = 256;
const MAX_MESSAGE_LENGTH = 4096;
const MAX_TAGS = 64;
const MAX_METADATA_LENGTH = 256;
const MAX_TIMESTAMP_LENGTH = 32;
const MAX_FINGERPRINT_LENGTH = 512;
const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFORMATION_URI = "https://github.com/cisco-ai-defense/skill-scanner";
const brand = new WeakMap<object, Buffer>();

const bounded = (maximum: number) => z.string().min(1).max(maximum);
const level = z.enum(["error", "warning", "note", "none"]);
const textSchema = z.strictObject({ text: bounded(MAX_MESSAGE_LENGTH) });
const snippetSchema = z.strictObject({ text: bounded(MAX_MESSAGE_LENGTH) });
const regionSchema = z.strictObject({
  startLine: z.number().int().min(1).max(10_000_000),
  snippet: snippetSchema.optional(),
});
const artifactLocationSchema = z.strictObject({
  uri: bounded(MAX_PATH_LENGTH),
  uriBaseId: z.literal("%SRCROOT%"),
});
const physicalLocationSchema = z.strictObject({
  artifactLocation: artifactLocationSchema,
  region: regionSchema.optional(),
});
const locationSchema = z.strictObject({ physicalLocation: physicalLocationSchema });
const resultPropertiesSchema = z.strictObject({
  category: bounded(MAX_METADATA_LENGTH),
  severity: bounded(MAX_METADATA_LENGTH),
  remediation: bounded(MAX_MESSAGE_LENGTH).optional(),
});
const fingerprintsSchema = z.strictObject({
  primaryLocationLineHash: bounded(MAX_FINGERPRINT_LENGTH),
});
const resultSchema = z.strictObject({
  ruleId: bounded(MAX_RULE_ID_LENGTH),
  level,
  message: textSchema,
  properties: resultPropertiesSchema,
  fingerprints: fingerprintsSchema,
  locations: z.array(locationSchema).min(1).max(MAX_LOCATIONS_PER_RESULT),
});
const rulePropertiesSchema = z.strictObject({
  category: bounded(MAX_METADATA_LENGTH),
  severity: bounded(MAX_METADATA_LENGTH),
  tags: z.array(bounded(MAX_METADATA_LENGTH)).min(1).max(MAX_TAGS),
});
const ruleSchema = z.strictObject({
  id: bounded(MAX_RULE_ID_LENGTH),
  name: bounded(MAX_MESSAGE_LENGTH),
  shortDescription: textSchema,
  fullDescription: textSchema,
  defaultConfiguration: z.strictObject({ level }),
  properties: rulePropertiesSchema,
  help: z
    .strictObject({ text: bounded(MAX_MESSAGE_LENGTH), markdown: bounded(MAX_MESSAGE_LENGTH) })
    .optional(),
});
const reporterSchema = z.strictObject({
  $schema: z.literal(SARIF_SCHEMA),
  version: z.literal("2.1.0"),
  runs: z
    .array(
      z.strictObject({
        tool: z.strictObject({
          driver: z.strictObject({
            name: z.literal("skill-scanner"),
            version: z.literal("1.0.0"),
            informationUri: z.literal(INFORMATION_URI),
            rules: z.array(ruleSchema).max(MAX_RULES),
          }),
        }),
        invocations: z
          .array(
            z.strictObject({
              executionSuccessful: z.literal(true),
              endTimeUtc: z
                .string()
                .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
                .max(MAX_TIMESTAMP_LENGTH),
            }),
          )
          .length(1),
        results: z.array(resultSchema).max(MAX_RESULTS),
      }),
    )
    .length(1),
});
const projectionSchema = z.strictObject({
  version: z.literal("2.1.0"),
  runs: z
    .array(
      z.strictObject({
        tool: z.strictObject({
          driver: z.strictObject({ name: z.literal("cisco-ai-skill-scanner") }),
        }),
        results: z.array(
          z.strictObject({
            ruleId: bounded(MAX_RULE_ID_LENGTH),
            level,
            message: textSchema,
            locations: z.array(
              z.strictObject({
                physicalLocation: z.strictObject({
                  artifactLocation: z.strictObject({ uri: bounded(MAX_PATH_LENGTH) }),
                  region: z
                    .strictObject({ startLine: z.number().int().min(1).max(10_000_000) })
                    .optional(),
                }),
              }),
            ),
          }),
        ),
      }),
    )
    .length(1),
});

export type CiscoSarifV1 = Readonly<z.infer<typeof projectionSchema>>;
export type CiscoSarifParseContextV1 = Readonly<{ sourceRoot: string }>;

function fail(message: string): never {
  throw new TypeError(`invalid Cisco SARIF V1: ${message}`);
}

function parseContext(value: unknown): CiscoSarifParseContextV1 | undefined {
  if (value === undefined) return undefined;
  try {
    assertStrictJsonValueV1(value, "Cisco SARIF parse context");
  } catch {
    fail("parse context");
  }
  const parsed = z.strictObject({ sourceRoot: z.string().min(1).max(4096) }).safeParse(value);
  if (!parsed.success) fail("parse context");
  if (!isAbsolute(parsed.data.sourceRoot) && !isWindowsAbsolute(parsed.data.sourceRoot))
    fail("parse context");
  return parsed.data;
}

function isWindowsAbsolute(path: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(path) || /^(?:\\\\|\/\/)/.test(path);
}

function relativeDescendant(root: string, candidate: string, windows: boolean): string {
  const path = windows ? win32 : { relative, resolve, isAbsolute };
  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(candidate);
  const descendant = path.relative(resolvedRoot, resolvedCandidate);
  if (
    descendant.length === 0 ||
    descendant === ".." ||
    descendant.startsWith(`..${windows ? "\\" : "/"}`) ||
    path.isAbsolute(descendant)
  )
    fail("artifact path outside source root");
  return windows ? descendant.replaceAll("\\", "/") : descendant;
}

function projectArtifactPath(uri: string, context: CiscoSarifParseContextV1 | undefined): string {
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri) && !/^[A-Za-z]:[\\/]/.test(uri))
    fail("artifact URI scheme");
  const windows = isWindowsAbsolute(uri);
  if (windows || isAbsolute(uri)) {
    if (context === undefined) fail("absolute artifact path requires source root");
    if (windows !== isWindowsAbsolute(context.sourceRoot)) fail("artifact path root mismatch");
    const projected = relativeDescendant(context.sourceRoot, uri, windows);
    assertSafeRelativePosixPathV1(projected, "Cisco SARIF artifact path");
    return projected;
  }
  assertSafeRelativePosixPathV1(uri, "Cisco SARIF artifact path");
  return uri;
}

function project(
  value: z.infer<typeof reporterSchema>,
  context: CiscoSarifParseContextV1 | undefined,
) {
  const run = value.runs[0];
  if (run === undefined) fail("SARIF run");
  return {
    version: "2.1.0" as const,
    runs: [
      {
        tool: { driver: { name: "cisco-ai-skill-scanner" as const } },
        results: run.results.map((result) => ({
          ruleId: result.ruleId,
          level: result.level,
          message: { text: result.message.text },
          locations: result.locations.map((location) => ({
            physicalLocation: {
              artifactLocation: {
                uri: projectArtifactPath(location.physicalLocation.artifactLocation.uri, context),
              },
              ...(location.physicalLocation.region === undefined
                ? {}
                : { region: { startLine: location.physicalLocation.region.startLine } }),
            },
          })),
        })),
      },
    ],
  };
}

export function parseCiscoSarifV1(text: string, context?: unknown): CiscoSarifV1 {
  if (Buffer.byteLength(text, "utf8") > MAX_SARIF_BYTES) fail("SARIF exceeds bounded size");
  const raw = parseStrictJsonObjectV1(text, "Cisco SARIF");
  const parsed = reporterSchema.safeParse(raw);
  if (!parsed.success) fail(parsed.error.issues[0]?.message ?? "schema");
  const projected = projectionSchema.safeParse(project(parsed.data, parseContext(context)));
  if (!projected.success) fail(projected.error.issues[0]?.message ?? "projection");
  const value = deepFreezeStrictJsonV1(structuredClone(projected.data)) as CiscoSarifV1;
  brand.set(value as object, canonicalStrictJsonBytesV1(value));
  return value;
}

export function canonicalCiscoSarifV1Bytes(value: unknown): Buffer {
  if (typeof value !== "object" || value === null)
    fail("canonical bytes require a validated value");
  const bytes = brand.get(value);
  if (bytes === undefined) fail("canonical bytes require a validated branded value");
  return Buffer.from(bytes);
}
