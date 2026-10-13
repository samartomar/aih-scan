import { z } from "zod";
import { resolveDetectorCapabilityV1 } from "../capability/detector-capability-v1.js";
import { bound, canonicalBytes, fail, sha256, strictParse } from "./json.js";
import { digestShape, labelShape } from "./shapes.js";

export const detectorDefinitionSchemaV1 = "urn:aihq:scan:detector-definition:1.0.0";
const maxRulesBytes = 1024 * 1024;
const definitionShape = z
  .object({
    schema: z.literal(detectorDefinitionSchemaV1),
    detectorId: labelShape,
    version: labelShape,
    adapter: z.literal("semgrep-sarif-v1"),
    profileId: z.literal("host-process-uv-v1"),
    rules: z
      .object({ sha256: digestShape, byteLength: z.number().int().min(1).max(maxRulesBytes) })
      .strict(),
  })
  .strict();
/** Portable, closed definition. Rule bytes are supplied separately by the host. */
export type DetectorDefinitionV1 = z.infer<typeof definitionShape>;
export interface SuppliedDetectorDefinitionV1 {
  definition: DetectorDefinitionV1;
  rules: Uint8Array;
}
export interface AdmittedSemgrepDefinitionV1 {
  readonly detectorId: string;
  readonly version: string;
  readonly definitionSha256: string;
  readonly adapter: "semgrep-sarif-v1";
  readonly profileId: "host-process-uv-v1";
  readonly rules: Readonly<{ utf8: string; sha256: string; byteLength: number }>;
}
const admitted = new WeakSet<object>();
export function isAdmittedSemgrepDefinitionV1(
  value: unknown,
): value is AdmittedSemgrepDefinitionV1 {
  return typeof value === "object" && value !== null && admitted.has(value);
}
/** Snapshot every supplied bundle before any source capture or detector effect. */
export async function admitDetectorDefinitionsV1(
  raw: unknown,
): Promise<ReadonlyMap<string, AdmittedSemgrepDefinitionV1>> {
  const result = new Map<string, AdmittedSemgrepDefinitionV1>();
  if (raw === undefined) return result;
  if (!Array.isArray(raw)) fail("Detector definitions must be an array");
  bound(raw.length <= 64, "detector definitions", 64);
  // Copy all caller-owned bytes synchronously before the first asynchronous digest.
  const snapshots = raw.map((bundle: unknown) => {
    if (
      typeof bundle !== "object" ||
      bundle === null ||
      Array.isArray(bundle) ||
      Object.keys(bundle).sort().join(",") !== "definition,rules"
    )
      fail("Invalid supplied detector bundle");
    const value = bundle as SuppliedDetectorDefinitionV1;
    const bytes = canonicalBytes(value.definition);
    const parsed = definitionShape.safeParse(strictParse(bytes, "detector definition", 16384));
    if (!parsed.success) fail("Detector definition does not match the closed supported schema");
    if (!(value.rules instanceof Uint8Array)) fail("Detector rules must be bytes");
    bound(value.rules.byteLength <= maxRulesBytes, "detector rule bytes", maxRulesBytes);
    return { definition: parsed.data, bytes: Uint8Array.from(value.rules) };
  });
  for (const { definition, bytes } of snapshots) {
    if (resolveDetectorCapabilityV1(definition.detectorId) || result.has(definition.detectorId))
      fail("Supplied detector IDs must be unique and cannot shadow built-in detectors");
    if (
      bytes.length !== definition.rules.byteLength ||
      (await sha256(bytes)) !== definition.rules.sha256
    )
      fail("Detector rule bytes disagree with the declared material identity");
    let utf8: string;
    try {
      utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      fail("Detector rule material must be valid UTF-8");
    }
    const descriptor: AdmittedSemgrepDefinitionV1 = Object.freeze({
      detectorId: definition.detectorId,
      version: definition.version,
      definitionSha256: await sha256(canonicalBytes(definition)),
      adapter: definition.adapter,
      profileId: definition.profileId,
      rules: Object.freeze({ utf8, ...definition.rules }),
    });
    admitted.add(descriptor);
    result.set(descriptor.detectorId, descriptor);
  }
  return result;
}
