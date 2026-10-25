import { z } from "zod";
import type { ReadArtifactResult } from "../artifact/types.js";
import {
  admitCoverageRead,
  coverageBatchLimits,
  maxContentDescriptors,
  readContentCoverageBatch,
  snapshotQueries,
} from "./content-coverage.js";
import { bound, canonicalBytes, equalBytes, errorDiagnostic, fail, sha256 } from "./json.js";
import {
  diagnosticShape,
  digestShape,
  findingShape,
  integerShape,
  labelShape,
  pathShape,
  scanIdShape,
  timestampShape,
} from "./shapes.js";
import type {
  ContentCoverageBatchRow,
  ContentCoverageObservation,
  Diagnostic,
  ExecutableState,
  Finding,
  ObservationInput,
  ReadReportResult,
  ScanId,
} from "./types.js";

export const itemRecordSchema = "urn:aihq:scan:item-record:1.0.0";
export interface ItemMaterial {
  path: string;
  sha256: string;
  byteLength: number;
  executable: ExecutableState;
  role: "content" | "behaviour";
}
export interface ItemSubject {
  frameworkId: string;
  itemId: string;
  contentSha256: string;
  behaviourSha256: string;
}
export interface ItemDescriptor extends ItemSubject {
  materials: ItemMaterial[];
}
export interface ItemRecord {
  schema: typeof itemRecordSchema;
  scanId: ScanId;
  createdAt: string;
  subject: ItemSubject;
  materials: (ItemMaterial & {
    captured: boolean;
    digestMatch: boolean;
    lengthMatch: boolean;
    executableComparison: "equal" | "differs" | "unknown";
  })[];
  coverage: "matched" | "mismatched";
  detectors: {
    detectorId: string;
    outcome: "succeeded" | "failed" | "refused" | "cancelled";
    requestedProfileId: string | null;
    effectiveProfileId: string | null;
    itemCoverage: "covered" | "partial" | "uncovered";
    findings: Finding[];
    inputSha256s: string[];
  }[];
  completion: "complete" | "partial";
  evidenceKey: string;
  authenticity: "unchecked";
}
export type ItemRecordResult =
  | ItemRecord
  | { coverage: "invalid" | "unavailable"; diagnostics: Diagnostic[] };
export type ItemAssessment = ReadReportResult | ReadArtifactResult;
export type ItemRecordBatchResult =
  | { status: "complete"; results: ItemRecordResult[] }
  | { status: "invalid"; diagnostics: Diagnostic[] };
const executable = z.union([z.boolean(), z.literal("unknown")]);
const materialShape = z
  .object({
    path: pathShape,
    sha256: digestShape,
    byteLength: integerShape,
    executable,
    role: z.enum(["content", "behaviour"]),
  })
  .strict();
const itemShape = z
  .object({
    frameworkId: labelShape,
    itemId: labelShape,
    contentSha256: digestShape,
    behaviourSha256: digestShape,
    materials: z.array(materialShape).min(1).max(maxContentDescriptors),
  })
  .strict();
export const itemRecordShape = z
  .object({
    schema: z.literal(itemRecordSchema),
    scanId: scanIdShape,
    createdAt: timestampShape,
    subject: itemShape.omit({ materials: true }),
    materials: z
      .array(
        materialShape.extend({
          captured: z.boolean(),
          digestMatch: z.boolean(),
          lengthMatch: z.boolean(),
          executableComparison: z.enum(["equal", "differs", "unknown"]),
        }),
      )
      .min(1)
      .max(maxContentDescriptors),
    coverage: z.enum(["matched", "mismatched"]),
    detectors: z.array(
      z
        .object({
          detectorId: labelShape,
          outcome: z.enum(["succeeded", "failed", "refused", "cancelled"]),
          requestedProfileId: labelShape.nullable(),
          effectiveProfileId: labelShape.nullable(),
          itemCoverage: z.enum(["covered", "partial", "uncovered"]),
          findings: z.array(findingShape),
          inputSha256s: z.array(digestShape),
        })
        .strict(),
    ),
    completion: z.enum(["complete", "partial"]),
    evidenceKey: digestShape,
    authenticity: z.literal("unchecked"),
  })
  .strict();
/** Public result schema includes truthful refusals when no record can be derived. */
export const itemRecordResultShape = z.union([
  itemRecordShape,
  z
    .object({ coverage: z.enum(["invalid", "unavailable"]), diagnostics: z.array(diagnosticShape) })
    .strict(),
]);
function descriptor(value: unknown): ItemDescriptor {
  const parsed = itemShape.safeParse(value);
  if (!parsed.success)
    fail("An item requires its subject and exact materials, including one behaviour file");
  if (parsed.data.materials.filter((m) => m.role === "behaviour").length !== 1)
    fail("An item requires exactly one behaviour material");
  if (new Set(parsed.data.materials.map((m) => m.path)).size !== parsed.data.materials.length)
    fail("Item material paths must be unique");
  return parsed.data;
}
const subjectOf = ({
  frameworkId,
  itemId,
  contentSha256,
  behaviourSha256,
}: ItemDescriptor): ItemSubject => ({ frameworkId, itemId, contentSha256, behaviourSha256 });
const comparison = (declared: ExecutableState, captured: ExecutableState) =>
  declared === "unknown" || captured === "unknown"
    ? ("unknown" as const)
    : declared === captured
      ? ("equal" as const)
      : ("differs" as const);

/** Pure derivation. The assessment is a revalidated public read result, never a trusted cache. */
export async function recordItem(
  assessment: ItemAssessment,
  item: ItemDescriptor,
): Promise<ItemRecordResult> {
  const batch = await recordItemBatch({ assessment, items: [item] });
  return batch.status === "complete"
    ? batch.results[0]!
    : { coverage: "invalid", diagnostics: batch.diagnostics };
}

/** Independent item rows; all byte/length and successful-observation checks use the batch coverage reader. */
export async function recordItemBatch(input: {
  assessment: ItemAssessment;
  items: ItemDescriptor[];
}): Promise<ItemRecordBatchResult> {
  try {
    if (
      !input ||
      typeof input !== "object" ||
      Reflect.ownKeys(input).length !== 2 ||
      Object.keys(input).sort().join(",") !== "assessment,items"
    )
      fail("Item batch requires assessment and items");
    if (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
      fail("Item batch requires a plain object");
    const itemsProperty = Object.getOwnPropertyDescriptor(input, "items");
    const assessmentProperty = Object.getOwnPropertyDescriptor(input, "assessment");
    if (
      !itemsProperty ||
      !("value" in itemsProperty) ||
      !assessmentProperty ||
      !("value" in assessmentProperty)
    )
      fail("Item batch requires own data properties");
    const items = snapshotQueries(itemsProperty.value).map((value) => {
      try {
        return { item: descriptor(value) };
      } catch (error) {
        return { invalid: { coverage: "invalid" as const, diagnostics: [errorDiagnostic(error)] } };
      }
    });
    const references = items.reduce(
      (count, entry) => count + (entry.item?.materials.length ?? 0),
      0,
    );
    bound(
      references <= coverageBatchLimits.maxDescriptorReferences,
      "descriptor references",
      coverageBatchLimits.maxDescriptorReferences,
    );
    // The existing batch reader bounds one conjunctive query per material, so one
    // successful observation need not span independent units to cover the item.

    const admitted = await admitCoverageRead({ read: assessmentProperty.value });
    if (admitted.status !== "admitted")
      return {
        status: "complete",
        results: items.map(
          (entry) =>
            entry.invalid ?? { coverage: "unavailable", diagnostics: admitted.diagnostics },
        ),
      };
    const { report, scanId } = admitted;
    const queries = items.flatMap(
      (entry) =>
        entry.item?.materials.map(({ path, sha256, byteLength }) => ({
          descriptors: [{ path, sha256, byteLength }],
        })) ?? [],
    );
    if (!queries.length)
      return { status: "complete", results: items.map((entry) => entry.invalid!) };
    const units = report.results.reduce((n, result) => n + result.observations.length + 1, 0);
    bound(
      units * (references + queries.length) <= coverageBatchLimits.maxClassificationWork,
      "classification work",
      coverageBatchLimits.maxClassificationWork,
    );
    const covered: {
      results: ContentCoverageBatchRow[];
      observations: ContentCoverageObservation[];
    } = { results: [], observations: [] };
    const positions = new Map<string, number>();
    let associations = 0,
      coverageBytes = 0;
    for (let start = 0; start < queries.length; start += coverageBatchLimits.maxQueries) {
      const chunk = await readContentCoverageBatch({
        read: {
          status: "read",
          report,
          scanId,
          authenticity: "unchecked",
          annexBytes: "not-supplied",
        },
        queries: queries.slice(start, start + coverageBatchLimits.maxQueries),
      });
      if (chunk.status === "invalid") return chunk;
      const remap = chunk.observations.map((view) => {
        let index = positions.get(view.observationId);
        if (index === undefined) {
          index = covered.observations.length;
          positions.set(view.observationId, index);
          coverageBytes += canonicalBytes(view).byteLength;
          covered.observations.push(view as ContentCoverageObservation);
        }
        return index;
      });
      for (const row of chunk.results) {
        const mapped =
          row.status === "matched"
            ? { ...row, observationIndexes: row.observationIndexes.map((i) => remap[i]!) }
            : row;
        if (mapped.status === "matched") associations += mapped.observationIndexes.length;
        coverageBytes += canonicalBytes(mapped).byteLength;
        bound(
          associations <= coverageBatchLimits.maxObservationAssociations,
          "observation associations",
          coverageBatchLimits.maxObservationAssociations,
        );
        bound(
          coverageBytes <= coverageBatchLimits.maxResponseBytes,
          "coverage response bytes",
          coverageBatchLimits.maxResponseBytes,
        );
        covered.results.push(mapped);
      }
    }
    const entries = new Map(report.source.capture.entries.map((entry) => [entry.path, entry]));
    const observations = new Map(
      report.results.flatMap((result) =>
        result.observations.map((observation) => [observation.observationId, observation] as const),
      ),
    );
    const resultIndex = new Map(report.results.map((result) => [result.detectorId, result]));
    const findingIndex = new Map(
      report.results.map((result) => {
        const byPath = new Map<string, { finding: Finding; order: number }[]>();
        let order = 0;
        for (const observation of result.observations)
          for (const finding of observation.body.findings) {
            if (finding.location.state === "present") {
              const bucket = byPath.get(finding.location.value.path) ?? [];
              bucket.push({ finding, order });
              byPath.set(finding.location.value.path, bucket);
            }
            order++;
          }
        return [result.detectorId, byPath];
      }),
    );
    const digests = new Map<string, string>();
    let at = 0;
    let responseBytes = canonicalBytes({ status: "complete", results: [] }).byteLength;
    const results: ItemRecordResult[] = [];
    const retain = (row: ItemRecordResult) => {
      responseBytes += canonicalBytes(row).byteLength + Number(results.length > 0);
      bound(
        responseBytes <= coverageBatchLimits.maxResponseBytes,
        "item record response bytes",
        coverageBatchLimits.maxResponseBytes,
      );
      results.push(row);
    };
    for (const entry of items) {
      if (entry.invalid) {
        retain(entry.invalid);
        continue;
      }
      const item = entry.item!;
      const rows = covered.results.slice(at, at + item.materials.length);
      at += item.materials.length;
      const materials = item.materials.map((material) => {
        const captured = entries.get(material.path);
        const file =
          captured?.kind === "file" || captured?.kind === "file-link" ? captured : undefined;
        return {
          ...material,
          captured: file !== undefined,
          digestMatch: file?.sha256 === material.sha256,
          lengthMatch: file?.byteLength === material.byteLength,
          executableComparison: comparison(material.executable, file?.executable ?? "unknown"),
        };
      });
      const detectors: ItemRecord["detectors"] = [];
      const keyDetectors = [];
      for (const requested of report.requestedDetectors) {
        const result = resultIndex.get(requested.detectorId)!;
        const indexes = new Set(
          rows.flatMap((row, index) =>
            materials[index]!.executableComparison !== "differs" && row.status === "matched"
              ? [...row.observationIndexes].filter(
                  (index) =>
                    covered.observations[index]!.detector.detectorId === requested.detectorId,
                )
              : [],
          ),
        );
        const covering = [...indexes].map(
          (index) => observations.get(covered.observations[index]!.observationId)!,
        );
        const modesMatch = materials.map((m) => m.executableComparison !== "differs");
        const count = rows.filter(
          (row, index) =>
            modesMatch[index] &&
            row.status === "matched" &&
            row.observationIndexes.some(
              (i) => covered.observations[i]!.detector.detectorId === requested.detectorId,
            ),
        ).length;
        const inputSha256s = [];
        for (const observation of covering) {
          let digest = digests.get(observation.observationId);
          if (!digest) {
            digest = await sha256(canonicalBytes(observation.body.input));
            digests.set(observation.observationId, digest);
          }
          inputSha256s.push(digest);
        }
        inputSha256s.sort();
        const identity: ObservationInput | undefined = result.observations[0]?.body.input;
        detectors.push({
          detectorId: requested.detectorId,
          outcome: result.outcome,
          requestedProfileId: requested.profileId,
          effectiveProfileId: identity?.profileId ?? null,
          itemCoverage:
            count === item.materials.length ? "covered" : count ? "partial" : "uncovered",
          findings: item.materials
            .flatMap((material) =>
              (findingIndex.get(requested.detectorId)?.get(material.path) ?? []).filter(
                ({ finding }) =>
                  finding.location.state === "present" &&
                  finding.location.value.fileSha256 === material.sha256,
              ),
            )
            .sort((a, b) => a.order - b.order)
            .map(({ finding }) => finding),
          inputSha256s,
        });
        keyDetectors.push({
          detectorId: requested.detectorId,
          detectorVersion: identity?.detectorVersion ?? null,
          adapterSha256: identity?.adapterSha256 ?? null,
          rulesSha256: identity?.rulesSha256 ?? null,
          configurationSha256: identity?.configurationSha256 ?? null,
          profileId: identity?.profileId ?? null,
          profileSha256: identity?.profileSha256 ?? null,
          platform: identity?.platform ?? null,
          inputSha256s,
        });
      }
      keyDetectors.sort((a, b) =>
        a.detectorId < b.detectorId ? -1 : a.detectorId > b.detectorId ? 1 : 0,
      );
      const subject = subjectOf(item);
      const evidenceKey = await sha256(
        canonicalBytes({
          subject,
          materials: item.materials.map(({ path, sha256, byteLength, executable }) => ({
            path,
            sha256,
            byteLength,
            executable,
          })),
          detectors: keyDetectors,
        }),
      );
      const record: ItemRecord = {
        schema: itemRecordSchema,
        scanId,
        createdAt: report.createdAt,
        subject,
        materials,
        coverage: materials.every(
          (m) =>
            m.captured && m.digestMatch && m.lengthMatch && m.executableComparison !== "differs",
        )
          ? "matched"
          : "mismatched",
        detectors,
        completion: report.completion,
        evidenceKey,
        authenticity: "unchecked",
      };
      retain(record);
    }
    return { status: "complete", results };
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
}

/** Stored records are caches. Re-derive every field before comparing. */
export async function verifyItemRecord(
  record: ItemRecord,
  assessment: ItemAssessment,
  item: ItemDescriptor,
): Promise<"same" | "differs" | "not-covered"> {
  const derived = await recordItem(assessment, item);
  if (!("subject" in derived))
    return derived.coverage === "unavailable" ? "not-covered" : "differs";
  if (derived.materials.some((m) => !m.captured || !m.digestMatch || !m.lengthMatch))
    return "not-covered";
  try {
    const snapshot = snapshotQueries([record], {
      ...coverageBatchLimits,
      maxRequestBytes: coverageBatchLimits.maxResponseBytes,
      maxRequestNodes: coverageBatchLimits.maxResponseBytes,
    })[0] as ItemRecord;
    if (!equalBytes(canonicalBytes(snapshot.subject), canonicalBytes(derived.subject)))
      return "not-covered";
    return equalBytes(canonicalBytes(snapshot), canonicalBytes(derived)) ? "same" : "differs";
  } catch {
    return "differs";
  }
}
