import { z } from "zod";
import type { ReadArtifactResult } from "../artifact/types.js";
import {
  admitCoverageRead,
  coverageBatchLimits,
  maxContentDescriptors,
  readContentCoverageBatch,
  snapshotQueries,
} from "./content-coverage.js";
import {
  bound,
  ContractError,
  canonicalBytes,
  equalBytes,
  errorDiagnostic,
  fail,
  sha256,
} from "./json.js";
import {
  classifyFindings,
  type SeverityProfile,
  severityProfileRef,
  severityProfileShape,
} from "./severity-profile.js";
import {
  diagnosticShape,
  digestShape,
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
} from "./types.js";

export const itemRecordSchema = "urn:aihq:scan:item-record:1.0.0";
/** The payload pseudo-material: the canonical JSON of the item's payload. */
export const payloadMaterialId = "#payload";
const coverageStates = ["matched", "mismatched", "unavailable", "invalid"] as const;
type Coverage = (typeof coverageStates)[number];

export interface ItemMaterial {
  materialId: string;
  /** POSIX path relative to the item; the path the item's `contentSha256` lines name. */
  relPath: string;
  /** Path in the assessment's capture namespace; defaults to `relPath`. */
  capturePath?: string;
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
/** The item as its release declares it: subject, behaviour fields and exact materials. */
export interface ItemDescriptor extends ItemSubject {
  kind: string;
  payload: unknown;
  requirements: unknown;
  dependencies: unknown;
  materials: ItemMaterial[];
}
/** `urn:aihq:scan:item-record:1.0.0`, exactly as the contract publishes it. */
export interface ItemRecord {
  scanId: string;
  createdAt: string;
  evidenceKey: string;
  subject: ItemSubject;
  authenticity: "unchecked";
  materials: {
    materialId: string;
    relPath: string;
    sha256: string;
    byteLength: number;
    executable: boolean;
    captured: boolean;
  }[];
  completion: "complete" | "partial";
  coverage: Coverage;
  severityProfile: string;
  detectors: {
    id: string;
    version: string;
    outcome: "succeeded" | "failed" | "refused" | "cancelled";
    coverage: Coverage;
    exclusions: string[];
    findings: { error: number; warning: number; note: number; unavailable: number };
    suppressed: { rule: string; count: number; reason: string }[];
    findingRefs?: string[];
  }[];
}
export type ItemRecordRefusal = { coverage: "invalid" | "unavailable"; diagnostics: Diagnostic[] };
export type ItemRecordResult = ItemRecord | ItemRecordRefusal;
/** A `readArtifact` or `readReport` result. */
export type ItemAssessment = ReadReportResult | ReadArtifactResult;
export type ItemRecordBatchResult =
  | { status: "complete"; results: ItemRecordResult[] }
  | { status: "invalid"; diagnostics: Diagnostic[] };
export type ItemRecordVerification = "same" | "differs" | "not-covered";

const json = z.custom<unknown>((value) => value !== undefined);
const materialShape = z
  .object({
    materialId: labelShape.refine((id) => id !== payloadMaterialId, "#payload is reserved"),
    relPath: pathShape,
    capturePath: pathShape.optional(),
    sha256: digestShape,
    byteLength: integerShape,
    executable: z.union([z.boolean(), z.literal("unknown")]),
    role: z.enum(["content", "behaviour"]),
  })
  .strict();
const itemShape = z
  .object({
    frameworkId: labelShape,
    itemId: labelShape,
    contentSha256: digestShape,
    behaviourSha256: digestShape,
    kind: labelShape,
    payload: json,
    requirements: json,
    dependencies: json,
    materials: z.array(materialShape).min(1).max(maxContentDescriptors),
  })
  .strict();
const subjectShape = z
  .object({
    frameworkId: labelShape,
    itemId: labelShape,
    contentSha256: digestShape,
    behaviourSha256: digestShape,
  })
  .strict();
const counted = z
  .object({
    error: integerShape,
    warning: integerShape,
    note: integerShape,
    unavailable: integerShape,
  })
  .strict();
export const itemRecordShape = z
  .object({
    scanId: scanIdShape,
    createdAt: timestampShape,
    evidenceKey: digestShape,
    subject: subjectShape,
    authenticity: z.literal("unchecked"),
    materials: z
      .array(
        z
          .object({
            materialId: labelShape,
            relPath: z.union([pathShape, z.literal(payloadMaterialId)]),
            sha256: digestShape,
            byteLength: integerShape,
            executable: z.boolean(),
            captured: z.boolean(),
          })
          .strict(),
      )
      .min(1)
      .max(maxContentDescriptors + 1),
    completion: z.enum(["complete", "partial"]),
    coverage: z.enum(coverageStates),
    severityProfile: z.string().min(1).max(256),
    detectors: z
      .array(
        z
          .object({
            id: labelShape,
            version: z.string().min(1).max(128),
            outcome: z.enum(["succeeded", "failed", "refused", "cancelled"]),
            coverage: z.enum(coverageStates),
            exclusions: z.array(z.string().min(1).max(1024)).max(256),
            findings: counted,
            suppressed: z
              .array(
                z
                  .object({ rule: labelShape, count: integerShape.min(1), reason: labelShape })
                  .strict(),
              )
              .max(1024),
            findingRefs: z.array(z.string().min(1).max(512)).max(4096).optional(),
          })
          .strict(),
      )
      .max(256),
  })
  .strict();
/** Public result schema includes truthful refusals when no record can be derived. */
export const itemRecordResultShape = z.union([
  itemRecordShape,
  z
    .object({ coverage: z.enum(["invalid", "unavailable"]), diagnostics: z.array(diagnosticShape) })
    .strict(),
]);

const encoder = new TextEncoder();
const bytewise = (left: string, right: string) => {
  const a = encoder.encode(left),
    b = encoder.encode(right);
  for (let at = 0; at < Math.min(a.length, b.length); at++)
    if (a[at] !== b[at]) return a[at]! - b[at]!;
  return a.length - b.length;
};
/** The exact text `contentSha256` hashes: one `relPath\tsha256\n` line per content material, sorted bytewise. */
export function contentIdentityText(
  content: readonly { relPath: string; sha256: string }[],
): string {
  return content
    .map(({ relPath, sha256 }) => `${relPath}\t${sha256}\n`)
    .sort(bytewise)
    .join("");
}
/**
 * The contract's two item hashes and the behaviour file bytes. `behaviourSha256` is SHA-256 over the canonical JSON
 * of `{ kind, payload, requirements, dependencies, materials: <content lines>, executable }`; the behaviour file holds
 * the canonical JSON of the same value without `materials`, plus LF.
 */
export async function itemIdentity(value: {
  kind: unknown;
  payload: unknown;
  requirements: unknown;
  dependencies: unknown;
  materials: readonly { relPath: string; sha256: string }[];
  executable: Record<string, ExecutableState>;
}): Promise<{ contentSha256: string; behaviourSha256: string; behaviourFile: Uint8Array }> {
  const { kind, payload, requirements, dependencies, executable } = value;
  const lines = contentIdentityText(value.materials);
  const behaviour = { kind, payload, requirements, dependencies, executable };
  const file = canonicalBytes(behaviour);
  const behaviourFile = new Uint8Array(file.length + 1);
  behaviourFile.set(file);
  behaviourFile[file.length] = 0x0a;
  return {
    contentSha256: await sha256(encoder.encode(lines)),
    behaviourSha256: await sha256(canonicalBytes({ ...behaviour, materials: lines })),
    behaviourFile,
  };
}

export function parseItemDescriptor(value: unknown): ItemDescriptor {
  const parsed = itemShape.safeParse(value);
  if (!parsed.success) fail("An item requires its subject, behaviour fields and exact materials");
  const item = parsed.data as ItemDescriptor;
  if (item.materials.filter((m) => m.role === "behaviour").length !== 1)
    fail("An item requires exactly one behaviour material");
  for (const key of ["materialId", "relPath"] as const)
    if (new Set(item.materials.map((m) => m[key])).size !== item.materials.length)
      fail(`Item material ${key} values must be unique`);
  if (new Set(item.materials.map(capturePath)).size !== item.materials.length)
    fail("Item material capture paths must be unique");
  canonicalBytes({ payload: item.payload, r: item.requirements, d: item.dependencies });
  return item;
}
const capturePath = (material: ItemMaterial) => material.capturePath ?? material.relPath;

/** Recomputes both subject hashes and the behaviour file from the item's own fields; any difference refuses. */
async function checkIdentity(item: ItemDescriptor): Promise<Uint8Array> {
  const content = item.materials.filter((m) => m.role === "content");
  const identity = await itemIdentity({
    ...item,
    materials: content,
    executable: Object.fromEntries(content.map((m) => [m.relPath, m.executable])),
  });
  const behaviour = item.materials.find((m) => m.role === "behaviour")!;
  if (
    behaviour.sha256 !== (await sha256(identity.behaviourFile)) ||
    behaviour.byteLength !== identity.behaviourFile.length
  )
    throw new ContractError(
      "behaviour-mismatch",
      "The behaviour material differs from the item's behaviour fields",
    );
  if (
    item.contentSha256 !== identity.contentSha256 ||
    item.behaviourSha256 !== identity.behaviourSha256
  )
    throw new ContractError(
      "item-identity-mismatch",
      "The item's hashes differ from its materials and behaviour",
    );
  return canonicalBytes(item.payload);
}

type MaterialState =
  | "match"
  | "material-missing"
  | "bytes-differ"
  | "executable-differs"
  | "executable-unknown";
const exclusionText = (reason: string, ids: string[]) => {
  const text = `${reason}: ${ids.join(", ")}`;
  return text.length <= 1024 ? text : `${text.slice(0, 1000)}… (${ids.length} materials)`;
};
function exclusions(
  states: readonly { id: string; state: MaterialState }[],
  only?: MaterialState[],
) {
  const groups = new Map<string, string[]>();
  for (const { id, state } of states)
    if (state !== "match" && (!only || only.includes(state)))
      groups.set(state, [...(groups.get(state) ?? []), id]);
  return [...groups.entries()].map(([reason, ids]) => exclusionText(reason, ids));
}

/**
 * Derives one contract item record per item from a revalidated assessment. Pure: the assessment is a public read
 * result, never a trusted cache. Findings are attributed only by exact capture path and file hash.
 */
export async function recordItems(input: {
  artifact: ItemAssessment;
  items: ItemDescriptor[];
  severityProfile: SeverityProfile;
}): Promise<ItemRecordBatchResult> {
  try {
    if (
      !input ||
      typeof input !== "object" ||
      Reflect.ownKeys(input).length !== 3 ||
      Object.keys(input).sort().join(",") !== "artifact,items,severityProfile"
    )
      fail("Item records require artifact, items and severityProfile");
    if (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
      fail("Item records require a plain object");
    const property = (key: string) => {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !("value" in descriptor)) fail("Item records require own data properties");
      return descriptor.value as unknown;
    };
    // Every input is snapshotted before the first await, so later caller mutation cannot change the result.
    const profile = severityProfileShape.parse(
      snapshotQueries([property("severityProfile")], {
        ...coverageBatchLimits,
        maxRequestDepth: 32,
      })[0],
    );
    const parsed = snapshotQueries(property("items"), {
      ...coverageBatchLimits,
      maxRequestDepth: 64,
    }).map((value) => {
      try {
        return { item: parseItemDescriptor(value) };
      } catch (error) {
        return { invalid: { coverage: "invalid" as const, diagnostics: [errorDiagnostic(error)] } };
      }
    });
    const admission = admitCoverageRead({ read: property("artifact") });
    const profileRef = await severityProfileRef(profile);
    const items: { item?: ItemDescriptor; payload?: Uint8Array; invalid?: ItemRecordRefusal }[] =
      [];
    for (const entry of parsed) {
      if (!entry.item) {
        items.push(entry);
        continue;
      }
      try {
        items.push({ item: entry.item, payload: await checkIdentity(entry.item) });
      } catch (error) {
        items.push({ invalid: { coverage: "invalid", diagnostics: [errorDiagnostic(error)] } });
      }
    }
    const references = items.reduce((n, entry) => n + (entry.item?.materials.length ?? 0), 0);
    bound(
      references <= coverageBatchLimits.maxDescriptorReferences,
      "descriptor references",
      coverageBatchLimits.maxDescriptorReferences,
    );
    const admitted = await admission;
    if (admitted.status !== "admitted")
      return {
        status: "complete",
        results: items.map(
          (entry) =>
            entry.invalid ?? { coverage: "unavailable", diagnostics: admitted.diagnostics },
        ),
      };
    const { report, scanId } = admitted;
    // One conjunctive query per material, so one observation need not span independent units to cover the item.
    const queries = items.flatMap(
      (entry) =>
        entry.item?.materials.map((material) => ({
          descriptors: [
            {
              path: capturePath(material),
              sha256: material.sha256,
              byteLength: material.byteLength,
            },
          ],
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
    const resultIndex = new Map(report.results.map((result) => [result.detectorId, result]));
    const findingIndex = new Map(
      report.results.map((result) => {
        const byPath = new Map<string, Finding[]>();
        for (const observation of result.observations)
          for (const finding of observation.body.findings)
            if (finding.location.state === "present") {
              const bucket = byPath.get(finding.location.value.path) ?? [];
              bucket.push(finding);
              byPath.set(finding.location.value.path, bucket);
            }
        return [result.detectorId, byPath];
      }),
    );
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
      const states = item.materials.map((material) => {
        const found = entries.get(capturePath(material));
        const file = found?.kind === "file" || found?.kind === "file-link" ? found : undefined;
        const captured = file?.executable ?? "unknown";
        const state: MaterialState = !file
          ? "material-missing"
          : file.sha256 !== material.sha256 || file.byteLength !== material.byteLength
            ? "bytes-differ"
            : captured === "unknown"
              ? "executable-unknown"
              : material.executable === "unknown" || captured === material.executable
                ? "match"
                : "executable-differs";
        return { id: material.materialId, material, captured, state };
      });
      const behaviour = states.find((s) => s.material.role === "behaviour")!;
      // The behaviour file's bytes embed the payload's canonical JSON (checked above), so the payload is captured and
      // scanned exactly when the behaviour file is.
      const payloadState = { id: payloadMaterialId, state: behaviour.state };
      const allStates = [...states, payloadState];
      const coverage: Coverage = allStates.some((s) =>
        ["material-missing", "bytes-differ", "executable-differs"].includes(s.state),
      )
        ? "mismatched"
        : allStates.some((s) => s.state === "executable-unknown")
          ? "unavailable"
          : "matched";
      const materials: ItemRecord["materials"] = [
        ...states.map(({ material, captured, state }) => ({
          materialId: material.materialId,
          relPath: material.relPath,
          sha256: material.sha256,
          byteLength: material.byteLength,
          // The bit the capture holds; else the declared bit; false when neither knows one (coverage then says so).
          executable:
            typeof captured === "boolean"
              ? captured
              : typeof material.executable === "boolean"
                ? material.executable
                : false,
          captured: state !== "material-missing" && state !== "bytes-differ",
        })),
        {
          materialId: payloadMaterialId,
          relPath: payloadMaterialId,
          sha256: await sha256(entry.payload!),
          byteLength: entry.payload!.length,
          executable: false,
          captured: behaviour.state !== "material-missing" && behaviour.state !== "bytes-differ",
        },
      ];
      const detectors: ItemRecord["detectors"] = [];
      const keyDetectors = [];
      for (const requested of report.requestedDetectors) {
        const result = resultIndex.get(requested.detectorId)!;
        const identity: ObservationInput | undefined = result.observations[0]?.body.input;
        const coveredBy = (index: number) =>
          rows[index]!.status === "matched" &&
          (
            rows[index] as Extract<ContentCoverageBatchRow, { status: "matched" }>
          ).observationIndexes.some(
            (i) => covered.observations[i]!.detector.detectorId === requested.detectorId,
          );
        let detectorCoverage: Coverage, reasons: string[];
        if (result.outcome !== "succeeded") {
          detectorCoverage = "unavailable";
          reasons = [`detector-${result.outcome}`];
        } else if (coverage !== "matched") {
          detectorCoverage = coverage;
          reasons = exclusions(allStates);
        } else {
          const uncovered = states.flatMap((s, index) => (coveredBy(index) ? [] : [s.id]));
          if (uncovered.includes(behaviour.id)) uncovered.push(payloadMaterialId);
          detectorCoverage = uncovered.length ? "unavailable" : "matched";
          reasons = uncovered.length ? [exclusionText("not-covered", uncovered)] : [];
        }
        const attributed = item.materials.flatMap((material) =>
          (findingIndex.get(requested.detectorId)?.get(capturePath(material)) ?? []).filter(
            (finding) =>
              finding.location.state === "present" &&
              finding.location.value.fileSha256 === material.sha256,
          ),
        );
        detectors.push({
          id: requested.detectorId,
          version: identity?.detectorVersion ?? "unavailable",
          outcome: result.outcome,
          coverage: detectorCoverage,
          exclusions: reasons,
          ...classifyFindings(requested.detectorId, attributed, profile),
        });
        keyDetectors.push({
          id: requested.detectorId,
          version: identity?.detectorVersion ?? "unavailable",
          rulesSha256: identity?.rulesSha256 ?? null,
          profileSha256: identity?.profileSha256 ?? null,
        });
      }
      const byId = (a: { id: string }, b: { id: string }) =>
        a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
      keyDetectors.sort(byId);
      retain({
        scanId,
        createdAt: report.createdAt,
        evidenceKey: await sha256(
          canonicalBytes({
            contentSha256: item.contentSha256,
            behaviourSha256: item.behaviourSha256,
            detectors: keyDetectors,
          }),
        ),
        subject: {
          frameworkId: item.frameworkId,
          itemId: item.itemId,
          contentSha256: item.contentSha256,
          behaviourSha256: item.behaviourSha256,
        },
        authenticity: "unchecked",
        materials,
        completion: report.completion,
        coverage,
        severityProfile: profileRef,
        detectors,
      });
    }
    return { status: "complete", results };
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
}

const jsonPath = (path: readonly PropertyKey[]) =>
  path.reduce<string>(
    (text, key) =>
      typeof key === "number"
        ? `${text}[${key}]`
        : /^[A-Za-z_$][\w$]*$/.test(String(key))
          ? `${text}.${String(key)}`
          : `${text}[${JSON.stringify(String(key))}]`,
    "$",
  );
/**
 * Reads a stored item record. A record may name its schema; any other schema is `SCHEMA_UNSUPPORTED`, and a field the
 * contract does not define is refused at its JSON path.
 */
export function readItemRecord(
  value: unknown,
): { status: "read"; record: ItemRecord } | { status: "refused"; diagnostics: Diagnostic[] } {
  try {
    const [copy] = snapshotQueries([value], {
      ...coverageBatchLimits,
      maxRequestBytes: coverageBatchLimits.maxResponseBytes,
      maxRequestNodes: coverageBatchLimits.maxResponseBytes,
    });
    if (copy && typeof copy === "object" && !Array.isArray(copy) && "schema" in copy) {
      const { schema, ...rest } = copy as Record<string, unknown>;
      if (schema !== itemRecordSchema)
        return {
          status: "refused",
          diagnostics: [
            {
              code: "SCHEMA_UNSUPPORTED",
              path: "$.schema",
              encountered: typeof schema === "string" ? schema.slice(0, 256) : typeof schema,
              supported: [itemRecordSchema],
              detail: "Unsupported item record schema at $.schema",
            },
          ],
        };
      return readItemRecord(rest);
    }
    const parsed = itemRecordShape.safeParse(copy);
    if (parsed.success) return { status: "read", record: parsed.data as ItemRecord };
    const unknown = parsed.error.issues.find((issue) => issue.code === "unrecognized_keys");
    if (unknown && unknown.code === "unrecognized_keys") {
      const path = jsonPath([...unknown.path, unknown.keys[0]!]);
      return {
        status: "refused",
        diagnostics: [{ code: "unknown-field", path, detail: `Unknown field at ${path}` }],
      };
    }
    const path = jsonPath(parsed.error.issues[0]!.path);
    return {
      status: "refused",
      diagnostics: [{ code: "invalid-record", path, detail: `Invalid item record at ${path}` }],
    };
  } catch (error) {
    return { status: "refused", diagnostics: [errorDiagnostic(error)] };
  }
}

/**
 * Checks a stored record against the artifact it names and the item's own materials, re-deriving every field. A
 * record of other bytes, a relabelled subject or a different `behaviourSha256` is `not-covered`; a record whose bytes
 * match but whose other fields do not is `differs`.
 */
export async function verifyItemRecord(
  record: unknown,
  artifact: ItemAssessment,
  item: ItemDescriptor,
  severityProfile: SeverityProfile,
): Promise<ItemRecordVerification> {
  // Snapshot every input before the first await; a malformed cache never runs accessors.
  const read = readItemRecord(record);
  const snapshot = read.status === "read" ? read.record : undefined;
  const batch = await recordItems({ artifact, items: [item], severityProfile });
  if (batch.status === "invalid") return "differs";
  const derived = batch.results[0]!;
  if (!("subject" in derived))
    return derived.coverage === "unavailable" ? "not-covered" : "differs";
  if (derived.materials.some((m) => !m.captured)) return "not-covered";
  if (!snapshot) return "differs";
  try {
    if (!equalBytes(canonicalBytes(snapshot.subject), canonicalBytes(derived.subject)))
      return "not-covered";
    const bytesOf = (materials: ItemRecord["materials"]) =>
      canonicalBytes(
        materials
          .map(({ materialId, sha256, byteLength }) => ({ materialId, sha256, byteLength }))
          .sort((a, b) => (a.materialId < b.materialId ? -1 : a.materialId > b.materialId ? 1 : 0)),
      );
    if (!equalBytes(bytesOf(snapshot.materials), bytesOf(derived.materials))) return "not-covered";
    return equalBytes(canonicalBytes(snapshot), canonicalBytes(derived)) ? "same" : "differs";
  } catch {
    return "differs";
  }
}
