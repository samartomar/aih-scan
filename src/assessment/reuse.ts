import type { ArtifactAnnex } from "../artifact/types.js";
import {
  base64Decode,
  canonicalBytes,
  equalBytes,
  observationIdFor,
  sha256,
  strictParse,
} from "./json.js";
import { observationBodyShape } from "./shapes.js";
import type { Limits, ObservationBody, ObservationInput, ReportBody, ScanId } from "./types.js";

/**
 * Observation reuse admission: Scan-managed own custody, and independently authenticated
 * imported prior artifacts. The two candidate channels stay distinct.
 *
 * Honesty rules enforced by construction:
 *
 * - own custody is process-local and private. Only a record this module minted is in the
 *   WeakMap, and only `runScan` ever writes a unit into it, from a body Scan itself just
 *   built. A caller object of the same shape, a clone, a JSON round-trip or a "trusted"
 *   flag is not own-custody data and admits nothing;
 * - imported candidates come only from `readPriorArtifacts`, which acquires them under its
 *   own bound, authenticates them with independently selected caller trust and fully reads
 *   them; this module never mints own custody from caller JSON;
 * - a retained body is stored as its canonical bytes, copied out of the result the caller
 *   receives, so mutating a returned assessment cannot alter retained data;
 * - every candidate, whoever supplied it, is re-read from bytes, has its observation
 *   identity re-derived, and is compared against the *current* input this run computed,
 *   never against another field of the cached observation;
 * - admission is only the lookup. An admitted unit still passes the same current coverage,
 *   report, annex and budget admission a fresh unit passes;
 * - retention is bounded, and the oldest units are dropped first.
 */

/** The protocol marker of a Scan-managed own-custody record. */
export const retainedObservationsProtocolV1 = "aih.retained-observations.v1" as const;

/**
 * A Scan-managed own-custody record. It is minted by `createRetainedObservationsV1` and
 * populated only by `runScan`; it is neither a wire format nor caller-supplied input.
 */
export interface RetainedObservationsV1 {
  readonly protocol: typeof retainedObservationsProtocolV1;
}

/** One observation annex as retained, with the exact bytes its descriptor names. */
export interface RetainedAnnexV1 {
  readonly id: string;
  readonly mediaType: string;
  readonly sha256: string;
  readonly byteLength: number;
  readonly bytes: Uint8Array;
}

interface RetainedUnitV1 {
  readonly detectorId: string;
  readonly observationId: `observation:sha256:${string}`;
  readonly bodyBytes: Uint8Array;
  readonly annexes: readonly RetainedAnnexV1[];
  /** The assessment that first produced this unit; stable across chained reuse. */
  readonly fromScanId: ScanId;
}

const custody = new WeakMap<object, RetainedUnitV1[]>();

/** Process-local custody bounds: a long-lived process must not grow without limit. */
const maxRetainedUnitsV1 = 64;
const maxRetainedBytesV1 = 64 * 1024 * 1024;

function retainedBytesV1(unit: RetainedUnitV1): number {
  return unit.bodyBytes.length + unit.annexes.reduce((sum, annex) => sum + annex.bytes.length, 0);
}

/** Drops the oldest units first until both the unit and byte bounds hold. */
function evictOverBoundsV1(units: RetainedUnitV1[]): void {
  while (units.length > maxRetainedUnitsV1) units.shift();
  let total = units.reduce((sum, unit) => sum + retainedBytesV1(unit), 0);
  while (units.length > 1 && total > maxRetainedBytesV1) {
    const dropped = units.shift();
    if (dropped === undefined) break;
    total -= retainedBytesV1(dropped);
  }
}

/** Mints one empty Scan-managed own-custody record. */
export function createRetainedObservationsV1(): RetainedObservationsV1 {
  const record = Object.freeze({ protocol: retainedObservationsProtocolV1 });
  custody.set(record, []);
  return record;
}

/** `true` only for a record this module minted and still holds in its private WeakMap. */
export function isRetainedObservationsV1(value: unknown): value is RetainedObservationsV1 {
  return typeof value === "object" && value !== null && custody.has(value);
}

/**
 * Retains one successful, current-assessment observation. Called by `runScan` only, with
 * the body it just validated and the exact annex bytes it just bound; the bytes are copied
 * so the caller's returned report cannot reach retained data.
 */
export async function retainObservationV1(
  store: unknown,
  unit: {
    readonly detectorId: string;
    readonly body: unknown;
    readonly annexes: readonly RetainedAnnexV1[];
    readonly fromScanId: ScanId;
  },
): Promise<void> {
  if (!isRetainedObservationsV1(store)) return;
  const units = custody.get(store);
  if (units === undefined) return;
  const annexes: RetainedAnnexV1[] = unit.annexes.map((annex) => ({
    id: annex.id,
    mediaType: annex.mediaType,
    sha256: annex.sha256,
    byteLength: annex.byteLength,
    bytes: new Uint8Array(annex.bytes),
  }));
  units.push(
    Object.freeze({
      detectorId: unit.detectorId,
      observationId: await observationIdFor(unit.body),
      bodyBytes: new Uint8Array(canonicalBytes(unit.body)),
      annexes: Object.freeze(annexes),
      fromScanId: unit.fromScanId,
    }),
  );
  evictOverBoundsV1(units);
}

const missV1 = (detail: string) => ({ status: "miss" as const, detail });

interface AdmissionCoreV1 {
  /** Where the candidate came from; it only keeps refusal reasons specific. */
  readonly label: "retained" | "imported";
  readonly detectorId: string;
  readonly input: ObservationInput;
  readonly limits: Limits;
}

type CandidateAdmissionV1 =
  | { readonly status: "admitted"; readonly body: ObservationBody; readonly annex: RetainedAnnexV1 }
  | { readonly status: "miss"; readonly detail: string };

/**
 * The one admission both candidate channels share: re-read the body bytes, re-derive the
 * observation identity, and bind the unit to the current input, current selected scope,
 * current annex digests and current byte limits. Age is never an invalidator.
 */
async function admitCandidateV1(
  core: AdmissionCoreV1,
  bodyBytes: Uint8Array,
  expectedObservationId: string,
  annexes: readonly RetainedAnnexV1[],
): Promise<CandidateAdmissionV1> {
  let parsedBody: unknown;
  try {
    parsedBody = strictParse(bodyBytes, `${core.label} observation`, core.limits.maxReportBytes);
  } catch {
    return missV1(
      `The ${core.label} observation bytes are unreadable within their declared bounds, so they cannot supply reusable work.`,
    );
  }
  const parsed = observationBodyShape.safeParse(parsedBody);
  if (!parsed.success)
    return missV1(
      `The ${core.label} observation does not match the supported observation contract, so it cannot supply reusable work.`,
    );
  const body = parsed.data as ObservationBody;
  if (!equalBytes(canonicalBytes(body), bodyBytes))
    return missV1(
      `The ${core.label} observation is not in canonical form, so it cannot supply reusable work.`,
    );
  if ((await observationIdFor(body)) !== expectedObservationId)
    return missV1(
      `The ${core.label} observation identity disagrees with its own bytes, so it cannot supply reusable work.`,
    );
  if (body.input.detectorId !== core.detectorId)
    return missV1(
      `The ${core.label} observation names a different detector, so the current detector runs fresh.`,
    );
  if (!equalBytes(canonicalBytes(body.input), canonicalBytes(core.input)))
    return missV1(
      `The current detector input differs from the ${core.label} observation input, so the affected scope is measured fresh.`,
    );
  if (
    !equalBytes(canonicalBytes(body.coverage.coveredPaths), canonicalBytes(core.input.targetPaths))
  )
    return missV1(
      `The ${core.label} observation does not cover exactly the current selected scope, so the current scope is measured fresh.`,
    );
  const annexId = body.annexIds[0];
  if (body.annexIds.length !== 1 || annexId === undefined)
    return missV1(
      `The ${core.label} observation carries an annex shape this runner does not assemble, so the current scope is measured fresh.`,
    );
  const annex = annexes.find((entry) => entry.id === annexId);
  if (annex === undefined)
    return missV1(
      `The ${core.label} observation is missing an annex its own body names, so it cannot supply reusable work.`,
    );
  if (annex.byteLength > core.limits.maxAnnexBytes)
    return missV1(
      `The ${core.label} observation annex exceeds the current annex byte limit, so the current scope is measured fresh.`,
    );
  if (annex.bytes.length !== annex.byteLength || annex.sha256 !== (await sha256(annex.bytes)))
    return missV1(
      `The ${core.label} observation annex bytes no longer match their descriptor, so they cannot supply reusable work.`,
    );
  if (body.startedAt > body.completedAt || body.completedAt > new Date().toISOString())
    return missV1(
      `The ${core.label} observation records times that cannot belong to a completed run, so it cannot supply reusable work.`,
    );
  return { status: "admitted", body, annex };
}

export interface RetainedAdmissionRequestV1 {
  /** The caller-supplied handle; only a Scan-minted record is ever consulted. */
  readonly store: unknown;
  readonly detectorId: string;
  /** The complete input this run derived from the current capture and detector identity. */
  readonly input: ObservationInput;
  readonly limits: Limits;
}

export type RetainedAdmissionV1 =
  | {
      readonly status: "admitted";
      readonly body: ObservationBody;
      readonly observationId: `observation:sha256:${string}`;
      readonly fromScanId: ScanId;
      readonly annex: RetainedAnnexV1;
    }
  | { readonly status: "miss"; readonly detail: string };

/** Re-reads, re-binds and re-derives one owned unit against the current input. */
async function admitUnitV1(
  unit: RetainedUnitV1,
  request: RetainedAdmissionRequestV1,
): Promise<RetainedAdmissionV1> {
  const admitted = await admitCandidateV1(
    {
      label: "retained",
      detectorId: request.detectorId,
      input: request.input,
      limits: request.limits,
    },
    unit.bodyBytes,
    unit.observationId,
    unit.annexes,
  );
  if (admitted.status === "miss") return admitted;
  return {
    status: "admitted",
    body: admitted.body,
    observationId: unit.observationId,
    fromScanId: unit.fromScanId,
    annex: admitted.annex,
  };
}

/**
 * Finds and freshly admits an owned unit for the current input, or explains the miss.
 * Age is never an invalidator: a unit stays eligible however old it is.
 */
export async function admitRetainedObservationV1(
  request: RetainedAdmissionRequestV1,
): Promise<RetainedAdmissionV1> {
  if (!isRetainedObservationsV1(request.store))
    return missV1(
      "The supplied retained-observations handle is not a Scan-managed own-custody record, so it admits nothing and current work is performed.",
    );
  const units = custody.get(request.store) ?? [];
  const candidates: RetainedUnitV1[] = [];
  for (let index = units.length - 1; index >= 0; index -= 1) {
    const unit = units[index];
    if (unit !== undefined && unit.detectorId === request.detectorId) candidates.push(unit);
  }
  if (candidates.length === 0)
    return missV1(
      "No Scan-managed retained observation exists for this detector, so current work is performed fresh.",
    );
  let newestMiss = "";
  for (const candidate of candidates) {
    const admitted = await admitUnitV1(candidate, request);
    if (admitted.status === "admitted") return admitted;
    if (newestMiss === "") newestMiss = admitted.detail;
  }
  return missV1(newestMiss);
}

/** One independently authenticated prior artifact, as fully read by `readPriorArtifacts`. */
export interface ImportedObservationSetV1 {
  readonly scanId: ScanId;
  readonly report: ReportBody;
  readonly annexes: readonly ArtifactAnnex[];
}

export interface ImportedAdmissionRequestV1 {
  readonly artifacts: readonly ImportedObservationSetV1[];
  readonly detectorId: string;
  readonly input: ObservationInput;
  readonly limits: Limits;
}

/** Decodes one imported artifact's annex payloads under the current annex bound. */
function decodedAnnexesV1(
  artifact: ImportedObservationSetV1,
  limits: Limits,
): RetainedAnnexV1[] | undefined {
  const annexes: RetainedAnnexV1[] = [];
  for (const annex of artifact.annexes) {
    try {
      annexes.push({
        id: annex.id,
        mediaType: annex.mediaType,
        sha256: annex.sha256,
        byteLength: annex.byteLength,
        bytes: base64Decode(annex.bytesBase64, limits.maxAnnexBytes),
      });
    } catch {
      return undefined;
    }
  }
  return annexes;
}

/**
 * Finds and freshly admits an imported unit for the current input, or explains the miss.
 * The prior result must be a complete success, and the unit still has to pass the shared
 * current-input, coverage, annex and limit admission.
 */
export async function admitImportedObservationV1(
  request: ImportedAdmissionRequestV1,
): Promise<RetainedAdmissionV1> {
  let missDetail = "";
  const note = (detail: string): void => {
    if (missDetail === "") missDetail = detail;
  };
  for (const artifact of request.artifacts) {
    const result = artifact.report.results.find((entry) => entry.detectorId === request.detectorId);
    if (result === undefined) {
      note(
        "No imported prior assessment carries a result for this detector, so the current detector runs fresh.",
      );
      continue;
    }
    if (result.outcome !== "succeeded" || !result.coverage.complete) {
      note(
        "The imported prior result for this detector is not a complete successful observation, so the current detector runs fresh.",
      );
      continue;
    }
    const annexes = decodedAnnexesV1(artifact, request.limits);
    if (annexes === undefined) {
      note(
        "An imported prior assessment annex could not be read within the current annex bound, so the current detector runs fresh.",
      );
      continue;
    }
    for (const observation of result.observations) {
      const admitted = await admitCandidateV1(
        {
          label: "imported",
          detectorId: request.detectorId,
          input: request.input,
          limits: request.limits,
        },
        canonicalBytes(observation.body),
        observation.observationId,
        annexes,
      );
      if (admitted.status === "admitted")
        return {
          status: "admitted",
          body: admitted.body,
          observationId: observation.observationId,
          fromScanId: artifact.scanId,
          annex: admitted.annex,
        };
      note(admitted.detail);
    }
  }
  return missV1(
    missDetail === ""
      ? "No imported prior assessment supplies reusable work for this detector, so current work is performed fresh."
      : missDetail,
  );
}
