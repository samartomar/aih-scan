import { z } from "zod";
import type { AssociationResult } from "../artifact/types.js";
import { coverageBatchLimits, snapshotQueries } from "./content-coverage.js";
import {
  type ItemAssessment,
  type ItemDescriptor,
  type ItemRecord,
  parseItemDescriptor,
  readItemRecord,
  verifyItemRecord,
} from "./item-record.js";
import { errorDiagnostic, fail } from "./json.js";
import { associationResultShape } from "./selection.js";
import {
  type SeverityProfile,
  severityProfileRef,
  severityProfileShape,
} from "./severity-profile.js";
import {
  diagnosticShape,
  digestShape,
  integerShape,
  labelShape,
  timestampShape,
} from "./shapes.js";
import { dataObject } from "./summary.js";
import type { Diagnostic } from "./types.js";

export const evidencePolicySchema = "urn:aihq:scan:evidence-policy:1.0.0";
export const itemSummarySchema = "urn:aihq:scan:item-summary:1.0.0";
const durationPattern =
  /^P(?=\d|T\d)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/;
/** Which detectors must have succeeded on the item, which severity profile counts, and how old a record may be. */
export const evidencePolicyShape = z
  .object({
    schema: z.literal(evidencePolicySchema),
    id: labelShape,
    version: labelShape,
    requiredDetectors: z
      .array(labelShape)
      .min(1)
      .max(256)
      .refine((ids) => new Set(ids).size === ids.length, "required detector IDs must be unique"),
    severityProfile: z.object({ id: labelShape, sha256: digestShape }).strict(),
    maxAge: z.string().max(256).regex(durationPattern).optional(),
  })
  .strict();
const why = [
  "not-authenticated",
  "unchecked",
  "offline",
  "revoked",
  "detector-missing",
  "profile-not-allowed",
  "future-dated",
  "older-than-policy",
] as const;
/** `urn:aihq:scan:item-summary:1.0.0`, exactly as the contract publishes it. */
export const itemSummaryShape = z
  .object({
    state: z.enum([
      "verified",
      "not-verified",
      "partial",
      "not-covered",
      "not-scanned",
      "unreadable",
    ]),
    why: z.enum(why).optional(),
    findings: z
      .object({
        error: integerShape,
        warning: integerShape,
        note: integerShape,
        unavailable: integerShape,
      })
      .strict(),
    suppressed: integerShape,
    scannedAt: timestampShape.nullable(),
  })
  .strict();
export const itemSummaryResultShape = z.union([
  itemSummaryShape,
  z.object({ status: z.literal("invalid"), diagnostics: z.array(diagnosticShape) }).strict(),
]);
export type EvidencePolicy = z.infer<typeof evidencePolicyShape>;
export type ItemSummary = z.infer<typeof itemSummaryShape>;
export type ItemAuthentication = AssociationResult | { status: "revoked" };
export type ItemTrustStatus = "available" | "unavailable" | "expired" | "revoked";
/** One stored record (a Catalog `scan[]` entry or a supplement's record), the artifact it names and its authentication. */
export interface ItemRecordCandidate {
  record: unknown;
  artifact: ItemAssessment;
  authentication: ItemAuthentication;
}
export interface PickRecordInput {
  records: ItemRecordCandidate[];
  item: ItemDescriptor;
  policy: EvidencePolicy;
  /** The documents of the severity profiles records may name; one must be the policy's. */
  severityProfiles: SeverityProfile[];
}
export type PickReason =
  | "only-record"
  | "coverage"
  | "authentication"
  | "required-detectors"
  | "severity-profile"
  | "completion"
  | "time"
  | "scan-id";
/** Why each candidate did not count, by its index. */
export type CandidateDiagnostic = Diagnostic & { index: number };
export type PickRecordResult =
  | {
      status: "picked";
      index: number;
      record: ItemRecord;
      why: PickReason;
      diagnostics: CandidateDiagnostic[];
    }
  | {
      status: "none";
      state: "not-scanned" | "unreadable" | "not-covered";
      diagnostics: CandidateDiagnostic[];
    }
  | { status: "invalid"; diagnostics: Diagnostic[] };
export interface SummariseItemInput extends PickRecordInput {
  trustStatus: ItemTrustStatus;
  evaluationTime: string;
}
export type SummariseItemResult =
  | {
      status: "summarised";
      summary: ItemSummary;
      picked: { index: number; scanId: string; why: PickReason } | null;
      diagnostics: CandidateDiagnostic[];
    }
  | { status: "invalid"; diagnostics: Diagnostic[] };

const authenticationShape = associationResultShape.extend({
  status: z.enum(["skipped", "authenticated", "unverifiable", "revoked"]),
});
// Calendar components use UTC and clamp an end-of-month day. Weeks and smaller
// units are elapsed time; this never changes historical authentication.
function duration(value: string): number[] {
  const match = durationPattern.exec(value);
  if (!match) fail("maxAge must be an ISO 8601 duration");
  const units = match.slice(1).map((value) => Number(value ?? 0));
  if (units.some((value) => !Number.isFinite(value) || value > Number.MAX_SAFE_INTEGER))
    fail("maxAge is outside supported time bounds");
  return units;
}
function expiresAt(createdAt: string, units: number[]): number {
  const [years = 0, months = 0, weeks = 0, days = 0, hours = 0, minutes = 0, seconds = 0] = units;
  const date = new Date(createdAt),
    day = date.getUTCDate();
  date.setUTCDate(1);
  date.setUTCFullYear(date.getUTCFullYear() + years, date.getUTCMonth() + months + 1, 0);
  date.setUTCDate(Math.min(day, date.getUTCDate()));
  const expiry =
    date.getTime() + ((weeks * 7 + days) * 86400 + hours * 3600 + minutes * 60 + seconds) * 1000;
  if (!Number.isFinite(expiry) || Math.abs(expiry) > 8640000000000000)
    fail("maxAge is outside supported time bounds");
  return expiry;
}
/** Row 6: every required detector is in the record, succeeded and covered this item's materials. */
const requiredSucceeded = (record: ItemRecord, policy: EvidencePolicy) =>
  policy.requiredDetectors.every((id) => {
    const detector = record.detectors.find((d) => d.id === id);
    return detector?.outcome === "succeeded" && detector.coverage === "matched";
  });

interface Admitted {
  item: ItemDescriptor;
  policy: EvidencePolicy;
  policyProfile: string;
  profiles: Map<string, SeverityProfile>;
  candidates: { record: unknown; artifact: unknown; authentication: unknown }[];
}
/** Snapshots and checks the shared inputs before any await. */
function admit(raw: Record<string, unknown>): Omit<Admitted, "policyProfile" | "profiles"> & {
  profileList: SeverityProfile[];
} {
  const item = parseItemDescriptor(
    snapshotQueries([raw.item], { ...coverageBatchLimits, maxRequestDepth: 64 })[0],
  );
  const policy = evidencePolicyShape.parse(snapshotQueries([raw.policy])[0]);
  if (policy.maxAge !== undefined) duration(policy.maxAge);
  const profileList = z
    .array(severityProfileShape)
    .min(1)
    .max(64)
    .parse(
      snapshotQueries([raw.severityProfiles], { ...coverageBatchLimits, maxRequestDepth: 32 })[0],
    );
  if (!Array.isArray(raw.records) || raw.records.length > 256)
    fail("Records must be an array of at most 256 candidates");
  const large = {
    ...coverageBatchLimits,
    maxRequestBytes: coverageBatchLimits.maxResponseBytes,
    maxRequestNodes: coverageBatchLimits.maxResponseBytes,
    maxRequestDepth: 64,
  };
  const candidates = (raw.records as unknown[]).map((value) => {
    const entry = dataObject(value, ["record", "artifact", "authentication"]);
    return {
      record: snapshotQueries([entry.record], large)[0],
      artifact: snapshotQueries([entry.artifact], large)[0],
      authentication: authenticationShape.parse(snapshotQueries([entry.authentication])[0]),
    };
  });
  return { item, policy, profileList, candidates };
}
async function complete(admitted: ReturnType<typeof admit>): Promise<Admitted> {
  const profiles = new Map<string, SeverityProfile>();
  for (const profile of admitted.profileList) {
    const ref = await severityProfileRef(profile);
    if (profiles.has(ref)) fail("Severity profiles must be distinct");
    profiles.set(ref, profile);
  }
  const policyProfile = [...profiles.keys()].find(
    (ref) =>
      ref ===
      `${admitted.policy.severityProfile.id}@sha256:${admitted.policy.severityProfile.sha256}`,
  );
  if (!policyProfile)
    throw Object.assign(
      new Error("The policy's severity profile is not among the supplied profiles."),
      {
        diagnostic: "severity-profile-mismatch",
      },
    );
  return { ...admitted, policyProfile, profiles };
}

async function pick(input: Admitted): Promise<PickRecordResult> {
  const diagnostics: CandidateDiagnostic[] = [];
  const note = (index: number, list: Diagnostic[]) => {
    for (const diagnostic of list) diagnostics.push({ ...diagnostic, index });
  };
  if (!input.candidates.length) return { status: "none", state: "not-scanned", diagnostics };
  // Every artifact read result is admitted before the first await.
  const passing: { index: number; record: ItemRecord; authentication: ItemAuthentication }[] = [];
  let readable = 0;
  const checks = input.candidates.map((candidate, index) => {
    const read = readItemRecord(candidate.record);
    if (read.status === "refused") {
      note(index, read.diagnostics);
      return undefined;
    }
    const artifact = candidate.artifact as ItemAssessment;
    if (!artifact || typeof artifact !== "object" || artifact.status !== "read") {
      note(
        index,
        artifact && typeof artifact === "object" && "diagnostics" in artifact
          ? (artifact.diagnostics as Diagnostic[])
          : [{ code: "invalid-read", detail: "The record's artifact could not be read." }],
      );
      return undefined;
    }
    if (artifact.scanId !== read.record.scanId) {
      note(index, [
        {
          code: "artifact-mismatch",
          detail: "The supplied artifact is not the one the record names.",
        },
      ]);
      return undefined;
    }
    const authentication = candidate.authentication as ItemAuthentication;
    if (
      "scanId" in authentication &&
      authentication.scanId !== undefined &&
      authentication.scanId !== read.record.scanId
    )
      fail("Host authentication names a different assessment");
    const profile = input.profiles.get(read.record.severityProfile);
    if (!profile) {
      note(index, [
        {
          code: "severity-profile-unavailable",
          detail: "The record's severity profile was not supplied.",
        },
      ]);
      return undefined;
    }
    readable++;
    return {
      index,
      record: read.record,
      authentication,
      verification: verifyItemRecord(read.record, artifact, input.item, profile),
    };
  });
  for (const check of checks) {
    if (!check) continue;
    const verification = await check.verification;
    if (verification === "same") passing.push(check);
    else
      note(check.index, [
        {
          code: verification === "not-covered" ? "record-not-covering" : "record-differs",
          detail:
            verification === "not-covered"
              ? "The record does not cover the item's own materials."
              : "The record differs from what its artifact gives for this item.",
        },
      ]);
  }
  if (!readable) return { status: "none", state: "unreadable", diagnostics };
  if (!passing.length) return { status: "none", state: "not-covered", diagnostics };
  // Ranked by coverage, authentication, required detectors, policy priority and completion, then time: never time alone.
  const keys: [PickReason, (entry: (typeof passing)[number]) => number][] = [
    ["coverage", ({ record }) => (record.coverage === "matched" ? 0 : 1)],
    [
      "authentication",
      ({ authentication }) =>
        authentication.status === "authenticated" ? 0 : authentication.status === "revoked" ? 2 : 1,
    ],
    ["required-detectors", ({ record }) => (requiredSucceeded(record, input.policy) ? 0 : 1)],
    ["severity-profile", ({ record }) => (record.severityProfile === input.policyProfile ? 0 : 1)],
    ["completion", ({ record }) => (record.completion === "complete" ? 0 : 1)],
    ["time", ({ record }) => -Date.parse(record.createdAt)],
  ];
  const compare = (
    a: (typeof passing)[number],
    b: (typeof passing)[number],
  ): [number, PickReason] => {
    for (const [reason, key] of keys) {
      const order = key(a) - key(b);
      if (order) return [order, reason];
    }
    return [
      a.record.scanId < b.record.scanId ? -1 : a.record.scanId > b.record.scanId ? 1 : 0,
      "scan-id",
    ];
  };
  const ranked = [...passing].sort((a, b) => compare(a, b)[0]);
  const winner = ranked[0]!;
  return {
    status: "picked",
    index: winner.index,
    record: winner.record,
    why: ranked.length === 1 ? "only-record" : compare(winner, ranked[1]!)[1],
    diagnostics,
  };
}
const refusal = (error: unknown) => ({
  status: "invalid" as const,
  diagnostics: [
    error instanceof Error && "diagnostic" in error
      ? { code: String(error.diagnostic), detail: error.message }
      : errorDiagnostic(error),
  ],
});

/** The one record that counts for an item: only records that pass `verifyItemRecord`, ranked by the contract's keys. */
export async function pickRecord(input: PickRecordInput): Promise<PickRecordResult> {
  try {
    const raw = dataObject(input, ["records", "item", "policy", "severityProfiles"]);
    return await pick(await complete(admit(raw)));
  } catch (error) {
    return refusal(error);
  }
}

/** The card summary, by the contract's decision table: the first row that applies wins. */
export async function summariseItem(input: SummariseItemInput): Promise<SummariseItemResult> {
  try {
    const raw = dataObject(input, [
      "records",
      "item",
      "policy",
      "severityProfiles",
      "trustStatus",
      "evaluationTime",
    ]);
    const trustStatus = z
      .enum(["available", "unavailable", "expired", "revoked"])
      .parse(raw.trustStatus);
    const evaluationTime = timestampShape.parse(raw.evaluationTime);
    const admitted = await complete(admit(raw));
    const picked = await pick(admitted);
    if (picked.status === "invalid") return picked;
    const none = { error: 0, warning: 0, note: 0, unavailable: 0 };
    if (picked.status === "none")
      return {
        status: "summarised",
        // Rows 1-3: nothing scanned, nothing readable, or no record covers the item's own materials.
        summary: { state: picked.state, findings: none, suppressed: 0, scannedAt: null },
        picked: null,
        diagnostics: picked.diagnostics,
      };
    const { record, index } = picked;
    const findings = { ...none };
    let suppressed = 0;
    for (const detector of record.detectors) {
      for (const key of Object.keys(findings) as (keyof typeof none)[])
        findings[key] += detector.findings[key];
      for (const entry of detector.suppressed) suppressed += entry.count;
    }
    const authentication = (admitted.candidates[index]!.authentication as ItemAuthentication)
      .status;
    const age = admitted.policy.maxAge === undefined ? null : duration(admitted.policy.maxAge);
    const [state, reason]: [ItemSummary["state"], ItemSummary["why"]?] =
      record.coverage !== "matched"
        ? ["not-covered"]
        : record.completion === "partial"
          ? ["partial"]
          : !requiredSucceeded(record, admitted.policy)
            ? ["not-verified", "detector-missing"]
            : record.severityProfile !== admitted.policyProfile
              ? ["not-verified", "profile-not-allowed"]
              : authentication === "revoked" || trustStatus === "revoked"
                ? ["not-verified", "revoked"]
                : trustStatus === "unavailable" || trustStatus === "expired"
                  ? ["not-verified", "offline"]
                  : authentication === "skipped"
                    ? ["not-verified", "unchecked"]
                    : authentication === "unverifiable"
                      ? ["not-verified", "not-authenticated"]
                      : Date.parse(record.createdAt) > Date.parse(evaluationTime)
                        ? ["not-verified", "future-dated"]
                        : age && expiresAt(record.createdAt, age) < Date.parse(evaluationTime)
                          ? ["not-verified", "older-than-policy"]
                          : ["verified"];
    return {
      status: "summarised",
      summary: {
        state,
        ...(reason ? { why: reason } : {}),
        findings,
        suppressed,
        scannedAt: record.createdAt,
      },
      picked: { index, scanId: record.scanId, why: picked.why },
      diagnostics: picked.diagnostics,
    };
  } catch (error) {
    return refusal(error);
  }
}
