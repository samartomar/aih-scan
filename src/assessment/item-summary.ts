import { z } from "zod";
import type { AssociationResult } from "../artifact/types.js";
import {
  type ItemDescriptor,
  type ItemRecord,
  parseItemDescriptor,
  recordItem,
  verifyItemRecord,
} from "./item-record.js";
import { bound, canonicalBytes, errorDiagnostic, fail, sha256 } from "./json.js";
import { selectAssessments, snapshotSelectionInput } from "./selection.js";
import {
  diagnosticShape,
  digestShape,
  integerShape,
  labelShape,
  pathShape,
  scanIdShape,
  timestampShape,
} from "./shapes.js";
import { dataObject, readDocument, snapshotJson } from "./summary.js";
import type {
  AssessmentContext,
  SelectAssessmentsInput,
  SelectAssessmentsResult,
} from "./summary-types.js";
import type { Diagnostic } from "./types.js";

export const evidencePolicySchema = "urn:aihq:scan:evidence-policy:1.0.0";
export const severityProfileSchema = "urn:aihq:scan:severity-profile:1.0.0";
export const itemSummarySchema = "urn:aihq:scan:item-summary:1.0.0";
export const severityProfileShape = z
  .object({
    schema: z.literal(severityProfileSchema),
    id: labelShape,
    version: labelShape,
    rules: z
      .array(
        z
          .object({
            detectorId: labelShape,
            level: labelShape,
            maps: z.enum(["error", "warning", "note", "unavailable"]),
          })
          .strict(),
      )
      .max(10000),
  })
  .strict();
export const evidencePolicyShape = z
  .object({
    schema: z.literal(evidencePolicySchema),
    id: labelShape,
    version: labelShape,
    requiredDetectors: z
      .array(
        z
          .object({ detectorId: labelShape, allowedProfileIds: z.array(labelShape).max(10000) })
          .strict(),
      )
      .max(10000),
    severityProfile: z.object({ id: labelShape, sha256: digestShape }).strict(),
    suppressions: z
      .array(
        z
          .object({
            detectorId: labelShape,
            nativeRuleId: labelShape,
            path: pathShape.optional(),
            reason: labelShape,
          })
          .strict(),
      )
      .max(10000),
    maxAge: z
      .string()
      .max(256)
      .regex(
        /^P(?=\d|T\d)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/,
      )
      .optional(),
  })
  .strict();
export const itemSummaryShape = z
  .object({
    schema: z.literal(itemSummarySchema),
    state: z.enum([
      "verified",
      "not-verified",
      "partial",
      "not-covered",
      "not-scanned",
      "unreadable",
    ]),
    why: z
      .enum([
        "no-sources",
        "not-found",
        "content-mismatch",
        "scope-mismatch",
        "source-mismatch",
        "provider-mismatch",
        "identity-conflict",
        "future-dated",
        "detector-missing",
        "detector-not-covering",
        "profile-not-allowed",
        "executable-unknown",
        "revoked",
        "offline",
        "unchecked",
        "not-authenticated",
        "older-than-policy",
      ])
      .optional(),
    freshness: z.enum(["checked", "last-known"]).nullable(),
    findings: z
      .object({
        error: integerShape,
        warning: integerShape,
        note: integerShape,
        unavailable: integerShape,
      })
      .strict(),
    suppressed: z
      .object({
        count: integerShape,
        reasons: z.array(
          z
            .object({
              detectorId: labelShape,
              nativeRuleId: labelShape,
              reason: labelShape,
              count: integerShape,
            })
            .strict(),
        ),
      })
      .strict(),
    scannedAt: timestampShape.nullable(),
    scanId: scanIdShape.nullable(),
  })
  .strict();
export const itemSummaryResultShape = z.union([
  itemSummaryShape,
  z.object({ status: z.literal("invalid"), diagnostics: z.array(diagnosticShape) }).strict(),
]);
export type EvidencePolicy = z.infer<typeof evidencePolicyShape>;
export type SeverityProfile = z.infer<typeof severityProfileShape>;
export type ItemSummary = z.infer<typeof itemSummaryShape>;
export type ItemAuthentication = AssociationResult | { status: "revoked" };
export type ItemTrustStatus = "available" | "unavailable" | "expired" | "revoked";
export interface SummariseItemInput {
  assessmentsInput: Omit<SelectAssessmentsInput, "context" | "evaluationTime"> & {
    context: Omit<AssessmentContext, "descriptors">;
  };
  item: ItemDescriptor;
  evidencePolicy: EvidencePolicy;
  severityProfile: SeverityProfile;
  authentication: ItemAuthentication;
  trustStatus: ItemTrustStatus;
  evaluationTime: string;
}
export type SummariseItemResult =
  | {
      status: "summarised";
      summary: ItemSummary;
      selection: Exclude<SelectAssessmentsResult, { status: "invalid" }> | null;
    }
  | { status: "invalid"; diagnostics: Diagnostic[] };
const authenticationShape = z
  .object({
    status: z.enum(["skipped", "authenticated", "unverifiable", "revoked"]),
    scanId: scanIdShape.optional(),
    reason: labelShape.optional(),
    producerIdentity: labelShape.optional(),
    keyId: labelShape.optional(),
    reportRead: z.enum(["supported", "unsupported", "not-requested"]).optional(),
  })
  .strict();
function countFindings(
  record: ItemRecord,
  policy: EvidencePolicy,
  profile: SeverityProfile,
): Pick<ItemSummary, "findings" | "suppressed"> {
  const findings: ItemSummary["findings"] = { error: 0, warning: 0, note: 0, unavailable: 0 };
  const suppressed: ItemSummary["suppressed"] = { count: 0, reasons: [] };
  const groups = new Map<string, ItemSummary["suppressed"]["reasons"][number]>();
  const count = record.detectors.reduce((count, detector) => count + detector.findings.length, 0);
  bound(
    count * (policy.suppressions.length + profile.rules.length + 1) <= 50000000,
    "summary classification work",
    50000000,
  );
  const add = (left: number, right: number) => {
    const sum = left + right;
    bound(Number.isSafeInteger(sum), "finding occurrences", Number.MAX_SAFE_INTEGER);
    return sum;
  };
  for (const detector of record.detectors)
    for (const finding of detector.findings) {
      const suppression = policy.suppressions.find(
        (rule) =>
          rule.detectorId === detector.detectorId &&
          finding.rule.state === "present" &&
          rule.nativeRuleId === finding.rule.value.nativeRuleId &&
          (rule.path === undefined ||
            (finding.location.state === "present" && rule.path === finding.location.value.path)),
      );
      if (suppression) {
        suppressed.count = add(suppressed.count, finding.multiplicity);
        const { detectorId, nativeRuleId, reason } = suppression;
        const key = JSON.stringify([detectorId, nativeRuleId, reason]);
        const group = groups.get(key) ?? { detectorId, nativeRuleId, reason, count: 0 };
        group.count = add(group.count, finding.multiplicity);
        groups.set(key, group);
      } else {
        const level = finding.severity.state === "present" ? finding.severity.value.level : null;
        const maps =
          profile.rules.find(
            (rule) =>
              (rule.detectorId === "*" || rule.detectorId === detector.detectorId) &&
              rule.level === level,
          )?.maps ?? "unavailable";
        findings[maps] = add(findings[maps], finding.multiplicity);
      }
    }
  suppressed.reasons = [...groups.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, reason]) => reason);
  return { findings, suppressed };
}
// Calendar components use UTC and clamp an end-of-month day. Weeks and smaller
// units are elapsed time; this never changes historical authentication.
function duration(value: string): number[] {
  const match =
    /^P(?=\d|T\d)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(
      value,
    );
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
/** One item view, with the unchanged full selector result alongside the portable summary document. */
export async function summariseItem(input: SummariseItemInput): Promise<SummariseItemResult> {
  try {
    const raw = dataObject(input, [
      "assessmentsInput",
      "item",
      "evidencePolicy",
      "severityProfile",
      "authentication",
      "trustStatus",
      "evaluationTime",
    ]);
    const item = parseItemDescriptor(snapshotJson(raw.item));
    const policy = evidencePolicyShape.parse(snapshotJson(raw.evidencePolicy));
    const profile = severityProfileShape.parse(snapshotJson(raw.severityProfile));
    const authentication = authenticationShape.parse(snapshotJson(raw.authentication));
    const trustStatus = z
      .enum(["available", "unavailable", "expired", "revoked"])
      .parse(raw.trustStatus);
    const evaluationTime = timestampShape.parse(raw.evaluationTime);
    const age = policy.maxAge === undefined ? null : duration(policy.maxAge);
    if (
      new Set(policy.requiredDetectors.map((d) => d.detectorId)).size !==
      policy.requiredDetectors.length
    )
      fail("Required detector IDs must be unique");
    const assessments = dataObject(
      raw.assessmentsInput,
      ["assessments", "context", "checks"],
      ["detectorIds"],
    );
    const context = dataObject(
      assessments.context,
      ["sourceIds", "selection"],
      ["git", "providers"],
    );
    // Reuse the selector's admission and byte snapshots, allowing only its source
    // minimum to differ for row1. No ranking occurs here.
    const snapshot = snapshotSelectionInput(
      {
        ...assessments,
        context: {
          ...context,
          descriptors: item.materials.map(({ path, sha256, byteLength }) => ({
            path,
            sha256,
            byteLength,
          })),
        },
        evaluationTime,
      } as unknown as SelectAssessmentsInput,
      true,
    );
    const selectionInput: SelectAssessmentsInput = {
      assessments: snapshot.assessments,
      context: snapshot.context,
      checks: snapshot.checks,
      evaluationTime,
      detectorIds: snapshot.ids,
    };
    if (
      policy.severityProfile.id !== profile.id ||
      (await sha256(canonicalBytes(profile))) !== policy.severityProfile.sha256
    )
      return {
        status: "invalid",
        diagnostics: [
          {
            code: "severity-profile-mismatch",
            detail: "The selected severity profile does not match the evidence policy.",
          },
        ],
      };
    const summary: ItemSummary = {
      schema: itemSummarySchema,
      state: "not-scanned",
      why: "no-sources",
      freshness: null,
      findings: { error: 0, warning: 0, note: 0, unavailable: 0 },
      suppressed: { count: 0, reasons: [] },
      scannedAt: null,
      scanId: null,
    };
    if (!snapshot.context.sourceIds.length)
      return { status: "summarised", selection: null, summary };
    const selection = await selectAssessments(selectionInput);
    if (selection.status === "invalid") return selection;
    summary.freshness = selection.freshness;
    summary.why = "not-found";
    if (!selection.selectedScanId) {
      const entries = selection.assessments;
      if (
        !entries.length &&
        (selection.failures.length ||
          selection.checks.some((check) => check.status !== "succeeded"))
      ) {
        summary.state = "unreadable";
        delete summary.why;
      } else if (entries.length && entries.every((entry) => entry.eligibility === "future-dated")) {
        summary.state = "not-verified";
        summary.why = "future-dated";
      } else if (
        entries.length &&
        entries.every((entry) => entry.eligibility === "content-mismatch")
      ) {
        summary.state = "not-covered";
        summary.why = "content-mismatch";
      } else {
        const order = [
          "scope-mismatch",
          "git-mismatch",
          "provider-mismatch",
          "identity-conflict",
        ] as const;
        const exclusion = order.find((reason) =>
          entries.some((entry) => entry.eligibility === reason),
        );
        if (exclusion) {
          summary.state = "not-covered";
          summary.why = exclusion === "git-mismatch" ? "source-mismatch" : exclusion;
        }
      }
    } else {
      const chosen = selection.assessments.find(
        (entry) => entry.summary.scanId === selection.selectedScanId,
      )!;
      const acquisition = chosen.acquisitions[0]!;
      let assessment: Awaited<ReturnType<typeof readDocument>> | undefined;
      for (const candidate of snapshot.assessments) {
        if (
          candidate.sourceId !== acquisition.sourceId ||
          candidate.location !== acquisition.location ||
          candidate.format !== acquisition.format
        )
          continue;
        const read = await readDocument(candidate);
        if (read.status === "read" && read.scanId === selection.selectedScanId) {
          assessment = read;
          break;
        }
      }
      if (assessment?.status !== "read") fail("Selected assessment is unavailable");
      if (authentication.scanId !== undefined && authentication.scanId !== assessment.scanId)
        fail("Host authentication names a different assessment");
      const record = await recordItem(assessment, item);
      summary.scanId = assessment.scanId;
      summary.scannedAt = assessment.report.createdAt;
      if ("schema" in record) Object.assign(summary, countFindings(record, policy, profile));
      delete summary.why;
      if (
        !("schema" in record) ||
        record.coverage !== "matched" ||
        (await verifyItemRecord(record, assessment, item)) !== "same"
      ) {
        summary.state = "not-covered";
        summary.why = "content-mismatch";
      } else if (record.completion === "partial") summary.state = "partial";
      else {
        const checked = policy.requiredDetectors.length
          ? policy.requiredDetectors
          : record.detectors.map(({ detectorId }) => ({ detectorId, allowedProfileIds: [] }));
        const missing = checked.some((required) => {
          const detector = record.detectors.find((d) => d.detectorId === required.detectorId);
          return detector?.outcome !== "succeeded" || detector.effectiveProfileId === null;
        });
        const notCovering = checked.some(
          (required) =>
            record.detectors.find((d) => d.detectorId === required.detectorId)?.itemCoverage !==
            "covered",
        );
        summary.state = "not-verified";
        if (missing) summary.why = "detector-missing";
        else if (notCovering) summary.why = "detector-not-covering";
        else if (
          record.materials.some(
            (material) =>
              material.executable === true && material.executableComparison === "unknown",
          )
        )
          summary.why = "executable-unknown";
        else if (
          checked.some(
            (required) =>
              required.allowedProfileIds.length > 0 &&
              !required.allowedProfileIds.includes(
                record.detectors.find((d) => d.detectorId === required.detectorId)!
                  .effectiveProfileId!,
              ),
          )
        )
          summary.why = "profile-not-allowed";
        else if (authentication.status === "revoked" || trustStatus === "revoked")
          summary.why = "revoked";
        else if (trustStatus === "unavailable" || trustStatus === "expired")
          summary.why = "offline";
        else if (authentication.status === "skipped") summary.why = "unchecked";
        else if (authentication.status === "unverifiable") summary.why = "not-authenticated";
        else if (age && expiresAt(record.createdAt, age) < Date.parse(evaluationTime))
          summary.why = "older-than-policy";
        else summary.state = "verified";
      }
    }
    return { status: "summarised", selection, summary };
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
}
