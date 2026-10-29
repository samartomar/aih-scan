import { z } from "zod";
import { bound, canonicalBytes, sha256 } from "./json.js";
import { labelShape, pathShape } from "./shapes.js";
import type { Finding } from "./types.js";

export const severityProfileSchema = "urn:aihq:scan:severity-profile:1.0.0";
/** Maps native levels to the four counted severities and records suppressions with their reasons. */
export const severityProfileShape = z
  .object({
    schema: z.literal(severityProfileSchema),
    id: labelShape.refine((value) => value.length <= 128, "profile id is at most 128 characters"),
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
  })
  .strict();
export type SeverityProfile = z.infer<typeof severityProfileShape>;
export type SeverityCounts = { error: number; warning: number; note: number; unavailable: number };
export type SuppressedCount = { rule: string; count: number; reason: string };

/** The record's `severityProfile` text for a profile id and the SHA-256 of its canonical JSON. */
export const formatProfileRef = ({ id, sha256 }: { id: string; sha256: string }) =>
  `${id}@sha256:${sha256}`;
/** The record's `severityProfile` for a profile document. */
export async function severityProfileRef(profile: SeverityProfile): Promise<string> {
  return formatProfileRef({ id: profile.id, sha256: await sha256(canonicalBytes(profile)) });
}

/** Counts one detector's item-attributed findings. Suppressed findings are counted with their reason, never dropped. */
export function classifyFindings(
  detectorId: string,
  findings: readonly Finding[],
  profile: SeverityProfile,
): { findings: SeverityCounts; suppressed: SuppressedCount[] } {
  bound(
    findings.length * (profile.suppressions.length + profile.rules.length + 1) <= 50000000,
    "finding classification work",
    50000000,
  );
  const add = (left: number, right: number) => {
    const sum = left + right;
    bound(Number.isSafeInteger(sum), "finding occurrences", Number.MAX_SAFE_INTEGER);
    return sum;
  };
  const counts: SeverityCounts = { error: 0, warning: 0, note: 0, unavailable: 0 };
  const groups = new Map<string, SuppressedCount>();
  for (const finding of findings) {
    const suppression = profile.suppressions.find(
      (rule) =>
        rule.detectorId === detectorId &&
        finding.rule.state === "present" &&
        rule.nativeRuleId === finding.rule.value.nativeRuleId &&
        (rule.path === undefined ||
          (finding.location.state === "present" && rule.path === finding.location.value.path)),
    );
    if (suppression) {
      const key = JSON.stringify([suppression.nativeRuleId, suppression.reason]);
      const group = groups.get(key) ?? {
        rule: suppression.nativeRuleId,
        count: 0,
        reason: suppression.reason,
      };
      group.count = add(group.count, finding.multiplicity);
      groups.set(key, group);
      continue;
    }
    const level = finding.severity.state === "present" ? finding.severity.value.level : null;
    const maps =
      profile.rules.find(
        (rule) =>
          (rule.detectorId === "*" || rule.detectorId === detectorId) && rule.level === level,
      )?.maps ?? "unavailable";
    counts[maps] = add(counts[maps], finding.multiplicity);
  }
  const suppressed = [...groups.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, group]) => group);
  return { findings: counts, suppressed };
}
