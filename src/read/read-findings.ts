import { isScanCode, type ScanCode } from "../contracts/codes.js";
import type { Problem } from "../contracts/formats.js";
import { sha256Hex } from "../contracts/git-tree.js";
import { limits } from "../contracts/limits.js";
import type { FindingPart, Severity } from "../contracts/risk.js";
import { severityOf } from "../contracts/risk.js";
import { displayPathProblem, isBytes, sanitizeText } from "../contracts/text.js";
import type { Summary } from "../contracts/validate.js";
import { isRecord } from "../shared/values.js";
import { parseJsonBytes } from "./read-summary.js";

export interface Finding {
  readonly severity: Severity;
  readonly code: ScanCode;
  readonly tool: string;
  readonly ruleId: string;
  readonly part: FindingPart;
  readonly fingerprint: string | null;
  readonly confidence: number | null;
  readonly fileSha256: string;
  readonly text: string;
  readonly path: string;
  readonly line: number;
}

export const FINDINGS_MISMATCH_MESSAGE = "Findings don't match this scan";

export type ReadFindingsResult =
  | Readonly<{ status: "ok"; findings: readonly Finding[] }>
  | Readonly<{
      status: "refused";
      reason: "findings-mismatch";
      message: typeof FINDINGS_MISMATCH_MESSAGE;
    }>
  | Problem;

const MISMATCH = Object.freeze({
  status: "refused" as const,
  reason: "findings-mismatch" as const,
  message: FINDINGS_MISMATCH_MESSAGE,
});

class Mismatch extends Error {}
class Bad extends Error {}

type Obj = Record<string, unknown>;
const isObject = isRecord;
function need(condition: unknown, error: new () => Error = Bad): asserts condition {
  if (!condition) throw new error();
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const LEVELS = ["error", "warning", "note", "none"] as const;
const PARTS = ["config", "dependencies", "code", "text", "none"] as const;

function locationOf(result: Obj): { uri: string; line: number } {
  const locations = result.locations;
  need(Array.isArray(locations) && locations.length >= 1);
  const physical = (locations as unknown[])[0];
  need(isObject(physical) && isObject(physical.physicalLocation));
  const location = (physical as Obj).physicalLocation as Obj;
  need(
    isObject(location.artifactLocation) &&
      typeof (location.artifactLocation as Obj).uri === "string",
  );
  const uri = (location.artifactLocation as Obj).uri as string;
  const region = location.region;
  const line = isObject(region) && region.startLine !== undefined ? region.startLine : 1;
  need(typeof line === "number" && Number.isSafeInteger(line) && line >= 1);
  return { uri, line: line as number };
}

/**
 * Reads one SARIF 2.1.0 document pinned by a summary into one line per finding. The SARIF's
 * sha256 must be listed by the summary, `scanKey` must be the summary's key and every result's,
 * and every location must be a file of the summary shown under the display path rule
 * (absolute, `..`, URL and scheme-prefixed paths such as `javascript:` or `notes:1.md` never are).
 * Otherwise only "Findings don't match this scan" is returned. Text, tool and rule ids are
 * untrusted: control, bidirectional and zero-width characters are removed and lengths are
 * held to `limits.output`. Resolves asynchronously (WebCrypto digest).
 */
export async function readFindings(
  summary: Summary,
  sarifBytes: Uint8Array,
  scanKey: string,
): Promise<ReadFindingsResult> {
  if (!isObject(summary) || !Array.isArray(summary.sarif) || !Array.isArray(summary.files))
    return Object.freeze({
      status: "invalid",
      reason: "summary",
      detail: "summary must be a readSummary result's summary",
    });
  if (!isBytes(sarifBytes))
    return Object.freeze({
      status: "invalid",
      reason: "bytes",
      detail: "SARIF must be supplied as bytes (Uint8Array)",
    });
  if (typeof scanKey !== "string" || scanKey !== summary.scanKey) return MISMATCH;
  if (sarifBytes.length > limits.output.sarifBytes)
    return Object.freeze({
      status: "refused",
      reason: "limit",
      detail: `SARIF exceeds ${limits.output.sarifBytes} bytes`,
    });
  const digest = await sha256Hex(sarifBytes);
  if (!summary.sarif.some((entry) => entry.sha256 === digest)) return MISMATCH;
  const parsed = parseJsonBytes(sarifBytes, "SARIF", limits.output.sarifBytes);
  if (!parsed.ok) return parsed.problem;
  const document = parsed.value;
  if (!isObject(document))
    return Object.freeze({ status: "invalid", reason: "sarif", detail: "SARIF must be an object" });
  if (document.version !== "2.1.0")
    return Object.freeze({
      status: "unsupported-version",
      reason: "unsupported-version",
      detail: "only SARIF 2.1.0 is supported",
    });
  const files = new Map(summary.files.map((file) => [file.path, file]));
  try {
    const findings: Finding[] = [];
    need(Array.isArray(document.runs));
    for (const run of document.runs as unknown[]) {
      need(isObject(run) && isObject(run.tool) && isObject((run.tool as Obj).driver));
      const driver = (run.tool as Obj).driver as Obj;
      need(typeof driver.name === "string" && driver.name.length > 0);
      const tool = sanitizeText(driver.name as string, limits.output.ruleId);
      const artifacts = (run as Obj).artifacts;
      if (artifacts !== undefined) {
        need(Array.isArray(artifacts));
        for (const artifact of artifacts as unknown[]) {
          need(isObject(artifact) && isObject(artifact.location));
          const uri = (artifact.location as Obj).uri;
          need(typeof uri === "string");
          const file = files.get(uri as string);
          need(file !== undefined, Mismatch);
          const hashes = artifact.hashes;
          if (isObject(hashes) && hashes["sha-256"] !== undefined)
            need(hashes["sha-256"] === file?.sha256, Mismatch);
        }
      }
      const results = (run as Obj).results;
      need(Array.isArray(results));
      for (const result of results as unknown[]) {
        need(findings.length < limits.output.findingsPerSarif);
        need(isObject(result));
        const entry = result as Obj;
        const { uri, line } = locationOf(entry);
        need(
          displayPathProblem(uri, limits.output.findingPath, limits.input.depth) === undefined,
          Mismatch,
        );
        const file = files.get(uri);
        need(file !== undefined, Mismatch);
        const properties = entry.properties;
        need(isObject(properties));
        const props = properties as Obj;
        need(props.scanKey === scanKey, Mismatch);
        need(isScanCode(props.code));
        need(
          typeof props.part === "string" &&
            (PARTS as readonly string[]).includes(props.part as string),
        );
        const severity = props.severity;
        need(
          severity === undefined || (SEVERITIES as readonly string[]).includes(severity as string),
        );
        const level = entry.level;
        need(level === undefined || (LEVELS as readonly string[]).includes(level as string));
        const confidence = props.confidence;
        need(
          confidence === undefined ||
            (typeof confidence === "number" && confidence >= 0 && confidence <= 1),
        );
        need(typeof entry.ruleId === "string");
        need(isObject(entry.message) && typeof (entry.message as Obj).text === "string");
        const fingerprints = isObject(entry.partialFingerprints)
          ? (entry.partialFingerprints as Obj)
          : {};
        const fingerprint = Object.values(fingerprints).find((value) => typeof value === "string");
        findings.push(
          Object.freeze({
            severity: severityOf({
              severity: severity as Severity | undefined,
              level: level as (typeof LEVELS)[number] | undefined,
            }),
            code: props.code as ScanCode,
            tool,
            ruleId: sanitizeText(entry.ruleId as string, limits.output.ruleId),
            part: props.part as FindingPart,
            fingerprint:
              typeof fingerprint === "string"
                ? sanitizeText(fingerprint, limits.output.ruleId)
                : null,
            confidence: typeof confidence === "number" ? confidence : null,
            fileSha256: (file as { sha256: string }).sha256,
            text: sanitizeText((entry.message as Obj).text as string, limits.output.findingText),
            path: uri,
            line,
          }),
        );
      }
    }
    return Object.freeze({ status: "ok", findings: Object.freeze(findings) });
  } catch (error) {
    if (error instanceof Mismatch) return MISMATCH;
    return Object.freeze({
      status: "invalid",
      reason: "sarif",
      detail: "SARIF does not follow the scan finding shape",
    });
  }
}
