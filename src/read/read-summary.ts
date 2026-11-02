import type { Problem } from "../contracts/formats.js";
import { limits } from "../contracts/limits.js";
import { isBytes } from "../contracts/text.js";
import { type Summary, validateSummary } from "../contracts/validate.js";
import { decodeStrictUtf8V1, parseStrictJsonV1 } from "../shared/strict-json.js";

export type ReadSummaryResult = Readonly<{ status: "ok"; summary: Summary }> | Problem;

const invalid = (reason: string, detail: string): Problem =>
  Object.freeze({ status: "invalid", reason, detail });

/** Parses strict JSON bytes (UTF-8, no duplicate keys, bounded) without throwing. */
export function parseJsonBytes(
  bytes: unknown,
  label: string,
  maxBytes: number,
): Readonly<{ ok: true; value: unknown }> | Readonly<{ ok: false; problem: Problem }> {
  if (!isBytes(bytes))
    return {
      ok: false,
      problem: invalid("bytes", `${label} must be supplied as bytes (Uint8Array)`),
    };
  if (bytes.length > maxBytes)
    return {
      ok: false,
      problem: Object.freeze({
        status: "refused",
        reason: "limit",
        detail: `${label} exceeds ${maxBytes} bytes`,
      }),
    };
  try {
    const text = decodeStrictUtf8V1(bytes, label);
    return {
      ok: true,
      value: parseStrictJsonV1(text.startsWith("\uFEFF") ? text.slice(1) : text, label, {
        requireNfc: false,
      }),
    };
  } catch {
    return { ok: false, problem: invalid("json", `${label} is not strict UTF-8 JSON`) };
  }
}

/**
 * Reads `aih-scan-summary/1` bytes. Never throws: malformed input is `invalid`, another
 * summary/routing/scoring version is `unsupported-version`, unsafe file paths or oversized
 * input are `refused`. A readable summary says nothing about who produced it (see verifySummary).
 */
export function readSummary(bytes: Uint8Array): ReadSummaryResult {
  const parsed = parseJsonBytes(bytes, "summary", limits.output.summaryBytes);
  if (!parsed.ok) return parsed.problem;
  return validateSummary(parsed.value);
}
