import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { limits } from "../contracts/limits.js";
import type { Summary } from "../contracts/validate.js";
import { hostNameProblem } from "../host/snapshot.js";
import { FINDINGS_MISMATCH_MESSAGE, type Finding } from "../read/read-findings.js";
import {
  AnalyzerOutputReadErrorV1,
  readBoundedAnalyzerOutputV1,
} from "../shared/bounded-output-read.js";
import {
  type CommandIo,
  decodeSavedSummary,
  exitCodes,
  parse,
  readSavedFindings,
  UsageError,
} from "./commands-v1.js";
import { safeOutputParents, sameParents } from "./exclusive-output.js";

export const reviewUsage = "Usage: aih-scan review <summary.json> [--mcp]\n";

export interface ReviewSnapshot {
  readonly summary: Summary;
  readonly findings: readonly Finding[];
}

async function loadSnapshot(path: string): Promise<ReviewSnapshot | { problem: string }> {
  // Review holds one aggregate snapshot. Reuse the existing summary byte and per-SARIF finding bounds.
  let remaining = limits.output.summaryBytes;

  function readFile(
    file: string,
    label: string,
    maximum: number,
  ): { bytes: Uint8Array } | { problem: string } {
    try {
      const parents = safeOutputParents(file);
      const bytes = readBoundedAnalyzerOutputV1(file, label, Math.min(maximum, remaining));
      if (!sameParents(parents, safeOutputParents(file))) throw new Error("parent changed");
      remaining -= bytes.byteLength;
      return { bytes };
    } catch (error) {
      return {
        problem:
          error instanceof AnalyzerOutputReadErrorV1 && error.reason === "size"
            ? `${label} is empty or exceeds the saved review byte limit`
            : `${label} could not be read as a regular file with unlinked parents`,
      };
    }
  }

  const input = readFile(path, "summary", limits.output.summaryBytes);
  if ("problem" in input) return input;
  const decoded = decodeSavedSummary(input.bytes);
  if ("problem" in decoded) return decoded;
  const { summary } = decoded;
  if (
    new Set(summary.sarif.map((entry) => entry.path)).size !== summary.sarif.length ||
    hostNameProblem(summary.sarif) !== undefined
  )
    return { problem: FINDINGS_MISMATCH_MESSAGE };
  const saved = await readSavedFindings(
    path,
    summary,
    summary.scanKey,
    (file, sha256) => {
      const result = readFile(file, "pinned SARIF", limits.output.sarifBytes);
      if ("problem" in result) return result;
      if (createHash("sha256").update(result.bytes).digest("hex") !== sha256)
        return { problem: FINDINGS_MISMATCH_MESSAGE };
      return result;
    },
    limits.output.findingsPerSarif,
  );
  if ("problem" in saved) return saved;
  return { summary, findings: saved.findings };
}

export async function runReviewCommand(args: readonly string[], io: CommandIo): Promise<number> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    io.stdout(reviewUsage);
    return exitCodes.ok;
  }
  try {
    const parsed = parse(args, [], ["--mcp"]);
    const [path] = parsed.positional;
    if (path === undefined || parsed.positional.length !== 1)
      throw new UsageError("name one summary file");
    const report = await loadSnapshot(resolve(io.cwd ?? process.cwd(), path));
    if ("problem" in report) {
      io.stderr(`aih-scan: ${report.problem}\n`);
      return exitCodes.input;
    }
    if (parsed.flags.has("--mcp")) {
      const { serveReview } = await import("./review-mcp-v1.js");
      serveReview(report);
    } else {
      io.stdout(`${JSON.stringify({ status: "ok", ...report }, null, 2)}\n`);
    }
    return exitCodes.ok;
  } catch (error) {
    const message =
      error instanceof UsageError
        ? `${error.message}\n${reviewUsage}`
        : "the saved report could not be reviewed\n";
    io.stderr(`aih-scan: ${message}`);
    return exitCodes.input;
  }
}
