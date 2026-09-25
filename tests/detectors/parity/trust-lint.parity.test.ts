import { rmSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import { buildTrustLintTreeV1, runTrustLintV1 } from "../../../src/detectors/trust-lint/index.js";
import { coreMcpConfigPathsV1, coreSelectionV1 } from "../trust-lint/support.js";
import { type GoldenCheckV1, goldenCaseV1, materializeCaseV1, parityCasesV1 } from "./support.js";

/**
 * `detector.aih-trust-lint` against W2's native goldens (C2a §2.2-§2.4, §2.6).
 *
 * Each case is materialized fresh, as W2's capture did, and run through
 * `runTrustLintV1` with the request Core would send: its trust inventory as
 * the selection, its incoming-MCP discovery as `mcpConfigPaths`, and the
 * case's `internalScopes`. The goldens are Core's graded checks at vibe
 * posture. Grading only prefixes the detail with
 * `warning-only (<posture> posture): ` and swaps verdict and code, so the
 * expected SARIF results are the golden `trust-lint` and
 * `mcp-description-lint` checks, in Core's order, with that prefix removed
 * and the check name mapped back to its code. Every field is compared:
 * ruleId, uri, startLine, detail and fingerprint.
 */

const GRADING_PREFIX = /^warning-only \([a-z]+ posture\): /;
const CODE_BY_NAME: Readonly<Record<string, string>> = {
  "plaintext-secret": "secrets.plaintext-detected",
  "mcp-hardcoded-secret": "mcp.hardcoded-secret",
  "mcp-config-invalid": "mcp.config-invalid",
};
const SUMMARY_DETAIL = /^scanned (\d+) trust document\(s\) in <root>$/;

const roots: string[] = [];
afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

function expectedResult(check: GoldenCheckV1) {
  return {
    ruleId: CODE_BY_NAME[check.name] ?? check.name,
    uri: check.uri,
    startLine: check.startLine,
    detail: check.detail.replace(GRADING_PREFIX, ""),
    fingerprint: check.fingerprint,
  };
}

describe("trust-lint parity with W2's native goldens", () => {
  for (const parityCase of parityCasesV1()) {
    it(`reproduces Core's native findings for ${parityCase.id}`, () => {
      const golden = goldenCaseV1(parityCase.id);
      expect(golden.native.identicalAcrossEnvironments).toBe(true);
      const checks = golden.native.byEnvironment["linux-x64"]?.checks ?? [];
      const root = materializeCaseV1(parityCase);
      roots.push(root);
      const tree = buildTrustLintTreeV1(root);
      const selectedClosurePaths = coreSelectionV1(tree);

      const outcome = runTrustLintV1({
        sourceRoot: root,
        selectedClosurePaths,
        detectorOptions: {
          internalScopes: parityCase.internalScopes ?? [],
          mcpConfigPaths: coreMcpConfigPathsV1(root, selectedClosurePaths),
        },
      });

      if (outcome.kind !== "completed") throw new Error(JSON.stringify(outcome));
      const run = outcome.sarif.runs[0];
      expect(
        run.results.map((result) => ({
          ruleId: result.ruleId,
          uri: result.locations[0].physicalLocation.artifactLocation.uri,
          startLine: result.locations[0].physicalLocation.region.startLine,
          detail: result.message.text,
          fingerprint: result.fingerprints["aih-trust/v1"],
        })),
      ).toEqual(
        checks
          .filter(
            (check) => check.family === "trust-lint" || check.family === "mcp-description-lint",
          )
          .map(expectedResult),
      );
      const summary = checks.find((check) => check.family === "summary");
      const counted = summary?.detail.match(SUMMARY_DETAIL)?.[1];
      if (counted !== undefined) {
        expect(run.properties["aih-trust/v1"].trustDocumentCount).toBe(Number(counted));
      }
    });
  }
});
