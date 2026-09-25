import { writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * U1i, coordinator decision D30: a Cisco source-tree or shard job asks `skill-scanner scan` for
 * its single-skill JSON report beside the SARIF (`--output-json`). A fake analyzer writes it
 * with this: the report of the scanned directory with no failed analyzer, plus `extra`.
 * Nothing is written when the argv asks for no JSON report.
 */
export function writeCiscoJobReportV1(
  argv: readonly string[],
  extra: Record<string, unknown> = {},
): void {
  const at = argv.indexOf("--output-json");
  if (at < 0) return;
  const target = argv[argv.indexOf("scan") + 1] ?? "";
  writeFileSync(
    argv[at + 1] ?? "",
    JSON.stringify({ skill_name: "fixture", skill_path: target, findings: [], ...extra }),
  );
}

/**
 * U1i, coordinator decision D30: the OCI capture's scanner writes its single-skill JSON report
 * to `/output/result.json` beside `result.sarif`. A fake container writes it with this, into
 * the host directory mounted there: the report of `/source` with no failed analyzer.
 */
export function writeCiscoCaptureReportV1(outputRoot: string): void {
  writeFileSync(
    join(outputRoot, "result.json"),
    JSON.stringify({ skill_name: "fixture", skill_path: "/source", findings: [] }),
  );
}
