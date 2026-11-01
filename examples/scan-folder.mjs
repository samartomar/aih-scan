// Scan one folder with @aihq/scan/host, then read, inspect and match every result through
// @aihq/scan/read. Usage: node examples/scan-folder.mjs <folder> <new-output-folder>
import { readFileSync } from "node:fs";
import { matchScan as matchFolder, scan } from "@aihq/scan/host";
import { readFindings, readSummary } from "@aihq/scan/read";

const [folder, outDir] = process.argv.slice(2);
if (folder === undefined || outDir === undefined) {
  console.error("usage: node examples/scan-folder.mjs <folder> <new-output-folder>");
  process.exit(2);
}
const run = await scan(
  {
    format: "aih-scan-request/1",
    origin: "local",
    source: { format: "aih-scan-source/1", type: "folder", path: folder },
  },
  { outDir },
);
if (run.status !== "ok") {
  console.error(`not scanned: ${run.status} ${run.reason ?? ""}`);
  process.exit(2);
}
for (const result of run.results) {
  if (result.status !== "ok") {
    console.log(`${result.kind} ${result.path} ${result.status} ${result.reason}`);
    continue;
  }
  const { summary } = readSummary(new Uint8Array(readFileSync(result.summaryPath)));
  const shown = summary.coverage === "partial" ? `${summary.label} (partial)` : summary.label;
  console.log(`${result.kind} ${result.path} ${summary.scanKey} ${shown} score ${summary.score}`);
  for (const path of result.sarifPaths) {
    const read = await readFindings(summary, new Uint8Array(readFileSync(path)), summary.scanKey);
    for (const finding of read.findings ?? [])
      console.log(`  ${finding.severity} ${finding.code} ${finding.path}:${finding.line} ${finding.text}`);
  }
}
console.log(`roll-up: ${run.rollup.label} (${run.rollup.coverage})`);
// Matching a summary to content checks the key and every file's sha256; a summary alone has no signer.
const first = run.results.find((result) => result.status === "ok" && result.kind !== "remaining-files");
if (first !== undefined) {
  const { summary } = readSummary(new Uint8Array(readFileSync(first.summaryPath)));
  const itemFolder = first.path === "." ? folder : `${folder}/${first.path}`;
  const match = await matchFolder(summary, itemFolder);
  console.log(`matches: ${match.matches} signer: ${match.signer}`);
}
