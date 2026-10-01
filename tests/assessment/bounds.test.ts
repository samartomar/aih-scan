import { createHash } from "node:crypto";
import { expect, test } from "vitest";
import { prepareArtifact, runScan } from "../../src/public/host.js";
import { readArtifact } from "../../src/public/read.js";
import { emptyReport } from "./fixtures.js";

test("reads a complete artifact at the supported 16 MiB annex boundary", async () => {
  const bytes = Buffer.alloc(16 * 1024 * 1024, 0xa5),
    report = emptyReport();
  report.annexes = [
    {
      id: "annex.maximum",
      mediaType: "application/octet-stream",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      byteLength: bytes.length,
    },
  ];
  const prepared = await prepareArtifact({ report, annexes: [{ id: "annex.maximum", bytes }] });
  expect(await readArtifact(prepared.bytes)).toMatchObject({
    status: "read",
    annexBytes: "checked",
    authenticity: "unchecked",
  });
}, 30000);
test("reports excessive direct-object depth as a bounded request refusal", async () => {
  let input: unknown = {};
  for (let at = 0; at < 10000; at++) input = { next: input };
  expect(await runScan(input)).toMatchObject({
    status: "diagnostic",
    phase: "request",
    diagnostics: [{ code: "resource-limit" }],
  });
});
