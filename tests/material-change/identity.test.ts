import { expect, test } from "vitest";
import type { MaterialChange } from "../../src/public/contracts.js";
import { deliverMaterialChange } from "../../src/public/host.js";
import { scanA, scanB, sourceId } from "./fixtures.js";

test("uses the contract change identity independently of scan context", async () => {
  const summary: MaterialChange = {
    schema: "urn:aihq:scan:material-change:1.0.0",
    sourceId,
    materialProjection: "aih-material-v1",
    beforeScanId: null,
    afterScanId: scanA,
    inventory: { beforeComplete: false, afterComplete: true, uncomparedItemIds: [] },
    changes: [
      { itemId: "skills/review", kind: "added", beforeSha256: null, afterSha256: "2".repeat(64) },
    ],
    diagnostics: [],
  };
  const first = await deliverMaterialChange({ summary, enabled: false });
  const second = await deliverMaterialChange({
    summary: {
      ...summary,
      afterScanId: scanB,
      diagnostics: [{ code: "display-context", detail: "A finding changed." }],
    },
    enabled: false,
  });
  expect(first.results[0]?.changeId).toBe(
    "change:sha256:c1977ca1a22a90853c3521959f7132065b27b2adf2f065f6aa7f4a0422d1443b",
  );
  expect(second.results[0]?.changeId).toBe(first.results[0]?.changeId);
});
