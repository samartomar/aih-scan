import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { sigstoreTrustedRootText, verification } from "../../src/public/contracts.js";

it("publishes the exact pinned trusted root the verifier embeds, under its recorded digest", () => {
  const bytes = readFileSync(
    join(import.meta.dirname, "..", "..", "trust", "sigstore-trusted-root.json"),
  );
  expect(bytes.toString("utf8")).toBe(sigstoreTrustedRootText);
  expect(bytes.length).toBe(verification.trustSnapshot.length);
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(verification.trustSnapshot.sha256);
});
