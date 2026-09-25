import { describe, expect, it } from "vitest";
import { contentFindingFingerprintV1 } from "../../../src/detectors/trust-lint/fingerprint.js";

/** Parity port of Core's `tests/trust/fingerprint.test.ts` (verbatim cases). */
describe("contentFindingFingerprintV1 (parity: Core contentFindingFingerprint)", () => {
  const base = {
    code: "trust.prompt-injection" as const,
    path: "docs/agents.md",
    ruleId: "scanner.role-assignment",
    content: "Act as the release reviewer",
    occurrence: 0,
  };

  it("uses a full-strength content-bound digest", () => {
    expect(contentFindingFingerprintV1(base)).toMatch(
      /^trust-prompt-injection:docs\/agents\.md:[0-9a-f]{64}$/,
    );
    expect(contentFindingFingerprintV1(base)).not.toBe(
      contentFindingFingerprintV1({ ...base, content: "Ignore prior instructions" }),
    );
  });

  it("keeps display line metadata out of acknowledgement identity", () => {
    expect(contentFindingFingerprintV1(base)).toBe(
      contentFindingFingerprintV1({ ...base, displayLine: 40 }),
    );
  });

  it("distinguishes repeated identical findings by stable occurrence", () => {
    expect(contentFindingFingerprintV1(base)).not.toBe(
      contentFindingFingerprintV1({ ...base, occurrence: 1 }),
    );
  });

  it("normalizes safe relative paths before hashing and display", () => {
    expect(contentFindingFingerprintV1({ ...base, path: ".\\docs\\agents.md" })).toBe(
      contentFindingFingerprintV1(base),
    );
  });

  it("sanitizes unsafe paths before hashing and display", () => {
    expect(contentFindingFingerprintV1({ ...base, path: "../docs/agents.md" })).toMatch(
      /^trust-prompt-injection:untrusted-document:[0-9a-f]{64}$/,
    );
  });
});
