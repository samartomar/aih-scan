import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../src/contracts/git-tree.js";
import {
  FINDINGS_MISMATCH_MESSAGE,
  matchScan,
  readFindings,
  readSummary,
} from "../../src/public/read.js";
import { contentFiles, corpusCase } from "../support/scan-v1-corpus.js";

const encoder = new TextEncoder();
const bytesOf = (value: unknown) => encoder.encode(JSON.stringify(value));
const risky = corpusCase("risky");
const clean = corpusCase("clean");
const summaryOf = (bytes: Uint8Array) => {
  const read = readSummary(bytes);
  if (read.status !== "ok") throw new Error(JSON.stringify(read));
  return read.summary;
};
const riskyObject = () => JSON.parse(new TextDecoder().decode(risky.summary));

describe("readSummary", () => {
  it("preserves every agreed field of a complete summary", () => {
    const summary = summaryOf(risky.summary);
    expect(summary).toEqual(riskyObject());
    expect(Object.keys(summary)).toEqual([
      "format",
      "scanKey",
      "revision",
      "origin",
      "scannedAt",
      "scanner",
      "routing",
      "scoring",
      "score",
      "label",
      "coverage",
      "reason",
      "files",
      "tools",
      "notAnalysed",
      "sarif",
      "dependencies",
    ]);
    expect(summaryOf(corpusCase("not-assessed").summary)).toMatchObject({
      label: "NOT ASSESSED",
      notAnalysed: [{ path: "Dockerfile", secretsChecked: true }],
    });
  });

  it.each([
    ["another summary version", { format: "aih-scan-summary/2" }, "unsupported-version"],
    ["another routing version", { routing: "aih-scan-routing/2" }, "unsupported-version"],
    ["another scoring version", { scoring: "aih-risk/9" }, "unsupported-version"],
    ["a foreign format", { format: "urn:aihq:scan:item-summary:1.0.0" }, "invalid"],
    ["an unknown field", { catalogId: "x" }, "invalid"],
    ["a label that does not follow from score and coverage", { label: "SAFE" }, "invalid"],
    ["a missing partial reason", { reason: undefined }, "invalid"],
    [
      "an absolute file path",
      { files: [{ path: "/etc/passwd", mode: "100644", part: "text", sha256: "0".repeat(64) }] },
      "refused",
    ],
    [
      "a parent path",
      { files: [{ path: "../x.md", mode: "100644", part: "text", sha256: "0".repeat(64) }] },
      "refused",
    ],
    [
      "a URL path",
      { files: [{ path: "https://x/y", mode: "100644", part: "text", sha256: "0".repeat(64) }] },
      "refused",
    ],
    [
      "a bidi control in a path",
      { files: [{ path: "a\u202Eb.md", mode: "100644", part: "text", sha256: "0".repeat(64) }] },
      "refused",
    ],
  ])("returns a result for %s instead of throwing", (_name, change, status) => {
    const document = { ...riskyObject(), ...change };
    for (const [key, value] of Object.entries(change))
      if (value === undefined) delete document[key];
    expect(readSummary(bytesOf(document)).status).toBe(status);
  });

  it("rejects malformed bytes, duplicate keys and non-bytes as invalid", () => {
    expect(readSummary(encoder.encode("{")).status).toBe("invalid");
    expect(readSummary(new Uint8Array([0xff, 0xfe])).status).toBe("invalid");
    expect(readSummary(encoder.encode('{"format":"aih-scan-summary/1","format":"x"}')).status).toBe(
      "invalid",
    );
    expect(readSummary("{}" as unknown as Uint8Array).status).toBe("invalid");
  });
});

describe("readFindings", () => {
  it("returns one line per finding bound to its file digest", async () => {
    const summary = summaryOf(risky.summary);
    const result = await readFindings(summary, risky.sarif[0]!.bytes, summary.scanKey);
    if (result.status !== "ok") throw new Error(JSON.stringify(result));
    expect(result.findings).toContainEqual({
      severity: "HIGH",
      code: "trust.prompt-injection",
      tool: "aih-trust-lint",
      ruleId: "trust.prompt-injection",
      part: "text",
      fingerprint: expect.any(String),
      confidence: 0.8,
      fileSha256: summary.files[0]!.sha256,
      text: expect.stringContaining("SKILL.md:7"),
      path: "SKILL.md",
      line: 7,
    });
  });

  it("shows only the mismatch message for unlisted SARIF, another key or another scan's SARIF", async () => {
    const summary = summaryOf(risky.summary);
    const mismatch = {
      status: "refused",
      reason: "findings-mismatch",
      message: FINDINGS_MISMATCH_MESSAGE,
    };
    expect(await readFindings(summary, clean.sarif[0]!.bytes, summary.scanKey)).toEqual(mismatch);
    expect(
      await readFindings(summary, risky.sarif[0]!.bytes, summaryOf(clean.summary).scanKey),
    ).toEqual(mismatch);
    const tampered = risky.sarif[0]!.bytes.slice();
    tampered[tampered.length - 2] = 0x20;
    expect(await readFindings(summary, tampered, summary.scanKey)).toEqual(mismatch);
  });

  /** A crafted SARIF pinned by an otherwise identical summary. */
  async function pinned(mutate: (sarif: Record<string, unknown>) => void) {
    const sarif = JSON.parse(new TextDecoder().decode(risky.sarif[0]!.bytes));
    mutate(sarif);
    const bytes = bytesOf(sarif);
    const sha256 = await sha256Hex(bytes);
    const summary = summaryOf(
      bytesOf({ ...riskyObject(), sarif: [{ path: `sarif/${sha256}.sarif`, sha256 }] }),
    );
    return readFindings(summary, bytes, summary.scanKey);
  }
  const firstResult = (sarif: Record<string, unknown>) =>
    (
      (sarif.runs as Record<string, unknown>[])[0]!.results as Record<string, unknown>[]
    )[0]! as Record<string, any>;

  it.each([
    "../../etc/passwd",
    "/etc/passwd",
    "https://example.com/x",
    "C:/x",
    "not-in-summary.md",
  ])("refuses a SARIF location %s that leaves the scan's files", async (uri) => {
    const result = await pinned((sarif) => {
      firstResult(sarif).locations[0].physicalLocation.artifactLocation.uri = uri;
    });
    expect(result).toMatchObject({ status: "refused", reason: "findings-mismatch" });
  });

  it.each([
    "javascript:alert(1)",
    "data:text/html,x",
    "mailto:a@b",
  ])("refuses a URL-like location %s even when the summary lists it", async (uri) => {
    const sarif = JSON.parse(new TextDecoder().decode(risky.sarif[0]!.bytes));
    firstResult(sarif).locations[0].physicalLocation.artifactLocation.uri = uri;
    const bytes = bytesOf(sarif);
    const sha256 = await sha256Hex(bytes);
    const object = riskyObject();
    object.files = [...object.files, { ...object.files[0], path: uri }];
    object.sarif = [{ path: `sarif/${sha256}.sarif`, sha256 }];
    const summary = summaryOf(bytesOf(object));
    expect(summary.files.map((file) => file.path)).toContain(uri);
    expect(await readFindings(summary, bytes, summary.scanKey)).toMatchObject({
      status: "refused",
      reason: "findings-mismatch",
    });
  });

  it("removes control, bidirectional and zero-width characters and cuts text to the published limit", async () => {
    const result = await pinned((sarif) => {
      firstResult(sarif).message.text = `a\u0007b\u202Ec\u200Bd\n${"x".repeat(2000)}`;
      firstResult(sarif).ruleId = "rule\u2066id";
    });
    if (result.status !== "ok") throw new Error(JSON.stringify(result));
    const finding = result.findings.find((entry) => entry.path === "SKILL.md")!;
    expect(finding.text.startsWith("abcd")).toBe(true);
    expect([...finding.text]).toHaveLength(500);
    expect(finding.ruleId).toBe("ruleid");
  });

  it("returns unsupported-version for another SARIF version and invalid for malformed results", async () => {
    expect(
      (
        await pinned((sarif) => {
          sarif.version = "2.0.0";
        })
      ).status,
    ).toBe("unsupported-version");
    expect(
      (
        await pinned((sarif) => {
          firstResult(sarif).properties.code = "trust.known-vulnerability";
        })
      ).status,
    ).toBe("invalid");
    expect(
      (
        await pinned((sarif) => {
          firstResult(sarif).properties.scanKey = "git-sha1:".padEnd(49, "0");
        })
      ).status,
    ).toBe("refused");
  });
});

describe("portable matchScan", () => {
  it("requires the exact inventory, tree key and sha256 list; a raw summary or look-alike has no signer", async () => {
    const summary = summaryOf(risky.summary);
    const files = contentFiles(risky);
    expect(await matchScan(summary, files)).toMatchObject({
      status: "ok",
      matches: true,
      coverage: "partial",
      signer: null,
    });
    const verified = {
      status: "ok",
      verified: true,
      withdrawn: false,
      signer: { identity: "example-signer", trusted: true },
      summary,
    };
    // A hand-built look-alike of a verifySummary result cannot supply a signer.
    expect(await matchScan(verified, files)).toMatchObject({ matches: true, signer: null });
    expect(
      await matchScan({ status: "refused", summary: null, signer: null }, files),
    ).toMatchObject({ status: "refused" });
  });

  it("reports mode changes, extra, missing and changed files as no match", async () => {
    const summary = summaryOf(risky.summary);
    const files = contentFiles(risky);
    const mode = files.map((file) =>
      file.path === "scripts/start.sh" ? { ...file, mode: "100644" as const } : file,
    );
    expect(await matchScan(summary, mode)).toMatchObject({
      status: "ok",
      matches: false,
      differences: { modeChanged: ["scripts/start.sh"] },
    });
    expect(
      await matchScan(summary, [
        ...files,
        { path: "extra.md", mode: "100644", bytes: new Uint8Array() },
      ]),
    ).toMatchObject({
      matches: false,
      differences: { extra: ["extra.md"] },
    });
    expect(await matchScan(summary, files.slice(1))).toMatchObject({
      matches: false,
      differences: { missing: ["SKILL.md"] },
    });
    const changed = files.map((file) =>
      file.path === "SKILL.md" ? { ...file, bytes: encoder.encode("# changed\n") } : file,
    );
    expect(await matchScan(summary, changed)).toMatchObject({
      matches: false,
      differences: { changed: ["SKILL.md"] },
    });
  });

  it("refuses a summary whose key matches but whose sha256 list or modes do not (collision or tampering)", async () => {
    const document = riskyObject();
    document.files[0].sha256 = "0".repeat(64);
    const tampered = summaryOf(bytesOf(document));
    expect(await matchScan(tampered, contentFiles(risky))).toMatchObject({
      status: "refused",
      reason: "collision-or-tampering",
    });
    const modes = riskyObject();
    modes.files[2].mode = "100644";
    expect(await matchScan(summaryOf(bytesOf(modes)), contentFiles(risky))).toMatchObject({
      status: "refused",
      reason: "collision-or-tampering",
    });
  });

  it("returns results for malformed file records", async () => {
    const summary = summaryOf(risky.summary);
    expect(
      (await matchScan(summary, [{ path: "../x", mode: "100644", bytes: new Uint8Array() }]))
        .status,
    ).toBe("refused");
    expect(
      (await matchScan(summary, [{ path: "x", mode: "120000" as never, bytes: new Uint8Array() }]))
        .status,
    ).toBe("invalid");
    expect(
      (await matchScan(summary, [{ path: "x", mode: "100644", bytes: "x" as never }])).status,
    ).toBe("invalid");
    expect((await matchScan(summary, "nope" as never)).status).toBe("invalid");
    expect((await matchScan({} as never, [])).status).toBe("invalid");
  });
});
