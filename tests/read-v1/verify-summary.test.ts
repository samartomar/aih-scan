import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { describe, expect, it } from "vitest";
import {
  defaultSigners,
  sigstoreTrustedRootText,
  verification,
} from "../../src/public/contracts.js";
import { matchScan, verifySummary } from "../../src/public/read.js";
import { corpusCase } from "../support/scan-v1-corpus.js";
import { buildVectors, loadVectors, vectorsPath } from "../support/sigstore-v1-vectors.js";

if (process.env.AIH_SCAN_UPDATE_SIGSTORE_VECTORS === "1") {
  mkdirSync(dirname(vectorsPath), { recursive: true });
  writeFileSync(vectorsPath, `${JSON.stringify(buildVectors())}\n`);
}
const vectors = loadVectors();
const bytes = (value: string) => new Uint8Array(Buffer.from(value, "base64"));

async function run(name: string) {
  const entry = vectors.cases.find((candidate) => candidate.name === name);
  if (entry === undefined) throw new Error(name);
  const root =
    entry.root === "shipped"
      ? undefined
      : entry.root === "none"
        ? null
        : (vectors.roots[entry.root] as never);
  return verifySummary(
    bytes(entry.summary),
    entry.bundleBytes === undefined ? (entry.bundle as never) : bytes(entry.bundleBytes),
    entry.signers as never,
    {
      ...(root === undefined ? {} : { trustedRoot: root }),
      withdrawn: (entry.withdrawn ?? []).map((w) => bytes(w.bytes)),
      withdrawnBundle: (entry.withdrawn ?? []).map((w) => w.bundle as never),
    },
  );
}

describe("verifySummary (aih-sigstore-keyless/1) over the shared fixture set", () => {
  for (const entry of vectors.cases)
    it(entry.name, async () => {
      const result = await run(entry.name);
      expect(result.status, JSON.stringify(result)).toBe(entry.expect.status);
      if (entry.expect.reason !== undefined)
        expect((result as { reason?: string }).reason).toBe(entry.expect.reason);
      if (result.status !== "ok") {
        expect(result.verified).toBe(false);
        expect(result.signer).toBeNull();
        expect(result.summary).toBeNull();
        return;
      }
      expect(result.verified).toBe(true);
      expect(result.signer.trusted).toBe(entry.expect.trusted);
      expect(result.withdrawn).toBe(entry.expect.withdrawn);
      expect(result.signer.identity).toBe(entry.expect.identity);
    });

  it("returns a promise and never throws on hostile input", async () => {
    const pending = verifySummary(new Uint8Array(), null as never);
    expect(pending).toBeInstanceOf(Promise);
    expect((await pending).status).toBe("invalid");
    for (const bundle of [undefined, 1, "x", [], { mediaType: 5 }])
      expect(
        (await verifySummary(bytes(vectors.cases[0]!.summary), bundle as never)).verified,
      ).toBe(false);
    expect(
      (
        await verifySummary(
          bytes(vectors.cases[0]!.summary),
          vectors.cases[0]!.bundle as never,
          "x" as never,
        )
      ).status,
    ).toBe("invalid");
  });

  it("reports withdrawal outcomes and keeps signatures separate from usability", async () => {
    const later = await run("later-revision-stays-valid");
    expect(later.status === "ok" && later.withdrawals).toEqual([
      { status: "not-applicable", reason: "later-revision", throughRevision: 3 },
    ]);
    const other = await run("withdrawal-by-other-signer-ignored");
    expect(other.status === "ok" && other.withdrawals[0]?.reason).toBe("other-signer");
    const tampered = await run("tampered-withdrawal-ignored");
    expect(tampered.status === "ok" && tampered.withdrawals[0]).toEqual({
      status: "refused",
      reason: "invalid-signature",
    });
    const withdrawn = await run("withdrawn-at-boundary-revision");
    expect(withdrawn.status === "ok" && withdrawn.verified && withdrawn.withdrawn).toBe(true);
  });

  it("supplies matchScan's signer only from verified results", async () => {
    const content = corpusCase("clean").content;
    const files = Object.entries(content).map(([path, file]) => ({
      path,
      mode: file.mode,
      bytes: new TextEncoder().encode(file.text),
    }));
    const trusted = await matchScan((await run("valid-rekor-v1-set")) as never, files);
    expect(trusted).toMatchObject({
      status: "ok",
      matches: true,
      signer: { identity: "TEST-ONLY signer A", trusted: true },
    });
    const withdrawn = await matchScan(
      (await run("withdrawn-at-boundary-revision")) as never,
      files,
    );
    expect(withdrawn).toMatchObject({
      status: "ok",
      signer: { identity: "TEST-ONLY signer A", trusted: false },
    });
    const failed = await matchScan((await run("tampered-summary-bytes")) as never, files);
    expect(failed).toMatchObject({ status: "refused", reason: "not-verified" });
    const raw = JSON.parse(Buffer.from(vectors.cases[0]!.summary, "base64").toString("utf8"));
    expect((await matchScan(raw, files)) as object).toMatchObject({ signer: null });
    // A hand-made "verified" object cannot be produced by readSummary; it is the caller's own claim.
  });

  it("ships the pinned public trust snapshot with its provenance and digest", () => {
    const sha256 = createHash("sha256").update(sigstoreTrustedRootText, "utf8").digest("hex");
    expect(sha256).toBe(verification.trustSnapshot.sha256);
    expect(sha256).toBe("6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66");
    expect(Buffer.byteLength(sigstoreTrustedRootText)).toBe(verification.trustSnapshot.length);
    expect(verification.trustSnapshot.source).toBe("https://tuf-repo-cdn.sigstore.dev");
    expect(verification.profile).toBe("aih-sigstore-keyless/1");
  });

  it("defaults to the documented publishing identity tuple", () => {
    expect(defaultSigners).toEqual([
      expect.objectContaining({
        identity: "aihq-scan-production",
        issuer: "https://token.actions.githubusercontent.com",
        subject:
          "https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main",
      }),
    ]);
    expect(defaultSigners[0]?.extensions?.["1.3.6.1.4.1.57264.1.15"]).toBe("1336836161");
    expect(defaultSigners[0]?.extensions?.["1.3.6.1.4.1.57264.1.17"]).toBe("9993940");
  });
});
