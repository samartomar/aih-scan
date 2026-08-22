import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const digest = (value) => createHash("sha256").update(value).digest("hex");
const ensureOutput = (value) => {
  if (typeof value !== "string" || !value) throw new TypeError("output path required");
  return resolve(value);
};
const [mode, output, candidatePath] = process.argv.slice(2);
if (mode === "capture") {
  const destination = ensureOutput(output);
  const fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-disposable-chain-"));
  writeFileSync(join(fixtureRoot, "SKILL.md"), "# disposable scanner chain fixture\n", { mode: 0o600 });
  const { canonicalScanCandidateBytesV2, createScanCandidateV2, sealSourceV2 } = await import("../dist/index.js");
  const seal = sealSourceV2({ sourceRoot: fixtureRoot, selectedClosurePaths: ["SKILL.md"] });
  const zero = "0".repeat(64);
  const candidate = createScanCandidateV2({
    protocol: "ScanCandidateV2",
    coreContract: { commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7", decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff" },
    subject: { name: "source-tree", digest: { sha256: seal.sourceTreeSha256 } },
    sourceSeals: { before: seal, after: seal },
    observation: { keySha256: zero, setSha256: zero },
    scanner: { manifestSha256: zero, runtimeSha256: zero, configurationSha256: zero },
    platform: { os: "linux", architecture: "amd64" },
    coverage: { kind: "selected-closure", sha256: seal.selectedClosureSha256, complete: true },
    annexes: [], cleanup: { outcome: "completed" }, scan: { outcome: "succeeded" },
  });
  writeFileSync(destination, canonicalScanCandidateBytesV2(candidate), { flag: "wx", mode: 0o600 });
} else if (mode === "prepare-sign") {
  const directory = ensureOutput(output);
  if (typeof candidatePath !== "string") throw new TypeError("candidate path required");
  const { ed25519KeyIdV2, parseScanCandidateV2Json } = await import("../dist/index.js");
  const candidate = parseScanCandidateV2Json((await import("node:fs")).readFileSync(resolve(candidatePath), "utf8"));
  const pair = generateKeyPairSync("ed25519");
  const keyId = ed25519KeyIdV2(pair.publicKey);
  const signedAt = new Date();
  const expiresAt = new Date(signedAt.getTime() + 60 * 60 * 1000);
  const claims = { repository: "samartomar/aih-scan", workflow: ".github/workflows/disposable-evidence-chain.yml", issuer: "https://token.actions.githubusercontent.com", sourceRef: "refs/heads/main", commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7", environment: "test", runId: "1", runAttempt: 1, signedAt: signedAt.toISOString(), expiresAt: expiresAt.toISOString() };
  const signer = { identity: "scanner.ci", class: "test-ephemeral", keyId };
  const expected = { ...claims, now: new Date(signedAt.getTime() + 30 * 60 * 1000).toISOString(), subjectSha256: candidate.subject.digest.sha256, signer };
  writeFileSync(join(directory, "signer.json"), JSON.stringify(signer), { flag: "wx", mode: 0o600 });
  writeFileSync(join(directory, "claims.json"), JSON.stringify(claims), { flag: "wx", mode: 0o600 });
  writeFileSync(join(directory, "private.pem"), pair.privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
  chmodSync(join(directory, "private.pem"), 0o600);
  writeFileSync(join(directory, "roots.json"), JSON.stringify({ roots: [{ ...signer, publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" })] }), { flag: "wx", mode: 0o600 });
  writeFileSync(join(directory, "expected.json"), JSON.stringify(expected), { flag: "wx", mode: 0o600 });
} else throw new TypeError("usage: disposable-chain-fixture.mjs capture <new-candidate> | prepare-sign <new-directory> <candidate>");
