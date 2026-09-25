/**
 * Regression lock: Catalog's declared source revision is its assessment profile
 * artifact, and that digest is not, and cannot be, one of the source files a
 * capture seals.
 *
 * Context, recorded as a diagnostic record in
 * `tests/fixtures/cisco/catalog-assessment-seal-binding.json`:
 *
 * - the published `@aihq/catalog` index carries the current `aih-core` member
 *   `agent.aih.governance-quality.core-0-6-2`, whose `subject.source.revision` is
 *   the digest of the entry's own assessment artifact
 *   `.../artifacts/profile.json` (`893b4d0b…`), not a revision of upstream bytes;
 * - that same profile is the artifact that declares the source closure, so the
 *   closure's file list, digests and upstream git revision come from it;
 * - the genuine capture scanned the declared skill root and sealed exactly its
 *   three files, so its seal covers `LICENSE`, `SKILL.md` and `profile.json` and
 *   nothing else.
 *
 * The seal is not copied here: the test materializes the declared source bytes
 * and reproduces it with Scan's own `sealSourceV2`, so the relationship is
 * checked against a reproduced seal rather than against a recorded claim.
 *
 * This file records the relationship only. Binding the assessment identity to
 * the scanned material is a Core-owned proof, designed against
 * `verifySubjectContentBindingV1` and presented for approval in the
 * diagnostic binding-proof report preserved with the package-analysis transfer
 * (`evidence/binding-run/DIAGNOSTIC-BINDING-PROOF-2026-09-21.md`); no
 * binding rule is exported from Scan, here or in production.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { sealSourceV2 } from "../../src/observation/source-seal-v2.js";

type Descriptor = Readonly<{ path: string; sha256: string }>;
type ClosureFile = Readonly<{ byteLength: number; path: string; sha256: string }>;
type MaterialRoot =
  | Readonly<{ kind: "closure"; path: "."; files: readonly string[]; excludes: readonly string[] }>
  | Readonly<{
      kind: "skill";
      path: string;
      marker: "SKILL.md";
      files: readonly string[];
      excludes: readonly string[];
    }>;
type RecordedSeal = Readonly<{
  algorithm: "code-unit-canonical-json-v1";
  digests: Readonly<{
    sourceTreeSha256: string;
    selectedClosureSha256: string;
    sealedSnapshotSha256: string;
  }>;
  entries: readonly ClosureFile[];
  selectedClosurePaths: readonly string[];
  selectedFiles: readonly ClosureFile[];
}>;
type Fixture = Readonly<{
  authority: string;
  capture: Readonly<{
    candidateSha256: string;
    coverage: Readonly<{ kind: string; sha256: string; complete: boolean }>;
    scan: Readonly<{ outcome: string }>;
    sourceSeals: Readonly<{ before: RecordedSeal; after: RecordedSeal }>;
    subject: Readonly<{ digest: Readonly<{ sha256: string }>; name: string }>;
  }>;
  catalog: Readonly<{
    collectionsDigest: string;
    contentDigest: string;
    entry: Readonly<{
      artifacts: Readonly<{ profile: Descriptor }>;
      entryId: string;
      subject: Readonly<{
        id: string;
        kind: string;
        source: Readonly<Record<string, string>>;
        sourceDigest: string;
        subjectDigest: string;
      }>;
    }>;
    organizationAdmission: string;
    sourceClosure: Readonly<{
      assessment: Readonly<{ profile: Descriptor }>;
      collection: Readonly<{ id: string; release: string }>;
      declaredTreeDigest: string;
      files: readonly ClosureFile[];
      materialRoots: readonly MaterialRoot[];
      source: Readonly<{ host: string; repository: string; revision: string }>;
    }>;
    status: Readonly<{ structure: string; artifacts: string }>;
  }>;
  sources: Readonly<Record<string, string>>;
}>;

const fixture = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, "../fixtures/cisco/catalog-assessment-seal-binding.json"),
    "utf8",
  ),
) as Fixture;

const revision = fixture.catalog.entry.subject.source.revision;
if (revision === undefined) throw new Error("fixture carries no declared source revision");
const recordedSeal = fixture.capture.sourceSeals.before;
const skillRoot = fixture.catalog.sourceClosure.materialRoots.find((root) => root.kind === "skill");
if (skillRoot === undefined || skillRoot.kind !== "skill")
  throw new Error("fixture declares no skill root");
const bare = (value: string) => value.replace(/^sha256:/, "");
const declaredByPath = new Map(
  fixture.catalog.sourceClosure.files.map((file) => [file.path, file.sha256]),
);
const skillRootFiles = skillRoot.files.map((path) => path.slice(path.lastIndexOf("/") + 1));
const declaredFiles = new Map(fixture.catalog.sourceClosure.files.map((file) => [file.path, file]));
const skillRootDeclared = skillRoot.files.map((path) => {
  const file = declaredFiles.get(path);
  if (file === undefined) throw new Error(`fixture declares no source file ${path}`);
  return file;
});
const uncoveredDeclaredPaths = fixture.catalog.sourceClosure.files
  .filter((file) => !skillRoot.files.includes(file.path))
  .map((file) => file.path);

/** The declared source bytes, materialized so Scan reproduces the seal from them. */
const sourceRoot = mkdtempSync(join(tmpdir(), "aih-assessment-seal-"));
for (const [name, text] of Object.entries(fixture.sources))
  writeFileSync(join(sourceRoot, name), text, "utf8");
afterAll(() => {
  rmSync(sourceRoot, { force: true, recursive: true });
});

const reproduced = sealSourceV2({
  selectedClosurePaths: recordedSeal.selectedClosurePaths,
  sourceRoot,
});
const digestOf = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

describe("Catalog assessment and scan seal", () => {
  it("records a published-contract reading, not an authority", () => {
    expect(fixture.authority).toBe("diagnostic-record-not-evidence");
    expect(fixture.catalog.contentDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fixture.catalog.collectionsDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fixture.catalog.organizationAdmission).toBe("not-authoritative");
    expect(fixture.catalog.status).toEqual({ artifacts: "verified", structure: "valid" });
    expect(fixture.catalog.entry.entryId).toBe("agent.aih.governance-quality.core-0-6-2");
    expect(fixture.capture.scan.outcome).toBe("succeeded");
  });

  it("reproduces the genuine capture's seal from the declared source bytes", () => {
    for (const [name, text] of Object.entries(fixture.sources))
      expect(digestOf(text)).toBe(declaredByPath.get(`${skillRoot.path}/${name}`));
    expect(reproduced.entries).toEqual(recordedSeal.entries);
    expect(reproduced.selectedClosurePaths).toEqual(recordedSeal.selectedClosurePaths);
    expect(reproduced.selectedFiles).toEqual(recordedSeal.selectedFiles);
    expect(reproduced.sourceTreeSha256).toBe(recordedSeal.digests.sourceTreeSha256);
    expect(reproduced.selectedClosureSha256).toBe(recordedSeal.digests.selectedClosureSha256);
    expect(reproduced.sealedSnapshotSha256).toBe(recordedSeal.digests.sealedSnapshotSha256);
    expect(fixture.capture.sourceSeals.after).toEqual(recordedSeal);
    expect(fixture.capture.subject.digest.sha256).toBe(reproduced.sourceTreeSha256);
    expect(bare(fixture.capture.coverage.sha256)).toBe(reproduced.selectedClosureSha256);
  });

  it("binds the entry's declared source revision to its own assessment profile", () => {
    const profileArtifact = fixture.catalog.entry.artifacts.profile;
    expect(revision).toBe(`sha256:${profileArtifact.sha256}`);
    expect(fixture.catalog.sourceClosure.assessment.profile).toEqual(profileArtifact);
    expect(fixture.catalog.entry.subject.source.release).toBe(
      fixture.catalog.sourceClosure.collection.release,
    );
    expect(fixture.catalog.entry.subject.source.type).toBe("aih");
    expect(profileArtifact.path).toContain(
      `${fixture.catalog.entry.entryId}/artifacts/profile.json`,
    );
  });

  it("reproduces the suspected refusal: the declared revision is not a scanned file", () => {
    const declared = fixture.catalog.sourceClosure.files.map((file) => file.sha256);
    const sealed = reproduced.selectedFiles.map((file) => file.sha256);
    expect(declared).not.toContain(bare(revision));
    expect(sealed).not.toContain(bare(revision));
    expect(declared).not.toContain(fixture.catalog.sourceClosure.source.revision);
    expect(sealed).toEqual([
      declaredByPath.get(`${skillRoot.path}/LICENSE`),
      declaredByPath.get(`${skillRoot.path}/SKILL.md`),
      declaredByPath.get(`${skillRoot.path}/profile.json`),
    ]);
    /** The rule this regression exists to keep refused: coverage by the declared revision. */
    const coversDeclaredRevision = (seal: readonly ClosureFile[]) =>
      seal.some((file) => file.sha256 === bare(revision));
    expect(coversDeclaredRevision(reproduced.selectedFiles)).toBe(false);
  });

  it("holds the digest-equal join that does exist: the sealed files are the skill root's", () => {
    expect(reproduced.selectedClosurePaths).toEqual(["LICENSE", "SKILL.md", "profile.json"]);
    expect(skillRootFiles).toEqual(reproduced.selectedClosurePaths);
    for (const declared of skillRootDeclared)
      expect(reproduced.selectedFiles.some((file) => file.sha256 === declared.sha256)).toBe(true);
    expect(skillRoot.excludes).toEqual(["aih-packs.json"]);
    expect(uncoveredDeclaredPaths).toEqual(["aih-packs.json"]);
    expect(declaredByPath.get("aih-packs.json")).toBe(
      "bc21b9787fb8cfb589085a4f7fb4308a73d30fa9adfa7aa67636efc6ffdce950",
    );
    expect(reproduced.selectedClosurePaths).not.toContain("aih-packs.json");
  });

  it("carries no digest join between the entry identity and the seal", () => {
    const sealedSubject = `sha256:${reproduced.sourceTreeSha256}`;
    expect(sealedSubject).not.toBe(fixture.catalog.entry.subject.subjectDigest);
    expect(sealedSubject).not.toBe(fixture.catalog.entry.subject.sourceDigest);
    expect(fixture.catalog.entry.subject.subjectDigest).not.toBe(
      fixture.catalog.entry.subject.sourceDigest,
    );
    expect(bare(fixture.catalog.sourceClosure.declaredTreeDigest)).not.toBe(
      reproduced.selectedClosureSha256,
    );
    expect(bare(fixture.catalog.sourceClosure.declaredTreeDigest)).not.toBe(
      reproduced.sourceTreeSha256,
    );
  });
});
