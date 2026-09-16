import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  baselinePublicationTag,
  verifyCompletedPublication,
} from "../../tools/verify-baseline-publication-reuse.mjs";

const requestSha256 = "a".repeat(64);
const publisherSha = "b".repeat(40);
const repository = "samartomar/aih-scan";
const tag = `baseline-v1-${publisherSha}-${requestSha256}`;
const now = "2026-09-07T12:00:00Z";

type CommandResult = { status: number; stdout: string; stderr: string };
type Runner = (command: string, args: readonly string[]) => CommandResult;
type Fixture = {
  root: string;
  release: { directory: string; inspection: string };
  reuseDirectory: string;
};

function hash(bytes: string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function releaseDirectory(
  root: string,
  reportSignedAt: string,
  locator = `https://github.com/${repository}/releases/download/${tag}/publication.json`,
): { directory: string; inspection: string } {
  const directory = join(root, "release");
  mkdirSync(directory);
  const files = {
    "publication.json": JSON.stringify({
      envelope: {
        payload: Buffer.from(
          JSON.stringify({
            predicate: {
              claims: {
                signedAt: reportSignedAt,
                expiresAt: new Date(Date.parse(reportSignedAt) + 3600000).toISOString(),
              },
            },
          }),
        ).toString("base64"),
      },
    }),
    "discovery.json": `${JSON.stringify({ locator })}\n`,
    "inspection.json": '{"inspection":true}\n',
  };
  for (const [name, content] of Object.entries(files))
    writeFileSync(join(directory, name), content, "utf8");
  const checksums = [
    `${hash(files["publication.json"])}  publication.json`,
    `${hash(files["discovery.json"])}  discovery.json`,
    `${hash(files["inspection.json"])}  inspection.json`,
  ].join("\n");
  writeFileSync(join(directory, "SHA256SUMS"), `${checksums}\n`, "utf8");
  return { directory, inspection: files["inspection.json"] };
}

function releaseMetadata(
  assetNames = ["publication.json", "discovery.json", "inspection.json", "SHA256SUMS"],
  releaseTag = tag,
): string {
  return JSON.stringify({
    tag_name: releaseTag,
    target_commitish: publisherSha,
    draft: false,
    assets: assetNames.map((name) => ({ name })),
  });
}

function fixture(
  reportSignedAt = now,
  locator = `https://github.com/${repository}/releases/download/${tag}/publication.json`,
): Fixture {
  const root = mkdtempSync(join(tmpdir(), "aih-baseline-publication-reuse-"));
  const release = releaseDirectory(root, reportSignedAt, locator);
  const reuseDirectory = join(root, "reused");
  mkdirSync(reuseDirectory);
  return { root, release, reuseDirectory };
}

function verify(current: Fixture, run: Runner, generation = "initial"): boolean {
  return verifyCompletedPublication({
    repository,
    publisherSha,
    sourceRef: "refs/heads/main",
    workflow: `${repository}/.github/workflows/baseline-publication.yml`,
    scanner: resolve(current.root, "scanner.mjs"),
    gh: "gh",
    reuseDirectory: current.reuseDirectory,
    request: {
      name: "batch-001.request.json",
      path: join(current.root, "request.json"),
      requestSha256,
    },
    now,
    generation,
    run,
  });
}

function completeRunner(
  release: { directory: string; inspection: string },
  inspection: string,
  calls: string[],
  releaseTag = tag,
  attestedAt = now,
): Runner {
  return (command, args) => {
    calls.push(`${command} ${args.join(" ")}`);
    if (args[0] === "api")
      return { status: 0, stdout: releaseMetadata(undefined, releaseTag), stderr: "" };
    if (args[0] === "release" && args[1] === "download") {
      const destination = args[args.indexOf("--dir") + 1];
      if (typeof destination !== "string") throw new Error("release download directory missing");
      cpSync(release.directory, destination, { recursive: true });
      return { status: 0, stdout: "", stderr: "" };
    }
    if (args[0] === "attestation" && args[1] === "verify")
      return {
        status: 0,
        stdout: JSON.stringify([
          {
            verificationResult: {
              verifiedTimestamps: [
                { type: "tlog", uri: "https://rekor.sigstore.dev", timestamp: attestedAt },
              ],
            },
          },
        ]),
        stderr: "",
      };
    if (command === process.execPath) return { status: 0, stdout: inspection, stderr: "" };
    throw new Error(`unexpected command: ${command} ${args.join(" ")}`);
  };
}

describe("baseline publication reuse verifier", () => {
  it("requires new analyzer work for a missing renewal even when the initial publication exists", () => {
    const current = fixture();
    const lookedUp: string[] = [];
    const complete = completeRunner(current.release, current.release.inspection, []);
    const run: Runner = (command, args) => {
      if (args[0] === "api" && args[1]?.includes("-r20261207")) {
        lookedUp.push(args[1]);
        return { status: 1, stdout: "", stderr: "HTTP 404: Not Found" };
      }
      return complete(command, args);
    };
    try {
      expect(verify(current, run, "20261207")).toBe(false);
      expect(lookedUp).toHaveLength(2);
      expect(verify(current, run)).toBe(true);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
  it("keeps renewals independently addressed and rejects unsafe generation identifiers", () => {
    expect(baselinePublicationTag(publisherSha, requestSha256)).toBe(tag);
    expect(baselinePublicationTag(publisherSha, requestSha256, "20260907")).toBe(
      `${tag}-r20260907`,
    );
    for (const generation of ["latest", "../other", "$(echo bad)", "202609071"])
      expect(() => baselinePublicationTag(publisherSha, requestSha256, generation)).toThrow();
  });
  it("rejects a complete renewal when discovery binds its publication to another generation", () => {
    const generation = "20261207";
    const renewalTag = baselinePublicationTag(publisherSha, requestSha256, generation);
    const current = fixture(
      now,
      `https://github.com/${repository}/releases/download/${tag}-r20261208/publication.json`,
    );
    try {
      expect(() =>
        verify(
          current,
          completeRunner(current.release, current.release.inspection, [], renewalTag),
          generation,
        ),
      ).toThrow("discovery locator");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
  it("reuses a completed renewal only when its discovery locator has the exact opaque generation tag", () => {
    const generation = "20261207";
    const renewalTag = baselinePublicationTag(publisherSha, requestSha256, generation);
    const current = fixture(
      now,
      `https://github.com/${repository}/releases/download/${renewalTag}/publication.json`,
    );
    try {
      expect(
        verify(
          current,
          completeRunner(current.release, current.release.inspection, [], renewalTag),
          generation,
        ),
      ).toBe(true);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
  it.each([
    8, 89, 90,
  ])("uses original report signing date for the 90-day lifetime (%s days)", (days) => {
    const signedAt = new Date(Date.parse(now) - days * 86400000).toISOString();
    const attestedAt = new Date(Date.parse(signedAt) + 60000).toISOString();
    const current = fixture(signedAt);
    try {
      const reuse = () =>
        verify(
          current,
          completeRunner(current.release, current.release.inspection, [], tag, attestedAt),
        );
      if (days < 90) expect(reuse()).toBe(true);
      else expect(reuse).toThrow(/report freshness/);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
  it.each([
    3600000, 3600001,
  ])("rejects attestation at or after the signed report expiry (%s ms)", (delay) => {
    const current = fixture(new Date(Date.parse(now) - delay).toISOString());
    try {
      expect(() =>
        verify(current, completeRunner(current.release, current.release.inspection, [])),
      ).toThrow(/report.*window/);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
  it("rejects a draft release before downloading its assets", () => {
    const current = fixture();
    try {
      expect(() =>
        verify(current, (_command, args) => {
          if (args[0] !== "api") throw new Error("must not download a draft release");
          return {
            status: 0,
            stdout: JSON.stringify({ ...JSON.parse(releaseMetadata()), draft: true }),
            stderr: "",
          };
        }),
      ).toThrow("release metadata");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
  it.each([
    "",
    "[]",
    '{"verificationResult":{}}',
    JSON.stringify([
      {
        verificationResult: {
          verifiedTimestamps: [
            { type: "tlog", uri: "https://rekor.sigstore.dev", timestamp: "2026-09-08T12:00:00Z" },
          ],
        },
      },
    ]),
  ])("fails closed on missing or future verified timestamps (%s)", (stdout) => {
    const current = fixture();
    const complete = completeRunner(current.release, current.release.inspection, []);
    try {
      expect(() =>
        verify(current, (command, args) =>
          args[0] === "attestation" ? { status: 0, stdout, stderr: "" } : complete(command, args),
        ),
      ).toThrow(/attestation/);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  it("rejects an expired immutable publication instead of reporting reuse or retrying its tag", () => {
    const current = fixture();
    const complete = completeRunner(current.release, current.release.inspection, []);
    const run: Runner = (command, args) =>
      args[0] === "attestation"
        ? {
            status: 0,
            stdout: JSON.stringify([
              {
                verificationResult: {
                  verifiedTimestamps: [
                    {
                      type: "tlog",
                      uri: "https://rekor.sigstore.dev",
                      timestamp: "2026-06-09T12:00:00Z",
                    },
                  ],
                },
              },
            ]),
            stderr: "",
          }
        : complete(command, args);
    try {
      expect(() => verify(current, run)).toThrow("expired immutable publication");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
  it("treats only a missing release and missing tag as pending work", () => {
    const current = fixture();
    const run: Runner = (_command, args) => {
      expect(args[0]).toBe("api");
      return { status: 1, stdout: "", stderr: "HTTP 404: Not Found" };
    };
    try {
      expect(verify(current, run)).toBe(false);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  it("fails closed for a release lookup error other than an explicit 404", () => {
    const current = fixture();
    const run: Runner = () => ({ status: 1, stdout: "", stderr: "request timeout" });
    try {
      expect(() => verify(current, run)).toThrow("release lookup");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  it("rejects an incomplete release closure before downloading or inspecting it", () => {
    const current = fixture();
    const run: Runner = (_command, args) => {
      if (args[0] === "api")
        return { status: 0, stdout: releaseMetadata(["publication.json"]), stderr: "" };
      throw new Error("release download must not run");
    };
    try {
      expect(() => verify(current, run)).toThrow("release metadata");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  it("rejects a replaced inspection receipt even when release filenames and hashes match", () => {
    const current = fixture();
    const calls: string[] = [];
    try {
      expect(() =>
        verify(current, completeRunner(current.release, '{"replaced":true}\n', calls)),
      ).toThrow("independent inspection");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  it("reuses only a complete exact publisher-and-request release and verifies its attestation", () => {
    const current = fixture();
    const calls: string[] = [];
    try {
      expect(
        verify(current, completeRunner(current.release, current.release.inspection, calls)),
      ).toBe(true);
      expect(calls.join("\n")).toContain(`--source-digest ${publisherSha}`);
      expect(calls.join("\n")).toContain(`--request-sha256 ${requestSha256}`);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });
});
