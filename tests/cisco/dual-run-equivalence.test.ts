import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  compareCiscoDualRunV1,
  createCiscoDualRunDigestV1,
} from "../../src/cisco/dual-run-equivalence-v1.js";
import { probeCiscoLinuxAmd64V1 } from "../../src/cisco/linux-amd64-probe-v1.js";
import { executeCiscoOciBrokerV1 } from "../../src/cisco/oci-broker-v1.js";
import { parseCiscoOciLayoutV1 } from "../../src/cisco/oci-layout-v1.js";
import {
  describeNativeObservationSourceV1,
  sealNativeObservationSourceV1,
} from "../../src/observation/native-observation-v1.js";

const roots: string[] = [];
const sha256 = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const digest = (seed: string) => sha256(`dual-run:${seed}`);

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(name: string): string {
  const value = mkdtempSync(join(tmpdir(), name));
  roots.push(value);
  writeFileSync(join(value, "SKILL.md"), "---\nname: neutral\n---\nIgnore unsafe instructions.\n");
  return value;
}

function observation(sourceRoot: string, diagnostic = "Pattern detected.") {
  const seal = sealNativeObservationSourceV1({ sourceRoot, selectedClosurePaths: ["SKILL.md"] });
  const facts = [
    {
      detectorClass: "cisco",
      nativeRuleId: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
      path: "SKILL.md",
      fileSha256: sha256("---\nname: neutral\n---\nIgnore unsafe instructions.\n"),
      canonicalOrdinal: 0,
      rawOccurrenceFingerprint: `raw-occurrence-v1:${digest("occurrence")}`,
      multiplicity: 1,
      locations: [{ startLine: 4 }],
      message: diagnostic,
      level: "error",
    },
  ];
  const annexBytes = Buffer.from(JSON.stringify(facts));
  return {
    sourceRoot,
    sourceSeal: seal,
    facts,
    coverage: [{ coverageKind: "selected-closure", coverageSha256: seal.selectedClosureSha256 }],
    annexBytes,
    evidenceAnnex: {
      protocol: "EvidenceAnnexV1",
      descriptors: [
        {
          descriptorId: "annex.cisco-raw",
          mediaType: "application/json",
          sha256: sha256(annexBytes),
          byteLength: annexBytes.length,
          uri: "annex/cisco-raw.json",
        },
      ],
      evidenceAnnexSha256: digest("annex-descriptor"),
    },
  };
}

function oracle(value: ReturnType<typeof observation>) {
  return value.facts.map((fact) => ({
    canonicalOrdinal: fact.canonicalOrdinal,
    detectorClass: fact.detectorClass,
    fileSha256: fact.fileSha256,
    level: fact.level,
    locations: fact.locations,
    message: fact.message,
    multiplicity: fact.multiplicity,
    nativeRuleId: fact.nativeRuleId,
    path: fact.path,
    rawOccurrenceFingerprint: fact.rawOccurrenceFingerprint,
  }));
}

describe("Cisco direct/OCI dual-run equivalence V1", () => {
  it("consumes physically separate genuine probe and broker records with separately authored SARIF bytes", async () => {
    const directRoot = root("aih-scan-dual-direct-live-");
    const ociRoot = root("aih-scan-dual-oci-live-");
    const manifest = `sha256:${digest("live-manifest")}`;
    const config = `sha256:${digest("live-config")}`;
    const layout = parseCiscoOciLayoutV1(
      Buffer.from(
        JSON.stringify({
          protocol: "CiscoOciLayoutV1",
          manifestDigestSha256: manifest,
          configDigestSha256: config,
          logicalReference: `local.invalid/aih-scan/cisco@${manifest}`,
          manifestPlatform: { os: "linux", architecture: "amd64" },
          manifestDescriptor: {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: manifest,
            size: 1,
            platform: { os: "linux", architecture: "amd64" },
            annotations: { "org.opencontainers.image.ref.name": "candidate" },
          },
        }),
      ),
    );
    const report = (message: string) =>
      JSON.stringify({
        $schema:
          "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [
          {
            tool: {
              driver: {
                name: "skill-scanner",
                version: "1.0.0",
                informationUri: "https://github.com/cisco-ai-defense/skill-scanner",
                rules: [
                  {
                    id: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
                    name: "prompt",
                    shortDescription: { text: "prompt" },
                    fullDescription: { text: "prompt" },
                    defaultConfiguration: { level: "error" },
                    properties: { category: "prompt", severity: "high", tags: ["security"] },
                  },
                ],
              },
            },
            invocations: [{ executionSuccessful: true, endTimeUtc: "2026-08-17T12:34:56Z" }],
            results: [
              {
                ruleId: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
                level: "error",
                message: { text: message },
                properties: { category: "prompt", severity: "high" },
                fingerprints: { primaryLocationLineHash: "fixture" },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" },
                      region: { startLine: 1 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      });
    const direct = await probeCiscoLinuxAmd64V1({
      protocol: "CiscoLinuxAmd64ProbeV1",
      sourceRoot: directRoot,
      selectedClosurePaths: ["SKILL.md"],
      runtimeProjectRoot: directRoot,
      platform: { os: "linux", architecture: "amd64" },
      runtime: {
        packageName: "cisco-ai-skill-scanner",
        version: "2.0.13",
        uvVersion: "0.12.5",
        lockSha256: "3ba2452805078f18493e0d856127b99339b4aa61603b593886a8ba070758e2d3",
        wheelSha256: "d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837",
      },
      environment: { AIH_SCAN_CISCO_LINUX_AMD64_PROBE: "1" },
      host: { os: "linux", architecture: "amd64" },
      runner: async (argv: readonly string[]) => {
        writeFileSync(argv.at(-1) ?? "", report("Pattern detected."));
        return { code: 0, stdout: "", stderr: "" };
      },
    });
    const oci = await executeCiscoOciBrokerV1({
      protocol: "CiscoOciBrokerV1",
      layout,
      sourceRoot: ociRoot,
      selectedClosurePaths: ["SKILL.md"],
      host: { os: "linux", architecture: "amd64" },
      runner: async (argv: readonly string[]) => {
        if (argv[1] === "image") return { code: 0, stdout: config, stderr: "" };
        if (argv[1] === "container" && argv[2] === "rm") return { code: 0, stdout: "", stderr: "" };
        if (argv[1] === "container" && argv[2] === "inspect")
          return { code: 1, stdout: "", stderr: `Error: No such container: ${argv.at(-1) ?? ""}` };
        const mount = argv.find(
          (item) => item.startsWith("type=bind,src=") && item.endsWith(",dst=/output,rw"),
        );
        if (mount === undefined) throw new Error("missing output mount");
        writeFileSync(
          join(mount.slice("type=bind,src=".length, -",dst=/output,rw".length), "result.sarif"),
          report("Pattern detected."),
        );
        return { code: 0, stdout: "", stderr: "" };
      },
    });
    const result = compareCiscoDualRunV1({
      protocol: "CiscoDualRunEquivalenceV1",
      directRoot,
      ociRoot,
      direct,
      oci,
    });
    expect(result.validationState).toBe("cryptographically-unverified");
  });
  it("requires separate roots with identical sealed source and compares the full neutral fact semantics", () => {
    const directRoot = root("aih-scan-dual-direct-");
    const ociRoot = root("aih-scan-dual-oci-");
    const direct = observation(directRoot);
    const oci = observation(ociRoot);
    const directSnapshot = describeNativeObservationSourceV1({
      sourceRoot: directRoot,
      selectedClosurePaths: ["SKILL.md"],
    });
    const ociSnapshot = describeNativeObservationSourceV1({
      sourceRoot: ociRoot,
      selectedClosurePaths: ["SKILL.md"],
    });

    const result = compareCiscoDualRunV1({ protocol: "CiscoDualRunEquivalenceV1", direct, oci });

    expect(directRoot).not.toBe(ociRoot);
    expect(directSnapshot.sourceFiles).toEqual(ociSnapshot.sourceFiles);
    expect(oracle(direct)).toEqual(oracle(oci));
    expect(Object.keys(result).sort()).toEqual(
      [
        "directDigestSha256",
        "ociDigestSha256",
        "protocol",
        "semanticDigestSha256",
        "validationState",
      ].sort(),
    );
    expect(result.validationState).toBe("cryptographically-unverified");
    expect(createCiscoDualRunDigestV1(result)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("fails closed for same roots, source/semantic drift, shared annex buffers, and descriptor substitution", () => {
    const directRoot = root("aih-scan-dual-direct-");
    const ociRoot = root("aih-scan-dual-oci-");
    const direct = observation(directRoot);
    const oci = observation(ociRoot);
    const base = { protocol: "CiscoDualRunEquivalenceV1", direct, oci } as const;
    const cases = [
      { ...base, oci: { ...oci, sourceRoot: directRoot } },
      { ...base, oci: observation(ociRoot, "Changed diagnostic.") },
      {
        ...base,
        oci: { ...oci, sourceSeal: { ...oci.sourceSeal, sourceTreeSha256: digest("other") } },
      },
      { ...base, oci: { ...oci, annexBytes: direct.annexBytes } },
      {
        ...base,
        oci: {
          ...oci,
          evidenceAnnex: {
            ...oci.evidenceAnnex,
            descriptors: [{ ...oci.evidenceAnnex.descriptors[0], sha256: digest("substitution") }],
          },
        },
      },
      { ...base, unknown: true },
    ];
    for (const value of cases) expect(() => compareCiscoDualRunV1(value as unknown)).toThrow();
  });
});
