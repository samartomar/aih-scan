import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

const lockSha256 = "3ba2452805078f18493e0d856127b99339b4aa61603b593886a8ba070758e2d3";
const wheelSha256 = "d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837";
const fixtureBytes = "# Demo\n\nNeutral fixture.\n";
const fixtureSha256 = "0e3b428e3a31f70f929c5bcbf43892519e4b4c5466a12f75e99128c496b0d64d";
const coverageSha256 = "5d83c254e1aa62c5a86809df6967b42eb5219f0f3c99ee42e884d5840382124e";
const roots: string[] = [];
const sha256 = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const digest = (seed: string) => sha256(`dual-run-red:${seed}`);
const raw = (value: string) => `raw-occurrence-v1:${value}`;
const path = "skills/demo/SKILL.md";

type ExpectedRow = {
  readonly detectorClass: "cisco";
  readonly nativeRuleId: string;
  readonly path: typeof path;
  readonly fileSha256: typeof fixtureSha256;
  readonly level: "error" | "note" | "warning";
  readonly message: string;
  readonly locations: readonly {
    readonly physicalLocation: {
      readonly artifactLocation: { readonly uri: typeof path };
      readonly region: { readonly startLine: number };
    };
  }[];
  readonly canonicalOrdinal: number;
  readonly multiplicity: 1;
  readonly rawOccurrenceFingerprint: string;
};

const expectedNeutralTable: readonly ExpectedRow[] = [
  {
    detectorClass: "cisco",
    nativeRuleId: "prompt-injection",
    path,
    fileSha256: fixtureSha256,
    level: "error",
    message: "untrusted instruction",
    locations: [
      { physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 3 } } },
    ],
    canonicalOrdinal: 0,
    multiplicity: 1,
    rawOccurrenceFingerprint: raw(
      "d268d2dbe48037534b1e1391e5eb4786717d3380c190e3ab17ad187126a2e7fe",
    ),
  },
  {
    detectorClass: "cisco",
    nativeRuleId: "prompt-injection",
    path,
    fileSha256: fixtureSha256,
    level: "error",
    message: "untrusted instruction",
    locations: [
      { physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 3 } } },
    ],
    canonicalOrdinal: 1,
    multiplicity: 1,
    rawOccurrenceFingerprint: raw(
      "57c7b5fbd787984625503b4b608538819d18db8b3649df1a1bd3fbd6c9919d10",
    ),
  },
  {
    detectorClass: "cisco",
    nativeRuleId: "prompt-injection",
    path,
    fileSha256: fixtureSha256,
    level: "error",
    message: "different diagnostic",
    locations: [
      { physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 4 } } },
      { physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 5 } } },
    ],
    canonicalOrdinal: 2,
    multiplicity: 1,
    rawOccurrenceFingerprint: raw(
      "4823ca889d6ba4c25478443a55a1be9953250a9301a0da918ba2ca3d06db2565",
    ),
  },
  {
    detectorClass: "cisco",
    nativeRuleId: "future-rule",
    path,
    fileSha256: fixtureSha256,
    level: "note",
    message: "unknown remains raw",
    locations: [
      { physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 5 } } },
    ],
    canonicalOrdinal: 0,
    multiplicity: 1,
    rawOccurrenceFingerprint: raw(
      "048a30ff65d86b980e227804a58dc50bfc6cd1f89bdad8df754b5ec6b186232f",
    ),
  },
  {
    detectorClass: "cisco",
    nativeRuleId: "skill-metadata-license",
    path,
    fileSha256: fixtureSha256,
    level: "warning",
    message: "license metadata missing",
    locations: [
      { physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 1 } } },
    ],
    canonicalOrdinal: 0,
    multiplicity: 1,
    rawOccurrenceFingerprint: raw(
      "34f875ffa9cf941d3e5ab227f89b6854e9ad889e5a77641870a403d10f61d817",
    ),
  },
];
const expectedFacts = expectedNeutralTable.map(
  ({ level: _level, message: _message, locations: _locations, ...fact }) => fact,
);
const expectedAnnexBytes = Buffer.from(
  JSON.stringify(
    expectedNeutralTable.map(
      ({
        canonicalOrdinal: _canonicalOrdinal,
        multiplicity: _multiplicity,
        rawOccurrenceFingerprint: _rawOccurrenceFingerprint,
        ...detail
      }) => detail,
    ),
  ),
);
const expectedCoverage = [{ coverageKind: "selected-closure", coverageSha256 }];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixtureRoot(prefix: string, bytes = fixtureBytes): string {
  const sourceRoot = mkdtempSync(join(tmpdir(), prefix));
  roots.push(sourceRoot);
  const directory = join(sourceRoot, "skills", "demo");
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "SKILL.md"), bytes, "utf8");
  return sourceRoot;
}

function location(startLine: number) {
  return {
    physicalLocation: {
      artifactLocation: { uri: path, uriBaseId: "%SRCROOT%" },
      region: { startLine },
    },
  };
}

type ReportKind = "full" | "dropped-duplicate" | "unknown-loss" | "zero" | "drift";
function results(kind: ReportKind) {
  const values = [
    {
      ruleId: "skill-metadata-license",
      level: "warning",
      message: { text: "license metadata missing" },
      properties: { category: "metadata", severity: "medium" },
      fingerprints: { primaryLocationLineHash: "license" },
      locations: [location(1)],
    },
    {
      ruleId: "prompt-injection",
      level: "error",
      message: { text: "untrusted instruction" },
      properties: { category: "prompt", severity: "high" },
      fingerprints: { primaryLocationLineHash: "prompt-duplicate-a" },
      locations: [location(3)],
    },
    {
      ruleId: "prompt-injection",
      level: "error",
      message: { text: "untrusted instruction" },
      properties: { category: "prompt", severity: "high" },
      fingerprints: { primaryLocationLineHash: "prompt-duplicate-b" },
      locations: [location(3)],
    },
    {
      ruleId: "prompt-injection",
      level: kind === "drift" ? "warning" : "error",
      message: { text: kind === "drift" ? "changed diagnostic" : "different diagnostic" },
      properties: { category: "prompt", severity: "high" },
      fingerprints: { primaryLocationLineHash: "prompt-variant" },
      locations: kind === "drift" ? [location(99)] : [location(4), location(5)],
    },
    {
      ruleId: "future-rule",
      level: "note",
      message: { text: "unknown remains raw" },
      properties: { category: "future", severity: "info" },
      fingerprints: { primaryLocationLineHash: "future" },
      locations: [location(5)],
    },
  ];
  if (kind === "zero") return [];
  if (kind === "unknown-loss") return values.filter((value) => value.ruleId !== "future-rule");
  if (kind === "dropped-duplicate") return values.filter((_, index) => index !== 2);
  return values;
}

function reportBytes(kind: ReportKind, timestamp: string, reverse: boolean): Buffer {
  const produced = results(kind).map((value) => structuredClone(value));
  if (reverse) produced.reverse();
  return Buffer.from(
    JSON.stringify({
      runs: [
        {
          invocations: [{ endTimeUtc: timestamp, executionSuccessful: true }],
          results: produced,
          tool: {
            driver: {
              informationUri: "https://github.com/cisco-ai-defense/skill-scanner",
              name: "skill-scanner",
              rules: [],
              version: "1.0.0",
            },
          },
        },
      ],
      version: "2.1.0",
      $schema:
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    }),
  );
}

function layout() {
  const manifestDigestSha256 = `sha256:${digest("manifest")}`;
  const configDigestSha256 = `sha256:${digest("config")}`;
  return parseCiscoOciLayoutV1(
    Buffer.from(
      JSON.stringify({
        protocol: "CiscoOciLayoutV1",
        manifestDigestSha256,
        configDigestSha256,
        logicalReference: `local.invalid/aih-scan/cisco@${manifestDigestSha256}`,
        manifestPlatform: { architecture: "amd64", os: "linux" },
        manifestDescriptor: {
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: manifestDigestSha256,
          size: 1,
          platform: { architecture: "amd64", os: "linux" },
          annotations: { "org.opencontainers.image.ref.name": "candidate" },
        },
      }),
    ),
  );
}

async function produce(
  directKind: ReportKind = "full",
  ociKind: ReportKind = "full",
  directBytes = fixtureBytes,
  ociBytes = fixtureBytes,
) {
  const directRoot = fixtureRoot("aih-scan-dual-direct-", directBytes);
  const ociRoot = fixtureRoot("aih-scan-dual-oci-", ociBytes);
  const ociLayout = layout();
  let directInvocation = 0;
  const direct = await probeCiscoLinuxAmd64V1({
    protocol: "CiscoLinuxAmd64ProbeV1",
    sourceRoot: directRoot,
    selectedClosurePaths: [path],
    runtimeProjectRoot: directRoot,
    platform: { os: "linux", architecture: "amd64" },
    runtime: {
      packageName: "cisco-ai-skill-scanner",
      version: "2.0.13",
      uvVersion: "0.12.5",
      lockSha256,
      wheelSha256,
    },
    environment: { AIH_SCAN_CISCO_LINUX_AMD64_PROBE: "1" },
    host: { os: "linux", architecture: "amd64" },
    runner: async (argv: readonly string[]) => {
      const output = argv.at(-1);
      if (output === undefined) throw new Error("direct SARIF output path missing");
      directInvocation += 1;
      writeFileSync(
        output,
        reportBytes(
          directKind,
          directInvocation === 1 ? "2026-08-17T12:34:56Z" : "2026-08-17T12:34:57Z",
          directInvocation === 2,
        ),
      );
      return { code: 0, stdout: "", stderr: "" };
    },
  });
  const oci = await executeCiscoOciBrokerV1({
    protocol: "CiscoOciBrokerV1",
    layout: ociLayout,
    sourceRoot: ociRoot,
    selectedClosurePaths: [path],
    host: { os: "linux", architecture: "amd64" },
    runner: async (argv: readonly string[]) => {
      if (argv[1] === "image") return { code: 0, stdout: ociLayout.configDigestSha256, stderr: "" };
      if (argv[1] === "container" && argv[2] === "rm") return { code: 0, stdout: "", stderr: "" };
      if (argv[1] === "container" && argv[2] === "inspect")
        return { code: 1, stdout: "", stderr: "no container" };
      const mount = argv.find(
        (value) => value.startsWith("type=bind,src=") && value.endsWith(",dst=/output,rw"),
      );
      if (mount === undefined) throw new Error("OCI output mount missing");
      const outputRoot = mount.slice("type=bind,src=".length, -",dst=/output,rw".length);
      writeFileSync(
        join(outputRoot, "result.sarif"),
        reportBytes(ociKind, "2026-08-17T12:35:56Z", true),
      );
      return { code: 0, stdout: "", stderr: "" };
    },
  });
  return { directRoot, ociRoot, direct, oci };
}

function expectNeutral(record: {
  readonly facts: unknown;
  readonly coverage: unknown;
  readonly annexBytes: Buffer;
  readonly evidenceAnnex: { readonly descriptors: readonly unknown[] };
}) {
  expect(record.facts).toEqual(expectedFacts);
  expect(record.coverage).toEqual(expectedCoverage);
  expect(record.annexBytes).toEqual(expectedAnnexBytes);
  expect(record.evidenceAnnex.descriptors).toEqual([
    {
      descriptorId: "annex.cisco-raw",
      mediaType: "application/json",
      sha256: sha256(expectedAnnexBytes),
      byteLength: expectedAnnexBytes.byteLength,
      uri: "annex/cisco-raw.json",
    },
  ]);
}

describe("Cisco direct/OCI dual-run equivalence V1", () => {
  it("compares distinct real producers against the independent neutral tuple table", async () => {
    const value = await produce();
    const executions = value.direct.executions as readonly {
      readonly facts: unknown;
      readonly coverage: unknown;
      readonly annexBytes: Buffer;
      readonly evidenceAnnex: { readonly descriptors: readonly unknown[] };
    }[];
    expect(value.directRoot).not.toBe(value.ociRoot);
    expect(value.direct.sourceSeal).toEqual(value.oci.sourceSeal);
    expect(executions).toHaveLength(2);
    for (const execution of executions) expectNeutral(execution);
    expectNeutral(value.oci);
    expect(executions[0]?.annexBytes).not.toBe(executions[1]?.annexBytes);
    expect(executions[0]?.annexBytes).not.toBe(value.oci.annexBytes);
    expect(executions[0]?.facts).not.toBe(value.oci.facts);
    const result = compareCiscoDualRunV1({
      protocol: "CiscoDualRunEquivalenceV1",
      directRoot: value.directRoot,
      ociRoot: value.ociRoot,
      direct: value.direct,
      oci: value.oci,
    });
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
    expect(createCiscoDualRunDigestV1(result)).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(result)).not.toMatch(
      /authority|policy|verdict|acceptance|acknowledg|qualified|trusted|signature/i,
    );
  });

  it("fails closed for producer drift, root overlap, and substitutions of actual outputs", async () => {
    for (const value of [
      await produce("full", "dropped-duplicate"),
      await produce("full", "unknown-loss"),
      await produce("full", "zero"),
      await produce("full", "drift"),
      await produce("full", "full", fixtureBytes, "# Demo\n\nChanged fixture.\n"),
    ])
      expect(() =>
        compareCiscoDualRunV1({
          protocol: "CiscoDualRunEquivalenceV1",
          directRoot: value.directRoot,
          ociRoot: value.ociRoot,
          direct: value.direct,
          oci: value.oci,
        }),
      ).toThrow();

    const base = await produce();
    const ordinal = structuredClone(base.oci);
    ordinal.facts[0].canonicalOrdinal = 99;
    const multiplicity = structuredClone(base.oci);
    multiplicity.facts[0].multiplicity = 2;
    const coverage = structuredClone(base.oci);
    coverage.coverage[0].coverageSha256 = digest("forged-coverage");
    const descriptor = structuredClone(base.oci);
    descriptor.evidenceAnnex.descriptors[0].sha256 = digest("forged-descriptor");
    const annex = structuredClone(base.oci);
    annex.annexBytes = Buffer.from("forged annex bytes");
    for (const oci of [ordinal, multiplicity, coverage, descriptor, annex])
      expect(() =>
        compareCiscoDualRunV1({
          protocol: "CiscoDualRunEquivalenceV1",
          directRoot: base.directRoot,
          ociRoot: base.ociRoot,
          direct: base.direct,
          oci,
        }),
      ).toThrow();
    for (const roots of [
      { directRoot: base.directRoot, ociRoot: base.directRoot },
      { directRoot: base.directRoot, ociRoot: join(base.directRoot, "skills") },
    ])
      expect(() =>
        compareCiscoDualRunV1({
          protocol: "CiscoDualRunEquivalenceV1",
          ...roots,
          direct: base.direct,
          oci: base.oci,
        }),
      ).toThrow();
  });
});
