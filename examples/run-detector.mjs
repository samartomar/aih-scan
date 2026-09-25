#!/usr/bin/env node
/**
 * Runs a detector through the public `runDetectorV1` entry point without the caller
 * writing any execution code.
 *
 * It does two things on every platform:
 *
 * 1. asks for `detector.cisco` in a way that is guaranteed to be refused before anything
 *    is spawned, and prints the typed reason. Off Linux amd64 the platform gate answers;
 *    on Linux amd64 the example asks for the OCI capture profile without supplying the
 *    capture material, so it never launches a real detector on any host;
 * 2. runs `detector.aih-native` for real against a throwaway fixture. That analyzer
 *    hashes the sealed snapshot inside this process and spawns nothing, so it is honest
 *    to run it anywhere.
 *
 * Usage: node examples/run-detector.mjs [--source-root <directory> --select <path>...]
 * With no arguments it creates, uses and removes its own temporary fixture.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadScan } from "./load-scan.mjs";

const { scan, from } = await loadScan();
process.stdout.write(`loaded ${from}\n`);

function parseArguments(argv) {
  const parsed = { sourceRoot: undefined, selected: [] };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--source-root") {
      parsed.sourceRoot = argv[index + 1];
      index += 1;
    } else if (argv[index] === "--select") {
      const value = argv[index + 1];
      if (value !== undefined) parsed.selected.push(value);
      index += 1;
    } else {
      process.stderr.write(
        "usage: node examples/run-detector.mjs [--source-root <directory> --select <path>...]\n",
      );
      process.exit(2);
    }
  }
  return parsed;
}

const args = parseArguments(process.argv.slice(2));
let fixtureRoot;
if (args.sourceRoot === undefined) {
  fixtureRoot = mkdtempSync(join(tmpdir(), "aih-scan-example-"));
  // A genuine skill directory: the marker is at the top level, declared, never discovered.
  writeFileSync(join(fixtureRoot, "README.md"), "# Example subject\n", "utf8");
  writeFileSync(join(fixtureRoot, "SKILL.md"), "# Demo skill\n", "utf8");
  args.sourceRoot = fixtureRoot;
  args.selected = ["README.md", "SKILL.md"];
}
if (args.selected.length === 0) {
  process.stderr.write("refused: --source-root needs at least one --select <path>\n");
  process.exit(2);
}

try {
  process.stdout.write(
    `${JSON.stringify(
      {
        detectors: scan.listDetectorCapabilitiesV1().map((capability) => ({
          detectorId: capability.detectorId,
          backend: capability.backend,
          defaultProfile: capability.executionProfile.id,
          isolation: capability.executionProfile.isolation,
          supportedPlatforms: capability.supportedPlatforms.map(
            (platform) => `${platform.os}/${platform.architecture}`,
          ),
        })),
      },
      null,
      2,
    )}\n`,
  );

  // 1. A hardened detector, asked for in a way that always refuses before any spawn.
  const hostRunsHardenedProfiles = process.platform === "linux" && process.arch === "x64";
  const hardened = await scan.runDetectorV1({
    detectorId: "detector.cisco",
    subject: {
      kind: "skill-directory",
      sourceRoot: args.sourceRoot,
      selectedClosurePaths: args.selected,
    },
    // On a host that could really run it, ask for the profile whose capture material
    // this example deliberately does not supply, so no container is ever started.
    ...(hostRunsHardenedProfiles ? { executionProfileId: "oci-hardened-cisco-v1" } : {}),
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        requested: "detector.cisco",
        hostRunsHardenedProfiles,
        outcome: hardened.outcome,
        ...(hardened.outcome === "refused"
          ? { reason: hardened.reason, detail: hardened.detail, host: hardened.host }
          : { profile: hardened.executionProfile?.id }),
      },
      null,
      2,
    )}\n`,
  );

  // 2. The in-process analyzer, which really runs here and spawns nothing.
  const native = await scan.runDetectorV1({
    detectorId: "detector.aih-native",
    subject: {
      kind: "source-tree",
      sourceRoot: args.sourceRoot,
      selectedClosurePaths: args.selected,
    },
  });
  if (native.outcome !== "succeeded") {
    process.stderr.write(
      `detector.aih-native did not run: ${JSON.stringify(native, null, 2)}\n`,
    );
    process.exit(2);
  }
  process.stdout.write(
    `${JSON.stringify(
      {
        requested: "detector.aih-native",
        outcome: native.outcome,
        executionProfile: native.executionProfile,
        seams: native.seams,
        coverage: native.coverage,
        evidence: {
          kind: native.evidence.kind,
          analyzer: native.evidence.observation.analyzer,
          analyzerVersion: native.evidence.observation.analyzerVersion,
          annex: native.evidence.observation.annex,
        },
        findings: {
          source: native.findings.source,
          count: native.findings.findings.length,
          gaps: native.findings.gaps.map((gap) => gap.kind),
        },
        sourceUnchanged:
          native.sourceSeal.before.sealedSnapshotSha256 ===
          native.sourceSeal.after.sealedSnapshotSha256,
        authority: "none",
        limitation:
          "An empty findings list is not a claim that nothing was found: the gaps say why the list is empty. Scanner evidence approves nothing.",
      },
      null,
      2,
    )}\n`,
  );
} finally {
  if (fixtureRoot !== undefined) rmSync(fixtureRoot, { recursive: true, force: true });
}
