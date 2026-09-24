import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const workflow = readFileSync(
  resolve(import.meta.dirname, "..", "..", ".github", "workflows", "installed-semgrep-parity.yml"),
  "utf8",
);

describe("installed Semgrep parity workflow", () => {
  it("compares only candidates it is given, never a default Core", () => {
    expect(workflow).not.toMatch(/67ba9a24/);
    expect(workflow).not.toMatch(/default:\s*[0-9a-f]{40}/);
    for (const input of [
      "core_ref:",
      "core_tarball_url:",
      "core_tarball_sha256:",
      "scan_tarball_url:",
      "scan_tarball_sha256:",
    ])
      expect(workflow, input).toContain(input);
    // The parity job runs only when a Core candidate is named.
    expect(workflow).toMatch(
      /parity:[\s\S]*?if: github\.event_name == 'workflow_dispatch' && \(inputs\.core_ref != '' \|\| inputs\.core_tarball_url != ''\)/,
    );
    // A downloaded candidate must match the sha256 the dispatcher states.
    expect(workflow).toContain("does not match the stated sha256");
  });

  it("proves the host profile on Linux, Windows and macOS runners from the installed package", () => {
    expect(workflow).toMatch(/host-profile:[\s\S]*?os: \[ubuntu-latest, windows-latest, macos-latest\]/);
    expect(workflow).toContain("tools/installed-host-profile-proof.mjs");
    expect(workflow).toMatch(/python-version: "3\.12"/);
  });

  it("runs the parity comparison under the profile each host supports", () => {
    for (const row of [
      "{ os: ubuntu-latest, profile: linux-namespace-uv-v1 }",
      "{ os: ubuntu-latest, profile: host-process-uv-v1 }",
      "{ os: windows-latest, profile: host-process-uv-v1 }",
      "{ os: macos-latest, profile: host-process-uv-v1 }",
    ])
      expect(workflow, row).toContain(row);
    expect(workflow).toContain("--execution-profile");
  });

  it("dispatches nothing itself and writes nothing to the repository", () => {
    expect(workflow).toMatch(/permissions:\s*\n\s*contents: read/);
    expect(workflow).not.toMatch(/contents: write|id-token: write|gh workflow run|npm publish/);
  });
});
