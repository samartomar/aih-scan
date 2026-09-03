import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const workflowPath = resolve(
  import.meta.dirname,
  "..",
  "..",
  ".github",
  "workflows",
  "baseline-publication.yml",
);

describe("immutable baseline publication workflow", () => {
  it("is explicit, exact-input, content-addressed, and split at the privilege boundary", () => {
    const workflow = readFileSync(workflowPath, "utf8");

    expect(workflow).toMatch(/^on:\n {2}workflow_dispatch:/m);
    expect(workflow).not.toMatch(/^ {2}(push|pull_request|schedule):/m);
    expect(workflow).toMatch(/^permissions:\n {2}contents: read\s*$/m);
    expect(workflow).toContain("CORE_REF");
    expect(workflow).toContain("SOURCE_REF");
    expect(workflow).toContain('[[ "$CORE_REF" =~ ^[0-9a-f]{40}$ ]]');
    expect(workflow).toContain('[[ "$SOURCE_REF" =~ ^[0-9a-f]{40}$ ]]');
    expect(workflow).toContain('test "$CORE_REF" = "$(git -C .core rev-parse HEAD)"');
    expect(workflow).toContain('test "$SOURCE_REF" = "$(git -C .source rev-parse HEAD)"');
    expect(workflow).toContain("npm --prefix .core run baseline:request");
    expect(workflow).not.toContain('mkdir -p "$RUNNER_TEMP/baseline/requests"');
    expect(workflow).toContain('mkdir -p "$RUNNER_TEMP/baseline" "$RUNNER_TEMP/baseline/bundles"');
    expect(workflow).toContain("node dist/cli.js baseline-vet");
    expect(workflow).toContain("node dist/cli.js baseline-pack");
    expect(workflow).toContain("node dist/cli.js baseline-inspect");
    expect(workflow).toContain("baseline-v1-$request_sha256");
    expect(workflow).toContain("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
    expect(workflow).toContain(
      "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    );
    expect(workflow).toContain(
      "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
    );
    expect(workflow).toMatch(
      /publish:\n[\s\S]*?environment: baseline-evidence-publish\n[\s\S]*?permissions:\n {6}contents: write\n {6}id-token: write\n {6}attestations: write/,
    );
    expect(workflow).toContain('gh release view "$tag"');
    expect(workflow).toContain('gh release create "$tag"');
    expect(workflow).not.toContain("npm publish");
  });
});
