import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const workflowPath = resolve(root, ".github", "workflows", "cisco-oci-equivalence.yml");
const verifierPath = resolve(root, "tools", "verify-cisco-oci-candidate.mjs");
const workflow = () => readFileSync(workflowPath, "utf8");
const verifier = () => readFileSync(verifierPath, "utf8");
const step = (text: string, name: string): string => {
  const match = new RegExp(
    `^      - name: ${name}\\s*\\n([\\s\\S]*?)(?=^      - name:|(?![\\s\\S]))`,
    "m",
  ).exec(text);
  if (match === null) throw new Error(`workflow step missing: ${name}`);
  return match[0];
};

const buildxSha256 = "f1332ddb9010bd0b72628266c3a906d9a6979848033df4c8d9bd2cd113bae12b";
const buildkit =
  "moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f";
const allowedActions = new Set([
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
  "astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
]);

describe("Cisco OCI direct/OCI equivalence workflow", () => {
  it("is PR/manual-only, least-privileged, and pins every action plus Buildx/BuildKit", () => {
    const text = workflow();
    expect(text).toMatch(/^on:\n {2}pull_request:\n {2}workflow_dispatch:\s*$/m);
    expect(text).not.toMatch(
      /pull_request_target|schedule:|workflow_run|repository_dispatch|push:/,
    );
    expect(text.match(/^permissions:/gm) ?? []).toHaveLength(1);
    expect(text).toMatch(/^permissions:\n {2}contents: read\s*$/m);
    expect(text).not.toMatch(/^\s+permissions:/gm);
    const uses = [...text.matchAll(/^\s+uses:\s+([^\s#]+)/gm)].map((match) => match[1]);
    expect(uses).not.toHaveLength(0);
    for (const action of uses) {
      expect(action).toMatch(/@[0-9a-f]{40}$/);
      expect(allowedActions.has(action ?? "")).toBe(true);
    }
    expect(text).toContain("buildx-v0.34.1.linux-amd64");
    expect(text).toContain(buildxSha256);
    expect(text).toContain(buildkit);
    expect(text).not.toMatch(/^- name:/m);
  });

  it("performs one Linux amd64 local-only build, verifies its two identities, and executes only the config ID", () => {
    const text = workflow();
    const build = step(text, "Build OCI layout and local image");
    const verify = step(text, "Verify OCI layout and local image identity");
    const execute = step(text, "Compare isolated direct and OCI observations");
    expect(build.match(/docker buildx build/g)).toHaveLength(1);
    expect(build).toContain("--platform linux/amd64");
    expect(build).toContain("--provenance=false");
    expect(build).toContain("--sbom=false");
    expect(build).toMatch(/type=oci,[^\n]*oci-mediatypes=true[^\n]*dest=\$RUNNER_TEMP\//);
    expect(build).toMatch(/type=docker,dest=\$RUNNER_TEMP\//);
    expect(build).toContain("local.invalid/aih-scan/cisco");
    expect(verify).toMatch(/docker load[^\n]*\$RUNNER_TEMP/);
    expect(verify).toContain("verify-cisco-oci-candidate.mjs");
    expect(verify).toMatch(/docker image inspect[^\n]*\{\{\.Id\}\}/);
    expect(execute).toMatch(/configDigestSha256|config-id/i);
    expect(text).not.toMatch(
      /--push|docker login|registry|cache-(?:from|to)|:latest|sign(?:ing)?|provenance=true|sbom=true/i,
    );
  });

  it("uses isolated temporary direct/OCI roots and uploads only short-lived sanitized digest summaries", () => {
    const text = workflow();
    expect(text).toMatch(/RUNNER_TEMP[^\n]*(?:direct|oci)/i);
    expect(text).toMatch(/if:\s*\$\{\{ always\(\) \}\}/);
    expect(text).toMatch(/retention-days:\s*[1-7]/);
    expect(text).toMatch(/digest-summary/i);
    expect(text).toMatch(/if-no-files-found:\s*error/);
    expect(text).not.toMatch(
      /sarif|archive|(?:stdout|stderr)-log|docker\.sock|env:.*(?:TOKEN|PASSWORD|SECRET)/i,
    );
    expect(text).not.toMatch(/qualif|trusted|verified|pass|verdict|acceptance|acknowledgement/i);
  });

  it("binds credential-free checkouts and contains execution in named steps", () => {
    const text = workflow();
    const scan = step(text, "Check out aih-scan");
    const aih = step(text, "Check out public ai-harness");
    const execute = step(text, "Compare isolated direct and OCI observations");
    expect(scan).toContain("persist-credentials: false");
    expect(aih).toContain("persist-credentials: false");
    expect(aih).toContain("ref: c0b4931d1f5435f10dc5d2bc57480f9275ed3eff");
    expect(aih).toContain("path: .candidate-sources/ai-harness");
    expect(execute).toMatch(/RUNNER_TEMP[^\n]*(?:direct|oci)/i);
    expect(execute).toContain("dual-run-equivalence");
  });

  it("keeps the verifier statically bounded and fail-closed", () => {
    const text = verifier();
    expect(text).toContain("CiscoOciLayoutV1");
    expect(text).toContain("local.invalid/aih-scan/cisco@sha256:");
    expect(text).toMatch(/manifest.*config/i);
    expect(text).toMatch(/process\.exitCode\s*=\s*1|throw new TypeError/);
    expect(text).not.toMatch(
      /child_process|exec\b|spawn\b|shell:\s*true|fetch\b|https?\.request|docker\s+build|registry/i,
    );
    expect(text).toMatch(/digest-summary|summarySha256/i);
  });
});
