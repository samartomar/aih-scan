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
const runBody = (text: string, name: string): string => {
  const body = /^ {8}run: \|\n((?:^ {10}.*(?:\n|$))*)/m.exec(step(text, name))?.[1];
  if (body === undefined) throw new Error(`workflow run body missing: ${name}`);
  return body.replace(/^ {10}/gm, "").trimEnd();
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

  it("keeps the named OCI build as one exact contiguous local export command", () => {
    const build = runBody(workflow(), "Build OCI layout and local image");
    const expected = [
      "docker buildx build \\",
      "  --platform linux/amd64 \\",
      "  --pull \\",
      "  --provenance=false \\",
      "  --sbom=false \\",
      "  --tag local.invalid/aih-scan/cisco \\",
      '  --metadata-file "$RUNNER_TEMP/oci-equivalence/build-metadata.json" \\',
      '  --output "type=oci,oci-mediatypes=true,dest=$RUNNER_TEMP/oci-equivalence/candidate-oci.tar" \\',
      '  --output "type=docker,dest=$RUNNER_TEMP/oci-equivalence/candidate-image.tar" \\',
      "  tools/cisco-oci-candidate",
    ].join("\n");
    expect(build).toContain(expected);
    expect(build.match(/^docker buildx build \\$/gm)).toHaveLength(1);
    expect(build.split("\n").filter((line) => line.trimStart().startsWith("--output "))).toEqual([
      '  --output "type=oci,oci-mediatypes=true,dest=$RUNNER_TEMP/oci-equivalence/candidate-oci.tar" \\',
      '  --output "type=docker,dest=$RUNNER_TEMP/oci-equivalence/candidate-image.tar" \\',
    ]);
    expect(build).not.toMatch(/#|--(?:export|load|push)|docker\s+build(?!x build)/);
  });

  it("uses exact local identity handoff, a pure verifier, an env-gated live test, and always cleanup", () => {
    const text = workflow();
    const verify = runBody(text, "Verify OCI layout and local image identity");
    const execute = runBody(text, "Compare isolated direct and OCI observations");
    const cleanup = runBody(text, "Clean up OCI equivalence resources");
    expect(verify).toContain(
      'docker load --input "$RUNNER_TEMP/oci-equivalence/candidate-image.tar"',
    );
    expect(verify).toContain(
      "docker image inspect --format '{{.Id}}' local.invalid/aih-scan/cisco > \"$RUNNER_TEMP/oci-equivalence/config-id.txt\"",
    );
    expect(verify).toContain(
      [
        "node tools/verify-cisco-oci-candidate.mjs \\",
        '  --metadata "$RUNNER_TEMP/oci-equivalence/build-metadata.json" \\',
        '  --layout "$RUNNER_TEMP/oci-equivalence/candidate-oci.tar" \\',
        '  --image-id "$RUNNER_TEMP/oci-equivalence/config-id.txt" \\',
        '  --summary "$RUNNER_TEMP/oci-equivalence/oci-equivalence-digest-summary.json"',
      ].join("\n"),
    );
    expect(verify).not.toMatch(/docker\s+(?:build|pull|push|run)|curl\b|fetch\b|https?:/i);
    expect(execute).toContain("AIH_SCAN_CISCO_OCI_EQUIVALENCE=1");
    expect(execute).toContain("AIH_SCAN_CISCO_OCI_CONFIG_DIGEST=");
    expect(execute).toContain("npm test -- --run tests/cisco/oci-equivalence-live.test.ts");
    expect(step(text, "Clean up OCI equivalence resources")).toContain("if: $" + "{{ always() }}");
    expect(cleanup).toContain("docker buildx rm --force aih-scan-cisco-oci-equivalence");
    expect(cleanup).toContain("docker image rm --force local.invalid/aih-scan/cisco");
    expect(cleanup).toContain(
      'rm -f "$RUNNER_TEMP/oci-equivalence/candidate-oci.tar" "$RUNNER_TEMP/oci-equivalence/candidate-image.tar"',
    );
  });

  it("uses isolated temporary direct/OCI roots and uploads only short-lived sanitized digest summaries", () => {
    const text = workflow();
    const upload = step(text, "Upload OCI equivalence digest summary");
    expect(text).toMatch(/RUNNER_TEMP[^\n]*(?:direct|oci)/i);
    expect(text).toMatch(/if:\s*\$\{\{ always\(\) \}\}/);
    expect(text).toMatch(/retention-days:\s*[1-7]/);
    expect(text).toMatch(/digest-summary/i);
    expect(text).toMatch(/if-no-files-found:\s*error/);
    expect(text).not.toMatch(
      /sarif|archive|(?:stdout|stderr)-log|docker\.sock|env:.*(?:TOKEN|PASSWORD|SECRET)/i,
    );
    expect(text).not.toMatch(/qualif|trusted|verified|pass|verdict|acceptance|acknowledgement/i);
    expect(upload).toMatch(
      /path:\s*\$\{\{ runner\.temp \}\}\/oci-equivalence\/oci-equivalence-digest-summary\.json/,
    );
    expect(upload).not.toMatch(/[|*]/);
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
    expect(text.match(/^ {6}- name: Check out /gm) ?? []).toHaveLength(2);
    expect(text.match(/persist-credentials: false/g) ?? []).toHaveLength(2);
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
