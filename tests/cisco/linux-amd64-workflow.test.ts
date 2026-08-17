import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const workflowPath = resolve(root, ".github", "workflows", "cisco-linux-amd64-probe.yml");
const readWorkflow = () => readFileSync(workflowPath, "utf8");

describe("Cisco Linux amd64 observation probe workflow", () => {
  it("keeps the candidate-evidence workflow pinned, read-only, and explicitly non-authoritative", () => {
    expect(existsSync(workflowPath)).toBe(true);
    const workflow = readWorkflow();

    expect(workflow).toMatch(/^on:\s*[\s\S]*?pull_request:/m);
    expect(workflow).toMatch(/^on:\s*[\s\S]*?workflow_dispatch:/m);
    expect(workflow).not.toMatch(/^\s*push:/m);
    expect(workflow).toMatch(/^permissions:\s*\n\s+contents:\s*read\s*$/m);
    expect(workflow).toMatch(/runs-on:\s*ubuntu-latest/);
    expect(workflow).toMatch(/timeout-minutes:\s*(?:1[0-9]|[1-9])/);
    expect(workflow).toContain("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1");
    expect(workflow).toContain("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97");
    expect(workflow).toContain("astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d");
    expect(workflow).toContain("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
    expect(workflow).toMatch(/persist-credentials:\s*false/);
    expect(workflow).toMatch(/repository:\s*samartomar\/ai-harness/);
    expect(workflow).toMatch(/ref:\s*c0b4931d1f5435f10dc5d2bc57480f9275ed3eff/);
    expect(workflow).toMatch(/path:\s*\.qualification-sources\/ai-harness/);
    expect(workflow).toMatch(/python-version:\s*["']?3\.12["']?/);
    expect(workflow).toMatch(/version:\s*["']?0\.12\.5["']?/);
    expect(workflow).toContain("ec52cc1cb4f7375a32ad56d3157820fe5aaf8cd9ba806e411c1bf9eb2f63bf41");
    expect(workflow).toContain("3ba2452805078f18493e0d856127b99339b4aa61603b593886a8ba070758e2d3");
    expect(workflow).toContain("d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837");
    expect(workflow).toMatch(/uv run --project .*--locked --isolated --python 3\.12/);
    expect(workflow).toMatch(/--offline --no-python-downloads --no-env-file/);
    expect(workflow).toContain("AIH_SCAN_CISCO_LINUX_AMD64_PROBE=1");
    expect(workflow).toMatch(/if:\s*\$\{\{\s*always\(\)\s*\}\}/);
    expect(workflow).toMatch(/retention-days:\s*[1-9]/);
    expect(workflow).toMatch(/sanitized-(?:sarif|observation)/);
    expect(workflow).not.toMatch(
      /docker|podman|registry|cosign|signer|signature|qualified|verified|verdict|acceptance|acknowledgement/i,
    );
  });
});
