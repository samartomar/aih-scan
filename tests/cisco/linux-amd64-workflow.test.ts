import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const workflowPath = resolve(root, ".github", "workflows", "cisco-linux-amd64-probe.yml");
const readWorkflow = () => readFileSync(workflowPath, "utf8");
const stepBlocks = (workflow: string) => workflow.split(/^\s*-\s+name:\s*/m).slice(1);
const blockContaining = (workflow: string, text: string) =>
  stepBlocks(workflow).find((step) => step.includes(text));

describe("Cisco Linux amd64 observation probe workflow", () => {
  it("keeps the candidate-evidence workflow pinned, read-only, and explicitly non-authoritative", () => {
    expect(existsSync(workflowPath)).toBe(true);
    const workflow = readWorkflow();

    expect(workflow.match(/^permissions:/gm)).toHaveLength(1);
    expect(workflow).not.toMatch(/^\s{2,}permissions:/gm);
    const triggerBlock = workflow.match(/^on:\s*\n([\s\S]*?)^permissions:/m)?.[1];
    expect(triggerBlock).toBeDefined();
    expect(
      [...(triggerBlock ?? "").matchAll(/^\s{2}([a-z_]+):\s*$/gm)].map((match) => match[1]),
    ).toEqual(["pull_request", "workflow_dispatch"]);
    expect(workflow).not.toMatch(
      /pull_request_target|schedule:|workflow_run:|push:|workflow_call:/,
    );
    const permissionsBlock = workflow.match(/^permissions:\s*\n([\s\S]*?)^jobs:/m)?.[1];
    expect(permissionsBlock?.trim()).toBe("contents: read");
    expect(workflow).toMatch(/runs-on:\s*ubuntu-latest/);
    expect(workflow).toMatch(/timeout-minutes:\s*(?:1[0-9]|[1-9])/);
    const uses = [...workflow.matchAll(/^\s*uses:\s*([^\s#]+)\s*(?:#.*)?$/gm)].map(
      (match) => match[1] ?? "",
    );
    expect(uses).toHaveLength(5);
    for (const action of uses) {
      expect(action).toMatch(
        /^(?:actions\/checkout|actions\/setup-python|astral-sh\/setup-uv|actions\/upload-artifact)@[a-f0-9]{40}$/,
      );
    }
    expect(uses.filter((action) => action.startsWith("actions/checkout@"))).toHaveLength(2);
    expect(uses).toContain("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1");
    expect(uses).toContain("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97");
    expect(uses).toContain("astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d");
    expect(uses).toContain("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
    const checkoutSteps = stepBlocks(workflow).filter((step) => step.includes("actions/checkout@"));
    expect(checkoutSteps).toHaveLength(2);
    for (const checkout of checkoutSteps) expect(checkout).toMatch(/persist-credentials:\s*false/);
    const aihCheckout = blockContaining(workflow, "repository: samartomar/ai-harness");
    expect(aihCheckout).toContain("ref: c0b4931d1f5435f10dc5d2bc57480f9275ed3eff");
    expect(aihCheckout).toContain("path: .candidate-sources/ai-harness");
    expect(aihCheckout).toMatch(/persist-credentials:\s*false/);
    expect(workflow).toMatch(/python-version:\s*["']?3\.12["']?/);
    expect(workflow).toMatch(/version:\s*["']?0\.12\.5["']?/);
    expect(workflow).toContain("ec52cc1cb4f7375a32ad56d3157820fe5aaf8cd9ba806e411c1bf9eb2f63bf41");
    expect(workflow).toContain("3ba2452805078f18493e0d856127b99339b4aa61603b593886a8ba070758e2d3");
    expect(workflow).toContain("d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837");
    const verification = blockContaining(workflow, "Verify exact runtime inputs");
    const warm = blockContaining(workflow, "Warm exact Cisco runtime");
    const live = blockContaining(workflow, "Capture Linux observation evidence");
    expect(verification).toMatch(/curl .*--output .*\.whl/);
    expect(verification).toMatch(/cisco[-_]ai[-_]skill[-_]scanner.*2\.0\.13/i);
    expect(verification).toMatch(/sha256sum -c\s+[^\s]+/);
    expect(verification).toMatch(
      /ec52cc1cb4f7375a32ad56d3157820fe5aaf8cd9ba806e411c1bf9eb2f63bf41.*pyproject\.toml/i,
    );
    expect(verification).toMatch(
      /3ba2452805078f18493e0d856127b99339b4aa61603b593886a8ba070758e2d3.*uv\.lock/i,
    );
    expect(verification).toMatch(
      /d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837.*\.whl/i,
    );
    expect(warm).toMatch(/uv sync --project .*--locked --isolated --python 3\.12/);
    expect(warm).not.toMatch(/--offline/);
    expect(warm).not.toMatch(/--no-env-file/);
    expect(warm).not.toMatch(/skill-scanner\s+(?:--version|scan)/);
    expect(warm).toMatch(/UV_CACHE_DIR=.*aih-scan-cisco-uv-cache/);
    expect(warm).toMatch(/UV_CONFIG_FILE=.*aih-scan-cisco-empty-uv\.toml/);
    expect(live).toMatch(/AIH_SCAN_CISCO_LINUX_AMD64_PROBE=1/);
    expect(live).toMatch(/UV_OFFLINE=1/);
    expect(live).toMatch(/AIH_SCAN_CISCO_RUNTIME_PROJECT=/);
    expect(live).toMatch(/AIH_SCAN_CISCO_CHILD_PATH=/);
    expect(live).toMatch(/AIH_SCAN_CISCO_CHILD_HOME=/);
    expect(live).toMatch(/AIH_SCAN_CISCO_CHILD_UV_CACHE_DIR=/);
    expect(live).toMatch(/npm test -- --run tests\/cisco\/linux-amd64-probe\.test\.ts/);
    expect(workflow.indexOf(verification ?? "")).toBeLessThan(workflow.indexOf(warm ?? ""));
    expect(workflow.indexOf(warm ?? "")).toBeLessThan(workflow.indexOf(live ?? ""));
    const upload = blockContaining(workflow, "actions/upload-artifact@");
    expect(upload).toMatch(/if:\s*\$\{\{\s*always\(\)\s*\}\}/);
    expect(upload).toMatch(/retention-days:\s*[1-9]/);
    expect(upload).toContain(
      "$" + "{{ runner.temp }}/aih-scan-cisco-artifacts/sanitized-sarif-*.json",
    );
    expect(upload).toContain(
      "$" + "{{ runner.temp }}/aih-scan-cisco-artifacts/sanitized-observation-summary.json",
    );
    expect(upload).not.toMatch(/raw|workspace|\*\*/i);
    expect(workflow).not.toMatch(
      /docker|podman|registry|cosign|signer|signature|qualif|qualified|verified|verdict|acceptance|acknowledgement/i,
    );
  });
});
