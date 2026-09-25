import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const workflowPath = resolve(root, ".github", "workflows", "cisco-linux-amd64-probe.yml");
const readWorkflow = () => readFileSync(workflowPath, "utf8");
const uvWheelUrl =
  "https://files.pythonhosted.org/packages/93/22/dacc9a0bc8604187a1ba954a3aef8329e4104eb0af772d2c3c634893bd9b/uv-0.12.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
const uvWheelSha256 = "3e195ccf1ed60c8bb24a6447ce306441a4181d54b602407e09bc56e963911c15";
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
    expect(uses).toHaveLength(3);
    for (const action of uses) {
      expect(action).toMatch(
        /^(?:actions\/checkout|actions\/setup-python|actions\/upload-artifact)@[a-f0-9]{40}$/,
      );
    }
    expect(uses.filter((action) => action.startsWith("actions/checkout@"))).toHaveLength(1);
    expect(uses).toContain("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1");
    expect(uses).toContain("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97");
    expect(uses.some((action) => action.startsWith("astral-sh/setup-uv@"))).toBe(false);
    expect(uses).toContain("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
    const checkoutSteps = stepBlocks(workflow).filter((step) => step.includes("actions/checkout@"));
    expect(checkoutSteps).toHaveLength(1);
    for (const checkout of checkoutSteps) expect(checkout).toMatch(/persist-credentials:\s*false/);
    expect(workflow).not.toMatch(/repository: samartomar\/ai-harness|candidate-sources/);
    expect(workflow).toContain('runtime="tools/baseline-analyzers/cisco-skill-scanner"');
    expect(workflow).toMatch(/python-version:\s*["']?3\.12["']?/);
    const installUv = blockContaining(workflow, "Install exact uv 0.12.5");
    expect(installUv).toContain(uvWheelUrl);
    expect(installUv).toContain(uvWheelSha256);
    expect(installUv).toMatch(/curl .*--fail .*--location .*--silent .*--show-error .*--output/);
    expect(installUv).toMatch(/sha256sum -c/);
    expect(installUv).toMatch(/python -m pip install --no-deps/);
    expect(installUv).toContain(
      'test "$(python -c "from importlib.metadata import version; print(version(\'uv\'))")" = "0.12.5"',
    );
    expect(installUv).toContain("python -m uv --version >/dev/null");
    expect(workflow).not.toMatch(/astral-sh\/setup-uv|versions-manifest/i);
    expect(workflow).toContain("35de8ad9e2d243fb418f8dbeba2f55c4a430495fe1c7163a21809f0ea3999ead");
    expect(workflow).toContain("1e98c5679994dc56f82c1d88a77528d4c4b076160aff85b4d97ce239360bc210");
    expect(workflow).toContain("c84292b720bf0eddc8913fe3017dcdb05bd7e98eb19f6ee61dee2c4eb9fa901e");
    const verification = blockContaining(workflow, "Verify exact runtime inputs");
    const warm = blockContaining(workflow, "Warm exact Cisco runtime");
    const live = blockContaining(workflow, "Capture Linux observation evidence");
    expect(verification).toMatch(/curl .*--output .*\.whl/);
    expect(verification).toMatch(/cisco[-_]ai[-_]skill[-_]scanner.*2\.1\.0/i);
    expect(verification).toMatch(/sha256sum -c\s+[^\s]+/);
    expect(verification).toMatch(
      /35de8ad9e2d243fb418f8dbeba2f55c4a430495fe1c7163a21809f0ea3999ead.*pyproject\.toml/i,
    );
    expect(verification).toMatch(
      /1e98c5679994dc56f82c1d88a77528d4c4b076160aff85b4d97ce239360bc210.*uv\.lock/i,
    );
    expect(verification).toMatch(
      /c84292b720bf0eddc8913fe3017dcdb05bd7e98eb19f6ee61dee2c4eb9fa901e.*\.whl/i,
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
    expect(live).toMatch(/--testTimeout=130000/);
    expect(workflow).not.toMatch(/(?:VITEST|TEST)_TIMEOUT|--testTimeout=(?!130000\b)/);
    expect(workflow.indexOf(verification ?? "")).toBeLessThan(workflow.indexOf(warm ?? ""));
    expect(workflow.indexOf(warm ?? "")).toBeLessThan(workflow.indexOf(live ?? ""));
    const upload = blockContaining(workflow, "actions/upload-artifact@");
    expect(upload).toMatch(/if:\s*\$\{\{\s*always\(\)\s*\}\}/);
    expect(upload).toMatch(/retention-days:\s*[1-9]/);
    expect(upload).toContain(
      "$" + "{{ runner.temp }}/aih-scan-cisco-artifacts/sanitized-sarif-*.json",
    );
    expect(upload).toContain(
      "$" + "{{ runner.temp }}/aih-scan-cisco-artifacts/sanitized-runner-failure-*.json",
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
