import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CISCO_VERSION } from "../../src/host/cisco.js";
import {
  SKILLSPECTOR_MAINTENANCE_VERSION,
  SKILLSPECTOR_VERSION,
} from "../../src/host/skillspector.js";

const read = (path: string) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");

describe("pinned analyzer runtimes", () => {
  it("locks SkillSpector to the v2.13.4 tag commit the adapter requires", () => {
    expect(SKILLSPECTOR_VERSION).toBe("2.13.4");
    const commit = "54824463814a0be01360792523ec7245a69190fc";
    expect(read("tools/analyzers/skillspector/pyproject.toml")).toContain(
      `skillspector @ git+https://github.com/NVIDIA/SkillSpector@${commit}`,
    );
    const lock = read("tools/analyzers/skillspector/uv.lock");
    expect(lock).toMatch(
      new RegExp(
        `name = "skillspector"\\nversion = "2\\.13\\.4"\\nsource = \\{ git = "https://github\\.com/NVIDIA/SkillSpector\\?rev=${commit}#${commit}" \\}`,
      ),
    );
  });

  it("binds the maintenance builder, artifact and adapter to the same 2.13.4 inputs", () => {
    const builder = JSON.parse(
      execFileSync(
        process.platform === "win32" ? "python" : "python3",
        ["tools/analyzers/skillspector/maintenance/build.py", "--identity"],
        { encoding: "utf8" },
      ),
    );
    const artifact = JSON.parse(read("tools/analyzers/skillspector/maintenance/artifact.json"));
    expect(builder).toEqual({
      upstream: "54824463814a0be01360792523ec7245a69190fc",
      sourceSha256: "562349db9ef4084cfe2f18707de3d942c5b94e221162c314c795e4501fabc07d",
      patchSha256: artifact.patchSha256,
      runtimeLockSha256: artifact.runtimeLockSha256,
      buildLockSha256: artifact.buildLockSha256,
      version: "2.13.4+aih.1.8ef6704a6123a29c3c219a6b3bee3ff419f6a75fc428a469bf7a46fc88c05159",
    });
    expect(artifact).toEqual({
      ...builder,
      wheel:
        "skillspector-2.13.4+aih.1.8ef6704a6123a29c3c219a6b3bee3ff419f6a75fc428a469bf7a46fc88c05159-py3-none-any.whl",
      wheelSha256: "f40324a28badbfd01c46fe2e77e9d2a0be2df874317d1ca84710b1ccb4e8aab8",
    });
    expect(SKILLSPECTOR_MAINTENANCE_VERSION).toBe(builder.version);
  });

  it("locks Cisco skill-scanner to the 2.3.2 release the adapter requires", () => {
    expect(CISCO_VERSION).toBe("2.3.2");
    expect(read("tools/analyzers/cisco-skill-scanner/pyproject.toml")).toContain(
      '"cisco-ai-skill-scanner==2.3.2"',
    );
    expect(read("tools/analyzers/cisco-skill-scanner/uv.lock")).toMatch(
      /name = "cisco-ai-skill-scanner"\nversion = "2\.3\.2"\nsource = \{ registry = "https:\/\/pypi\.org\/simple" \}/,
    );
  });
});
