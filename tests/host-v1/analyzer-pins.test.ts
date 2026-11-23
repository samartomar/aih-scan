import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CISCO_VERSION } from "../../src/host/cisco.js";
import {
  SKILLSPECTOR_MAINTENANCE_VERSION,
  SKILLSPECTOR_VERSION,
} from "../../src/host/skillspector.js";

const read = (path: string) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
const maintenanceSource = process.env.AIH_SCAN_TEST_SKILLSPECTOR_SOURCE;

describe("pinned analyzer runtimes", () => {
  it("locks SkillSpector to the v2.13.6 tag commit the adapter requires", () => {
    expect(SKILLSPECTOR_VERSION).toBe("2.13.6");
    const commit = "e2674da339b0bddc6e565d059c0577c6d9cd25da";
    expect(read("tools/analyzers/skillspector/pyproject.toml")).toContain(
      `skillspector @ git+https://github.com/NVIDIA/SkillSpector@${commit}`,
    );
    const lock = read("tools/analyzers/skillspector/uv.lock");
    expect(lock).toMatch(
      new RegExp(
        `name = "skillspector"\\nversion = "2\\.13\\.6"\\nsource = \\{ git = "https://github\\.com/NVIDIA/SkillSpector\\?rev=${commit}#${commit}" \\}`,
      ),
    );
  });

  it("binds the maintenance builder, artifact and adapter to the same 2.13.6 inputs", () => {
    const builder = JSON.parse(
      execFileSync(
        process.platform === "win32" ? "python" : "python3",
        ["tools/analyzers/skillspector/maintenance/build.py", "--identity"],
        { encoding: "utf8" },
      ),
    );
    const artifact = JSON.parse(read("tools/analyzers/skillspector/maintenance/artifact.json"));
    const builderRecipeSha256 = createHash("sha256")
      .update(read("tools/analyzers/skillspector/maintenance/build.py").replace(/\r\n/gu, "\n"))
      .digest("hex");
    expect(builderRecipeSha256).toBe(
      "696354b8404a98526b4a9b761df57bc772724ada49bc9ba26022433a150fcf20",
    );
    expect(builder).toEqual({
      upstream: "e2674da339b0bddc6e565d059c0577c6d9cd25da",
      sourceSha256: "678f5dd59b5dff0c62181c045e15e8411727cc425c653a793b36e60fb50b11e1",
      patchSha256: "e69867562c561f07a28f2ea41aa8edc77e1bf0216db59627734ea4a3d741de3b",
      runtimeLockSha256: "54c41965dece90280da2c54c5f3e04ab4c2a9ee219ae740ab64e02ca26b68e0f",
      buildLockSha256: "63eb9f0abd6ae0f8ea6aa36cc900c80a2f391b4f7ecd3b5b7d84320d7249a936",
      builderRecipeSha256,
      version: "2.13.6+aih.1.06fc3defc5b6f792396162f5f3678f7f07c32adf1f440194637392bfadac9e81",
    });
    expect(artifact).toEqual({
      ...builder,
      wheel:
        "skillspector-2.13.6+aih.1.06fc3defc5b6f792396162f5f3678f7f07c32adf1f440194637392bfadac9e81-py3-none-any.whl",
      wheelSha256: "6edbd210f237cb0ca0b950d2e45b4941f3bf13efcbb0fe068e740969fc9f3261",
    });
    expect(builder.version).not.toBe(
      "2.13.4+aih.1.4ad76d9621cde6753dc73beb47b6f602db64893cd577cdfdf974c0a1e284b4aa",
    );
    expect(artifact.wheelSha256).not.toBe(
      "2e361e6fc6255d0ca32d5fdf0fd4c0ca559b0a9a74ad6bfdcdf208c76fb18284",
    );
    expect(SKILLSPECTOR_MAINTENANCE_VERSION).toBe(builder.version);
  });

  it.runIf(maintenanceSource !== undefined)(
    "reproduces the reviewed maintenance wheel from authenticated source on this platform",
    () => {
      if (maintenanceSource === undefined) throw new Error("AIH_SCAN_TEST_SKILLSPECTOR_SOURCE");
      expect(existsSync(maintenanceSource), "AIH_SCAN_TEST_SKILLSPECTOR_SOURCE").toBe(true);
      const python = process.platform === "win32" ? "python" : "python3";
      const root = mkdtempSync(join(tmpdir(), "aih-scan-maintenance-build-"));
      try {
        const out = join(root, "build");
        execFileSync(
          python,
          [
            "tools/analyzers/skillspector/maintenance/build.py",
            "--source",
            maintenanceSource,
            "--out",
            out,
          ],
          {
            env: {
              ...process.env,
              UV_CACHE_DIR: join(root, "uv-cache"),
              UV_LINK_MODE: "copy",
              PYTHONDONTWRITEBYTECODE: "1",
            },
            stdio: "pipe",
          },
        );
        const artifactText = read("tools/analyzers/skillspector/maintenance/artifact.json");
        const receiptText = readFileSync(join(out, "receipt.json"), "utf8");
        expect(receiptText).toBe(artifactText);
        const artifact = JSON.parse(artifactText);
        const receipt = JSON.parse(receiptText);
        expect(receipt).toEqual(artifact);
        const wheel = readFileSync(join(out, "wheels", artifact.wheel));
        expect(createHash("sha256").update(wheel).digest("hex")).toBe(artifact.wheelSha256);
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
    180000,
  );

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
