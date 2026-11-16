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
    const builderRecipeSha256 = createHash("sha256")
      .update(read("tools/analyzers/skillspector/maintenance/build.py").replace(/\r\n/gu, "\n"))
      .digest("hex");
    expect(builderRecipeSha256).toBe(
      "dae0a74261c5b15df1d6e7986b42c7ccf96538f9a6959f4e6172d2b41c383a8e",
    );
    expect(builder).toEqual({
      upstream: "54824463814a0be01360792523ec7245a69190fc",
      sourceSha256: "562349db9ef4084cfe2f18707de3d942c5b94e221162c314c795e4501fabc07d",
      patchSha256: "79578d6ea997a331d649bb17173818b84a893a4760142681557bb836db0b9407",
      runtimeLockSha256: "b30e05171b22849c963e5de7606bfe3e8fbe02ad4f019a2f6c5fea0e8b1147bd",
      buildLockSha256: "63eb9f0abd6ae0f8ea6aa36cc900c80a2f391b4f7ecd3b5b7d84320d7249a936",
      builderRecipeSha256,
      version: "2.13.4+aih.1.4ad76d9621cde6753dc73beb47b6f602db64893cd577cdfdf974c0a1e284b4aa",
    });
    expect(artifact).toEqual({
      ...builder,
      wheel:
        "skillspector-2.13.4+aih.1.4ad76d9621cde6753dc73beb47b6f602db64893cd577cdfdf974c0a1e284b4aa-py3-none-any.whl",
      wheelSha256: "2e361e6fc6255d0ca32d5fdf0fd4c0ca559b0a9a74ad6bfdcdf208c76fb18284",
    });
    expect(builder.version).not.toBe(
      "2.13.4+aih.1.8ef6704a6123a29c3c219a6b3bee3ff419f6a75fc428a469bf7a46fc88c05159",
    );
    expect(artifact.wheelSha256).not.toBe(
      "f40324a28badbfd01c46fe2e77e9d2a0be2df874317d1ca84710b1ccb4e8aab8",
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
