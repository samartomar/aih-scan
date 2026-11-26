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
  it("locks SkillSpector to the v2.13.7 tag commit the adapter requires", () => {
    expect(SKILLSPECTOR_VERSION).toBe("2.13.7");
    const commit = "c323ad4c43e3c8f2de051572cc25b2711d11e648";
    expect(read("tools/analyzers/skillspector/pyproject.toml")).toContain(
      `skillspector @ git+https://github.com/NVIDIA/SkillSpector@${commit}`,
    );
    const lock = read("tools/analyzers/skillspector/uv.lock");
    expect(lock).toMatch(
      new RegExp(
        `name = "skillspector"\\nversion = "2\\.13\\.7"\\nsource = \\{ git = "https://github\\.com/NVIDIA/SkillSpector\\?rev=${commit}#${commit}" \\}`,
      ),
    );
  });

  it("binds the maintenance builder, artifact and adapter to the same 2.13.7 inputs", () => {
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
      "42a6aff0aea105b35e1ae299887a6b14210df92e2c4864d348b8cdd4a678d6da",
    );
    expect(builder).toEqual({
      upstream: "c323ad4c43e3c8f2de051572cc25b2711d11e648",
      sourceSha256: "ba6db55083e904cd7d44d8b060977eedca5c6463bdb4b0d68681c10a367f5c7d",
      patchSha256: "08375d9323ee040d02ce904e60aafe49a5371f0a64578174ac7e641f6b55562f",
      runtimeLockSha256: "bbf191c6fe87f1f164f23d9a9d495dc85fc158657127f5661a4e355ac9d77120",
      buildLockSha256: "749ad0309a104d4708570e978f362fffa8bebe16ac416b399ac2d085b20b0a56",
      builderRecipeSha256,
      version: "2.13.7+aih.1.9a867b5e3f4e5142c27bad050c8c72a89cad4d9f21ee7b3157f61d19148952e7",
    });
    expect(artifact).toEqual({
      ...builder,
      wheel:
        "skillspector-2.13.7+aih.1.9a867b5e3f4e5142c27bad050c8c72a89cad4d9f21ee7b3157f61d19148952e7-py3-none-any.whl",
      wheelSha256: "934716fbdc5665b94ec6656f046fbdd0cf46eda68cf4b65712563b78bbe9794e",
    });
    expect(builder.version).not.toBe(
      "2.13.4+aih.1.4ad76d9621cde6753dc73beb47b6f602db64893cd577cdfdf974c0a1e284b4aa",
    );
    expect(artifact.wheelSha256).not.toBe(
      "2e361e6fc6255d0ca32d5fdf0fd4c0ca559b0a9a74ad6bfdcdf208c76fb18284",
    );
    expect(SKILLSPECTOR_MAINTENANCE_VERSION).toBe(builder.version);
    expect(SKILLSPECTOR_MAINTENANCE_VERSION.startsWith(`${SKILLSPECTOR_VERSION}+aih.1.`)).toBe(
      true,
    );
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
