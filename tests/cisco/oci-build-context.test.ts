import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const candidateRoot = resolve(root, "tools", "cisco-oci-candidate");
const read = (name: string) => readFileSync(resolve(candidateRoot, name), "utf8");
const sha256 = (name: string) => createHash("sha256").update(read(name)).digest("hex");

const pyprojectSha256 = "35de8ad9e2d243fb418f8dbeba2f55c4a430495fe1c7163a21809f0ea3999ead";
const lockSha256 = "1e98c5679994dc56f82c1d88a77528d4c4b076160aff85b4d97ce239360bc210";
const ciscoWheelSha256 = "c84292b720bf0eddc8913fe3017dcdb05bd7e98eb19f6ee61dee2c4eb9fa901e";
const uvWheelSha256 = "3e195ccf1ed60c8bb24a6447ce306441a4181d54b602407e09bc56e963911c15";

describe("Cisco OCI candidate build context", () => {
  it("is deny-all and contains only the deterministic OCI build inputs", () => {
    expect(read(".dockerignore").trim()).toBe(
      "*\n!Dockerfile\n!.dockerignore\n!pyproject.toml\n!uv.lock",
    );
    expect(sha256("pyproject.toml")).toBe(pyprojectSha256);
    expect(sha256("uv.lock")).toBe(lockSha256);
  });

  it("uses only immutable bases and a directly hash-verified uv wheel", () => {
    const dockerfile = read("Dockerfile");

    expect(dockerfile).toContain(
      "python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134",
    );
    expect(dockerfile.match(/FROM python:3\.12-slim-bookworm@sha256:/g) ?? []).toHaveLength(2);
    expect(dockerfile).toContain(
      "https://files.pythonhosted.org/packages/93/22/dacc9a0bc8604187a1ba954a3aef8329e4104eb0af772d2c3c634893bd9b/uv-0.12.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    );
    expect(dockerfile).toContain(uvWheelSha256);
    expect(dockerfile).toMatch(new RegExp(`python -m pip install[^\\n]*#sha256=${uvWheelSha256}`));
    expect(dockerfile).toContain(ciscoWheelSha256);
    expect(dockerfile).toContain("uv sync --frozen");
    expect(dockerfile).toContain(pyprojectSha256);
    expect(dockerfile).toContain(lockSha256);
    expect(dockerfile).toMatch(/sha256sum -c/);
    expect(dockerfile).toContain("SOURCE_DATE_EPOCH=1785167267");
    expect(dockerfile).toContain("UV_EXCLUDE_NEWER=2026-09-24T00:00:00Z");
    expect(dockerfile).toMatch(/tar[^\n]*--sort=name[^\n]*--mtime=@1785167267/);
    expect(dockerfile).toMatch(/USER\s+65532(?::65532)?/);
    expect(dockerfile).toContain('ENTRYPOINT ["/runtime/.venv/bin/skill-scanner"]');
    expect(dockerfile).not.toMatch(
      /ADD\s+https?:|curl\b|pip install\s+uv\b|latest|credential|policy/i,
    );
    const runtimeStage = dockerfile.slice(dockerfile.lastIndexOf("\nFROM "));
    // One copy of the environment: the tar is bind-mounted from the builder, never a layer.
    expect(runtimeStage).not.toMatch(/^(COPY|ADD)\b/m);
    expect(runtimeStage).toContain(
      "RUN --mount=type=bind,from=builder,source=/runtime-venv.tar,target=/runtime-venv.tar tar -xf /runtime-venv.tar\n",
    );
    expect(read("uv.lock")).toMatch(
      /cisco-ai-skill-scanner[\s\S]*2\.1\.0[\s\S]*c84292b720bf0eddc8913fe3017dcdb05bd7e98eb19f6ee61dee2c4eb9fa901e/i,
    );
  });
});
