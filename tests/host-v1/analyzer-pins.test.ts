import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CISCO_VERSION } from "../../src/host/cisco.js";
import { SKILLSPECTOR_VERSION } from "../../src/host/skillspector.js";

const read = (path: string) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");

describe("pinned analyzer runtimes", () => {
  it("locks SkillSpector to the v2.13.3 tag commit the adapter requires", () => {
    expect(SKILLSPECTOR_VERSION).toBe("2.13.3");
    const commit = "38a1dfe93325d2f8bfcd4f8d0241eed706334915";
    expect(read("tools/analyzers/skillspector/pyproject.toml")).toContain(
      `skillspector @ git+https://github.com/NVIDIA/SkillSpector@${commit}`,
    );
    const lock = read("tools/analyzers/skillspector/uv.lock");
    expect(lock).toMatch(
      new RegExp(
        `name = "skillspector"\\nversion = "2\\.13\\.3"\\nsource = \\{ git = "https://github\\.com/NVIDIA/SkillSpector\\?rev=${commit}#${commit}" \\}`,
      ),
    );
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
