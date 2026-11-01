import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { displayPathProblem, pathProblem } from "../../src/contracts/text.js";
import { scanWith } from "../../src/host/scan.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

let fixture: FixtureRoot;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-path-rule-");
});
afterEach(() => fixture.dispose());

const itemsRequest = (items: unknown[]) => ({
  format: "aih-scan-request/1",
  origin: "local",
  items,
});

describe("the item path rule (pathProblem)", () => {
  const check = (path: string) => pathProblem(path, 1024, 64);

  it("accepts other format characters and colons inside a name", () => {
    expect(check("\u{1F469}\u200D\u{1F4BB}.md")).toBeUndefined();
    expect(check("notes:1.md")).toBeUndefined();
    expect(check("docs/notes:1.md")).toBeUndefined();
    expect(check("a\u2028b.md")).toBeUndefined();
  });

  it.each([
    ["a C0 control", "a\u0007.md"],
    ["a C1 control", "a\u0085.md"],
    ["a bidirectional override", "a\u202Eb.md"],
    ["a bidirectional isolate", "a\u2066b.md"],
    ["a right-to-left mark", "a\u200Fb.md"],
    ["a backslash", "a\\b.md"],
    ["a drive letter", "c:notes.md"],
    ["a URL", "https://example.com/x"],
    ["a custom URL scheme", "x-y+z://host"],
    ["an unpaired surrogate", "a\uD800.md"],
  ])("refuses %s", (_name, path) => {
    expect(check(path)).toBeDefined();
  });

  it("keeps the reader's display rule strict", () => {
    expect(displayPathProblem("\u{1F469}\u200D\u{1F4BB}.md", 1024, 64)).toBeDefined();
    expect(displayPathProblem("a\u2028b.md", 1024, 64)).toBeDefined();
    expect(displayPathProblem("notes:1.md", 1024, 64)).toBeUndefined();
  });

  it.skipIf(process.platform === "win32")(
    "scans a folder with a zero-width joiner and a colon in its names",
    async () => {
      const item = fixture.folder("item", {
        "SKILL.md": "# X\n",
        "\u{1F469}\u200D\u{1F4BB}.md": "x\n",
        "notes:1.md": "y\n",
      });
      const result = await scanWith(itemsRequest([{ path: item }]), {
        outDir: fixture.path("out"),
      });
      expect(result.status).toBe("ok");
    },
  );
});
