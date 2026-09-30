import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("aih-scan self-hosting boundary", () => {
  it("states the no-self-application boundary in the agent entry point", () => {
    expect(readFileSync(resolve(root, "AGENTS.md"), "utf8")).toContain(
      "Never run an installed aih-scan against this checkout.",
    );
  });

  it("keeps public scanner metadata out of repository bootstrap commands", () => {
    const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
    expect(packageJson.bin).toEqual({ "aih-scan": "./dist/cli.js" });
    expect(packageJson.scripts).not.toHaveProperty("repo:publish");
  });
});
