import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";

test("maintainer parser refuses rounded and underflowing lexemes while preserving exact integers", () => {
  const directory = mkdtempSync(join(tmpdir(), "refresh-number-boundary-"));
  try {
    const driver = join(directory, "parse.mjs");
    writeFileSync(
      driver,
      `import {parseJson,validateInput,ceilings,roster} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
const [mode,lexeme]=process.argv.slice(2);let bytes;
if(mode==='input'){const input={schema:'urn:aihq:scan:refresh-input:1.0.0',scannerSourceCommit:'a'.repeat(40),runtime:{node:'v24.15.0',platform:'linux',architecture:'x64'},profile:'independent-linux-v1',limits:{...ceilings,detectorTimeoutMs:1000},targets:roster.map(repository=>({repository,ref:'b'.repeat(40),selection:{paths:'all',excludedPaths:[]},trustLint:{internalScopes:[],mcpConfigPaths:[]}}))};bytes=Buffer.from(JSON.stringify(input).replace('"detectorTimeoutMs":1000','"detectorTimeoutMs":'+lexeme));}else bytes=Buffer.from('{"value":'+lexeme+'}');
const value=parseJson(bytes);if(mode==='input')validateInput(value);process.stdout.write(JSON.stringify(value));`,
    );
    const run = (mode: string, lexeme: string) =>
      spawnSync(process.execPath, [driver, mode, lexeme], { encoding: "utf8", windowsHide: true });
    expect(run("input", "1000.00000000000000001").status).not.toBe(0);
    for (const lexeme of [
      "1e-999",
      "9007199254740990.9",
      "9007199254740992",
      "-0",
      `1e${"9".repeat(1100)}`,
    ])
      expect(run("parse", lexeme).status, lexeme).not.toBe(0);
    for (const lexeme of ["1000", "1e3", "10e2", "1000.000000", "1.000e+3"])
      expect(run("input", lexeme).status, lexeme).toBe(0);
    expect(JSON.parse(run("parse", "0e-999").stdout)).toEqual({ value: 0 });
    expect(JSON.parse(run("parse", "9007199254740991.000").stdout)).toEqual({
      value: 9007199254740991,
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
