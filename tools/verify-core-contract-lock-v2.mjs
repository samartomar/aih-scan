import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const commit = "e27a55dcebb635c8298aa4fd6fd871f59089bcf7";
const schemaSha256 = "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff";
const schemaRelativePath = "schemas/aih-governance-decision-v2.schema.json";

function fail(reason) {
  throw new Error(`Core Strict V2 compatibility gate failed: ${reason}`);
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--core-root" || !args[1])
  fail("usage is --core-root <checked-out-ai-harness>");
const coreRoot = resolve(args[1]);
const head = execFileSync("git", ["-C", coreRoot, "rev-parse", "HEAD"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
}).trim();
if (head !== commit) fail("unexpected Core commit");
const schemaPath = resolve(coreRoot, schemaRelativePath);
if (!schemaPath.startsWith(`${coreRoot}/`) && !schemaPath.startsWith(`${coreRoot}\\`))
  fail("schema path escapes Core root");
const stat = lstatSync(schemaPath);
if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > 2 * 1024 * 1024)
  fail("schema artifact shape");
const actual = createHash("sha256").update(readFileSync(schemaPath)).digest("hex");
if (actual !== schemaSha256) fail("schema digest drift");
process.stdout.write(`${schemaSha256}\n`);
