import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const { name, version } = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
if (name !== "@aihq/scan" || typeof version !== "string" || version.length === 0)
  throw new Error("Cannot generate the installed Scan package identity");

const target = resolve(root, "src/public/package-identity.ts");
const content = [
  "// Generated from package.json by tools/generate-package-identity.mjs.",
  "// Portable metadata: importing it performs no host operations.",
  "export const packageIdentity = Object.freeze({",
  `  name: ${JSON.stringify(name)},`,
  `  version: ${JSON.stringify(version)},`,
  "} as const);",
  "",
].join("\n");

if (process.argv.includes("--check")) {
  if (readFileSync(target, "utf8") !== content)
    throw new Error("Generated package identity is stale; run npm run generate:identity");
} else {
  mkdirSync(resolve(root, "src/public"), { recursive: true });
  writeFileSync(target, content, "utf8");
}
