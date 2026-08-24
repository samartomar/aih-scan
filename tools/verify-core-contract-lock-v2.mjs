import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { closeSync, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const commit = "e53fe219002515c092ebb68c5b91c91a2fc6110d";
const contracts = [
  {
    relativePath: "schemas/aih-governance-decision-v2.schema.json",
    sha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
  },
  {
    relativePath: "schemas/aih-organization-evidence-envelope-v1.schema.json",
    sha256: "88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc",
  },
];

function fail(reason) {
  throw new Error(`Core Strict V2 compatibility gate failed: ${reason}`);
}
function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--core-root" || !args[1])
  fail("usage is --core-root <checked-out-ai-harness>");
const coreRoot = resolve(args[1]);
const rootStat = lstatSync(coreRoot);
if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("Core root shape");
const head = execFileSync("git", ["-C", coreRoot, "rev-parse", "HEAD"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
}).trim();
if (head !== commit) fail("unexpected Core commit");
const status = execFileSync("git", ["-C", coreRoot, "status", "--porcelain=v1", "--untracked-files=all"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
});
if (status.length !== 0) fail("Core checkout must be clean");
const verified = {};
for (const contract of contracts) {
  const schemaPath = resolve(coreRoot, contract.relativePath);
  const fromRoot = relative(coreRoot, schemaPath);
  if (!fromRoot || fromRoot === ".." || fromRoot.startsWith(`..\\`) || fromRoot.startsWith("../") || isAbsolute(fromRoot))
    fail("schema path escapes Core root");
  const beforePath = lstatSync(schemaPath);
  if (
    !beforePath.isFile() ||
    beforePath.isSymbolicLink() ||
    beforePath.nlink !== 1 ||
    beforePath.size <= 0 ||
    beforePath.size > 2 * 1024 * 1024
  )
    fail("schema artifact shape");
  const descriptor = openSync(schemaPath, "r");
  let bytes;
  try {
    const beforeDescriptor = fstatSync(descriptor);
    if (!beforeDescriptor.isFile() || !sameIdentity(beforePath, beforeDescriptor))
      fail("schema artifact changed before read");
    bytes = readFileSync(descriptor);
    const afterDescriptor = fstatSync(descriptor);
    const afterPath = lstatSync(schemaPath);
    if (
      !sameIdentity(beforeDescriptor, afterDescriptor) ||
      !sameIdentity(afterDescriptor, afterPath)
    )
      fail("schema artifact changed during read");
  } finally {
    closeSync(descriptor);
  }
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== contract.sha256) fail(`schema digest drift: ${contract.relativePath}`);
  verified[contract.relativePath] = actual;
}
process.stdout.write(`${JSON.stringify({ coreCommit: commit, schemas: verified })}\n`);
