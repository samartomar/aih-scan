import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { closeSync, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const commit = "aa93128ff56b3ed978ec428e29d1b1ce8036e53b";
const packageIdentity = {
  name: "@aihq/core",
  version: "0.1.0",
  sha256: "af64feda4e3e57808e1a262e15a5cb8f41581f77e8f9b49eb9b459317b803ecd",
};
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
function readPinnedArtifact(coreRoot, relativePath) {
  const artifactPath = resolve(coreRoot, relativePath);
  const fromRoot = relative(coreRoot, artifactPath);
  if (
    !fromRoot ||
    fromRoot === ".." ||
    fromRoot.startsWith(`..\\`) ||
    fromRoot.startsWith("../") ||
    isAbsolute(fromRoot)
  )
    fail("artifact path escapes Core root");
  const beforePath = lstatSync(artifactPath);
  if (
    !beforePath.isFile() ||
    beforePath.isSymbolicLink() ||
    beforePath.nlink !== 1 ||
    beforePath.size <= 0 ||
    beforePath.size > 2 * 1024 * 1024
  )
    fail("artifact shape");
  const descriptor = openSync(artifactPath, "r");
  try {
    const beforeDescriptor = fstatSync(descriptor);
    if (!beforeDescriptor.isFile() || !sameIdentity(beforePath, beforeDescriptor))
      fail("artifact changed before read");
    const bytes = readFileSync(descriptor);
    const afterDescriptor = fstatSync(descriptor);
    const afterPath = lstatSync(artifactPath);
    if (!sameIdentity(beforeDescriptor, afterDescriptor) || !sameIdentity(afterDescriptor, afterPath))
      fail("artifact changed during read");
    return bytes;
  } finally {
    closeSync(descriptor);
  }
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
const packageManifestBytes = readPinnedArtifact(coreRoot, "package.json");
if (createHash("sha256").update(packageManifestBytes).digest("hex") !== packageIdentity.sha256)
  fail("Core package manifest digest");
let packageManifest;
try {
  packageManifest = JSON.parse(packageManifestBytes.toString("utf8"));
} catch {
  fail("Core package manifest JSON");
}
if (
  packageManifest === null ||
  typeof packageManifest !== "object" ||
  Array.isArray(packageManifest) ||
  packageManifest.name !== packageIdentity.name ||
  packageManifest.version !== packageIdentity.version ||
  packageManifest.private === true
)
  fail("Core package identity");
const verified = {};
for (const contract of contracts) {
  const bytes = readPinnedArtifact(coreRoot, contract.relativePath);
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== contract.sha256) fail(`schema digest drift: ${contract.relativePath}`);
  verified[contract.relativePath] = actual;
}
process.stdout.write(
  `${JSON.stringify({ coreCommit: commit, package: packageIdentity, schemas: verified })}\n`,
);
