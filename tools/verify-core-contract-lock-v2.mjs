import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { closeSync, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

// The contract is the schema bytes, not the package version number. Each accepted Core
// commit is paired with the exact decision-schema digest Core carries at that commit, so
// declaring one commit while presenting another commit's schema still fails.
// The organization-evidence envelope schema is byte-identical at every accepted commit.
const acceptedCores = [
  {
    commit: "6130dd837b8e8bd41e999fb40733e0e460e69720",
    decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
  },
  {
    commit: "c31741602b3dbd5f228dafe00591e5679c782878",
    decisionSchemaSha256: "7fdf101568cd7caa28516d0be37704c0dfd51198bc54d41d65829abbe77547cc",
  },
];
const organizationEvidenceEnvelopeSchema = {
  relativePath: "schemas/aih-organization-evidence-envelope-v1.schema.json",
  sha256: "88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc",
};
const decisionSchemaPath = "schemas/aih-governance-decision-v2.schema.json";
const corePackageName = "@aihq/core";

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

const USAGE =
  "usage is --core-root <ai-harness-tree> [--core-commit <accepted-sha>] [--expect-core-version <version>]";

function parseArguments(argv) {
  const flags = {
    "--core-root": "coreRoot",
    "--core-commit": "coreCommit",
    "--expect-core-version": "expectedCoreVersion",
  };
  const parsed = { coreRoot: undefined, coreCommit: undefined, expectedCoreVersion: undefined };
  if (argv.length === 0 || argv.length % 2 !== 0) fail(USAGE);
  for (let index = 0; index < argv.length; index += 2) {
    const field = flags[argv[index]];
    const value = argv[index + 1];
    if (field === undefined || !value || parsed[field] !== undefined) fail(USAGE);
    parsed[field] = value;
  }
  if (!parsed.coreRoot) fail(USAGE);
  return parsed;
}

const args = parseArguments(process.argv.slice(2));
const coreRoot = resolve(args.coreRoot);
const rootStat = lstatSync(coreRoot);
if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("Core root shape");

// A git checkout proves which commit these bytes come from. An extracted tree cannot,
// so the commit must then be declared and the paired schema digest below is what
// decides: declaring one accepted commit while presenting another one's schema fails.
let head = args.coreCommit;
let checkoutProof = "declared-commit";
let gitHead;
try {
  gitHead = execFileSync("git", ["-C", coreRoot, "rev-parse", "HEAD"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
} catch {
  gitHead = undefined;
}
if (gitHead) {
  checkoutProof = "git-checkout";
  if (head !== undefined && head !== gitHead) fail("declared commit is not the checked-out commit");
  head = gitHead;
  const status = execFileSync(
    "git",
    ["-C", coreRoot, "status", "--porcelain=v1", "--untracked-files=all"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  );
  if (status.length !== 0) fail("Core checkout must be clean");
}
if (!head) fail("a tree without git history requires --core-commit");
const accepted = acceptedCores.find((entry) => entry.commit === head);
if (accepted === undefined) fail("unexpected Core commit");

const packageManifestBytes = readPinnedArtifact(coreRoot, "package.json");
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
  packageManifest.name !== corePackageName ||
  typeof packageManifest.version !== "string" ||
  packageManifest.private === true
)
  fail("Core package identity");
// The package version is recorded, never required to equal a pinned value: the schema
// bytes are the contract, and Core's version legitimately differs between accepted
// commits. An expected version is checked only when the caller supplies one.
if (args.expectedCoreVersion !== undefined && packageManifest.version !== args.expectedCoreVersion)
  fail("Core package version");

const verified = {};
for (const contract of [
  { relativePath: decisionSchemaPath, sha256: accepted.decisionSchemaSha256 },
  organizationEvidenceEnvelopeSchema,
]) {
  const bytes = readPinnedArtifact(coreRoot, contract.relativePath);
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== contract.sha256) fail(`schema digest drift: ${contract.relativePath}`);
  verified[contract.relativePath] = actual;
}
process.stdout.write(
  `${JSON.stringify({
    coreCommit: head,
    checkoutProof,
    package: {
      name: packageManifest.name,
      version: packageManifest.version,
      sha256: createHash("sha256").update(packageManifestBytes).digest("hex"),
    },
    acceptedCoreCommits: acceptedCores.map((entry) => entry.commit),
    schemas: verified,
  })}
`,
);
