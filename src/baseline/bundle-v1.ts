import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import {
  type BaselineVetAnnexArtifactV1,
  type BaselineVetBatchResultV1,
  type BaselineVetReceiptV1,
  canonicalBaselineVetReceiptV1Bytes,
  parseBaselineVetReceiptV1Json,
} from "./batch-v1.js";

const maxReceiptBytes = 1024 * 1024;
const maxAnnexBytes = 16 * 1024 * 1024;

function fail(reason: string): never {
  throw new TypeError(`invalid BaselineVetBundleV1: ${reason}`);
}

type DirectoryWitness = Readonly<{ path: string; real: string; stat: Stats }>;
type ProtectedDirectoryDescriptor = Readonly<{
  descriptor: number;
  path: string;
  real: string;
}>;

function sameReference(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function directoryWitness(path: string, label: string): DirectoryWitness {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} directory shape`);
  return { path, real: realpathSync.native(path), stat };
}

function assertDirectoryWitness(witness: DirectoryWitness, label: string): void {
  const current = lstatSync(witness.path);
  if (
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    !sameReference(witness.stat, current) ||
    realpathSync.native(witness.path) !== witness.real
  )
    fail(`${label} directory replacement`);
}

function isDirectoryWitnessCurrent(witness: DirectoryWitness): boolean {
  try {
    assertDirectoryWitness(witness, "cleanup");
    return true;
  } catch {
    return false;
  }
}

function protectedDirectoryDescriptor(path: string, label: string): ProtectedDirectoryDescriptor {
  if (process.platform !== "linux") fail("protected signer custody requires Linux");
  const beforePath = lstatSync(path);
  if (!beforePath.isDirectory() || beforePath.isSymbolicLink()) fail(`${label} directory shape`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      path,
      constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0),
    );
    const opened = fstatSync(descriptor);
    const afterPath = lstatSync(path);
    const uid = process.getuid?.();
    if (
      !opened.isDirectory() ||
      !sameReference(beforePath, opened) ||
      !sameReference(opened, afterPath) ||
      uid === undefined ||
      opened.uid !== uid ||
      (opened.mode & 0o022) !== 0
    )
      fail(`${label} protected directory custody`);
    const anchoredPath = `/proc/self/fd/${descriptor}`;
    const real = realpathSync.native(path);
    if (realpathSync.native(anchoredPath) !== real) fail(`${label} protected directory descriptor`);
    return { descriptor, path: anchoredPath, real };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    throw error;
  }
}

function boundedFile(path: string, maximum: number, label: string): Buffer {
  const beforePath = lstatSync(path);
  if (
    !beforePath.isFile() ||
    beforePath.isSymbolicLink() ||
    beforePath.nlink !== 1 ||
    beforePath.size <= 0 ||
    beforePath.size > maximum
  )
    fail(`${label} file shape`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameReference(beforePath, before))
      fail(`${label} file replacement`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const afterPath = lstatSync(path);
    if (
      bytes.byteLength === 0 ||
      bytes.byteLength > maximum ||
      after.nlink !== 1 ||
      !sameReference(before, after) ||
      !sameReference(before, afterPath) ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      fail(`${label} file replacement`);
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function writeNewRegularFile(
  path: string,
  bytes: Buffer,
  parent: DirectoryWitness,
  label: string,
): void {
  assertDirectoryWitness(parent, `${label} parent`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    writeFileSync(descriptor, bytes);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size !== bytes.byteLength)
      fail(`${label} output shape`);
    const pathStat = lstatSync(path);
    if (pathStat.isSymbolicLink() || pathStat.nlink !== 1 || !sameReference(stat, pathStat))
      fail(`${label} output replacement`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  assertDirectoryWitness(parent, `${label} parent`);
}

function checkedArtifacts(
  receipt: BaselineVetReceiptV1,
  artifacts: readonly BaselineVetAnnexArtifactV1[],
): Map<string, Buffer> {
  const values = new Map<string, Buffer>();
  for (const artifact of artifacts) {
    if (values.has(artifact.path)) fail("duplicate annex artifact");
    values.set(artifact.path, Buffer.from(artifact.bytes));
  }
  if (values.size !== receipt.observations.length) fail("annex artifact cardinality");
  for (const observation of receipt.observations) {
    const bytes = values.get(observation.annex.path);
    if (
      bytes === undefined ||
      bytes.byteLength !== observation.annex.byteLength ||
      createHash("sha256").update(bytes).digest("hex") !== observation.annex.sha256
    )
      fail(`annex artifact mismatch: ${observation.analyzer}`);
  }
  return values;
}

export function writeBaselineVetBundleV1(input: {
  readonly outputDirectory: string;
  readonly result: BaselineVetBatchResultV1;
}): void {
  const receipt = parseBaselineVetReceiptV1Json(
    canonicalBaselineVetReceiptV1Bytes(input.result.receipt).toString("utf8"),
  );
  const artifacts = checkedArtifacts(receipt, input.result.annexArtifacts);
  const output = resolve(input.outputDirectory);
  const parent = dirname(output);
  const parentWitness = directoryWitness(parent, "output parent");
  let created = false;
  let outputWitness: DirectoryWitness | undefined;
  try {
    mkdirSync(output, { recursive: false, mode: 0o700 });
    created = true;
    assertDirectoryWitness(parentWitness, "output parent");
    outputWitness = directoryWitness(output, "output");
    if (dirname(outputWitness.real) !== parentWitness.real) fail("output parent containment");
    const annexPath = join(output, "annex");
    mkdirSync(annexPath, { recursive: false, mode: 0o700 });
    assertDirectoryWitness(outputWitness, "output");
    const annexWitness = directoryWitness(annexPath, "annex");
    if (dirname(annexWitness.real) !== outputWitness.real) fail("annex parent containment");
    writeNewRegularFile(
      join(output, "receipt.json"),
      canonicalBaselineVetReceiptV1Bytes(receipt),
      outputWitness,
      "receipt",
    );
    for (const [path, bytes] of artifacts) {
      if (dirname(path) !== "annex" || basename(path) !== path.slice("annex/".length))
        fail("annex output path depth");
      writeNewRegularFile(join(output, path), bytes, annexWitness, `${path} annex`);
    }
    assertDirectoryWitness(annexWitness, "annex");
    assertDirectoryWitness(outputWitness, "output");
    assertDirectoryWitness(parentWitness, "output parent");
  } catch (error) {
    if (created && outputWitness !== undefined && isDirectoryWitnessCurrent(outputWitness))
      rmSync(output, { recursive: true, force: true });
    throw error;
  }
}

export function readBaselineVetBundleV1(input: {
  readonly bundleDirectory: string;
}): BaselineVetBatchResultV1 {
  const root = resolve(input.bundleDirectory);
  const rootWitness = directoryWitness(root, "bundle");
  const rootEntries = readdirSync(root).sort();
  assertDirectoryWitness(rootWitness, "bundle");
  if (rootEntries.length !== 2 || rootEntries[0] !== "annex" || rootEntries[1] !== "receipt.json")
    fail("bundle members");
  const annexDirectory = join(root, "annex");
  const annexWitness = directoryWitness(annexDirectory, "annex");
  if (dirname(annexWitness.real) !== rootWitness.real) fail("annex parent containment");
  const receiptBytes = boundedFile(join(root, "receipt.json"), maxReceiptBytes, "receipt");
  assertDirectoryWitness(rootWitness, "bundle");
  const receipt = parseBaselineVetReceiptV1Json(receiptBytes.toString("utf8"));
  const expectedNames = receipt.observations.map((item) => basename(item.annex.path)).sort();
  const names = readdirSync(annexDirectory).sort();
  assertDirectoryWitness(annexWitness, "annex");
  if (
    names.length !== expectedNames.length ||
    names.some((name, index) => name !== expectedNames[index])
  )
    fail("annex members");
  const annexArtifacts = receipt.observations.map((item) => ({
    path: item.annex.path,
    bytes: boundedFile(join(root, item.annex.path), maxAnnexBytes, `${item.analyzer} annex`),
  }));
  checkedArtifacts(receipt, annexArtifacts);
  assertDirectoryWitness(annexWitness, "annex");
  assertDirectoryWitness(rootWitness, "bundle");
  return Object.freeze({ receipt, annexArtifacts: Object.freeze(annexArtifacts) });
}

/** Linux-only organization-signing reader anchored to protected directory descriptors. */
export function readBaselineVetBundleForSigningV1(input: {
  readonly bundleDirectory: string;
}): BaselineVetBatchResultV1 {
  let root: ProtectedDirectoryDescriptor | undefined;
  let annex: ProtectedDirectoryDescriptor | undefined;
  try {
    root = protectedDirectoryDescriptor(resolve(input.bundleDirectory), "signing bundle");
    const rootEntries = readdirSync(root.path).sort();
    if (rootEntries.length !== 2 || rootEntries[0] !== "annex" || rootEntries[1] !== "receipt.json")
      fail("signing bundle members");
    const annexDirectory = protectedDirectoryDescriptor(join(root.path, "annex"), "signing annex");
    annex = annexDirectory;
    if (dirname(annexDirectory.real) !== root.real) fail("signing annex parent containment");
    const receiptBytes = boundedFile(
      join(root.path, "receipt.json"),
      maxReceiptBytes,
      "signing receipt",
    );
    const receipt = parseBaselineVetReceiptV1Json(receiptBytes.toString("utf8"));
    const expectedNames = receipt.observations.map((item) => basename(item.annex.path)).sort();
    const names = readdirSync(annexDirectory.path).sort();
    if (
      names.length !== expectedNames.length ||
      names.some((name, index) => name !== expectedNames[index])
    )
      fail("signing annex members");
    const annexArtifacts = receipt.observations.map((item) => ({
      path: item.annex.path,
      bytes: boundedFile(
        join(annexDirectory.path, basename(item.annex.path)),
        maxAnnexBytes,
        `${item.analyzer} signing annex`,
      ),
    }));
    checkedArtifacts(receipt, annexArtifacts);
    const rootAfter = readdirSync(root.path).sort();
    const namesAfter = readdirSync(annexDirectory.path).sort();
    if (
      rootAfter.length !== rootEntries.length ||
      rootAfter.some((name, index) => name !== rootEntries[index]) ||
      namesAfter.length !== names.length ||
      namesAfter.some((name, index) => name !== names[index])
    )
      fail("signing bundle changed during custody transfer");
    return Object.freeze({ receipt, annexArtifacts: Object.freeze(annexArtifacts) });
  } finally {
    if (annex !== undefined) closeSync(annex.descriptor);
    if (root !== undefined) closeSync(root.descriptor);
  }
}
