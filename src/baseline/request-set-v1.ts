import { lstatSync, mkdirSync, readdirSync, rmSync, type Stats } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  BASELINE_REQUEST_SET_MAX_V1,
  type BaselineAnalyzerExecutionV1,
  type BaselineVetRequestV1,
  canonicalBaselineVetRequestV1Bytes,
  executeBaselineVetBatchSetV1,
  parseBaselineVetRequestV1Json,
} from "./batch-v1.js";
import { writeBaselineVetBundleV1 } from "./bundle-v1.js";

/**
 * D49: `baseline-vet --request-set <directory> --source <directory> --output-root <new-directory>`.
 * The directory is closed: only regular `batch-NNN.request.json` files (three or four digits),
 * 1 to 1000 of them, no links. Every request runs as one set (executeBaselineVetBatchSetV1),
 * and only after everything succeeded, the request files unchanged, is the output root created
 * and `<output-root>/batch-NNN.bundle` written for each request by the no-overwrite writer.
 */

const REQUEST_FILE = /^(batch-(\d{3,4}))\.request\.json$/u;
const SET_FLAGS = new Map([
  ["--request-set", "requestSetDirectory"],
  ["--source", "sourceRoot"],
  ["--output-root", "outputRoot"],
] as const);

export type BaselineVetRequestSetArgumentsV1 = Readonly<{
  requestSetDirectory: string;
  sourceRoot: string;
  outputRoot: string;
}>;

function fail(message: string): never {
  throw new TypeError(`aih-scan: ${message}`);
}

/** Exactly the three set flags, each once, in any order, each with a non-flag value. */
export function parseBaselineVetRequestSetArgumentsV1(
  args: readonly string[],
): BaselineVetRequestSetArgumentsV1 {
  if (args.length !== SET_FLAGS.size * 2) fail("baseline-vet usage");
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (
      key === undefined ||
      value === undefined ||
      !SET_FLAGS.has(key as never) ||
      values.has(key) ||
      value.length === 0 ||
      value.startsWith("--")
    )
      fail("baseline-vet usage");
    values.set(key, value);
  }
  return {
    requestSetDirectory: values.get("--request-set") ?? fail("baseline-vet usage"),
    sourceRoot: values.get("--source") ?? fail("baseline-vet usage"),
    outputRoot: values.get("--output-root") ?? fail("baseline-vet usage"),
  };
}

function realDirectory(path: string, label: string): Stats {
  let stat: Stats;
  try {
    stat = lstatSync(path);
  } catch {
    fail(label);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(label);
  return stat;
}

type RequestSetEntry = Readonly<{
  batch: string;
  request: BaselineVetRequestV1;
  bytes: Buffer;
}>;

function readRequestSet(
  directory: string,
  readText: (path: string, label: string) => string,
): RequestSetEntry[] {
  const root = resolve(directory);
  const before = realDirectory(root, "baseline vet request set directory");
  const entries = readdirSync(root, { withFileTypes: true });
  const after = realDirectory(root, "baseline vet request set directory");
  if (before.dev !== after.dev || before.ino !== after.ino)
    fail("baseline vet request set directory replacement");
  if (entries.length === 0) fail("baseline vet request set layout: no request files");
  if (entries.length > BASELINE_REQUEST_SET_MAX_V1)
    fail(`baseline request set exceeds ${BASELINE_REQUEST_SET_MAX_V1} requests`);
  return entries
    .map((entry) => {
      const match = REQUEST_FILE.exec(entry.name);
      if (match === null || !entry.isFile() || entry.isSymbolicLink())
        fail(`baseline vet request set layout: ${JSON.stringify(entry.name)}`);
      return { name: entry.name, batch: match[1] as string, number: Number(match[2]) };
    })
    .sort((left, right) =>
      left.number !== right.number
        ? left.number - right.number
        : left.name < right.name
          ? -1
          : left.name > right.name
            ? 1
            : 0,
    )
    .map(({ name, batch }) => {
      const request = parseBaselineVetRequestV1Json(
        readText(join(root, name), "baseline vet request"),
      );
      return { batch, request, bytes: canonicalBaselineVetRequestV1Bytes(request) };
    });
}

/** The output root must not exist; its parent must be a real directory. */
function newOutputRoot(outputRoot: string): string {
  const output = resolve(outputRoot);
  try {
    lstatSync(output);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    realDirectory(dirname(output), "baseline-vet output root parent");
    return output;
  }
  fail("baseline-vet output root already exists");
}

export async function runBaselineVetRequestSetV1(input: {
  readonly requestSetDirectory: string;
  readonly sourceRoot: string;
  readonly outputRoot: string;
  /** The CLI's bounded, link-refusing reader of one request file. */
  readonly readText: (path: string, label: string) => string;
  /** Optional: Scan's own hardened analyzer execution is the default. */
  readonly execute?: BaselineAnalyzerExecutionV1;
}): Promise<readonly Readonly<{ batch: string; requestSha256: string; receiptSha256: string }>[]> {
  const set = readRequestSet(input.requestSetDirectory, input.readText);
  const output = newOutputRoot(input.outputRoot);
  const results = await executeBaselineVetBatchSetV1(
    set.map((entry) => entry.request),
    input.execute === undefined
      ? { sourceRoot: input.sourceRoot }
      : { sourceRoot: input.sourceRoot, execute: input.execute },
  );
  // Every request file is still exactly what ran: the same names and canonical bytes.
  let after: RequestSetEntry[];
  try {
    after = readRequestSet(input.requestSetDirectory, input.readText);
  } catch {
    fail("baseline vet request set changed during execution");
  }
  if (
    after.length !== set.length ||
    after.some(
      (entry, index) =>
        entry.batch !== set[index]?.batch ||
        !entry.bytes.equals(set[index]?.bytes ?? Buffer.alloc(0)),
    )
  )
    fail("baseline vet request set changed during execution");
  newOutputRoot(input.outputRoot);
  mkdirSync(output, { recursive: false, mode: 0o700 });
  const created = lstatSync(output);
  try {
    for (const [index, entry] of set.entries())
      writeBaselineVetBundleV1({
        outputDirectory: join(output, `${entry.batch}.bundle`),
        result: results[index] ?? fail("missing baseline vet result"),
      });
  } catch (error) {
    // No partial set: remove the output root this call created, if it is still that one.
    const current = lstatSync(output, { throwIfNoEntry: false });
    if (
      current?.isDirectory() === true &&
      !current.isSymbolicLink() &&
      current.dev === created.dev &&
      current.ino === created.ino
    )
      rmSync(output, { recursive: true, force: true });
    throw error;
  }
  return set.map((entry, index) => ({
    batch: entry.batch,
    requestSha256: entry.request.requestSha256,
    receiptSha256: results[index]?.receipt.receiptSha256 ?? fail("missing baseline vet result"),
  }));
}
