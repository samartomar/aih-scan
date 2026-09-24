import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Loaders for W2's verbatim parity capture (`./fixtures/PROVENANCE.md`).
 * Nothing here computes an expected value: expectations are read from the
 * goldens, and analyzer output comes only from the recorded transcripts.
 */

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), "fixtures");
const TRUST_PARITY = join(FIXTURES, "trust-parity");

export type ParityEnvironmentV1 = "linux-x64" | "win32-x64";

export interface ParityCaseV1 {
  readonly id: string;
  readonly tree: string | null;
  readonly internalScopes?: readonly string[];
  readonly materialize: readonly Readonly<{ path: string; utf8?: string; base64?: string }>[];
}

export interface GoldenCheckV1 {
  readonly family: string;
  readonly name: string;
  readonly verdict: string;
  readonly code: string | null;
  readonly uri: string | null;
  readonly startLine: number | null;
  readonly detail: string;
  readonly fingerprint: string | null;
}

export interface GoldenRawOccurrenceV1 {
  readonly analyzer: string;
  readonly ruleId: string;
  readonly level: string | null;
  readonly message: string;
  readonly uri: string;
  readonly startLine: number;
}

export interface GoldenDetectorEnvironmentV1 {
  readonly outcome: string;
  readonly reason?: string;
  readonly rawOccurrences?: readonly GoldenRawOccurrenceV1[];
}

export interface GoldenCaseV1 {
  readonly internalScopes: readonly string[];
  readonly native: Readonly<{
    identicalAcrossEnvironments: boolean;
    byEnvironment: Readonly<Record<string, Readonly<{ checks: readonly GoldenCheckV1[] }>>>;
  }>;
  readonly detectors: Readonly<
    Record<
      string,
      Readonly<{ byEnvironment: Readonly<Record<string, GoldenDetectorEnvironmentV1>> }>
    >
  >;
}

export interface TranscriptCallV1 {
  readonly argv: readonly string[];
  readonly cwd: string | null;
  readonly timeoutMs: number;
  readonly code: number | null;
  readonly spawnError: boolean;
  readonly truncated: boolean;
  readonly stdout: string;
  readonly stderr: string;
  /** The SARIF file text the analyzer wrote (cisco). */
  readonly outputSarif?: string | null;
  /** The tools manifest text the engine wrote (mcp-scanner). */
  readonly toolsInput?: string;
}

export interface TranscriptV1 {
  readonly case: string;
  readonly detector: string;
  readonly environment: ParityEnvironmentV1;
  readonly calls: readonly TranscriptCallV1[];
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export function parityCasesV1(): readonly ParityCaseV1[] {
  return readJson<{ cases: ParityCaseV1[] }>(join(TRUST_PARITY, "cases.json")).cases;
}

export function goldenCaseV1(id: string): GoldenCaseV1 {
  return readJson<GoldenCaseV1>(join(TRUST_PARITY, "golden", `${id}.json`));
}

export function recordedSnykV1<T>(): T {
  return readJson<T>(join(TRUST_PARITY, "recorded", "snyk-agent-scan.json"));
}

export function recordedSnykGoldenV1<T>(): T {
  return readJson<T>(join(TRUST_PARITY, "golden", "recorded-snyk-agent-scan.json"));
}

/** The transcript for one case and detector, or undefined when it was not captured. */
export function transcriptV1(
  environment: ParityEnvironmentV1,
  caseId: string,
  detector: string,
): TranscriptV1 | undefined {
  try {
    return readJson<TranscriptV1>(
      join(FIXTURES, "transcripts", environment, caseId, `${detector}.json`),
    );
  } catch {
    return undefined;
  }
}

/**
 * A fresh temporary copy of a case, as W2's capture made it: the corpus tree
 * (none for `empty`), then each `materialize` entry written byte-exactly.
 * Returns the root's realpath (Core's `subject.sourceRoot`).
 */
export function materializeCaseV1(parityCase: ParityCaseV1): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), `aih-parity-${parityCase.id}-`)));
  if (parityCase.tree !== null)
    cpSync(join(TRUST_PARITY, parityCase.tree), root, { recursive: true });
  for (const entry of parityCase.materialize) {
    const target = join(root, ...entry.path.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    if (entry.base64 !== undefined) writeFileSync(target, Buffer.from(entry.base64, "base64"));
    else writeFileSync(target, entry.utf8 ?? "", "utf8");
  }
  return root;
}

/** A path of the materialized root as the transcripts spell it (`<root>/a/b`). */
export function placeholderPathV1(root: string, path: string): string {
  const rel = relative(root, path).replace(/\\/g, "/");
  return rel.length === 0 ? "<root>" : `<root>/${rel}`;
}
