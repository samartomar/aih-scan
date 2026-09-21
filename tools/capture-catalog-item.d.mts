/**
 * Types for `tools/capture-catalog-item.mjs`, which is deliberately plain ESM.
 * They describe the functions the command runs — preparation, the source-closure
 * staging that selects the skill root, the subject gate and the capture attempt —
 * so a test can drive the production code path instead of a copy of it.
 */

export type CatalogCapturePlatformV1 = Readonly<{
  /** The host, in Node's vocabulary. */
  node: Readonly<{ os: string; architecture: string }>;
  /** The capture target, in the adapter/registration/layout/daemon vocabulary. */
  oci: Readonly<{ os: "linux"; architecture: "amd64" }>;
}>;

/** One file of the closure, exactly as the installed package's reader serves it. */
export type CatalogCaptureClosureFileV1 = Readonly<{
  /** The path Catalog publishes this file at, relative to the closure root. */
  path: string;
  sha256: string;
  byteLength: number;
  bytes: Uint8Array;
}>;

/** A material root as Catalog declares it; `files` holds published relative paths. */
export type CatalogCaptureMaterialRootV1 = Readonly<{
  kind: string;
  /** `.` names the closure root itself. */
  path: string;
  marker?: string;
  files: readonly string[];
  excludes?: readonly string[];
}>;

export type CatalogCaptureSourceClosureV1 = Readonly<{
  format: string;
  version: number;
  collection: Readonly<Record<string, unknown>>;
  entry: Readonly<{ entryId: string; subject: Readonly<Record<string, unknown>> }>;
  asset: Readonly<Record<string, unknown>>;
  assessment: Readonly<Record<string, unknown>>;
  source: Readonly<Record<string, unknown>>;
  root: string;
  materialRoots: readonly CatalogCaptureMaterialRootV1[];
  declaredTreeDigest: string;
  files: readonly CatalogCaptureClosureFileV1[];
}>;

/** What the documented public reader returns: a served closure, or a named refusal. */
export type CatalogCaptureSourceClosureResultV1 =
  | Readonly<{ state: "verified"; closure: CatalogCaptureSourceClosureV1 }>
  | Readonly<{ state: "refused"; reason?: string; path?: string }>;

export type CatalogCaptureReaderV1 = Readonly<{
  readCatalogSourceClosureV1: (request: {
    collectionId: string;
    subjectId: string;
  }) => CatalogCaptureSourceClosureResultV1;
  createDetectorRegistrationV1: (value: unknown) => CatalogCaptureRegistrationV1;
  readScanCaptureBundleV2: (request: {
    bundleDirectory: string;
  }) => Readonly<{ annexArtifacts: readonly Readonly<{ descriptorId: string; sha256: string }>[] }>;
}>;

export type CatalogCaptureRegistrationEntryV1 = Readonly<{
  detector: Readonly<{
    detectorId: string;
    sbom: Readonly<{ sha256: string }>;
    provenance: Readonly<{ sha256: string }>;
    supportedPlatforms: readonly Readonly<{ os: string; architecture: string }>[];
  }>;
  runtime: Readonly<{ sourceReference: string; sourceSha256: string; configSha256: string }>;
  adapterCapability: string;
  broker: Readonly<{ capability: string }>;
}>;

export type CatalogCaptureRegistrationV1 = Readonly<{
  registrations: readonly CatalogCaptureRegistrationEntryV1[];
  registrationSha256: string;
}>;

/** The installed package's own validator; the tool derives no registration value. */
export type CatalogCaptureRegistrationReaderV1 = Readonly<{
  createDetectorRegistrationV1: (value: unknown) => CatalogCaptureRegistrationV1;
}>;

export type CatalogCaptureOptionsV1 = Readonly<{
  catalogTarball: string;
  scanTarball: string;
  output: string;
  registration: string;
  layout: string;
  imageId: string;
  sbom: string;
  provenance: string;
  detectorId?: string;
  /** The collection view the source closure is read from. */
  collectionId: string;
  /** The subject whose source closure is read; the entry id comes back with it. */
  subjectId: string;
  consumerRoot?: string;
  prepareOnly?: boolean;
}>;

/** The installed Catalog the closure was read from, as preparation recorded it. */
export type CatalogCaptureCatalogRefV1 = Readonly<{
  name: string;
  version: string;
  tarball: Readonly<{ flag: string; path: string; sha256: string }>;
}>;

/** One published file staged under its own path, with the digest re-verified. */
export type CatalogCaptureStagedFileV1 = Readonly<{
  publishedPath: string;
  stagedPath: string;
  sha256: string;
  byteLength: number;
}>;

/** A published file the mounted root cannot cover, recorded rather than implied. */
export type CatalogCaptureUncoveredFileV1 = Readonly<{
  publishedPath: string;
  stagedPath: string;
  declaredExcluded: boolean;
  reason: string;
}>;

export type CatalogCaptureItemV1 = Readonly<{
  /** The declared skill material root, staged: the root the capture mounts. */
  sourceRoot: string;
  /** Paths relative to `sourceRoot` that the capture will be asked to cover. */
  selectedClosurePaths: readonly string[];
  /** The staged files the capture covers, with paths relative to `sourceRoot`. */
  files: readonly Readonly<{
    publishedPath: string;
    path: string;
    sha256: string;
    byteLength: number;
  }>[];
  /** Entry identity as the public reader returned it; never a default here. */
  entry: Readonly<{ entryId: string; subject: Readonly<Record<string, unknown>> }>;
  closure: Readonly<{
    format: string;
    version: number;
    collection: Readonly<Record<string, unknown>>;
    asset: Readonly<Record<string, unknown>>;
    assessment: Readonly<Record<string, unknown>>;
    source: Readonly<Record<string, unknown>>;
    root: string | null;
    declaredTreeDigest: string | null;
    materialRoots: readonly CatalogCaptureMaterialRootV1[];
  }>;
  skillRoot: Readonly<{
    declaredPath: string;
    marker: string;
    /** Published paths under the declared skill root. */
    files: readonly string[];
    excludes: readonly string[];
  }>;
  stagedFiles: readonly CatalogCaptureStagedFileV1[];
  uncoveredPublishedPaths: readonly CatalogCaptureUncoveredFileV1[];
}>;

export type CatalogCaptureDetectorV1 = Readonly<{
  registrationInput: unknown;
  registrationRecord: CatalogCaptureRegistrationV1;
  detectorId: string;
  layout: Readonly<Record<string, unknown>>;
  annexFiles: readonly Readonly<{ descriptorId: string; path: string }>[];
}>;

export type CatalogCapturePreparedV1 = Readonly<{
  consumerRoot: string;
  tarballs: readonly Readonly<{ flag: string; path: string; sha256: string }>[];
  packages: readonly Readonly<{ name: string; version: string }>[];
  reader: CatalogCaptureReaderV1;
  cliEntry: string;
  item: CatalogCaptureItemV1;
  /** The diagnostic record of the staged closure; not evidence and not in the bundle. */
  sourceClosurePath: string;
  detector: CatalogCaptureDetectorV1;
  request: Readonly<Record<string, unknown>>;
  requestPath: string;
}>;

export function assertPlatform(
  descriptor?: Readonly<{ platform: string; arch: string }>,
): CatalogCapturePlatformV1;
export function createRunDirectory(output: string): string;
export function npmCliPath(environment?: { readonly npm_execpath?: string }): string;
export function installEnvironment(environment?: NodeJS.ProcessEnv): Record<string, string>;
export function prepareCapture(
  options: CatalogCaptureOptionsV1,
  runRoot: string,
): Promise<CatalogCapturePreparedV1>;

/**
 * Reads and stages the published source closure, then selects the skill material
 * root Catalog declares. Refuses a refused closure, an unserved digest, an unsafe
 * path, an ambiguous or missing skill root and a false declared exclusion.
 */
export function readCatalogSourceClosure(
  reader: CatalogCaptureReaderV1,
  options: CatalogCaptureOptionsV1,
  runRoot: string,
  catalog: CatalogCaptureCatalogRefV1,
): Readonly<{ item: CatalogCaptureItemV1; recordPath: string }>;

export function readDetectorInputs(
  reader: CatalogCaptureRegistrationReaderV1,
  options: CatalogCaptureOptionsV1,
  runRoot: string,
): CatalogCaptureDetectorV1;

/** The staged file the registered route loads as the skill: never renamed or generated. */
export type CatalogCaptureSkillV1 = Readonly<{
  /** The path Catalog publishes this file at, relative to the closure root. */
  publishedPath: string;
  /** The staged path inside the capture source root, so far always `SKILL.md`. */
  path: string;
  sha256: string;
  byteLength: number;
}>;

/** The outcome the command writes to stdout: preparation only, or a kept capture bundle. */
export type CatalogCaptureOutcomeV1 = Readonly<{
  outcome: "prepared" | "captured";
  requestPath?: string;
  captureCommand?: string;
  bundlePath?: string;
  candidateSha256?: string;
  executionLog?: string;
}>;

/**
 * Suitability of the staged root for the registered route, read from the staged
 * material alone. It refuses rather than selecting any other directory.
 */
export function assertSkillSourceRoot(item: CatalogCaptureItemV1): CatalogCaptureSkillV1;
export function runPreparedCapture(
  options: CatalogCaptureOptionsV1,
  runRoot: string,
  platform: CatalogCapturePlatformV1,
  prepared: CatalogCapturePreparedV1,
): Promise<CatalogCaptureOutcomeV1>;

/**
 * One capture attempt. A failed attempt is already recorded in the run directory as
 * `capture-failure.json`, with nulls for whatever that phase never produced and an
 * unknown `findingsProduced` whenever a capture process existed.
 */
export type CatalogCaptureAttemptV1 =
  | Readonly<{ outcome: "captured"; bundlePath: string; candidateSha256: string }>
  | Readonly<{
      outcome: "failed";
      phase: string;
      reason: string;
      captureCommand: readonly string[];
      captureProcessExisted: boolean;
      exitCode: number | null;
      signal: string | null;
      spawnError: string | null;
      stdout: string | null;
      stderr: string | null;
    }>;

export function attemptCapture(
  prepared: CatalogCapturePreparedV1,
  runRoot: string,
): CatalogCaptureAttemptV1;
