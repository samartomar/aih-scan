/**
 * Types for `tools/capture-catalog-item.mjs`, which is deliberately plain ESM.
 * They describe the functions the command runs — preparation, the subject gate and
 * the capture attempt — so a test can drive the production code path instead of a
 * copy of it.
 */

export type CatalogCapturePlatformV1 = Readonly<{
  /** The host, in Node's vocabulary. */
  node: Readonly<{ os: string; architecture: string }>;
  /** The capture target, in the adapter/registration/layout/daemon vocabulary. */
  oci: Readonly<{ os: "linux"; architecture: "amd64" }>;
}>;

export type CatalogCaptureArtifactV1 = Readonly<{
  state: string;
  path: string;
  sha256: string;
  byteLength: number;
  bytes: Uint8Array;
  reason?: string;
}>;

export type CatalogCaptureEntryV1 = Readonly<{
  entryId: string;
  subject: Readonly<{ subjectDigest: string }>;
  artifacts: Readonly<Record<string, CatalogCaptureArtifactV1 | undefined>>;
}>;

export type CatalogCaptureContentV1 = Readonly<{
  digest: string;
  package: Readonly<{ name: string; version: string }>;
  organizationAdmission: string;
  entries: readonly CatalogCaptureEntryV1[];
}>;

export type CatalogCaptureItemReaderV1 = Readonly<{
  catalogIndexPath: string;
  readCatalogContentV1: (request: {
    bytes: Uint8Array;
    input: { root: string; verifyArtifacts: true };
  }) => CatalogCaptureContentV1 | undefined;
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
  item: string;
  consumerRoot?: string;
  prepareOnly?: boolean;
}>;

export type CatalogCaptureItemV1 = Readonly<{
  sourceRoot: string;
  selectedClosurePaths: readonly string[];
  content: CatalogCaptureContentV1;
  entry: CatalogCaptureEntryV1;
  files: readonly Readonly<{
    name: string;
    path: string;
    sha256: string;
    byteLength: number;
  }>[];
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
  reader: CatalogCaptureItemReaderV1;
  cliEntry: string;
  item: CatalogCaptureItemV1;
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
export function readCatalogItem(
  reader: CatalogCaptureItemReaderV1,
  catalogRoot: string,
  runRoot: string,
  itemId: string,
): Promise<CatalogCaptureItemV1>;
export function readDetectorInputs(
  reader: CatalogCaptureRegistrationReaderV1,
  options: CatalogCaptureOptionsV1,
  runRoot: string,
): CatalogCaptureDetectorV1;

/** The staged artifact the registered route loads as the skill: never renamed or generated. */
export type CatalogCaptureSkillV1 = Readonly<{
  /** The Catalog artifact slot these bytes were published under. */
  artifact: string;
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
 * `capture-failure.json`, with nulls for whatever that phase never produced.
 */
export type CatalogCaptureAttemptV1 =
  | Readonly<{ outcome: "captured"; bundlePath: string; candidateSha256: string }>
  | Readonly<{
      outcome: "failed";
      phase: string;
      reason: string;
      captureCommand: readonly string[];
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
