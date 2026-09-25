export type BaselinePublicationCommandResult = Readonly<{
  status: number | null;
  stdout: string;
  stderr: string;
}>;

export type BaselinePublicationCommandRunner = (
  command: string,
  args: readonly string[],
  cwd?: string,
) => BaselinePublicationCommandResult;

export type BaselinePublicationRequest = Readonly<{
  name: string;
  path: string;
  requestSha256: string;
}>;

export function baselinePublicationTag(publisherSha: string, requestSha256: string, generation?: string): string;

export function verifyCompletedPublication(input: Readonly<{
  repository: string;
  publisherSha: string;
  sourceRef: string;
  workflow: string;
  scanner: string;
  gh: string;
  reuseDirectory: string;
  request: BaselinePublicationRequest;
  now?: string;
  generation?: string;
  run?: BaselinePublicationCommandRunner;
}>): boolean;

/**
 * The workflow step: verifies each request's completed publication or queues it as pending.
 * D49: a request set that is only partly published is refused, since the analyzers run once
 * for a whole set; the operator dispatches a fresh publication_generation instead.
 */
export function main(
  argv?: readonly string[],
  options?: Readonly<{ run?: BaselinePublicationCommandRunner; now?: string }>,
): void;

/** Exactly the four release files, each hashed file matching `SHA256SUMS`. */
export function verifyDownloadedFiles(directory: string): void;

/** The discovery document names exactly this repository's release download locator. */
export function assertDiscoveryLocator(discoveryPath: string, repository: string, tag: string): void;
