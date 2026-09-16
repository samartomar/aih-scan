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
