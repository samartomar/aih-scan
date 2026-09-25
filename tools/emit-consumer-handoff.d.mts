export type ConsumerHandoffGhResult = Readonly<{ status: number | null; stdout: string }>;

/** Runs `gh <args>` in `cwd`; the default spawns the gh on PATH. */
export type ConsumerHandoffGhRunner = (args: readonly string[], cwd: string) => ConsumerHandoffGhResult;

export type ConsumerHandoffOptions = Readonly<{
  releaseRoot: string;
  release: string;
  attestationBundle: string;
  run: string;
  mapping: string;
  repository: string;
  publisherCommit: string;
  output: string;
}>;

export type ConsumerHandoffResult = Readonly<{
  handoff: string;
  publication: string;
  components: number;
  outcome: "observed" | "observed_with_gaps";
}>;

export function emitConsumerHandoffV1(
  options: ConsumerHandoffOptions,
  dependencies?: Readonly<{ runGh?: ConsumerHandoffGhRunner }>,
): ConsumerHandoffResult;

export function parseArguments(argv: readonly string[]): ConsumerHandoffOptions;
