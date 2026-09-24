export declare const COMPLETION_EXTRACT_SOURCE: string;

export type ProofRunCompletion = {
  executionSuccessful: unknown;
  evidence: Record<string, unknown> | null;
};

export declare function subjectPaths(input: {
  detectorId: string;
  subjectKind: string;
  root: string;
  selected: readonly string[];
  detectorOptions?: { mcpConfigPaths?: readonly string[] };
}): string[];

export declare function subjectDigest(
  root: string,
  paths: readonly string[],
): { subjectTreeSha256: string; analyzedFileCount: number };

export declare function completionProblem(
  runs: readonly ProofRunCompletion[] | null | undefined,
  expected: {
    root: string;
    paths: readonly string[];
    detectorId: string;
    version: string | undefined;
    lockSha256: string | null | undefined;
  },
): string | undefined;
