export declare const REPOSITORY: Readonly<{ id: number; fullName: string }>;
export declare const OWNER: Readonly<{ id: number; login: string }>;
export declare const CANDIDATE_WORKFLOW: string;
export declare const CANDIDATE_ARTIFACT: string;
export declare const MAX_SOURCES: number;
export declare const MAX_CANDIDATE_BYTES: number;
export declare function validateSources(
  bytes: Uint8Array,
  expectedSha256: string,
): { target: string; ref?: string }[];
export declare function checkCandidateRun(
  run: unknown,
  artifacts: unknown,
  runId: string,
  head: string,
  artifactId: string,
  artifactDigest: string,
): { runId: number; head: string; artifactId: number; artifactDigest: string };
export declare function selectSummaries(
  candidate: string,
  expectedSha256: string,
  out: string,
): { count: number; listing: string; paths: string[] };
