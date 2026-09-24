export type CoreSemgrepStatus = {
  parsedJson: boolean;
  executorsLine: string | null;
  semgrepDetector: { verdict: string; detail: string } | null;
};

export declare function coreRanSemgrep(core: CoreSemgrepStatus): boolean;
export declare function normaliseFindingPath(
  uri: string | null,
  files: readonly string[],
  originRoot: string,
): { path: string | null; accepted: boolean };
export declare function scanRefusedForEmpty(scan: {
  exit: number | null;
  childError: string | null;
  summary: {
    outcome: string;
    reason: string | null;
    executionProfileId: string | null;
  } | null;
}): boolean;
export declare function compareFindingKeys(
  coreKeys: string[],
  scanKeys: string[],
  allPathsRecognised?: boolean,
): { onlyCore: string[]; onlyScan: string[]; identical: boolean };
