export type AdaptiveSsdStats = {
  submittedTasks: number;
  validatedTasks: number;
  failedTasks: number;
  modelRequests: number;
  multiItemRequests: number;
  maxBatchWidth: number;
};

export function startAdaptiveSsd(options: {
  signal?: AbortSignal;
  infer: (prompt: string, signal: AbortSignal) => Promise<string>;
  contextTokens?: number;
  outputTokens?: number;
  batchDelayMs?: number;
}): Promise<{
  socketPath: string;
  close: () => Promise<void>;
  stats: () => AdaptiveSsdStats;
}>;
