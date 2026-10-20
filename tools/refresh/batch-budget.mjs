// One monotonic deadline per freeze/run. The public detector limits stay intact.
export function batchBudget(maxDurationMs, callerSignal) {
  const started = performance.now();
  const deadline = maxDurationMs === undefined ? Infinity : started + maxDurationMs;
  const cancellation = new AbortController();
  const timer = maxDurationMs === undefined ? undefined : setTimeout(() => cancellation.abort(), maxDurationMs);
  timer?.unref();
  const signal = callerSignal ? AbortSignal.any([callerSignal, cancellation.signal]) : cancellation.signal;
  const termination = () => performance.now() >= deadline || cancellation.signal.aborted ? "deadline-exceeded" : callerSignal?.aborted ? "cancelled" : "completed";
  function checkpoint() {
    if (termination() !== "completed") {
      if (performance.now() >= deadline) cancellation.abort();
      throw new Error("Capture batch cancelled or deadline exceeded");
    }
    return Math.max(1, Math.ceil(deadline - performance.now()));
  }
  const transport = api => Object.fromEntries(["json", "bytes"].map(method => [method, async (path, options = {}) => {
    const remaining = checkpoint();
    const result = await api[method](path, {...options, timeout: Math.min(options.timeout ?? 30000, remaining)});
    checkpoint();
    return result;
  }]));
  return {signal,termination,checkpoint,transport,durationMs:()=>Math.round(performance.now()-started),dispose: () => clearTimeout(timer)};
}
