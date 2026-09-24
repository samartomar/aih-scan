import {
  AnalyzerRunFailureV1,
  type BaselineProcessRunnerV1,
  boundedDiagnosticDetailV1,
  CISCO_SKILL_SCANNER_HOST_PROJECT_V1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  runHostUvEngineV1,
} from "../baseline/runtime-v1.js";
import {
  type DetectorExecutionProfileV1,
  resolveDetectorCapabilityV1,
} from "../capability/detector-capability-v1.js";
import {
  type CiscoShardJobSarifOutputV1,
  type CiscoShardJobV1,
  preflightCiscoShardV1,
  runCiscoShardV1 as runCiscoShardEngineV1,
} from "../detectors/cisco-multi-skill/shard-v1.js";
import {
  capabilityPlatform,
  detail,
  executionFieldRefusal,
  failureStage,
  platformRefusal,
  probeStates,
  producer,
  type RunDetectorFailureCauseV1,
  type RunDetectorFailureStageV1,
  type RunDetectorProducerV1,
} from "./run-detector-v1.js";

/**
 * C2a §3.7: one exact-source Cisco shard for Core's baseline vet, through the public
 * boundary. The request names its execution profile; the shard's `expected.lockSha256` must
 * equal that profile's published `analyzerLock.sha256`, and the expected analyzer version is
 * checked by the version gate, before any job runs. Job paths are sealed at the start and the
 * end; each job's SARIF comes back with its sha256, in job order; on any failure the
 * lowest-index one is reported and no partial output is returned.
 *
 * Only host-process-uv-v1 runs a shard in this build. linux-namespace-uv-v1 is refused.
 */

export type { CiscoShardJobSarifOutputV1, CiscoShardJobV1 };

export type RunCiscoShardRefusalReasonV1 =
  | "shard-request-invalid"
  | "analyzer-lock-mismatch"
  | "execution-profile-unavailable"
  | "unsupported-platform"
  | "prerequisite-missing";

export type RunCiscoShardV1Result =
  | Readonly<{
      outcome: "succeeded";
      executionProfile: DetectorExecutionProfileV1;
      producer: RunDetectorProducerV1;
      /** The verified analyzer: `version` is the expected version before any `+` suffix. */
      analyzer: Readonly<{ version: string; lockSha256: string }>;
      /** One SARIF per job, in the request's job order. */
      outputs: readonly CiscoShardJobSarifOutputV1[];
      /** Tree seals over every job path, taken at the start and the end. */
      sourceSeal: Readonly<{ before: string; after: string }>;
    }>
  | Readonly<{
      outcome: "refused";
      reason: RunCiscoShardRefusalReasonV1;
      /** One actionable sentence; bounded and control-character encoded. */
      detail: string;
    }>
  | Readonly<{
      outcome: "failed";
      failure: Readonly<{
        stage: RunDetectorFailureStageV1;
        detail: string;
        cause?: RunDetectorFailureCauseV1;
      }>;
      executionProfile: DetectorExecutionProfileV1;
      producer: RunDetectorProducerV1;
    }>;

const SHARD_PROFILE_V1 = "host-process-uv-v1";

const REQUEST_FIELDS = [
  "sourceRoot",
  "jobs",
  "expected",
  "executionProfileId",
  "concurrency",
  "env",
  "signal",
  "timeoutMs",
  "runner",
] as const;

function refused(reason: RunCiscoShardRefusalReasonV1, text: string): RunCiscoShardV1Result {
  return Object.freeze({
    outcome: "refused" as const,
    reason,
    detail: boundedDiagnosticDetailV1(text),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reads every request field, each job's fields and the expected identity exactly once into
 * plain frozen copies, so no caller accessor runs again. A read that throws is a refusal.
 */
function snapshot(request: unknown): Record<string, unknown> | string {
  if (!isRecord(request)) return "a shard request must be an object";
  const value: Record<string, unknown> = {};
  try {
    for (const field of REQUEST_FIELDS) value[field] = request[field];
    const jobs = value.jobs;
    if (Array.isArray(jobs))
      value.jobs = Object.freeze(
        Array.from(jobs, (job: unknown) =>
          isRecord(job)
            ? Object.freeze({ id: job.id, path: job.path, inputSha256: job.inputSha256 })
            : job,
        ),
      );
    const expected = value.expected;
    if (isRecord(expected))
      value.expected = Object.freeze({
        analyzerVersion: expected.analyzerVersion,
        lockSha256: expected.lockSha256,
      });
    const env = value.env;
    if (isRecord(env)) value.env = Object.freeze(Object.fromEntries(Object.entries(env)));
  } catch (error) {
    return `the shard request could not be read: ${
      error instanceof Error ? error.message : "a field accessor threw"
    }`;
  }
  return value;
}

/** Runs one Cisco shard (C2a §3.7). Never throws; every shortfall is a typed outcome. */
export async function runCiscoShardV1(request: unknown): Promise<RunCiscoShardV1Result> {
  try {
    return await shard(request);
  } catch (error) {
    return refused("shard-request-invalid", detail(error));
  }
}

async function shard(request: unknown): Promise<RunCiscoShardV1Result> {
  const input = snapshot(request);
  if (typeof input === "string") return refused("shard-request-invalid", input);
  const capability = resolveDetectorCapabilityV1("detector.cisco");
  if (capability === undefined) throw new TypeError("detector.cisco is not registered");
  const named = input.executionProfileId;
  if (named === "linux-namespace-uv-v1")
    return refused(
      "execution-profile-unavailable",
      `A detector.cisco shard under linux-namespace-uv-v1 is not implemented in this build; name ${SHARD_PROFILE_V1}.`,
    );
  if (named !== SHARD_PROFILE_V1)
    return refused(
      "execution-profile-unavailable",
      `A detector.cisco shard names its execution profile, and this build runs shards only under ${SHARD_PROFILE_V1}.`,
    );
  const profile = capability.executionProfiles.find((entry) => entry.id === named);
  const publishedLock = profile?.analyzerLock?.sha256;
  if (profile === undefined || publishedLock === undefined)
    throw new TypeError(`detector.cisco publishes no ${SHARD_PROFILE_V1} analyzer lock`);
  const failed = (stage: RunDetectorFailureStageV1, error: unknown): RunCiscoShardV1Result =>
    Object.freeze({
      outcome: "failed" as const,
      failure: Object.freeze({
        stage,
        detail: detail(error),
        ...(error instanceof AnalyzerRunFailureV1 ? { cause: error.failureCause } : {}),
      }),
      executionProfile: profile,
      producer: producer(),
    });
  const fieldRefusal = executionFieldRefusal(capability, input);
  if (fieldRefusal !== undefined) return refused("shard-request-invalid", fieldRefusal);
  if (input.runner !== undefined && typeof input.runner !== "function")
    return refused("shard-request-invalid", "runner must be a function.");
  const shardRequest = {
    sourceRoot: input.sourceRoot as string,
    jobs: input.jobs as readonly CiscoShardJobV1[],
    expected: input.expected as { analyzerVersion: string; lockSha256: string },
    concurrency: input.concurrency as number,
    analyzerProject: CISCO_SKILL_SCANNER_HOST_PROJECT_V1,
  };
  // The shard's identity is the named profile's published lock, before any file is read.
  const expected = shardRequest.expected;
  if (
    isRecord(expected) &&
    typeof expected.lockSha256 === "string" &&
    /^[0-9a-f]{64}$/.test(expected.lockSha256) &&
    expected.lockSha256 !== publishedLock
  )
    return refused(
      "analyzer-lock-mismatch",
      `expected.lockSha256 is not the ${SHARD_PROFILE_V1} analyzerLock of detector.cisco (${publishedLock}).`,
    );
  const preflight = preflightCiscoShardV1(shardRequest);
  if (!preflight.ok) {
    const outcome = preflight.outcome;
    if (outcome.kind === "refused") return refused(outcome.reason, outcome.detail);
    // The lock the capability read at load is unreadable now: an incomplete install.
    return failed(
      outcome.kind === "failed" ? outcome.stage : "acquisition",
      new TypeError(outcome.kind === "failed" ? outcome.detail : "Cisco shard preflight failed"),
    );
  }
  const platform = capabilityPlatform();
  if (
    platform === undefined ||
    !profile.supportedPlatforms.some(
      (entry) => entry.os === platform.os && entry.architecture === platform.architecture,
    )
  )
    return refused("unsupported-platform", platformRefusal(capability, profile));
  const env = (input.env as Readonly<NodeJS.ProcessEnv> | undefined) ?? process.env;
  const probed = probeStates(profile.prerequisites, undefined, env);
  const missing = profile.prerequisites.find(
    (prerequisite, index) => prerequisite.required && probed.states[index]?.state === "missing",
  );
  if (missing !== undefined)
    return refused(
      "prerequisite-missing",
      `detector.cisco needs ${missing.kind} ${missing.id}, which is not present. ${missing.detail}`,
    );

  const signal = input.signal as AbortSignal | undefined;
  const timeoutMs = input.timeoutMs as number | undefined;
  const deadline = timeoutMs === undefined ? undefined : Date.now() + timeoutMs;
  let ran: Awaited<
    ReturnType<typeof runHostUvEngineV1<Awaited<ReturnType<typeof runCiscoShardEngineV1>>>>
  >;
  try {
    ran = await runHostUvEngineV1({
      project: CISCO_SKILL_SCANNER_HOST_PROJECT_V1,
      version: CISCO_SKILL_SCANNER_VERSION_V1,
      tools: ["skill-scanner"],
      sourceRoot: preflight.safeRoot,
      ...(input.runner === undefined ? {} : { runner: input.runner as BaselineProcessRunnerV1 }),
      callerEnv: env,
      ...(signal === undefined ? {} : { signal }),
      ...(deadline === undefined ? {} : { deadline }),
      body: ({ run }) =>
        runCiscoShardEngineV1({
          ...shardRequest,
          run: (argv, options) => run(argv, options ?? {}),
          platform:
            process.platform === "win32"
              ? "windows"
              : process.platform === "darwin"
                ? "darwin"
                : "linux",
          env: {},
        }),
    });
  } catch (error) {
    return failed(failureStage(detail(error)), error);
  }
  const outcome = ran.value;
  if (outcome.kind === "refused") return refused(outcome.reason, outcome.detail);
  if (outcome.kind === "failed") return failed(outcome.stage, new TypeError(outcome.detail));
  return Object.freeze({
    outcome: "succeeded" as const,
    executionProfile: profile,
    producer: producer(),
    analyzer: outcome.analyzer,
    outputs: outcome.outputs,
    sourceSeal: outcome.sourceSeal,
  });
}
