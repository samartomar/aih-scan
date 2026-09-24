import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BASELINE_ENVIRONMENT_ALLOW_LIST_V1,
  BASELINE_NATIVE_ANALYZER_IDENTITY_V1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  HOST_DOCKER_CONTEXT_VARIABLES_V1,
  HOST_DOCKER_ENVIRONMENT_V1,
  HOST_PROCESS_TEMPORARY_PATH_LIMIT_V1,
  HOST_PROCESS_UV_DISCOVERY_VARIABLES_V1,
  HOST_PROCESS_UV_ENVIRONMENT_V1,
  HOST_PROCESS_UV_PYTHON_REQUEST_V1,
  SEMGREP_VERSION_V1,
  SKILLSPECTOR_IMAGE_V1,
  SKILLSPECTOR_LOCAL_IMAGE_TAG_V1,
  SKILLSPECTOR_SOURCE_REVISION_V1,
} from "../baseline/runtime-v1.js";
import {
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_DOCKER_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
} from "../cli/process-runner.js";
import {
  canonicalStrictJsonSha256V1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
} from "../contract/strict-json-v1.js";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
} from "../core/core-contract-lock-v2.js";
import { CISCO_MCP_SCANNER_VERSION_V1 } from "../detectors/cisco-mcp-scanner/index.js";
import { SNYK_AGENT_SCAN_VERSION } from "../detectors/snyk-agent-scan/index.js";

/**
 * What Scan can honestly execute, stated as data instead of as code a caller must write.
 *
 * Honesty rules enforced by construction:
 *
 * - `supportedPlatforms` restates the platform gates the execution code already
 *   applies. Scan's hardened detector profiles are Linux `amd64` only. The host profiles
 *   (`host-process-uv-v1`, `docker-host-local-skillspector-v1`) run on Linux, macOS and
 *   Windows where their exact-pinned inputs exist, and the in-process profiles run
 *   anywhere; none of those is isolated beyond what it declares.
 * - Every execution profile carries its own `supportedPlatforms` and `prerequisites`,
 *   and the runner gates on the selected profile's; a capability's own fields restate
 *   its default profile's. A host profile is never a default: it runs only when named,
 *   and `host-process-uv-v1` reports `isolation: "none"` and `network: "unenforced"`.
 * - `executionProfile.sha256` is the digest of the readable profile document this
 *   module publishes, so "which profile ran" is answerable from the package rather
 *   than from an opaque number. It is deliberately NOT the author-supplied
 *   `executionProfileSha256` a registration or candidate carries: that digest is taken
 *   over the OCI build inputs of one capture, not over any readable document.
 * - `analyzerIdentity` is `null` wherever Scan does not mint one. Only the in-process
 *   analyzers have a Scan-owned identity; for the vendor analyzers the identity is
 *   supplied by whoever registers the detector.
 * - Every uv-backed profile publishes `analyzerLock`: the package-relative path of the
 *   bundled uv.lock it installs and the sha256 of that file as shipped, read when this
 *   module loads. A missing lock is an incomplete install and fails the load.
 * - A capability grants no qualification, approval, installation or adoption
 *   authority, and nothing in this module executes anything.
 */

export type DetectorSubjectKindV1 =
  /** A directory whose top level holds `SKILL.md`. */
  | "skill-directory"
  /** Any selected closure of files under one declared root. */
  | "source-tree"
  /** A derived MCP tool list. Declared for completeness; Scan ships no backend for it. */
  | "mcp-tool-manifest"
  /** An unpacked npm package tree. Declared for completeness; Scan ships no backend for it. */
  | "npm-package-tree";

export type DetectorBackendKindV1 =
  | "oci-container"
  | "linux-namespace-uv"
  | "host-process-uv"
  | "in-process";

export type DetectorPlatformV1 = Readonly<{
  os: "linux" | "darwin" | "windows";
  architecture: "amd64" | "arm64";
}>;

export interface DetectorPrerequisiteV1 {
  /**
   * `executable` is an absolute path; `host-executable` is a name resolved from the
   * declared PATH, then fixed well-known directories; `uv-python` is a Python version
   * request uv must satisfy without downloading, which cannot be settled before a spawn.
   */
  readonly kind:
    | "executable"
    | "host-executable"
    | "uv-python"
    | "container-image"
    | "environment-variable"
    | "network"
    | "bundled-asset";
  /** `/usr/bin/bwrap`, `uv`, `3.12`, an immutable OCI reference, a variable name, a host. */
  readonly id: string;
  /** `true` when the run cannot proceed without it. */
  readonly required: boolean;
  /** One sentence an operator can act on. */
  readonly detail: string;
}

export interface DetectorExecutionProfileV1 {
  /** Stable and readable, for example `linux-namespace-uv-v1`. */
  readonly id: string;
  readonly isolation: "container" | "linux-namespace" | "none";
  /** `unenforced`: Scan applies no network restriction at any stage of the run. */
  readonly network: "none" | "acquisition-only" | "unenforced";
  /** Digest of this module's readable profile document for `id`. */
  readonly sha256: string;
  /** The evidence protocol a run under this profile produces. */
  readonly evidence: "BaselineAnalyzerObservationV1" | "ScanCandidateV2";
  /** Hosts this profile runs on; any other host is refused before a probe or spawn. */
  readonly supportedPlatforms: readonly DetectorPlatformV1[];
  /** Exactly what the runner probes, and requires, when this profile is selected. */
  readonly prerequisites: readonly DetectorPrerequisiteV1[];
  /**
   * The bundled uv lock this profile installs for this detector, by package-relative path,
   * with the sha256 of its bytes as shipped; absent where the profile installs no lock.
   */
  readonly analyzerLock?: Readonly<{ path: string; sha256: string }>;
}

/**
 * The readable document whose canonical digest is a profile's `sha256`.
 *
 * Every literal below is the argv, executable, image or environment rule the
 * execution code actually applies, so the document can be checked against a run.
 */
export interface DetectorExecutionProfileDocumentV1 {
  readonly protocol: "DetectorExecutionProfileDocumentV1";
  readonly id: string;
  readonly isolation: "container" | "linux-namespace" | "none";
  readonly network: "none" | "acquisition-only" | "unenforced";
  readonly backend: DetectorBackendKindV1;
  /** Absolute executables the profile is allowed to spawn; empty when it spawns nothing. */
  readonly executables: readonly string[];
  /** Immutable image reference the profile runs, when it runs one. */
  readonly image: string | null;
  /** Containment arguments the profile always applies, in the order the code emits them. */
  readonly containment: readonly string[];
  /** Arguments of the network-enabled acquisition stage, when the profile has one. */
  readonly acquisition: readonly string[];
  /** Mount declarations the profile always applies, with run-specific paths elided. */
  readonly mounts: readonly string[];
  /**
   * `allow-list-scrub`: the caller environment reduced to `allowed`. `fixed-values-by-os`:
   * the spawn's whole environment is exactly `values[os]`, where a `<…>` value is a
   * run-private path or the host's own `%SystemRoot%`; only the listed resolution spawns
   * (Python discovery, the Docker context lookup) also read `callerVariables[os]`.
   */
  readonly environment:
    | Readonly<{
        policy: "allow-list-scrub";
        allowed: readonly string[];
      }>
    | Readonly<{
        policy: "fixed-values-by-os";
        values: Readonly<Record<"linux" | "darwin" | "windows", Readonly<Record<string, string>>>>;
        callerVariables: Readonly<Record<"linux" | "darwin" | "windows", readonly string[]>>;
      }>;
  /** Statements that are true of this profile and that a reader should not have to infer. */
  readonly notes: readonly string[];
}

export interface DetectorCapabilityV1 {
  readonly protocol: "DetectorCapabilityV1";
  readonly detectorId: string;
  /** `null` wherever Scan does not mint the analyzer identity itself. */
  readonly analyzerIdentity: string | null;
  /** The pinned analyzer version this package targets. */
  readonly analyzerVersion: string;
  readonly backend: DetectorBackendKindV1;
  /** The profile used when the caller names none. */
  readonly executionProfile: DetectorExecutionProfileV1;
  /** Every profile this detector can run under; `executionProfile` is the first entry. */
  readonly executionProfiles: readonly DetectorExecutionProfileV1[];
  readonly subjectKinds: readonly DetectorSubjectKindV1[];
  readonly subjectRequirements: readonly string[];
  /**
   * An empty source root (no entries, empty selection): `completes` runs the analyzer over
   * an empty snapshot and reports what it reports; `refused` refuses
   * `subject-requirement-unmet` before anything runs.
   */
  readonly emptySource: "completes" | "refused";
  readonly supportedPlatforms: readonly DetectorPlatformV1[];
  readonly prerequisites: readonly DetectorPrerequisiteV1[];
  readonly outputs: readonly ("sarif-2.1.0" | "aih-baseline-native-v1" | "vendor-json")[];
  readonly contracts: Readonly<{
    capabilityVersion: 1;
    candidateProtocol: "BaselineAnalyzerObservationV1" | "ScanCandidateV2";
    findingsProtocol: "ScanFindingsV1";
    coreContractCommit: string;
    decisionSchemaSha256: string;
  }>;
  readonly capabilitySha256: string;
}

const LINUX_AMD64: readonly DetectorPlatformV1[] = [{ os: "linux", architecture: "amd64" }];
/**
 * Where the exact-pinned, build-free uv installs exist: every Semgrep and Cisco dependency
 * publishes a binary wheel for these hosts. macOS amd64 has none for cryptography 50.0.0
 * (and Cisco's onnxruntime 1.27.0), and Windows arm64 none for Semgrep itself.
 */
const HOST_UV_PLATFORMS: readonly DetectorPlatformV1[] = [
  { os: "darwin", architecture: "arm64" },
  { os: "linux", architecture: "amd64" },
  { os: "linux", architecture: "arm64" },
  { os: "windows", architecture: "amd64" },
];
/**
 * snyk-agent-scan imports Python's POSIX-only `pwd` module on its scan path, so it cannot run
 * on Windows; macOS amd64 lacks a binary wheel for its cryptography 50.0.0.
 */
const SNYK_PLATFORMS: readonly DetectorPlatformV1[] = [
  { os: "darwin", architecture: "arm64" },
  { os: "linux", architecture: "amd64" },
  { os: "linux", architecture: "arm64" },
];
/** litellm 1.93.0, in the cisco-mcp-scanner lock, publishes manylinux wheels only. */
const MCP_SCANNER_PLATFORMS: readonly DetectorPlatformV1[] = [
  { os: "linux", architecture: "amd64" },
  { os: "linux", architecture: "arm64" },
];
/** Hosts whose Docker engine runs the linux/amd64 SkillSpector image, natively or emulated. */
const HOST_DOCKER_PLATFORMS: readonly DetectorPlatformV1[] = [
  { os: "darwin", architecture: "amd64" },
  { os: "darwin", architecture: "arm64" },
  { os: "linux", architecture: "amd64" },
  { os: "windows", architecture: "amd64" },
];
const SARIF_NORMALIZATION_NOTE =
  "Every SARIF artifact URI is rewritten relative to the declared source root, with forward slashes, before the annex digest is taken; a URI outside that root fails the run.";
const IN_PROCESS_CONTROL_NOTE =
  "The analysis is synchronous and cannot be preempted: the cancellation signal and the time budget are checked before the analysis starts and again before its result is accepted, and a result that arrives after either has fired is discarded and the run reports cancelled or timed-out.";
const IN_PROCESS_SEAL_NOTE =
  "It reads the declared source root directly, without a snapshot; the source seal is taken before and after the analysis, and any change between the two fails the run.";
const EVERY_PLATFORM: readonly DetectorPlatformV1[] = [
  { os: "darwin", architecture: "amd64" },
  { os: "darwin", architecture: "arm64" },
  { os: "linux", architecture: "amd64" },
  { os: "linux", architecture: "arm64" },
  { os: "windows", architecture: "amd64" },
  { os: "windows", architecture: "arm64" },
];

const PROFILE_DOCUMENTS: readonly DetectorExecutionProfileDocumentV1[] = [
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "in-process-native-v1",
    isolation: "none",
    network: "none",
    backend: "in-process",
    executables: [],
    image: null,
    containment: [],
    acquisition: [],
    mounts: [],
    environment: { policy: "allow-list-scrub", allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1 },
    notes: [
      "Scan hashes the sealed analyzer snapshot inside this Node process and spawns nothing.",
      "Isolation is 'none' because there is no second process to isolate, not because a sandbox was skipped.",
      "Its gates allow every operating system and architecture Scan knows.",
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "in-process-trust-lint-v1",
    isolation: "none",
    network: "none",
    backend: "in-process",
    executables: [],
    image: null,
    containment: [],
    acquisition: [],
    mounts: [],
    environment: { policy: "allow-list-scrub", allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1 },
    notes: [
      "detector.aih-trust-lint runs the native trust lint over the selected closure inside this Node process and spawns nothing.",
      "Isolation is 'none' because there is no second process to isolate, not because a sandbox was skipped.",
      "It reads no environment variable and makes no network request; detectorOptions carries the caller's internal scopes and MCP config paths.",
      IN_PROCESS_SEAL_NOTE,
      IN_PROCESS_CONTROL_NOTE,
      "Its gates allow every operating system and architecture Scan knows.",
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "in-process-binding-gate-v1",
    isolation: "none",
    network: "none",
    backend: "in-process",
    executables: [],
    image: null,
    containment: [],
    acquisition: [],
    mounts: [],
    environment: { policy: "allow-list-scrub", allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1 },
    notes: [
      "detector.aih-binding-gate runs the binding scan gate's fast-tier inspectors over the selected closure inside this Node process and spawns nothing.",
      "Isolation is 'none' because there is no second process to isolate, not because a sandbox was skipped.",
      "It reads no environment variable and makes no network request; it accepts no detectorOptions other than an empty object.",
      IN_PROCESS_SEAL_NOTE,
      IN_PROCESS_CONTROL_NOTE,
      "Its gates allow every operating system and architecture Scan knows.",
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "linux-namespace-uv-v1",
    isolation: "linux-namespace",
    network: "acquisition-only",
    backend: "linux-namespace-uv",
    executables: [BASELINE_BWRAP_EXECUTABLE_V1, BASELINE_UV_EXECUTABLE_V1],
    image: null,
    containment: [
      "--unshare-all",
      "--unshare-user",
      "--die-with-parent",
      "--as-pid-1",
      "--disable-userns",
      "--assert-userns-disabled",
      "--clearenv",
      "--proc",
      "--dev",
      "--tmpfs",
    ],
    acquisition: [
      "sync",
      "--locked",
      "--no-dev",
      "--no-install-project",
      "--no-build",
      "--link-mode",
      "copy",
      "--no-python-downloads",
      "--no-config",
      "--no-sources",
      "--keyring-provider",
      "disabled",
    ],
    mounts: [
      "--ro-bind <bundled analyzer project> /aih/project",
      "--ro-bind <sealed analyzer snapshot> /aih/source",
      "--bind <run work directory> /aih/work",
      "--bind <run cache directory> /aih/cache",
      "--bind <run venv directory> /aih/venv",
    ],
    environment: { policy: "allow-list-scrub", allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1 },
    notes: [
      "Only the uv acquisition stage adds --share-net; the scan stage runs with no network at all.",
      "The analyzer is resolved from the bundled uv.lock, so the run is exact-pinned rather than latest.",
      "bubblewrap and uv are absolute Linux paths, so this profile cannot run on Windows or macOS.",
      `${SARIF_NORMALIZATION_NOTE} The /aih/source mount prefix is removed, and Cisco's per-skill URIs are mapped through its JSON report.`,
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "host-process-uv-v1",
    isolation: "none",
    network: "unenforced",
    backend: "host-process-uv",
    executables: [
      "uv: the first uv (uv.exe on Windows) on the declared PATH, else in a well-known directory (~/.local/bin, ~/.cargo/bin, Homebrew, /usr/local/bin, /usr/bin); spawned and recorded by real path, with its version",
      "Windows supervisor: %SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe, never resolved through PATH",
    ],
    image: null,
    containment: [
      "linux, darwin: every spawn leads its own process group; a timeout, an abort, an output cap or descendants outliving the leader send SIGTERM and then SIGKILL to the whole group",
      "windows: every spawn is created suspended inside a Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and no breakaway, its membership part of process creation (PROC_THREAD_ATTRIBUTE_JOB_LIST); a timeout or an abort makes the supervisor terminate the job, the supervisor is killed (closing the job) only if it has not exited within a bounded grace, and descendants outliving the leader are terminated with the job",
      "windows: after the run, every process whose command line or image names the run's private directories is killed and the run fails closed",
      "linux, darwin: after the run, every process whose command line, inherited environment or working directory names the run's private directories is killed and the run fails closed",
    ],
    acquisition: [
      "sync",
      "--locked",
      "--no-dev",
      "--no-install-project",
      "--no-build",
      "--link-mode",
      "copy",
      "--no-python-downloads",
      "--no-config",
      "--no-sources",
      "--keyring-provider",
      "disabled",
    ],
    mounts: [],
    environment: {
      policy: "fixed-values-by-os",
      values: HOST_PROCESS_UV_ENVIRONMENT_V1,
      callerVariables: HOST_PROCESS_UV_DISCOVERY_VARIABLES_V1,
    },
    notes: [
      "Used only when a caller names it; Scan never falls back to it, or from it, when a prerequisite is missing.",
      "Isolation is 'none': uv and the analyzer run as host processes with the invoking user's filesystem access.",
      "Network is not enforced at any stage. Acquisition (uv sync) may download the locked wheels into a persistent, Scan-owned uv cache under the user's cache directory, addressed by the lock's sha256, so a warm cache is not downloaded again; the scan stage passes --offline to uv, and Semgrep gets --metrics=off and SEMGREP_ENABLE_VERSION_CHECK=0, but nothing blocks a connection.",
      `uv discovers a CPython ${HOST_PROCESS_UV_PYTHON_REQUEST_V1} (uv python find ${HOST_PROCESS_UV_PYTHON_REQUEST_V1} --no-python-downloads --no-project --no-config --resolve-links), and only that discovery reads the caller variables listed in callerVariables; every analyzer spawn gets only the fixed per-OS values.`,
      "The observation records the resolved uv path and version, the discovered interpreter path and version, the uv cache key and the containment used.",
      `The run's private temporary directory must be at most ${HOST_PROCESS_TEMPORARY_PATH_LIMIT_V1} characters, because Semgrep's core fails once it passes 79; a longer host temporary directory fails the run at availability.`,
      "Semgrep, Cisco and snyk-agent-scan publish exact-pinned binary wheels for Linux (glibc 2.34 or later) amd64 and arm64, macOS arm64 (macOS 14 or later for Cisco) and Windows amd64. macOS amd64 (cryptography 50.0.0) and Windows arm64 (Semgrep, and cryptography 50.0.0 for snyk-agent-scan) have none, and Scan never builds analyzer dependencies from source, so those hosts are not supported.",
      "detector.cisco-mcp-scanner runs on Linux amd64 and arm64 only: its lock pins litellm 1.93.0, which publishes manylinux wheels alone, so macOS and Windows would need a source build Scan never performs.",
      "Cisco installs the cisco-skill-scanner-host lock (litellm 1.92.2, no win-unicode-console), not the namespace profile's cisco-skill-scanner lock, so its analyzerVersion names a different uvlock digest. Each profile's analyzerLock names the lock it installs.",
      "A detector.cisco source-tree subject runs one skill-scanner scan job per directory holding a selected SKILL.md, over that directory of the private snapshot, at most detectorOptions.concurrency (1 through 64, default 4) at a time; the jobs' SARIF is merged in job order.",
      "detector.cisco-mcp-scanner runs mcp-scanner --raw --analyzers yara static over the tool list Scan derives from the declared MCP config paths; neither analyzer calls a model or a remote service.",
      "Network, detector.snyk-agent-scan: snyk-agent-scan contacts Snyk's service during the scan stage to analyze what it finds, so for it the scan stage is not offline even though uv runs with --offline.",
      "SNYK_TOKEN reaches only the scan invocation, taken from the request env and nowhere else; the acquisition and the help check get only the fixed per-OS values, and no diagnostic carries the token or the analyzer's own output.",
      `${SARIF_NORMALIZATION_NOTE} The private snapshot root is removed, and Cisco's per-skill URIs are mapped through its JSON report.`,
      "An empty source root completes for detector.semgrep and detector.snyk-agent-scan: each runs over an empty snapshot and reports its own empty result.",
      "Residual limit on linux and darwin: a descendant that deliberately leaves the session (setsid) and also clears its environment and moves its working directory out of the run carries nothing that ties it to the run, so neither the process group nor the residual sweep can find it and it may outlive the run. This profile does not contain a hostile analyzer; linux-namespace-uv-v1 is the containment option on Linux.",
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "docker-hardened-skillspector-v1",
    isolation: "container",
    network: "none",
    backend: "oci-container",
    executables: [BASELINE_DOCKER_EXECUTABLE_V1],
    image: SKILLSPECTOR_IMAGE_V1,
    containment: [
      "--rm",
      "--network",
      "none",
      "--cpus",
      "2",
      "--memory",
      "4g",
      "--memory-swap",
      "4g",
      "--pids-limit",
      "256",
      "--cap-drop",
      "ALL",
      "--cap-add",
      "DAC_OVERRIDE",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
    ],
    acquisition: ["--context", "default", "pull", SKILLSPECTOR_IMAGE_V1],
    mounts: ["type=bind,src=<sealed analyzer snapshot>,dst=/scan,readonly"],
    environment: { policy: "allow-list-scrub", allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1 },
    notes: [
      "The image is pinned by digest and the inspected image ID must equal that digest before any scan.",
      "Each run gets a private DOCKER_CONFIG directory that is removed afterwards.",
      "Acquisition pulls only the digest-addressed reference; no tag is ever resolved.",
      "When the scan's Docker client is ended on a timeout, an abort or a failure, the container is removed by name with docker rm --force --volumes.",
      `${SARIF_NORMALIZATION_NOTE} The /scan mount prefix is removed.`,
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "docker-host-local-skillspector-v1",
    isolation: "container",
    network: "none",
    backend: "oci-container",
    executables: [
      "docker: the first docker (docker.exe on Windows) on the declared PATH, else in a well-known Docker Desktop directory; spawned and recorded by real path",
      "Windows supervisor: %SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe, never resolved through PATH",
    ],
    image: SKILLSPECTOR_LOCAL_IMAGE_TAG_V1,
    containment: [
      "--pull",
      "never",
      "--rm",
      "--network",
      "none",
      "--cpus",
      "2",
      "--memory",
      "4g",
      "--memory-swap",
      "4g",
      "--pids-limit",
      "256",
      "--cap-drop",
      "ALL",
      "--cap-add",
      "DAC_OVERRIDE",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
    ],
    acquisition: [],
    mounts: ["type=bind,src=<sealed analyzer snapshot>,dst=/scan,readonly"],
    environment: {
      policy: "fixed-values-by-os",
      values: HOST_DOCKER_ENVIRONMENT_V1,
      callerVariables: HOST_DOCKER_CONTEXT_VARIABLES_V1,
    },
    notes: [
      "Used only when a caller names it; the Linux default stays docker-hardened-skillspector-v1.",
      `This profile never pulls: it inspects only the local tag ${SKILLSPECTOR_LOCAL_IMAGE_TAG_V1} and runs with --pull never, so no stage reaches a registry.`,
      "The local tag's image is admitted when its Id is Scan's pinned digest or one of the request's acceptedImageDigests, and then runs by that bare digest; otherwise when one of its RepoDigests entries is (whole value or its @ suffix), and then runs by that full entry. Anything else fails at availability naming the pinned digest.",
      "The host's current Docker context is read once (docker context inspect) with only the caller variables listed in callerVariables; every later Docker call uses that context's local npipe:// or unix:// endpoint as DOCKER_HOST and a private, empty DOCKER_CONFIG, so no credential helper or plugin reaches the run. A context carrying TLS material is refused.",
      "The Docker client runs under the same process-tree containment as host-process-uv-v1: a POSIX process group, or a Windows Job Object.",
      "When the scan's Docker client is ended on a timeout, an abort or a failure, the container is removed by name with docker rm --force --volumes, because ending the client does not stop the container.",
      "The image is linux/amd64; arm64 hosts depend on the Docker engine's amd64 emulation.",
      `${SARIF_NORMALIZATION_NOTE} The /scan mount prefix is removed.`,
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "oci-hardened-cisco-v1",
    isolation: "container",
    network: "none",
    backend: "oci-container",
    executables: [BASELINE_DOCKER_EXECUTABLE_V1],
    image: "<caller-supplied immutable OCI layout config digest>",
    containment: [
      "--pull=never",
      "--network=none",
      "--read-only",
      "--user",
      "65532:65532",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--cpus",
      "1",
      "--memory",
      "512m",
      "--memory-swap",
      "512m",
      "--pids-limit",
      "128",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
    ],
    acquisition: [],
    mounts: [
      "type=bind,src=<declared source root>,dst=/source,readonly",
      "type=bind,src=<run output root>,dst=/output",
    ],
    environment: { policy: "allow-list-scrub", allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1 },
    notes: [
      "--pull=never means the image must already be present; this profile never reaches a registry.",
      "Container ownership is proved through a cidfile, and the container is force-removed afterwards.",
      "Any SARIF location outside the declared selected closure fails the run.",
      "The broker refuses any host that is not linux/amd64 before it creates a container.",
    ],
  },
];

const profileDocuments = new Map(
  PROFILE_DOCUMENTS.map((document) => [document.id, deepFreezeStrictJsonV1(document)]),
);

function profileDocument(id: string): DetectorExecutionProfileDocumentV1 {
  const document = profileDocuments.get(id);
  if (document === undefined)
    throw new TypeError(`invalid DetectorCapabilityV1: unknown execution profile ${id}`);
  return document;
}

type ProfileGates = Pick<DetectorExecutionProfileV1, "supportedPlatforms" | "prerequisites">;

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The shipped lock's identity; a lock that cannot be read is an incomplete install. */
function analyzerLock(path: string): Readonly<{ path: string; sha256: string }> {
  let bytes: Buffer;
  try {
    bytes = readFileSync(join(packageRoot, ...path.split("/")));
  } catch {
    throw new TypeError(
      `invalid DetectorCapabilityV1: bundled analyzer lock ${path} is unreadable`,
    );
  }
  return { path, sha256: createHash("sha256").update(bytes).digest("hex") };
}

function profile(
  id: string,
  evidence: DetectorExecutionProfileV1["evidence"],
  gates: ProfileGates,
  lock?: string,
): DetectorExecutionProfileV1 {
  const document = profileDocument(id);
  return deepFreezeStrictJsonV1({
    id: document.id,
    isolation: document.isolation,
    network: document.network,
    sha256: canonicalStrictJsonSha256V1(document),
    evidence,
    supportedPlatforms: gates.supportedPlatforms,
    prerequisites: gates.prerequisites,
    ...(lock === undefined ? {} : { analyzerLock: analyzerLock(lock) }),
  });
}

type CapabilityAuthoring = Omit<
  DetectorCapabilityV1,
  "protocol" | "capabilitySha256" | "supportedPlatforms" | "prerequisites"
>;

function capability(authoring: CapabilityAuthoring): DetectorCapabilityV1 {
  // The capability's own gates restate its default profile's, so the two cannot drift.
  const base = {
    protocol: "DetectorCapabilityV1" as const,
    ...authoring,
    supportedPlatforms: authoring.executionProfile.supportedPlatforms,
    prerequisites: authoring.executionProfile.prerequisites,
  };
  return deepFreezeStrictJsonV1({
    ...base,
    capabilitySha256: canonicalStrictJsonSha256V1({
      domain: "aih.detector-capability-v1",
      capability: base,
    }),
  });
}

const BWRAP_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "executable",
  id: BASELINE_BWRAP_EXECUTABLE_V1,
  required: true,
  detail: `Install bubblewrap so that ${BASELINE_BWRAP_EXECUTABLE_V1} exists; Scan refuses to run this analyzer unsandboxed.`,
};
const UV_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "executable",
  id: BASELINE_UV_EXECUTABLE_V1,
  required: true,
  detail: `Install uv at ${BASELINE_UV_EXECUTABLE_V1}; the analyzer environment is resolved from the bundled uv.lock.`,
};
const HOST_UV_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "host-executable",
  id: "uv",
  required: true,
  detail:
    "Install uv so that it is on PATH or in a well-known directory (~/.local/bin, ~/.cargo/bin, Homebrew, /usr/local/bin); the analyzer environment is resolved from the bundled uv.lock.",
};
const HOST_PYTHON_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "uv-python",
  id: HOST_PROCESS_UV_PYTHON_REQUEST_V1,
  required: true,
  detail: `Provide a CPython ${HOST_PROCESS_UV_PYTHON_REQUEST_V1} that uv can discover (on PATH, uv-managed, or registered with Windows); uv runs with --no-python-downloads, so it never fetches one, and whether one exists is known only once uv looks.`,
};
const HOST_DOCKER_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "host-executable",
  id: "docker",
  required: true,
  detail:
    "Install Docker so that docker is on PATH or in a well-known Docker Desktop directory; this profile runs the SkillSpector container through the host's current Docker context.",
};
const DOCKER_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "executable",
  id: BASELINE_DOCKER_EXECUTABLE_V1,
  required: true,
  detail: `Install Docker so that ${BASELINE_DOCKER_EXECUTABLE_V1} exists; this detector has no non-container backend in Scan.`,
};
const ACQUISITION_NETWORK_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "network",
  id: "https://pypi.org/simple",
  required: true,
  detail:
    "The acquisition stage resolves the locked analyzer from the default index unless the uv cache already holds it; Scan cannot determine that without running the stage.",
};
const CISCO_LOCK_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "bundled-asset",
  id: "tools/baseline-analyzers/cisco-skill-scanner/uv.lock",
  required: true,
  detail:
    "The exact-pinned analyzer lock ships with this package; a missing lock means the install is incomplete.",
};
const CISCO_HOST_LOCK_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "bundled-asset",
  id: "tools/baseline-analyzers/cisco-skill-scanner-host/uv.lock",
  required: true,
  detail:
    "The exact-pinned host analyzer lock ships with this package; a missing lock means the install is incomplete.",
};
const SEMGREP_LOCK_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "bundled-asset",
  id: "tools/baseline-analyzers/semgrep/uv.lock",
  required: true,
  detail:
    "The exact-pinned analyzer lock ships with this package; a missing lock means the install is incomplete.",
};
const MCP_SCANNER_LOCK_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "bundled-asset",
  id: "tools/baseline-analyzers/cisco-mcp-scanner/uv.lock",
  required: true,
  detail:
    "The exact-pinned analyzer lock ships with this package; a missing lock means the install is incomplete.",
};
const SNYK_LOCK_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "bundled-asset",
  id: "tools/baseline-analyzers/snyk-agent-scan/uv.lock",
  required: true,
  detail:
    "The exact-pinned analyzer lock ships with this package; a missing lock means the install is incomplete.",
};
const SNYK_TOKEN_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "environment-variable",
  id: "SNYK_TOKEN",
  required: true,
  detail:
    "Pass SNYK_TOKEN in the request env; Scan reads it from nowhere else, gives it only to the scan invocation and never records its value.",
};

const NATIVE_GATES: ProfileGates = { supportedPlatforms: EVERY_PLATFORM, prerequisites: [] };
const CISCO_GATES: ProfileGates = {
  supportedPlatforms: LINUX_AMD64,
  prerequisites: [
    BWRAP_PREREQUISITE,
    UV_PREREQUISITE,
    CISCO_LOCK_PREREQUISITE,
    ACQUISITION_NETWORK_PREREQUISITE,
  ],
};
/**
 * The OCI capture profile runs only the Docker CLI at exactly the gated absolute path, never a
 * `PATH` lookup, against a caller-supplied image that must already be present
 * (`--pull=never`, `--network=none`).
 * It needs no bubblewrap, uv, uv.lock or acquisition network; the image itself is run
 * material the caller supplies, so it is validated with the request, not probed here.
 */
const CISCO_OCI_GATES: ProfileGates = {
  supportedPlatforms: LINUX_AMD64,
  prerequisites: [
    {
      kind: "executable",
      id: BASELINE_DOCKER_EXECUTABLE_V1,
      required: true,
      detail: `Install Docker so that ${BASELINE_DOCKER_EXECUTABLE_V1} exists; the OCI capture profile runs the caller-supplied image through it and never pulls.`,
    },
  ],
};
const SEMGREP_GATES: ProfileGates = {
  supportedPlatforms: LINUX_AMD64,
  prerequisites: [
    BWRAP_PREREQUISITE,
    UV_PREREQUISITE,
    SEMGREP_LOCK_PREREQUISITE,
    ACQUISITION_NETWORK_PREREQUISITE,
  ],
};
/**
 * The host profile needs no bubblewrap: uv is resolved on the host, Python is discovered by
 * uv, and the process tree is contained by a process group or a Windows Job Object.
 */
const SEMGREP_HOST_GATES: ProfileGates = {
  supportedPlatforms: HOST_UV_PLATFORMS,
  prerequisites: [
    HOST_UV_PREREQUISITE,
    HOST_PYTHON_PREREQUISITE,
    SEMGREP_LOCK_PREREQUISITE,
    ACQUISITION_NETWORK_PREREQUISITE,
  ],
};
const CISCO_HOST_GATES: ProfileGates = {
  supportedPlatforms: HOST_UV_PLATFORMS,
  prerequisites: [
    HOST_UV_PREREQUISITE,
    HOST_PYTHON_PREREQUISITE,
    CISCO_HOST_LOCK_PREREQUISITE,
    ACQUISITION_NETWORK_PREREQUISITE,
  ],
};
const MCP_SCANNER_HOST_GATES: ProfileGates = {
  supportedPlatforms: MCP_SCANNER_PLATFORMS,
  prerequisites: [
    HOST_UV_PREREQUISITE,
    HOST_PYTHON_PREREQUISITE,
    MCP_SCANNER_LOCK_PREREQUISITE,
    ACQUISITION_NETWORK_PREREQUISITE,
  ],
};
const SNYK_HOST_GATES: ProfileGates = {
  supportedPlatforms: SNYK_PLATFORMS,
  prerequisites: [
    HOST_UV_PREREQUISITE,
    HOST_PYTHON_PREREQUISITE,
    SNYK_LOCK_PREREQUISITE,
    ACQUISITION_NETWORK_PREREQUISITE,
    SNYK_TOKEN_PREREQUISITE,
  ],
};
const SKILLSPECTOR_HOST_GATES: ProfileGates = {
  supportedPlatforms: HOST_DOCKER_PLATFORMS,
  prerequisites: [
    HOST_DOCKER_PREREQUISITE,
    {
      kind: "container-image",
      id: SKILLSPECTOR_LOCAL_IMAGE_TAG_V1,
      required: true,
      detail:
        "Build or load the approved SkillSpector image under this local tag; this profile never pulls, and whether the tag is present and carries an allowed digest cannot be determined without Docker.",
    },
  ],
};
const SKILLSPECTOR_GATES: ProfileGates = {
  supportedPlatforms: LINUX_AMD64,
  prerequisites: [
    DOCKER_PREREQUISITE,
    {
      kind: "container-image",
      id: SKILLSPECTOR_IMAGE_V1,
      required: true,
      detail:
        "Scan pulls this exact digest-addressed image when it is absent; whether it is present cannot be determined without Docker.",
    },
  ],
};

const OBSERVATION = "BaselineAnalyzerObservationV1" as const;
const NATIVE_PROFILE = profile("in-process-native-v1", OBSERVATION, NATIVE_GATES);
/**
 * The in-process profiles for the native trust lint and the binding scan gate's inspectors.
 * They run everywhere and need nothing; the detectors that use them register them.
 */
export const IN_PROCESS_TRUST_LINT_PROFILE_V1: DetectorExecutionProfileV1 = profile(
  "in-process-trust-lint-v1",
  OBSERVATION,
  NATIVE_GATES,
);
export const IN_PROCESS_BINDING_GATE_PROFILE_V1: DetectorExecutionProfileV1 = profile(
  "in-process-binding-gate-v1",
  OBSERVATION,
  NATIVE_GATES,
);
const CISCO_NAMESPACE_PROFILE = profile(
  "linux-namespace-uv-v1",
  OBSERVATION,
  CISCO_GATES,
  CISCO_LOCK_PREREQUISITE.id,
);
const CISCO_HOST_PROFILE = profile(
  "host-process-uv-v1",
  OBSERVATION,
  CISCO_HOST_GATES,
  CISCO_HOST_LOCK_PREREQUISITE.id,
);
const CISCO_OCI_PROFILE = profile("oci-hardened-cisco-v1", "ScanCandidateV2", CISCO_OCI_GATES);
const SEMGREP_NAMESPACE_PROFILE = profile(
  "linux-namespace-uv-v1",
  OBSERVATION,
  SEMGREP_GATES,
  SEMGREP_LOCK_PREREQUISITE.id,
);
const SEMGREP_HOST_PROFILE = profile(
  "host-process-uv-v1",
  OBSERVATION,
  SEMGREP_HOST_GATES,
  SEMGREP_LOCK_PREREQUISITE.id,
);
const MCP_SCANNER_HOST_PROFILE = profile(
  "host-process-uv-v1",
  OBSERVATION,
  MCP_SCANNER_HOST_GATES,
  MCP_SCANNER_LOCK_PREREQUISITE.id,
);
const SNYK_HOST_PROFILE = profile(
  "host-process-uv-v1",
  OBSERVATION,
  SNYK_HOST_GATES,
  SNYK_LOCK_PREREQUISITE.id,
);
const SKILLSPECTOR_PROFILE = profile(
  "docker-hardened-skillspector-v1",
  OBSERVATION,
  SKILLSPECTOR_GATES,
);
const SKILLSPECTOR_HOST_PROFILE = profile(
  "docker-host-local-skillspector-v1",
  OBSERVATION,
  SKILLSPECTOR_HOST_GATES,
);

const CAPABILITIES: readonly DetectorCapabilityV1[] = Object.freeze(
  [
    capability({
      detectorId: "detector.aih-native",
      analyzerIdentity: BASELINE_NATIVE_ANALYZER_IDENTITY_V1,
      analyzerVersion: BASELINE_NATIVE_ANALYZER_IDENTITY_V1,
      backend: "in-process",
      executionProfile: NATIVE_PROFILE,
      executionProfiles: [NATIVE_PROFILE],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "The declared source root must hold at least one file.",
        "Every declared selected closure path must exist as a regular file under that root.",
        "A top-level .git directory is not given to the analyzer, so its files are reported as uncovered.",
      ],
      emptySource: "refused",
      outputs: ["aih-baseline-native-v1"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
    capability({
      detectorId: "detector.cisco",
      analyzerIdentity: null,
      analyzerVersion: CISCO_SKILL_SCANNER_VERSION_V1,
      backend: "linux-namespace-uv",
      executionProfile: CISCO_NAMESPACE_PROFILE,
      executionProfiles: [CISCO_NAMESPACE_PROFILE, CISCO_HOST_PROFILE, CISCO_OCI_PROFILE],
      subjectKinds: ["skill-directory", "source-tree"],
      subjectRequirements: [
        "A skill-directory subject: the declared source root must hold a top-level SKILL.md, and that SKILL.md must be one of the declared selected closure paths; the scan must cover every SKILL.md the sealed snapshot holds and may skip none.",
        "A source-tree subject runs one skill-scanner job per directory holding a selected SKILL.md, in Core's order, and only under host-process-uv-v1; a selection with no SKILL.md is refused, and detectorOptions.concurrency bounds how many jobs run at once.",
        "Scan never creates, renames, copies or discovers a SKILL.md to satisfy either requirement.",
        "The oci-hardened-cisco-v1 profile additionally needs a caller-supplied immutable OCI layout, runtime registration, broker identity and annex payloads.",
        "A top-level .git directory is not given to the analyzer, so its files are reported as uncovered.",
      ],
      emptySource: "refused",
      outputs: ["sarif-2.1.0"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
    capability({
      detectorId: "detector.cisco-mcp-scanner",
      analyzerIdentity: null,
      analyzerVersion: CISCO_MCP_SCANNER_VERSION_V1,
      backend: "host-process-uv",
      executionProfile: MCP_SCANNER_HOST_PROFILE,
      executionProfiles: [MCP_SCANNER_HOST_PROFILE],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "detectorOptions.mcpConfigPaths names the MCP config files to read, each a selected regular file, in Core's order; the tool list is derived from them before anything runs.",
        "A selection with no MCP config path, or config files declaring no tool, is refused before anything runs.",
        "The host profile is this detector's only profile, and it runs only when the request names it.",
      ],
      emptySource: "refused",
      outputs: ["sarif-2.1.0"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
    capability({
      detectorId: "detector.semgrep",
      analyzerIdentity: null,
      analyzerVersion: SEMGREP_VERSION_V1,
      backend: "linux-namespace-uv",
      executionProfile: SEMGREP_NAMESPACE_PROFILE,
      executionProfiles: [SEMGREP_NAMESPACE_PROFILE, SEMGREP_HOST_PROFILE],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "Every declared selected closure path must exist as a regular file under the declared source root.",
        "A source root with no entries at all is accepted only with an empty selection; Semgrep then runs over an empty snapshot and reports its own empty SARIF.",
        "The analyzer is given the whole tree, a top-level .git and dependency or build directories included, as Core's own run is.",
      ],
      emptySource: "completes",
      outputs: ["sarif-2.1.0"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
    capability({
      detectorId: "detector.skillspector",
      analyzerIdentity: null,
      analyzerVersion: `${SKILLSPECTOR_SOURCE_REVISION_V1}@${SKILLSPECTOR_IMAGE_V1.slice(
        SKILLSPECTOR_IMAGE_V1.indexOf("@") + 1,
      )}`,
      backend: "oci-container",
      executionProfile: SKILLSPECTOR_PROFILE,
      executionProfiles: [SKILLSPECTOR_PROFILE, SKILLSPECTOR_HOST_PROFILE],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "A source root with no entries at all is accepted only with an empty selection; SkillSpector then runs over an empty snapshot and reports its own SARIF.",
        "The source root path must be representable as a Docker bind mount, so it may hold no comma or control character.",
        "The analyzer is given the whole tree, a top-level .git and dependency or build directories included, as Core's own run is.",
      ],
      emptySource: "completes",
      outputs: ["sarif-2.1.0"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
    capability({
      detectorId: "detector.snyk-agent-scan",
      analyzerIdentity: null,
      analyzerVersion: SNYK_AGENT_SCAN_VERSION,
      backend: "host-process-uv",
      executionProfile: SNYK_HOST_PROFILE,
      executionProfiles: [SNYK_HOST_PROFILE],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "The request env must carry SNYK_TOKEN, and nothing else; without it the run is refused prerequisite-missing before anything runs.",
        "A source root with no entries at all is accepted only with an empty selection; snyk-agent-scan then runs over an empty snapshot and reports what it reports.",
        "The host profile is this detector's only profile, and it runs only when the request names it.",
      ],
      emptySource: "completes",
      outputs: ["sarif-2.1.0"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
    capability({
      detectorId: "detector.aih-trust-lint",
      analyzerIdentity: "aih-trust-lint@1.0.0",
      analyzerVersion: "1.0.0",
      backend: "in-process",
      executionProfile: IN_PROCESS_TRUST_LINT_PROFILE_V1,
      executionProfiles: [IN_PROCESS_TRUST_LINT_PROFILE_V1],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "Every declared selected closure path must exist as a regular file under the declared source root.",
        "detectorOptions may carry internalScopes and mcpConfigPaths, validated as Core validates them; any other key is refused.",
        "An empty selection completes with an empty SARIF run.",
      ],
      emptySource: "completes",
      outputs: ["sarif-2.1.0"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
    capability({
      detectorId: "detector.aih-binding-gate",
      analyzerIdentity: "aih-binding-gate@1.0.0",
      analyzerVersion: "1.0.0",
      backend: "in-process",
      executionProfile: IN_PROCESS_BINDING_GATE_PROFILE_V1,
      executionProfiles: [IN_PROCESS_BINDING_GATE_PROFILE_V1],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "The selected closure is Core's binding inventory: every file outside .git, in Core's order, each a regular file under the declared source root.",
        "detectorOptions is absent or an empty object.",
        "An empty selection completes with an empty SARIF run.",
      ],
      emptySource: "completes",
      outputs: ["sarif-2.1.0"],
      contracts: {
        capabilityVersion: 1,
        candidateProtocol: "BaselineAnalyzerObservationV1",
        findingsProtocol: "ScanFindingsV1",
        coreContractCommit: AI_HARNESS_STRICT_V2_COMMIT,
        decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
      },
    }),
  ].sort((left, right) => codeUnitCompare(left.detectorId, right.detectorId)),
);

/** Every detector this package can execute, in canonical detector-ID order. */
export function listDetectorCapabilitiesV1(): readonly DetectorCapabilityV1[] {
  return CAPABILITIES;
}

/** The capability for one detector ID, or `undefined` when Scan owns no such detector. */
export function resolveDetectorCapabilityV1(detectorId: unknown): DetectorCapabilityV1 | undefined {
  if (typeof detectorId !== "string") return undefined;
  return CAPABILITIES.find((entry) => entry.detectorId === detectorId);
}

/** The readable document whose canonical digest is that profile's `sha256`. */
export function resolveDetectorExecutionProfileDocumentV1(
  profileId: unknown,
): DetectorExecutionProfileDocumentV1 | undefined {
  if (typeof profileId !== "string") return undefined;
  return profileDocuments.get(profileId);
}

/** Every readable execution-profile document this package publishes. */
export function listDetectorExecutionProfileDocumentsV1(): readonly DetectorExecutionProfileDocumentV1[] {
  return Object.freeze([...profileDocuments.values()]);
}
