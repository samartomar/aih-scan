import {
  BASELINE_ENVIRONMENT_ALLOW_LIST_V1,
  BASELINE_HOST_FIXED_ENVIRONMENT_V1,
  BASELINE_NATIVE_ANALYZER_IDENTITY_V1,
  BASELINE_PYTHON_EXECUTABLE_V1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  SEMGREP_VERSION_V1,
  SKILLSPECTOR_IMAGE_V1,
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

/**
 * What Scan can honestly execute, stated as data instead of as code a caller must write.
 *
 * Honesty rules enforced by construction:
 *
 * - `supportedPlatforms` restates the platform gates the execution code already
 *   applies. Scan's hardened detector profiles are Linux `amd64` only; only the
 *   in-process `aih-native` analyzer runs anywhere else, and it is not isolated
 *   because it spawns nothing.
 * - Every execution profile carries its own `supportedPlatforms` and `prerequisites`,
 *   and the runner gates on the selected profile's; a capability's own fields restate
 *   its default profile's. `host-process-uv-v1` is never a default: it runs only when
 *   named, reports `isolation: "none"` and `network: "unenforced"`, and stays Linux-only
 *   until Windows process-tree containment and a hosted macOS proof exist.
 * - `executionProfile.sha256` is the digest of the readable profile document this
 *   module publishes, so "which profile ran" is answerable from the package rather
 *   than from an opaque number. It is deliberately NOT the author-supplied
 *   `executionProfileSha256` a registration or candidate carries: that digest is taken
 *   over the OCI build inputs of one capture, not over any readable document.
 * - `analyzerIdentity` is `null` wherever Scan does not mint one. Only the in-process
 *   analyzer has a Scan-owned identity; for the vendor analyzers the identity is
 *   supplied by whoever registers the detector.
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
  readonly kind:
    | "executable"
    | "container-image"
    | "environment-variable"
    | "network"
    | "bundled-asset";
  /** `/usr/bin/bwrap`, an immutable OCI reference, an environment variable name, a host. */
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
   * `allow-list-scrub`: the caller environment reduced to `allowed`. `fixed-values`: the
   * spawn's whole environment is exactly `values`; a `<…>` value is a run-private path.
   */
  readonly environment:
    | Readonly<{
        policy: "allow-list-scrub";
        allowed: readonly string[];
      }>
    | Readonly<{
        policy: "fixed-values";
        values: Readonly<Record<string, string>>;
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
      "This is the only profile that runs on a host other than Linux amd64.",
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
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "host-process-uv-v1",
    isolation: "none",
    network: "unenforced",
    backend: "host-process-uv",
    executables: [BASELINE_UV_EXECUTABLE_V1],
    image: null,
    containment: [],
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
      policy: "fixed-values",
      values: {
        ...BASELINE_HOST_FIXED_ENVIRONMENT_V1,
        HOME: "<run home directory>",
        TMPDIR: "<run temporary directory>",
        UV_CACHE_DIR: "<run cache directory>",
        UV_PROJECT_ENVIRONMENT: "<run venv directory>",
      },
    },
    notes: [
      "Used only when a caller names it; Scan never falls back to it when bubblewrap is missing.",
      "Isolation is 'none': uv and Semgrep run as host processes with the invoking user's filesystem access.",
      "Network is not enforced at any stage; the scan stage passes --offline to uv and --metrics=off to Semgrep, but nothing blocks a connection.",
      "Each spawn leads its own process group; Scan signals the group on timeout or when descendants outlive the leader, polls for it for a bounded time, and fails the spawn as truncated with a nonzero code if it is still present. Cleanup of every descendant is not guaranteed.",
      "Every spawn receives only run-private HOME, TMPDIR and uv paths plus fixed PATH, LANG and Python values; no caller variable reaches it.",
      "Windows is refused because Scan has no proven fail-closed process-tree containment there; macOS is refused pending a hosted proof.",
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
    ],
  },
  {
    protocol: "DetectorExecutionProfileDocumentV1",
    id: "oci-hardened-cisco-v1",
    isolation: "container",
    network: "none",
    backend: "oci-container",
    executables: ["docker"],
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

function profile(
  id: string,
  evidence: DetectorExecutionProfileV1["evidence"],
  gates: ProfileGates,
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
const PYTHON_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "executable",
  id: BASELINE_PYTHON_EXECUTABLE_V1,
  required: true,
  detail: `Install Python 3.13 at ${BASELINE_PYTHON_EXECUTABLE_V1}; uv runs with --no-python-downloads, so it never fetches an interpreter.`,
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
const SEMGREP_LOCK_PREREQUISITE: DetectorPrerequisiteV1 = {
  kind: "bundled-asset",
  id: "tools/baseline-analyzers/semgrep/uv.lock",
  required: true,
  detail:
    "The exact-pinned analyzer lock ships with this package; a missing lock means the install is incomplete.",
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
 * The host profile needs no bubblewrap. Windows stays excluded until Scan has fail-closed
 * process-tree containment there, and macOS until a hosted proof exists.
 */
const SEMGREP_HOST_GATES: ProfileGates = {
  supportedPlatforms: LINUX_AMD64,
  prerequisites: [
    UV_PREREQUISITE,
    PYTHON_PREREQUISITE,
    SEMGREP_LOCK_PREREQUISITE,
    ACQUISITION_NETWORK_PREREQUISITE,
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
const CISCO_NAMESPACE_PROFILE = profile("linux-namespace-uv-v1", OBSERVATION, CISCO_GATES);
const CISCO_OCI_PROFILE = profile("oci-hardened-cisco-v1", "ScanCandidateV2", CISCO_GATES);
const SEMGREP_NAMESPACE_PROFILE = profile("linux-namespace-uv-v1", OBSERVATION, SEMGREP_GATES);
const SEMGREP_HOST_PROFILE = profile("host-process-uv-v1", OBSERVATION, SEMGREP_HOST_GATES);
const SKILLSPECTOR_PROFILE = profile(
  "docker-hardened-skillspector-v1",
  OBSERVATION,
  SKILLSPECTOR_GATES,
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
      ],
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
      executionProfiles: [CISCO_NAMESPACE_PROFILE, CISCO_OCI_PROFILE],
      subjectKinds: ["skill-directory"],
      subjectRequirements: [
        "The declared source root must hold a top-level SKILL.md, and that SKILL.md must be one of the declared selected closure paths.",
        "Scan never creates, renames, copies or discovers a SKILL.md to satisfy this requirement.",
        "The scan must cover every SKILL.md the sealed snapshot holds and may skip none.",
        "The oci-hardened-cisco-v1 profile additionally needs a caller-supplied immutable OCI layout, runtime registration, broker identity and annex payloads.",
      ],
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
        "The declared source root must hold at least one file.",
        "Every declared selected closure path must exist as a regular file under that root.",
      ],
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
      executionProfiles: [SKILLSPECTOR_PROFILE],
      subjectKinds: ["source-tree"],
      subjectRequirements: [
        "The declared source root must hold at least one file.",
        "The source root path must be representable as a Docker bind mount, so it may hold no comma or control character.",
      ],
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
