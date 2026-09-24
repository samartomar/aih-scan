import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";
import {
  buildTrustLintTreeV1,
  type TrustLintTreeEntryV1,
  type TrustLintTreeV1,
} from "../trust-lint/inventory.js";
import { validateSelectedClosurePathsV1 } from "../trust-lint/selection.js";
import {
  inspectBindingGateContentRiskV1,
  inspectBindingGateSuspiciousExecutionV1,
} from "./content-risk.js";
import {
  type BindingGateDimensionReportV1,
  type BindingGateSarifV1,
  bindingGateReportsToSarifV1,
} from "./findings.js";
import {
  inspectBindingGateBinariesV1,
  inspectBindingGateHooksV1,
  inspectBindingGateLicensesV1,
  inspectBindingGateMcpV1,
  inspectBindingGateNetworkUpdateV1,
  inspectBindingGateScriptsV1,
  inspectBindingGateStructureV1,
  inspectBindingGateTelemetryV1,
  inspectBindingGateWriteDestinationsV1,
} from "./inspectors.js";

/**
 * `detector.aih-binding-gate` — the FAST-tier binding scan-gate inspectors,
 * ported from Core's `src/binding/scan-gate.ts` (C2a decision 3). Pure
 * analysis: no process spawning, no network.
 *
 * {@link runBindingGateV1} is the engine function behind Core's request:
 * `subject.sourceRoot` is the resolved binding tree and
 * `subject.selectedClosurePaths` is Core's binding inventory of it (every
 * file outside `.git`, Core's `BINDING_SCAN_SKIP_DIRS`, in Core's
 * localeCompare order — the fileset the tree digest covers). Scan never
 * derives that inventory itself (decision 1). The eleven dimensions run in
 * Core's `W2_DEFAULT_INSPECTORS` order over exactly those files: structure,
 * scripts, binaries, hooks, mcp, licenses, hidden-unicode (content risk),
 * suspicious-execution, network-update, telemetry, write-destinations.
 *
 * Stays in Core: source resolution (git/npm, checkout cache), digest checks
 * and the identity-coverage report, acceptance matching, rollup, closure
 * classification, the typography overlay and the gate decision. The dormant
 * duplicate engines in Core's `scan-cache-tiers.ts:499-555` are deleted in
 * Core, not moved here.
 */

export const BINDING_GATE_DETECTOR_ID_V1 = "detector.aih-binding-gate";
/** Core-requested execution profile id (in-process, every platform). */
export const BINDING_GATE_PROFILE_ID_V1 = "in-process-binding-gate-v1";

/** The eleven D12 FAST-tier dimensions, in Core's inspector registry order. */
export const BINDING_GATE_DIMENSIONS_V1: readonly string[] = Object.freeze([
  "structure",
  "scripts",
  "binaries",
  "hooks",
  "mcp",
  "licenses",
  "hidden-unicode",
  "suspicious-execution",
  "network-update",
  "telemetry",
  "write-destinations",
]);

export type BindingGateRefusalReasonV1 = "detector-options-invalid" | "subject-requirement-unmet";

export type BindingGateRunOutcomeV1 =
  | Readonly<{ kind: "completed"; sarif: BindingGateSarifV1; sarifText: string }>
  | Readonly<{ kind: "refused"; reason: BindingGateRefusalReasonV1; detail: string }>
  | Readonly<{ kind: "failed"; stage: "execution"; detail: string; cause?: "cancelled" }>;

export interface BindingGateRunRequestV1 {
  /** `subject.sourceRoot`: absolute realpath of the resolved binding tree. */
  readonly sourceRoot: string;
  /** `subject.selectedClosurePaths`: Core's binding inventory, in Core's order. */
  readonly selectedClosurePaths: unknown;
  /** The detector takes no options: absent or `{}`. */
  readonly detectorOptions?: unknown;
  readonly signal?: AbortSignal;
}

const MAX_DETAIL_LENGTH = 300;

function bounded(detail: string): string {
  const visible = detail.replace(/[\p{C}]/gu, " ");
  return visible.length > MAX_DETAIL_LENGTH
    ? `${visible.slice(0, MAX_DETAIL_LENGTH - 3)}...`
    : visible;
}

function refused(reason: BindingGateRefusalReasonV1, detail: string): BindingGateRunOutcomeV1 {
  return Object.freeze({ kind: "refused" as const, reason, detail: bounded(detail) });
}

/** Read through a call so the post-inspection check is not narrowed away. */
function aborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function cancelled(): BindingGateRunOutcomeV1 {
  return Object.freeze({
    kind: "failed" as const,
    stage: "execution" as const,
    detail: "binding gate inspection was cancelled before it completed",
    cause: "cancelled" as const,
  });
}

function isEmptyOptions(value: unknown): boolean {
  if (value === undefined) return true;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null) && Object.keys(value).length === 0;
}

/**
 * Runs all eleven FAST-tier inspectors in Core's registry order over the
 * tree's listed files and returns one frozen report per dimension — Core's
 * `inspectTree` with the default inspectors. The tree's `files` are the
 * inventory; {@link runBindingGateV1} narrows them to Core's declared paths.
 */
export function inspectBindingGateTreeV1(tree: TrustLintTreeV1): BindingGateDimensionReportV1[] {
  const reports: BindingGateDimensionReportV1[] = [
    inspectBindingGateStructureV1(tree),
    inspectBindingGateScriptsV1(tree),
    inspectBindingGateBinariesV1(tree),
    inspectBindingGateHooksV1(tree),
    inspectBindingGateMcpV1(tree),
    inspectBindingGateLicensesV1(tree),
    inspectBindingGateContentRiskV1(tree),
    inspectBindingGateSuspiciousExecutionV1(tree),
    inspectBindingGateNetworkUpdateV1(tree),
    inspectBindingGateTelemetryV1(tree),
    inspectBindingGateWriteDestinationsV1(tree),
  ];
  return deepFreezeStrictJsonV1(structuredClone(reports));
}

/** The sealed tree narrowed to the declared paths, in the declared order. */
export function bindingGateSelectionViewV1(
  tree: TrustLintTreeV1,
  selection: readonly string[],
): TrustLintTreeV1 {
  const files: readonly TrustLintTreeEntryV1[] = Object.freeze(
    selection.map((rel) => {
      const entry = tree.fileEntry(rel);
      if (entry === undefined) throw new TypeError(`binding-gate: unlisted path ${rel}`);
      return entry;
    }),
  );
  const listed = new Set(selection);
  return Object.freeze({
    files,
    *matching(predicate: (entry: TrustLintTreeEntryV1) => boolean) {
      for (const entry of files) if (predicate(entry)) yield entry;
    },
    fileEntry: (rel: string) => (listed.has(rel) ? tree.fileEntry(rel) : undefined),
    pathKind: tree.pathKind,
    isDirectory: tree.isDirectory,
    hasFile: (rel: string) => listed.has(rel),
    readText: (rel: string) => (listed.has(rel) ? tree.readText(rel) : undefined),
  });
}

/**
 * The `detector.aih-binding-gate` engine function. A malformed selection or
 * source root is `subject-requirement-unmet`; any detector option is
 * `detector-options-invalid`; an already-aborted signal fails with
 * `cause: "cancelled"` (checked again before returning, the inspection being
 * synchronous). The SARIF carries one result per finding plus, under
 * `runs[0].properties["aih-binding-gate/v1"].dimensions`, every dimension's
 * status and finding count.
 */
export function runBindingGateV1(request: BindingGateRunRequestV1): BindingGateRunOutcomeV1 {
  if (aborted(request.signal)) return cancelled();
  if (typeof request.sourceRoot !== "string" || request.sourceRoot.length === 0)
    return refused("subject-requirement-unmet", "sourceRoot must be a non-empty absolute path");
  let tree: TrustLintTreeV1;
  try {
    tree = buildTrustLintTreeV1(request.sourceRoot);
  } catch (error) {
    return refused(
      "subject-requirement-unmet",
      `source tree could not be enumerated: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
  const selection = validateSelectedClosurePathsV1(request.selectedClosurePaths, tree);
  if (!selection.ok) return refused("subject-requirement-unmet", selection.detail);
  if (!isEmptyOptions(request.detectorOptions))
    return refused(
      "detector-options-invalid",
      "detector.aih-binding-gate takes no detectorOptions",
    );
  let sarif: BindingGateSarifV1;
  try {
    sarif = bindingGateReportsToSarifV1(
      inspectBindingGateTreeV1(bindingGateSelectionViewV1(tree, selection.selection)),
    );
  } catch (error) {
    return Object.freeze({
      kind: "failed" as const,
      stage: "execution" as const,
      detail: bounded(error instanceof Error ? error.message : "binding gate inspection failed"),
    });
  }
  if (aborted(request.signal)) return cancelled();
  return Object.freeze({ kind: "completed" as const, sarif, sarifText: JSON.stringify(sarif) });
}

export {
  inspectBindingGateContentRiskV1,
  inspectBindingGateSuspiciousExecutionV1,
} from "./content-risk.js";
export type {
  BindingGateCoverageV1,
  BindingGateDimensionReportV1,
  BindingGateFindingV1,
  BindingGateSarifResultV1,
  BindingGateSarifV1,
  BindingGateSeverityV1,
} from "./findings.js";
export {
  BINDING_GATE_CAPS_V1,
  BINDING_GATE_MAX_FINDINGS_PER_DIMENSION_V1,
  BINDING_GATE_MAX_SCAN_BYTES_V1,
  BINDING_GATE_STRUCTURE_MAX_FILE_BYTES_V1,
  BINDING_GATE_STRUCTURE_MAX_FILES_V1,
  bindingGateReportsToSarifV1,
  bindingGateSeverityForCodeV1,
} from "./findings.js";
export {
  inspectBindingGateBinariesV1,
  inspectBindingGateHooksV1,
  inspectBindingGateLicensesV1,
  inspectBindingGateMcpV1,
  inspectBindingGateNetworkUpdateV1,
  inspectBindingGateScriptsV1,
  inspectBindingGateStructureV1,
  inspectBindingGateTelemetryV1,
  inspectBindingGateWriteDestinationsV1,
  isBindingGateDocSurfaceV1,
} from "./inspectors.js";
export type {
  FileTypographyVerdictV1,
  SentinelLineShapeV1,
  TypographyAdvisoryV1,
  TypographyOccurrenceV1,
} from "./visible-typography.js";
export {
  classifyFileTypographyV1,
  classifySentinelLineShapeV1,
  enumerateTypographyV1,
  fileHasBlockingTypographyCharV1,
} from "./visible-typography.js";
