import type { FindingPart, SarifLevel, Severity } from "../contracts/risk.js";
import type { RoutedFile, ToolId } from "../contracts/routing.js";
import type { ScanMode } from "../contracts/validate.js";
import type { SnapshotFile } from "./snapshot.js";

/** One item as every tool receives it: the exact snapshot bytes, their routing and the read-only copy. */
export interface AssessItem {
  readonly scanKey: string;
  readonly files: readonly SnapshotFile[];
  readonly routed: ReadonlyMap<string, RoutedFile>;
  /** The Scan-owned read-only working copy holding exactly `files`. */
  readonly snapshotRoot: string;
}

export interface ToolContext {
  readonly mode: ScanMode;
  readonly signal: AbortSignal;
  readonly internalScopes: readonly string[];
}

export interface ToolFinding {
  readonly ruleId: string;
  readonly message: string;
  readonly path: string;
  readonly line: number;
  readonly part: FindingPart;
  readonly severity?: Severity;
  readonly level?: SarifLevel;
  readonly confidence?: number;
  readonly fingerprint?: string;
}

/** Why a tool did not run. `not selected` is the caller's choice; the rest are failures. */
export type NotRunReason =
  | "not selected"
  | "unavailable"
  | "failed"
  | "timeout"
  | "refused"
  | "cancelled";

export type ToolRun =
  | Readonly<{
      status: "ran";
      version: string;
      mode: ScanMode;
      ai?: Readonly<{ via: "cli" | "local" | "provider"; provider: string; model: string }>;
      findings: readonly ToolFinding[];
      suppressed?: readonly Readonly<{ count: number; reason: string }>[];
      /** Rule descriptions for the SARIF driver, by rule id. */
      rules?: Readonly<Record<string, string>>;
    }>
  | Readonly<{
      status: "not-run";
      version: string;
      mode: ScanMode;
      reason: NotRunReason;
      detail?: string;
    }>;

/**
 * A routed analyzer. Adapters read only `item.snapshotRoot` (or the in-memory bytes, which are
 * the same bytes), never execute supplied content and honour `context.signal`.
 */
export interface ToolAdapter {
  readonly id: ToolId;
  /** The pinned version this adapter runs, recorded even when the tool does not run. */
  readonly version: string;
  run(item: AssessItem, context: ToolContext): Promise<ToolRun>;
}

/** SkillSpector before its native adapter lands: always truthfully unavailable. */
export const unavailableSkillSpector: ToolAdapter = Object.freeze({
  id: "skillspector" as const,
  version: "2.13.2",
  async run(_item: AssessItem, context: ToolContext): Promise<ToolRun> {
    return Object.freeze({
      status: "not-run" as const,
      version: "2.13.2",
      mode: context.mode,
      reason: "unavailable" as const,
      detail: "SkillSpector is not available in this build",
    });
  },
});

/** Cisco skill-scanner before its adapter lands: unavailable when named; never counts for coverage. */
export const unavailableCisco: ToolAdapter = Object.freeze({
  id: "cisco" as const,
  version: "2.3.2",
  async run(_item: AssessItem, _context: ToolContext): Promise<ToolRun> {
    return Object.freeze({
      status: "not-run" as const,
      version: "2.3.2",
      mode: "static" as const,
      reason: "unavailable" as const,
      detail: "Cisco skill-scanner is not available in this build",
    });
  },
});
