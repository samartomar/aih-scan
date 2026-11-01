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
  /** The tool's own category, used for codes when its rule ids are open-ended (Cisco). */
  readonly category?: string;
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
      /**
       * The tool ran but part of the requested analysis failed (SkillSpector's AI pass in AI
       * mode); a counted tool then makes coverage `partial` with reason `failed`. Unsigned detail.
       */
      failedPart?: string;
      /** Unsigned notes for the caller (for example why AI was not used); never in the summary. */
      notes?: readonly string[];
    }>
  | Readonly<{
      status: "not-applicable";
      version: string;
      mode: ScanMode;
      detail?: string;
      notes?: readonly string[];
    }>
  | Readonly<{
      status: "not-run";
      version: string;
      mode: ScanMode;
      reason: NotRunReason;
      detail?: string;
      notes?: readonly string[];
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
