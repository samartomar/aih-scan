import type { Diagnostic } from "../assessment/types.js";
import type { MaterialChange } from "./types.js";

export interface GitHubTarget {
  owner: string;
  repository: string;
}
export interface GitHubRequestContext {
  target: GitHubTarget;
  credential: string;
  signal: AbortSignal;
}
/** External API seam. Responses remain untrusted and are validated by delivery. */
export interface GitHubTransport {
  listIssues(input: GitHubRequestContext & { page: number; perPage: number }): Promise<{
    issues: unknown[];
    hasNextPage: boolean;
  }>;
  createIssue(input: GitHubRequestContext & { title: string; body: string }): Promise<unknown>;
  updateIssue(
    input: GitHubRequestContext & { issueNumber: number; body: string },
  ): Promise<unknown>;
}
export interface DeliverMaterialChangeInput {
  summary: MaterialChange;
  enabled: boolean;
  target?: GitHubTarget;
  /** Explicit target-delivery bearer credential; no ambient discovery. */
  credential?: string;
  transport?: GitHubTransport;
}
export interface MaterialChangeDeliveryEntry {
  changeId: `change:sha256:${string}`;
  status: "created" | "updated" | "closed-disposition" | "failed";
  issueUrl?: string;
  diagnostics: Diagnostic[];
}
export interface MaterialChangeDeliveryResult {
  results: MaterialChangeDeliveryEntry[];
  /** Invocation/configuration diagnostics, observable even for an empty summary. */
  diagnostics: Diagnostic[];
  /** Exact validated snapshot, retained whenever any change failed. */
  retryableSummary?: MaterialChange;
}
