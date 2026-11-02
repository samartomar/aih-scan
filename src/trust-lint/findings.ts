/**
 * The check codes aih-trust-lint's checks emit. The host adapter (src/host/trust-lint-tool.ts)
 * maps each to its aih-codes/1 code, severity and confidence.
 */
export type TrustLintCheckCodeV1 =
  | "secrets.plaintext-detected"
  | "mcp.config-invalid"
  | "mcp.hardcoded-secret"
  | "trust.auto-exec-hook"
  | "trust.dependency-confusion"
  | "trust.external-egress"
  | "trust.hidden-unicode"
  | "trust.malicious-code"
  | "trust.permission-risk"
  | "trust.prompt-injection"
  | "trust.typosquat"
  | "trust.unpinned-dependency"
  | "trust.visible-unicode";

/** Where an MCP server description finding came from. */
export interface TrustLintMcpDescriptionV1 {
  /** The MCP config file's item-relative path. */
  readonly configPath: string;
  /** `mcpServers`, `servers` or `mcp`. */
  readonly mapKey: string;
  /** The raw server map key (not `safeMcpName`-normalized). */
  readonly server: string;
}

/**
 * One native trust detection. Mirrors the detection-relevant fields of Core's
 * `Check` (`src/internals/verify.ts`): same `name`, `detail`, `code`,
 * `location` and `fingerprint` strings Core produces, with the verdict fixed
 * to the raw pre-grading `fail`.
 */
export interface TrustLintFindingV1 {
  readonly name: string;
  readonly verdict: "fail";
  readonly detail: string;
  readonly code: TrustLintCheckCodeV1;
  readonly location: Readonly<{ uri: string; startLine: number }>;
  readonly fingerprint: string;
  /** Present only on MCP server description lint findings (§2.2(5)). */
  readonly mcpDescription?: TrustLintMcpDescriptionV1;
}
