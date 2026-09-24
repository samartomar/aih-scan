import { mcpConfigPathsProblemV1, visibleOptionsDetailV1 } from "../mcp-config-paths-v1.js";
import type { TrustLintTreeV1 } from "./inventory.js";

/**
 * C2a §2.1 request-option validation for `detector.aih-trust-lint`
 * (coordinator decisions 6 and 8). The validator never throws and never
 * coerces: anything malformed is a typed `detector-options-invalid` result
 * that the B2 runner wiring maps to the Core refusal reason of the same
 * name, before anything is read.
 *
 * The options are a plain object with EXACTLY the keys `internalScopes` and
 * `mcpConfigPaths`, both required:
 *
 * - `internalScopes`: 0–256 unique strings matching
 *   `^@[a-z0-9][a-z0-9._~-]*$`, already normalized the way Core's
 *   `resolveInternalScopes` produces them (trimmed, `@`-prefixed,
 *   lowercased, deduplicated, localeCompare-sorted). The pattern enforces
 *   trimmed/@-prefixed/lowercased; uniqueness and sort order are checked
 *   separately. An entry that is not in normalized form is refused — Scan
 *   does not normalize again.
 * - `mcpConfigPaths`: 0–1 024 unique source-relative POSIX paths
 *   (`assertSafeRelativePosixPathV1` semantics) whose names match Core's
 *   incoming config names, each at the root or under a directory holding a
 *   selected `SKILL.md`, in Core's discovery order (root first, then each
 *   skill directory in Core's localeCompare order, the names in
 *   `INCOMING_MCP_CONFIG_FILES_V1` order; one validator shared with
 *   `detector.cisco-mcp-scanner`, `../mcp-config-paths-v1.ts`). A path absent from the tree is
 *   refused; a directory or symlink at the path is ACCEPTED and handled per
 *   §2.2(4)-(5).
 */

export const TRUST_LINT_OPTIONS_INVALID_REASON_V1 = "detector-options-invalid";

const MAX_INTERNAL_SCOPES = 256;
const INTERNAL_SCOPE_PATTERN = /^@[a-z0-9][a-z0-9._~-]*$/;

export interface TrustLintDetectorOptionsV1 {
  readonly internalScopes: readonly string[];
  readonly mcpConfigPaths: readonly string[];
}

export type TrustLintOptionsValidationV1 =
  | { readonly ok: true; readonly options: TrustLintDetectorOptionsV1 }
  | {
      readonly ok: false;
      readonly reason: typeof TRUST_LINT_OPTIONS_INVALID_REASON_V1;
      readonly detail: string;
    };

/** One actionable sentence, bounded and free of control characters (§8.4). */
function refusal(detail: string): TrustLintOptionsValidationV1 {
  return {
    ok: false,
    reason: TRUST_LINT_OPTIONS_INVALID_REASON_V1,
    detail: visibleOptionsDetailV1(detail),
  };
}

function shown(value: unknown): string {
  const text = typeof value === "string" ? value : (JSON.stringify(value) ?? String(value));
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * The `internalScopes` rule on its own, for the runner's pre-seal options read: the
 * refusal detail, or `undefined` when the value is valid. Never throws.
 */
export function trustLintInternalScopesProblemV1(value: unknown): string | undefined {
  const problem = validateInternalScopes(value);
  return problem === undefined || problem.ok ? undefined : problem.detail;
}

function validateInternalScopes(value: unknown): TrustLintOptionsValidationV1 | undefined {
  if (!Array.isArray(value)) return refusal("detectorOptions.internalScopes must be an array");
  if (value.length > MAX_INTERNAL_SCOPES) {
    return refusal(
      `detectorOptions.internalScopes has ${value.length} entries; the bound is ${MAX_INTERNAL_SCOPES}`,
    );
  }
  const seen = new Set<string>();
  let previous: string | undefined;
  for (const [index, entry] of value.entries()) {
    const at = `detectorOptions.internalScopes[${index}]`;
    if (typeof entry !== "string" || !INTERNAL_SCOPE_PATTERN.test(entry)) {
      return refusal(`${at} is not a normalized internal scope: ${shown(entry)}`);
    }
    if (seen.has(entry)) return refusal(`${at} duplicates an earlier scope: ${shown(entry)}`);
    seen.add(entry);
    if (previous !== undefined && previous.localeCompare(entry) > 0) {
      return refusal(`${at} is out of Core's normalized (localeCompare) order: ${shown(entry)}`);
    }
    previous = entry;
  }
  return undefined;
}

/**
 * Validates `detectorOptions` for `detector.aih-trust-lint` against the
 * request's selection and the sealed tree. Returns the frozen options on
 * success; a typed invalid-options result otherwise.
 */
export function validateTrustLintDetectorOptionsV1(
  input: unknown,
  tree: TrustLintTreeV1,
  selection: readonly string[],
): TrustLintOptionsValidationV1 {
  if (!isPlainObject(input)) {
    return refusal("detectorOptions must be a plain object with internalScopes and mcpConfigPaths");
  }
  const keys = Object.keys(input).sort((a, b) => a.localeCompare(b));
  if (keys.length !== 2 || keys[0] !== "internalScopes" || keys[1] !== "mcpConfigPaths") {
    return refusal(
      "detectorOptions must have exactly the keys internalScopes and mcpConfigPaths, both required",
    );
  }
  const internalScopes = validateInternalScopes(input.internalScopes);
  if (internalScopes !== undefined) return internalScopes;
  // The one §2.1 path validator, shared with detector.cisco-mcp-scanner (§4.1).
  const mcpConfigPaths = mcpConfigPathsProblemV1(
    input.mcpConfigPaths,
    selection,
    (path) => tree.pathKind(path) !== "absent",
  );
  if (mcpConfigPaths !== undefined) return refusal(mcpConfigPaths);
  return {
    ok: true,
    options: Object.freeze({
      internalScopes: Object.freeze([...(input.internalScopes as readonly string[])]),
      mcpConfigPaths: Object.freeze([...(input.mcpConfigPaths as readonly string[])]),
    }),
  };
}
