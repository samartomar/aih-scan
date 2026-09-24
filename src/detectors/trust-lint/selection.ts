import { isSourceRelativeUriV1 } from "./findings.js";
import type { TrustLintTreeV1 } from "./inventory.js";

/**
 * Boundary validation of `subject.selectedClosurePaths` for the in-process
 * detectors that analyze a Core-declared selection of the sealed tree
 * (`detector.aih-trust-lint`, `detector.aih-binding-gate`; C2a decision 1:
 * Core declares the subject, Scan never enumerates it for Core).
 *
 * The selection must be an array of at most {@link MAX_SELECTED_PATHS}
 * unique source-relative POSIX paths, each naming a listed file of the tree
 * (a regular file, or a symlink to a file) whose realpath stays inside the
 * root. The order is Core's and is kept. Anything else is a subject
 * mismatch; the returned refusal text is bounded and free of control
 * characters.
 */

/** At least Scan's snapshot entry bound (C2a §1.3). */
const MAX_SELECTED_PATHS = 100_000;

function shown(value: unknown): string {
  const text = typeof value === "string" ? value : (JSON.stringify(value) ?? String(value));
  const visible = text.replace(/[\p{C}]/gu, " ");
  return visible.length > 80 ? `${visible.slice(0, 77)}...` : visible;
}

export type SelectedClosurePathsValidationV1 =
  | Readonly<{ ok: true; selection: readonly string[] }>
  | Readonly<{ ok: false; detail: string }>;

export function validateSelectedClosurePathsV1(
  value: unknown,
  tree: TrustLintTreeV1,
): SelectedClosurePathsValidationV1 {
  const refuse = (detail: string) => Object.freeze({ ok: false as const, detail });
  if (!Array.isArray(value)) return refuse("selectedClosurePaths must be an array of paths");
  if (value.length > MAX_SELECTED_PATHS)
    return refuse(`selectedClosurePaths exceeds the ${MAX_SELECTED_PATHS}-path bound`);
  const seen = new Set<string>();
  for (const [index, entry] of value.entries()) {
    const at = `selectedClosurePaths[${index}]`;
    if (typeof entry !== "string" || !isSourceRelativeUriV1(entry))
      return refuse(`${at} is not a source-relative POSIX path: ${shown(entry)}`);
    if (seen.has(entry)) return refuse(`${at} repeats ${shown(entry)}`);
    seen.add(entry);
    const file = tree.fileEntry(entry);
    if (file === undefined)
      return refuse(`${at} is not a file of the source tree: ${shown(entry)}`);
    if (!file.realpathContained)
      return refuse(`${at} resolves outside the source root: ${shown(entry)}`);
  }
  return Object.freeze({ ok: true as const, selection: Object.freeze([...(value as string[])]) });
}
