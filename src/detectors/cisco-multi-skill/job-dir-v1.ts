import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";

/**
 * Containment of one Cisco job directory inside the scanned root. A job path
 * is a source-relative POSIX path (`""` names the root job); the job
 * directory must be a real directory chain inside the root: every component
 * from the root down is lstat'ed and must be a directory, never a symbolic
 * link or a Windows junction (Node reports both as links), and the job
 * directory's realpath must stay inside the root's realpath.
 *
 * Core's component hash inspects the job directory and its descendants only,
 * so a linked ANCESTOR would otherwise pass the input identity and send the
 * analyzer outside the declared source. The check is repeated before each
 * job's scan so a link swapped in after the boundary check is still refused.
 */
export type CiscoJobDirectoryResolutionV1 =
  | Readonly<{ ok: true; skillDir: string }>
  | Readonly<{ ok: false; problem: "unsafe-path" | "link" | "not-directory" | "escapes-root" }>;

function isSafeJobPathV1(path: string): boolean {
  return (
    path.length === 0 ||
    !(
      path.startsWith("/") ||
      path.includes("\\") ||
      path.includes(":") ||
      path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
    )
  );
}

/**
 * Resolves `path` below `root` (an absolute directory; its realpath is the
 * containment boundary). Never throws: a missing or unreadable component is
 * `not-directory`.
 */
export function resolveContainedCiscoJobDirectoryV1(
  root: string,
  path: string,
): CiscoJobDirectoryResolutionV1 {
  const refuse = (problem: "unsafe-path" | "link" | "not-directory" | "escapes-root") =>
    Object.freeze({ ok: false as const, problem });
  if (typeof path !== "string" || !isSafeJobPathV1(path)) return refuse("unsafe-path");
  let realRoot: string;
  try {
    realRoot = realpathSync(root);
  } catch {
    return refuse("not-directory");
  }
  let current = realRoot;
  for (const part of path.length === 0 ? [] : path.split("/")) {
    current = join(current, part);
    try {
      const stats = lstatSync(current);
      if (stats.isSymbolicLink()) return refuse("link");
      if (!stats.isDirectory()) return refuse("not-directory");
    } catch {
      return refuse("not-directory");
    }
  }
  let realJob: string;
  try {
    realJob = realpathSync(current);
  } catch {
    return refuse("not-directory");
  }
  const inside = relative(realRoot, realJob);
  if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
    return refuse("escapes-root");
  }
  return Object.freeze({ ok: true as const, skillDir: current });
}

/** The refusal text for a failed resolution, naming the (already bounded) path. */
export function ciscoJobDirectoryProblemTextV1(
  problem: "unsafe-path" | "link" | "not-directory" | "escapes-root",
): string {
  switch (problem) {
    case "unsafe-path":
      return "is not a safe POSIX source-relative path";
    case "link":
      return "crosses a symbolic link or junction";
    case "not-directory":
      return "is not a directory chain inside the source root";
    case "escapes-root":
      return "resolves outside the source root";
  }
}
