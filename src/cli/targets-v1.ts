import { resolve } from "node:path";
import { classifyScanTarget, GitSourceRefusal } from "./git-source.js";

/** A command-line target that cannot become a source descriptor; the message is fixed text. */
export class TargetError extends Error {}

export type TargetSource =
  | Readonly<{ type: "folder"; path: string }>
  | Readonly<{ type: "git"; repo: string; ref?: string; path?: string }>
  | Readonly<{ type: "npm"; package: string; version: string; kind: "mcp" }>
  | Readonly<{ type: "npm-file"; path: string; kind: "mcp" }>
  | Readonly<{ type: "remote"; url: string; kind: "mcp" }>;

const githubLink =
  /^https:\/\/github\.com\/([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100})\/(tree|blob)\/(.+)$/;

function decoded(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    throw new TargetError("the GitHub link is not a valid URL");
  }
}

/** `https://github.com/<owner>/<repo>/(tree|blob)/<ref>/<path>`: the ref is `--ref` when the link starts with it, else the first segment. */
function itemLink(spelling: string, ref: string | undefined): TargetSource | undefined {
  if (spelling.includes("?") || spelling.includes("#")) return undefined;
  const match = githubLink.exec(spelling);
  if (match === null) return undefined;
  const owner = match[1] as string;
  const repo = (match[2] as string).replace(/\.git$/, "");
  const segments = (match[4] as string).split("/").filter(Boolean).map(decoded);
  let refSegments = 1;
  if (ref !== undefined) {
    const wanted = ref.split("/");
    if (wanted.every((part, index) => segments[index] === part)) refSegments = wanted.length;
    else throw new TargetError("--ref does not match the ref in the GitHub link");
  }
  const linkRef = segments.slice(0, refSegments).join("/");
  const path = segments.slice(refSegments).join("/");
  return Object.freeze({
    type: "git" as const,
    repo: `https://github.com/${owner}/${repo}.git`,
    ref: linkRef,
    ...(path === "" ? {} : { path }),
  });
}

/**
 * Reads one command-line target as the matching `aih-scan-source/1` descriptor: `npm:<pkg>@<ver>`,
 * `npm-file:<package.tgz>`, `mcp-url:<url>`, a GitHub item link, an `https://` repository URL,
 * `owner/repo` (when no local path has that spelling), otherwise a local folder (a private
 * repository is cloned by its owner and scanned as a folder). Validation of the descriptor itself
 * happens in `scan`.
 */
export function targetSource(spelling: string, cwd: string, ref: string | undefined): TargetSource {
  const withRef = (source: TargetSource): TargetSource => {
    if (ref !== undefined && source.type !== "git")
      throw new TargetError("--ref applies only to Git repository targets");
    return source;
  };
  if (spelling.startsWith("npm:")) {
    const spec = spelling.slice(4);
    const at = spec.lastIndexOf("@");
    if (at <= 0)
      throw new TargetError("npm: targets name an exact version: npm:<package>@<version>");
    return withRef({
      type: "npm",
      package: spec.slice(0, at),
      version: spec.slice(at + 1),
      kind: "mcp",
    });
  }
  if (spelling.startsWith("npm-file:")) {
    const path = spelling.slice("npm-file:".length);
    if (path === "") throw new TargetError("npm-file: targets name a package tarball");
    return withRef({ type: "npm-file", path: resolve(cwd, path), kind: "mcp" });
  }
  if (spelling.startsWith("mcp-url:"))
    return withRef({ type: "remote", url: spelling.slice("mcp-url:".length), kind: "mcp" });
  const link = itemLink(spelling, ref);
  if (link !== undefined) return link;
  let classified: ReturnType<typeof classifyScanTarget>;
  try {
    classified = classifyScanTarget(spelling, cwd);
  } catch (error) {
    throw new TargetError(
      error instanceof GitSourceRefusal ? error.message : "the target could not be read",
    );
  }
  if (classified.kind === "git")
    return Object.freeze({
      type: "git" as const,
      repo: classified.repository,
      ...(ref === undefined ? {} : { ref }),
    });
  return withRef({ type: "folder", path: resolve(cwd, spelling) });
}
