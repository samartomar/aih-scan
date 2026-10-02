import { lstatSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { startGitFetchRelay } from "../assessment/git-fetch-relay.js";
import { GitContainmentError, runPinnedGit } from "../assessment/git-runner.js";
import { repositoryShape } from "../assessment/shapes.js";
import { decodeStrictUtf8V1 } from "../assessment/strict-json.js";

/**
 * Scan-command Git sources: classifies the command-line target and resolves a Git
 * source to one full, immutable commit before the assessment acquires exactly that
 * commit. Resolution runs `git ls-remote` through the same hardened runner and bounded
 * relay as pinned acquisition, in a private temporary directory that is always removed.
 * Credentials are never accepted, passed or printed; a refusal message never repeats
 * the target spelling, so a token in a refused URL cannot reach the terminal.
 */

/** A refusal whose message is fixed text, safe to print. */
export class GitSourceRefusal extends Error {}
function refuse(message: string): never {
  throw new GitSourceRefusal(message);
}

export type ScanTarget =
  | { readonly kind: "local" }
  | { readonly kind: "git"; readonly repository: string };

const unsupportedSource = "unsupported Git source; use an https:// URL or a GitHub owner/repo";
const fullCommit = /^[0-9a-f]{40}$/;
/** GitHub owner and repository names; `owner/repo.git` names the same repository. */
const githubShorthand = /^([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100})$/;
/** A URL scheme of two or more characters, so a Windows drive letter is never one. */
const urlScheme = /^[A-Za-z][A-Za-z0-9+.-]+:\/\//;
/** scp-like `user@host:path` Git remotes. */
const scpLike = /^[^/\\@:]+@[^/\\:]+:/;

function httpsRepository(spelling: string): string {
  if (!/^https:\/\//i.test(spelling)) refuse(unsupportedSource);
  let url: URL;
  try {
    url = new URL(spelling);
  } catch {
    refuse("the Git URL is not a valid https:// URL");
  }
  if (url.username || url.password)
    refuse("the Git URL contains credentials; credentials are never accepted in a Git URL");
  if (url.search || url.hash || spelling.includes("?") || spelling.includes("#"))
    refuse("the Git URL has a query or fragment; name the repository URL only");
  if (!repositoryShape.safeParse(spelling).success)
    refuse("the Git URL is not a supported https:// repository URL");
  return spelling;
}

function shorthandRepository(spelling: string): string | undefined {
  const match = githubShorthand.exec(spelling);
  if (!match) return undefined;
  const owner = match[1] as string;
  const repo = (match[2] as string).replace(/\.git$/, "");
  if (repo === "" || repo === "." || repo === "..") return undefined;
  return `https://github.com/${owner}/${repo}.git`;
}

function missing(path: string): boolean {
  try {
    lstatSync(path);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
}

/**
 * `https://...` is a Git source. `owner/repo` is a GitHub repository only when no local
 * path has that spelling; every other target, and any existing path, stays local.
 */
export function classifyScanTarget(spelling: string, cwd: string): ScanTarget {
  if (urlScheme.test(spelling)) return { kind: "git", repository: httpsRepository(spelling) };
  const path = resolve(cwd, spelling);
  if (!missing(path)) return { kind: "local" };
  if (scpLike.test(spelling)) refuse(unsupportedSource);
  const shorthand = shorthandRepository(spelling);
  return shorthand === undefined ? { kind: "local" } : { kind: "git", repository: shorthand };
}

const refSyntax =
  "--ref must name a branch, a tag, refs/heads/<name>, refs/tags/<name> or a full 40-character commit";

/**
 * What a Git source asks for, parsed once: the default HEAD, a full commit used as given,
 * a qualified branch or tag, or a short name that may be either.
 */
export type GitRefRequest =
  | { readonly kind: "head" }
  | { readonly kind: "commit"; readonly commit: string }
  | { readonly kind: "branch"; readonly name: string }
  | { readonly kind: "tag"; readonly name: string }
  | { readonly kind: "either"; readonly name: string };

export type GitRefParse =
  | { readonly ok: true; readonly request: GitRefRequest }
  | { readonly ok: false; readonly detail: string };

function invalidRefName(ref: string): boolean {
  const components = ref.split("/");
  return (
    ref.length === 0 ||
    ref.length > 255 ||
    /[^\x21-\x7e]/.test(ref) ||
    /[~^:?*[\\]/.test(ref) ||
    ref.startsWith("-") ||
    ref.startsWith("/") ||
    ref.endsWith("/") ||
    ref.endsWith(".") ||
    ref.includes("..") ||
    ref.includes("@{") ||
    ref.includes("//") ||
    ref === "@" ||
    components.some((component) => component.startsWith(".") || component.endsWith(".lock"))
  );
}

/**
 * Parses `--ref` (absent means the default HEAD) with check-ref-format-like rules,
 * before any Git process or network.
 */
export function parseGitRef(ref: string | undefined): GitRefParse {
  if (ref === undefined) return { ok: true, request: { kind: "head" } };
  if (fullCommit.test(ref)) return { ok: true, request: { kind: "commit", commit: ref } };
  if (ref === "HEAD")
    return { ok: false, detail: "--ref HEAD is the default; omit --ref to use the default branch" };
  if (invalidRefName(ref)) return { ok: false, detail: refSyntax };
  if (/^refs\/heads\/./.test(ref)) return { ok: true, request: { kind: "branch", name: ref } };
  if (/^refs\/tags\/./.test(ref)) return { ok: true, request: { kind: "tag", name: ref } };
  if (ref.startsWith("refs/")) return { ok: false, detail: refSyntax };
  return { ok: true, request: { kind: "either", name: ref } };
}

export interface ResolvedGitSource {
  readonly repository: string;
  readonly commit: string;
  /** The full ref the commit was resolved from; absent for a commit given as --ref. */
  readonly ref?: string;
}

const unavailable =
  "the Git repository is unavailable, requires credentials, or could not be resolved";
const cleanupUnconfirmed = "Git process cleanup could not be confirmed";
const malformedListing =
  "the Git repository returned an unsupported ref listing (only SHA-1 repositories are supported)";
/** Ref listings are small; the relay bounds transport and the runner bounds the listing. */
const listingBytes = 1024 * 1024;
const transportBytes = 16 * 1024 * 1024;

interface Listing {
  readonly refs: ReadonlyMap<string, string>;
  readonly headTarget?: string;
}

/** Strict `ls-remote` output: `<sha1>\t<ref>` and, with --symref, `ref: <target>\t<ref>`. */
function parseListing(bytes: Uint8Array): Listing {
  let text: string;
  try {
    text = decodeStrictUtf8V1(bytes, "Git ref listing");
  } catch {
    refuse(malformedListing);
  }
  if (text !== "" && !text.endsWith("\n")) refuse(malformedListing);
  const refs = new Map<string, string>();
  let headTarget: string | undefined;
  for (const line of text.split("\n").slice(0, -1)) {
    const object = /^([0-9a-f]{40})\t([^\0-\x20\x7f]+)$/.exec(line);
    const symref = /^ref: ([^\0-\x20\x7f]+)\t([^\0-\x20\x7f]+)$/.exec(line);
    if (object) {
      const [, commit, name] = object as unknown as [string, string, string];
      if (refs.has(name)) refuse(malformedListing);
      refs.set(name, commit);
    } else if (symref) {
      if (symref[2] === "HEAD") {
        if (headTarget !== undefined) refuse(malformedListing);
        headTarget = symref[1];
      }
    } else refuse(malformedListing);
  }
  return { refs, ...(headTarget === undefined ? {} : { headTarget }) };
}

type ListedRequest = Exclude<GitRefRequest, { kind: "commit" }>;

/** `ls-remote` patterns are tail matches; a tag's peeled `^{}` entry is listed only by name. */
function listingPatterns(request: ListedRequest): string[] {
  const tag = (name: string) => [name, `${name}^{}`];
  switch (request.kind) {
    case "head":
      return ["HEAD"];
    case "branch":
      return [request.name];
    case "tag":
      return tag(request.name);
    case "either":
      return [`refs/heads/${request.name}`, ...tag(`refs/tags/${request.name}`)];
  }
}

/** Selects the exact requested ref from the listing; an annotated tag yields its commit. */
function select(listing: Listing, request: ListedRequest): { commit: string; ref?: string } {
  const { refs } = listing;
  const branch = (name: string) => {
    const commit = refs.get(name);
    return commit === undefined ? undefined : { commit, ref: name };
  };
  const tag = (name: string) => {
    const commit = refs.get(`${name}^{}`) ?? refs.get(name);
    return commit === undefined ? undefined : { commit, ref: name };
  };
  if (request.kind === "head") {
    const commit = refs.get("HEAD");
    if (commit === undefined)
      refuse("the Git repository has no default branch (HEAD); name one with --ref");
    // The branch HEAD points to, as the server advertises it, when it is a valid branch name.
    const target = listing.headTarget === undefined ? undefined : parseGitRef(listing.headTarget);
    return target?.ok && target.request.kind === "branch"
      ? { commit, ref: target.request.name }
      : { commit };
  }
  let found: { commit: string; ref: string } | undefined;
  if (request.kind === "branch") found = branch(request.name);
  else if (request.kind === "tag") found = tag(request.name);
  else {
    const asBranch = branch(`refs/heads/${request.name}`);
    const asTag = tag(`refs/tags/${request.name}`);
    if (asBranch && asTag)
      refuse(
        `--ref ${request.name} names both a branch and a tag; use refs/heads/${request.name} or refs/tags/${request.name}`,
      );
    found = asBranch ?? asTag;
  }
  if (found === undefined)
    refuse(
      `--ref ${request.name} was not found as a branch or tag; a commit must be the full 40-character hash`,
    );
  return found;
}

/** Removes the resolver's own temporary directory, retrying transient Windows locks. */
function removeStage(stage: string): boolean {
  try {
    rmSync(stage, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    return true;
  } catch {
    return false;
  }
}

async function listRefs(
  stage: string,
  repository: string,
  request: ListedRequest,
  signal: AbortSignal,
): Promise<Listing> {
  const hooks = join(stage, "empty-hooks");
  const work = join(stage, "git");
  mkdirSync(hooks);
  mkdirSync(work);
  let listing: Uint8Array;
  try {
    // An own empty repository stops Git from discovering any enclosing repository.
    await runPinnedGit(["init", "--quiet", `--template=${hooks}`], work, { signal }, hooks);
    const relay = await startGitFetchRelay(repository, transportBytes, signal);
    try {
      listing = await runPinnedGit(
        [
          "-c",
          `http.proxy=${relay.proxy}`,
          "-c",
          "credential.helper=",
          "ls-remote",
          ...(request.kind === "head" ? ["--symref"] : []),
          repository,
          ...listingPatterns(request),
        ],
        work,
        { signal: AbortSignal.any([signal, relay.limitSignal]) },
        hooks,
        listingBytes,
      );
    } finally {
      await relay.close();
    }
    relay.assertWithinBounds();
  } catch (error) {
    if (error instanceof GitContainmentError) refuse(cleanupUnconfirmed);
    refuse(unavailable);
  }
  return parseListing(listing);
}

/**
 * Resolves a parsed ref request, or the default HEAD, to one full commit. A full commit
 * is used as given; pinned acquisition verifies it. Every failure is a
 * {@link GitSourceRefusal} with a fixed message; Git's own output is never surfaced. The
 * caller distinguishes cancellation through its signal.
 *
 * The private temporary directory is removed on every path. If it cannot be removed
 * after retries, a refusal already in flight is kept; otherwise the resolution is refused
 * so that no assessment runs with an owned temporary left behind.
 */
export async function resolveGitSource(
  repository: string,
  request: GitRefRequest,
  signal: AbortSignal,
): Promise<ResolvedGitSource> {
  if (request.kind === "commit") return { repository, commit: request.commit };
  const stage = mkdtempSync(join(tmpdir(), "aih-scan-git-source-"));
  let resolved: { commit: string; ref?: string };
  try {
    resolved = select(await listRefs(stage, repository, request, signal), request);
  } catch (error) {
    removeStage(stage);
    throw error;
  }
  if (!removeStage(stage))
    refuse("a temporary Git directory could not be removed; no assessment was produced");
  return { repository, ...resolved };
}
