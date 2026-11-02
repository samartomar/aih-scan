import { lstatSync } from "node:fs";
import { resolve } from "node:path";
import { limits } from "../contracts/limits.js";
import { NPM_SCOPE_PATTERN } from "../contracts/npm.js";
import type { Dependency } from "../contracts/routing.js";
import { sanitizeText } from "../contracts/text.js";
import { sourceDependencies } from "../host/scan.js";
import {
  type AdvisoryDependency,
  type AdvisoryFetch,
  type AdvisoryResult,
  checkAdvisories,
  osvEndpoint,
} from "../read/check-advisories.js";
import {
  type CommandIo,
  exitCodes,
  parse,
  readSummaryFile,
  single,
  UsageError,
} from "./commands-v1.js";
import { TargetError, type TargetSource, targetSource } from "./targets-v1.js";

/** Internal seams for the advisory service (a controlled local service and clock in tests). */
export interface AdvisoriesIo extends CommandIo {
  readonly advisories?: Readonly<{ endpoint?: string; fetch?: AdvisoryFetch; now?: () => Date }>;
}

export const advisoriesUsage = `${[
  "Usage: aih-scan advisories <target> [--internal-scope <@scope>]... [--private | --include-private] [--ref <name>] [--json]",
  "",
  "Targets:",
  "  <owner/repo | https-url>    a public Git repository or GitHub item link: checked",
  "  npm:<package>@<version>     a public npm package: checked",
  "  <folder>                    private: nothing is sent unless --include-private",
  "  npm-file:<package.tgz>      private: nothing is sent unless --include-private",
  "  <summary.json>              private (a summary carries no source): nothing is sent unless --include-private",
  "",
  "Checks the dependencies the content declares against live OSV advisories (api.osv.dev).",
  "The result is unsigned and separate from every scan: it never changes a score or summary.",
  "Packages under an internal scope and versions that are not exact are never sent.",
  "",
  "Options:",
  "  --internal-scope <@scope>   repeatable; packages under it are never sent",
  "  --private                   treat a public source as private (send nothing)",
  "  --include-private           send the exact public versions of a private source",
  "  --ref <name>                branch, tag or full commit of a Git target",
  "  --json",
  "",
  "Exit: 0 finished (advisories found or not), 2 bad input or unreadable source, 130 cancelled.",
].join("\n")}\n`;

type Target =
  | Readonly<{ type: "summary"; path: string }>
  | Readonly<{ type: "source"; source: TargetSource }>;

function targetOf(spelling: string, cwd: string, ref: string | undefined): Target {
  if (spelling.startsWith("mcp-url:"))
    throw new UsageError("mcp-url: targets declare no dependencies to check");
  const path = resolve(cwd, spelling);
  if (!/^(npm|npm-file):/.test(spelling) && spelling.toLowerCase().endsWith(".json")) {
    let file = false;
    try {
      file = lstatSync(path).isFile();
    } catch {
      file = false;
    }
    if (file) {
      if (ref !== undefined) throw new UsageError("--ref applies only to Git repository targets");
      return { type: "summary", path };
    }
  }
  try {
    return { type: "source", source: targetSource(spelling, cwd, ref) };
  } catch (error) {
    throw new UsageError(error instanceof TargetError ? error.message : "unreadable target");
  }
}

const safe = (value: string, max = 214) => sanitizeText(value, max);

function nameOf(
  entry: Readonly<{ ecosystem: string; name: string; version: string | null; file?: string }>,
) {
  return `${entry.ecosystem} ${safe(entry.name)}@${entry.version === null ? "?" : safe(entry.version, 128)}${
    entry.file === undefined ? "" : ` (${safe(entry.file, limits.output.findingPath)})`
  }`;
}

function resultLines(entry: AdvisoryResult): string {
  if (entry.state === "none-known") return `none known   ${nameOf(entry)}\n`;
  if (entry.state === "not-checked") return `not checked  ${nameOf(entry)}: ${entry.reason}\n`;
  return `VULNERABLE   ${nameOf(entry)}\n${entry.advisories
    .map(
      (advisory) =>
        `  ${safe(advisory.id, 128)}${advisory.severity ? ` ${safe(advisory.severity, 32)}` : ""}${
          advisory.fixedIn ? ` fixed in ${safe(advisory.fixedIn, 128)}` : ""
        }${advisory.summary ? `: ${safe(advisory.summary, limits.output.findingText)}` : ""}\n`,
    )
    .join("")}`;
}

/**
 * `aih-scan advisories <target>`: lists the dependencies a source or summary declares and
 * checks them with `checkAdvisories`. Public repositories and `npm:` packages are checked;
 * folders, `npm-file:` tarballs and summaries are private and send nothing unless
 * `--include-private`. `--private` forces privacy; both flags together are invalid.
 */
export async function runAdvisoriesCommand(
  args: readonly string[],
  io: AdvisoriesIo,
): Promise<number> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    io.stdout(advisoriesUsage);
    return exitCodes.ok;
  }
  let target: Target;
  let json: boolean;
  let scopes: string[];
  let forcePrivate: boolean;
  let includePrivate: boolean;
  try {
    const parsed = parse(
      args,
      ["--internal-scope", "--ref"],
      ["--private", "--include-private", "--json"],
    );
    if (parsed.positional.length !== 1) throw new UsageError("name one target");
    forcePrivate = parsed.flags.has("--private");
    includePrivate = parsed.flags.has("--include-private");
    if (forcePrivate && includePrivate)
      throw new UsageError("--private and --include-private cannot be combined");
    json = parsed.flags.has("--json");
    scopes = [...new Set(parsed.values.get("--internal-scope") ?? [])].sort();
    for (const scope of scopes)
      if (!NPM_SCOPE_PATTERN.test(scope)) throw new UsageError("--internal-scope takes @scope");
    target = targetOf(
      parsed.positional[0] as string,
      io.cwd ?? process.cwd(),
      single(parsed, "--ref"),
    );
  } catch (error) {
    io.stderr(
      `aih-scan: ${error instanceof UsageError ? error.message : "invalid arguments"}\n${advisoriesUsage}`,
    );
    return exitCodes.input;
  }

  let dependencies: readonly AdvisoryDependency[];
  let fetched = false;
  let sourceType: string;
  if (target.type === "summary") {
    sourceType = "summary";
    const read = readSummaryFile(target.path);
    if ("problem" in read) {
      io.stderr(`aih-scan: ${read.problem}\n`);
      return exitCodes.input;
    }
    dependencies = read.summary.dependencies;
  } else {
    sourceType = target.source.type;
    const listed = await sourceDependencies(target.source, io.cancellation, io.internals);
    if (listed.status === "cancelled") {
      io.stderr("aih-scan: cancelled\n");
      return exitCodes.cancelled;
    }
    if (listed.status !== "ok") {
      io.stderr(
        `aih-scan: ${listed.status} (${safe(listed.reason, 200)})${listed.detail ? `: ${safe(listed.detail, 300)}` : ""}\n`,
      );
      return exitCodes.input;
    }
    dependencies = listed.dependencies.map((dependency: Dependency) => dependency);
    fetched = listed.acquisition.fetched;
  }
  const publicSource = sourceType === "git" || sourceType === "npm";
  const isPrivate = forcePrivate || !publicSource;
  if (isPrivate && !includePrivate) {
    if (json)
      io.stdout(
        `${JSON.stringify(
          { status: "ok", source: sourceType, private: true, checked: false, dependencies },
          null,
          2,
        )}\n`,
      );
    else
      io.stdout(
        `This ${sourceType === "summary" ? "summary" : "source"} is treated as private: nothing was sent. ${dependencies.length} dependencies found${
          dependencies.length > 0
            ? `; run again with --include-private to check their exact versions with OSV (internal scopes and ranges are never sent).\n${dependencies
                .map((dependency) => `  ${nameOf(dependency)}\n`)
                .join("")}`
            : ".\n"
        }`,
      );
    return exitCodes.ok;
  }
  const checked = await checkAdvisories(dependencies, {
    internalScopes: scopes,
    ...(io.cancellation === undefined ? {} : { signal: io.cancellation }),
    ...(io.advisories?.endpoint === undefined ? {} : { endpoint: io.advisories.endpoint }),
    ...(io.advisories?.fetch === undefined ? {} : { fetch: io.advisories.fetch }),
    ...(io.advisories?.now === undefined ? {} : { now: io.advisories.now }),
  });
  if (checked.status !== "ok") {
    if (checked.reason === "cancelled") {
      io.stderr("aih-scan: cancelled\n");
      return exitCodes.cancelled;
    }
    io.stderr(`aih-scan: ${checked.status} (${safe(checked.reason, 200)})\n`);
    return exitCodes.input;
  }
  const unreachable = checked.results.some(
    (entry) => entry.state === "not-checked" && entry.reason === "advisory service unreachable",
  );
  if (json)
    io.stdout(
      `${JSON.stringify(
        { ...checked, source: sourceType, private: isPrivate, checked: true },
        null,
        2,
      )}\n`,
    );
  else {
    if (fetched)
      io.stdout(
        `Fetched the ${sourceType} source to list its dependencies; nothing in it was run.\n`,
      );
    io.stdout(
      `Advisories from ${safe(io.advisories?.endpoint ?? osvEndpoint, 256)} at ${checked.checkedAt} (live, unsigned, separate from scan scores):\n`,
    );
    if (checked.results.length === 0) io.stdout("No dependencies found.\n");
    for (const entry of checked.results) io.stdout(resultLines(entry));
  }
  if (unreachable)
    io.stderr(
      "aih-scan: the advisory service could not be reached; those entries are not checked\n",
    );
  return exitCodes.ok;
}
