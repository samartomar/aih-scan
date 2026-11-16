// Read-only DCO verification of every commit reachable from head but not base, merges included.
import { execFileSync } from "node:child_process";

try {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--base" || args[2] !== "--head" ||
      ![args[1], args[3]].every((value) => /^[0-9a-f]{40}$/.test(value)))
    throw new Error("Usage: node tools/verify-signoffs.mjs --base <commit SHA> --head <commit SHA>");
  const git = (...values) => execFileSync("git", values, {
    encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  for (const sha of [args[1], args[3]]) git("rev-parse", "--verify", `${sha}^{commit}`);
  const commits = git("rev-list", `${args[1]}..${args[3]}`).split("\n").filter(Boolean);
  if (commits.length === 0) throw new Error("No branch commits to verify");
  const missing = commits.filter((sha) => {
    // Git parses the final trailer block; a matching line inside message prose is not DCO.
    const trailers = git("show", "-s", "--format=%(trailers:key=Signed-off-by,valueonly,unfold)", sha);
    return !trailers.split("\n").some((value) => /^[^<>\r\n]*[^<>\s] <[^<>\s@]+@[^<>\s@]+>$/.test(value));
  });
  if (missing.length) throw new Error(`Missing valid Signed-off-by trailer:\n${missing.join("\n")}`);
  console.log(`Verified DCO signoffs on ${commits.length} commits`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
