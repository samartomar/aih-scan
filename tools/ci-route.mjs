/** Ordinary CI routing. Ambiguous impact always selects the complete route. */
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "@babel/parser";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fullPlan = (reason) => ({ mode: "full", reason, coverage: true, python: true, refresh: true, tests: [] });
const docsPath = (path) => /^(?:docs\/.*\.md|[^/]+\.md)$/.test(path);

// Follow local source imports, including type imports conservatively. Refresh loads
// package exports dynamically, so its public contracts/read/host entries are explicit roots.
// Analyzer locks/scripts and package/schema resources are handled separately below.
function closure(entries) {
  const seen = new Set();
  const pending = [...entries];
  while (pending.length) {
    const path = pending.pop();
    if (seen.has(path)) continue;
    seen.add(path);
    const ast = parse(readFileSync(resolve(root, path), "utf8"), {
      sourceType: "module",
      plugins: path.endsWith(".ts") ? ["typescript"] : [],
    });
    for (const statement of ast.program.body) {
      const specifier = statement.source?.value;
      if (typeof specifier !== "string" || !specifier.startsWith(".")) continue;
      let target = resolve(root, dirname(path), specifier);
      if (target.endsWith(".js") && existsSync(target.replace(/\.js$/, ".ts")))
        target = target.replace(/\.js$/, ".ts");
      const local = relative(root, target).replaceAll("\\", "/");
      if (local.startsWith("../") || !existsSync(target)) throw new Error("Unresolved CI dependency");
      pending.push(local);
    }
  }
  return seen;
}
function select(changes, explicitFull) {
  if (explicitFull) return fullPlan("explicit-full");
  if (!Array.isArray(changes) || changes.length === 0) return fullPlan("unknown-change-set");
  if (changes.some((entry) => !entry || !["A", "M"].includes(entry.status) ||
      typeof entry.path !== "string" || entry.previousPath !== undefined ||
      !existsSync(resolve(root, entry.path)))) return fullPlan("unknown-deleted-or-renamed");
  const paths = changes.map(({ path }) => path);
  const tests = new Set(["tests/ci"]);
  let coverage = false;
  for (const path of paths) {
    if (docsPath(path)) continue;
    if (/^src\/(?:public|contract)\//.test(path) || /^src\/assessment\/(?:types|shapes|json)\.ts$/.test(path))
      return fullPlan("shared-public-contract");
    if (/^tools\/artifact\/[^/]+\.mjs$/.test(path)) tests.add("tests/artifact");
    else if (/^tools\/refresh\/[^/]+\.(mjs|sh)$/.test(path)) tests.add("tests/refresh");
    else if (/^src\/(artifact|material-change)\/.+\.ts$/.test(path)) {
      tests.add(`tests/${path.split("/")[1]}`);
      tests.add("tests/assessment");
      tests.add("tests/package-install-v2.test.ts");
      tests.add("tests/public-boundary.test.ts");
    } else if (/^src\/.+\.ts$/.test(path)) coverage = true;
    else if (/^tests\/(?!support\/|fixtures\/).+\.test\.ts$/.test(path)) tests.add(path);
    else return fullPlan("shared-dependency-workflow-or-unknown");
  }
  let pythonDependencies, refreshDependencies;
  try {
    pythonDependencies = closure(["src/baseline/runtime-v1.ts"]);
    refreshDependencies = closure([
      "tools/refresh/refresh.mjs", "src/public/host.ts", "src/public/read.ts", "src/public/contracts.ts",
    ]);
  } catch {
    return fullPlan("dependency-graph-unavailable");
  }
  const runtimeData = (path) => path.startsWith("tools/baseline-analyzers/");
  return {
    mode: paths.every(docsPath) ? "docs" : "focused",
    reason: "known-dependency-impact",
    coverage,
    python: paths.some((path) => pythonDependencies.has(path) || path.startsWith("src/cli/") || runtimeData(path)),
    refresh: paths.some((path) => path.startsWith("src/cli/") || refreshDependencies.has(path) || runtimeData(path) || path === "tests/refresh/operation.test.ts"),
    tests: coverage ? [] : [...tests].sort(),
  };
}
function gitChanges(base, head) {
  if (![base, head].every((value) => /^[a-f0-9]{40}$/.test(value ?? ""))) return null;
  const diff = spawnSync("git", ["diff", "--name-status", "-z", "--find-renames", base, head], { cwd: root, encoding: "utf8" });
  if (diff.status !== 0) return null;
  const fields = diff.stdout.split("\0"), changes = [];
  for (let i = 0; i < fields.length - 1;) {
    const status = fields[i++];
    if (/^[RC]/.test(status)) changes.push({ status, previousPath: fields[i++], path: fields[i++] });
    else changes.push({ status, path: fields[i++] });
  }
  return changes;
}
const args = process.argv.slice(2);
const value = (flag) => args[args.indexOf(flag) + 1];
if (args.includes("--run-tests")) {
  const plan = JSON.parse(readFileSync(value("--run-tests"), "utf8"));
  if (typeof plan.coverage !== "boolean" || !Array.isArray(plan.tests) ||
      (!plan.coverage && plan.tests.length === 0) ||
      !plan.tests.every((path) => /^tests\/[a-zA-Z0-9_./-]+$/.test(path) && !path.includes("..")))
    throw new Error("Invalid CI test selection");
  const result = spawnSync(process.execPath, [resolve("node_modules/vitest/vitest.mjs"), "run",
    ...(plan.coverage ? ["--coverage"] : plan.tests)], { stdio: "inherit" });
  process.exitCode = result.status ?? 1;
} else {
  let changes;
  try {
    changes = args.includes("--changes") ? JSON.parse(readFileSync(value("--changes"), "utf8")) : gitChanges(value("--base"), value("--head"));
  } catch {
    changes = null;
  }
  const plan = select(changes, args.includes("--full"));
  if (args.includes("--plan")) writeFileSync(value("--plan"), JSON.stringify(plan));
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT,
    `mode=${plan.mode}\npython=${plan.python}\nrefresh=${plan.refresh}\n`);
  console.log(JSON.stringify(plan));
}
