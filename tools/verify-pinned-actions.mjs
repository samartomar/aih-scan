import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const workflowDirectory = resolve(import.meta.dirname, "../.github/workflows");
const workflowPaths = readdirSync(workflowDirectory, { withFileTypes: true })
  .filter((entry) => entry.isFile() && /\.ya?ml$/u.test(entry.name))
  .map((entry) => resolve(workflowDirectory, entry.name))
  .sort((left, right) => left.localeCompare(right));

const references = [];
for (const workflowPath of workflowPaths) {
  const workflow = readFileSync(workflowPath, "utf8");
  for (const match of workflow.matchAll(/^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+).*$/gmu)) {
    const [, action, revision] = match;
    if (!action || !revision || !/^[\w.-]+\/[\w.-]+$/u.test(action))
      throw new Error(`invalid action reference in ${workflowPath}`);
    if (!/^[0-9a-f]{40}$/u.test(revision))
      throw new Error(`workflow action is not full-SHA pinned: ${action}@${revision}`);
    references.push({ action, revision });
  }
}

if (references.length === 0) throw new Error("no workflow action references found");

if (process.argv.includes("--online")) {
  const uniqueReferences = [
    ...new Map(references.map((reference) => [`${reference.action}@${reference.revision}`, reference])).values(),
  ];
  for (const { action, revision } of uniqueReferences) {
    const response = await fetch(`https://api.github.com/repos/${action}/commits/${revision}`, {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "aih-scan-action-pin-check",
      },
    });
    if (!response.ok) throw new Error(`unresolvable action pin: ${action}@${revision}`);
  }
  process.stdout.write(`Pinned workflow actions resolve PASS (${uniqueReferences.length} unique)\n`);
} else {
  process.stdout.write(`Pinned workflow action syntax PASS (${references.length} references)\n`);
}
