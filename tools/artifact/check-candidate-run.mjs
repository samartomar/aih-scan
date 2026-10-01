// Trusted producer admission. GitHub's run/artifact metadata is input data;
// expected run, head and artifact identities are independently selected config.
// This tool has no network, credential, signing or candidate-execution capability.
import { strictParse } from "../../dist/assessment/json.js";
import { readRegular } from "./check-statement.mjs";

// Each stage is a fixed diagnostic code, never metadata or a caught error.
let stage = "selector";
try {
  if (process.argv.length !== 10) throw new Error("Invalid invocation");
  const [runPath, artifactsPath, runId, head, unsignedId, unsignedDigest, statementId, statementDigest] = process.argv.slice(2);
  const id = (value) => {
    if (!/^[1-9][0-9]{0,15}$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error("Invalid identity");
    return Number(value);
  };
  const expectedRun = id(runId);
  const expectedUnsigned = id(unsignedId), expectedStatement = id(statementId);
  if (expectedUnsigned === expectedStatement || !/^[0-9a-f]{40}$/.test(head) ||
    !/^sha256:[0-9a-f]{64}$/.test(unsignedDigest) || !/^sha256:[0-9a-f]{64}$/.test(statementDigest)) throw new Error("Invalid custody selection");
  stage = "run-metadata";
  const run = strictParse(readRegular(runPath, 256 * 1024), "run metadata", 256 * 1024);
  stage = "artifact-metadata";
  const uploads = strictParse(readRegular(artifactsPath, 256 * 1024), "artifact metadata", 256 * 1024);
  const repositoryMatches = (value) => value?.id === 1336836161 && value.full_name === "samartomar/aih-scan" && value.owner?.id === 9993940;
  const actorMatches = (value) => value?.id === 333589491 && value.login === "stomar-tech";
  stage = "run-custody";
  if (run?.id !== expectedRun || run.run_attempt !== 1 || run.event !== "workflow_dispatch" ||
    run.status !== "completed" || run.conclusion !== "success" || run.head_sha !== head || run.head_branch !== "main" ||
    run.path !== ".github/workflows/scan-report-candidate-upload.yml" || !repositoryMatches(run.repository) ||
    !repositoryMatches(run.head_repository)) throw new Error("Unreviewed run");
  stage = "actor-custody";
  if (!actorMatches(run.actor) || !actorMatches(run.triggering_actor)) throw new Error("Unreviewed actor");
  stage = "artifact-ambiguity";
  if (uploads?.total_count !== 2 || !Array.isArray(uploads.artifacts) || uploads.artifacts.length !== 2) throw new Error("Ambiguous uploads");
  for (const [selectedId, selectedName, selectedDigest] of [
    [expectedUnsigned, "scan-unsigned-artifact", unsignedDigest],
    [expectedStatement, "scan-detached-statement", statementDigest],
  ]) {
    const matches = uploads.artifacts.filter((artifact) => artifact?.id === selectedId);
    stage = matches.length > 1 ? "artifact-ambiguity" : "artifact-custody";
    if (matches.length !== 1) throw new Error("Absent upload");
    const artifact = matches[0];
    if (artifact.name !== selectedName || artifact.digest !== selectedDigest || artifact.expired !== false ||
      !Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes < 1 || artifact.size_in_bytes > 128 * 1024 ||
      artifact.workflow_run?.id !== expectedRun || artifact.workflow_run.head_sha !== head) throw new Error("Upload custody mismatch");
  }
  process.stdout.write("Candidate custody verified.\n");
} catch {
  process.stderr.write(`Candidate custody refused: ${stage}.\n`);
  process.exitCode = 2;
}
