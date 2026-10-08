import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseJson, readRegular } from "../refresh/contracts.mjs";

export const archiveCeiling = 768 * 1024 * 1024;
const identifier = (value) => {
  if (
    typeof value !== "string" ||
    !/^[1-9][0-9]{0,15}$/.test(value) ||
    !Number.isSafeInteger(Number(value))
  )
    throw new Error("Invalid immutable ID");
  return Number(value);
};
export function checkRefreshRun(
  run,
  artifacts,
  runId,
  head,
  artifactId,
  serviceDigest,
  name = "scan-refresh-candidate",
) {
  const expectedRun = identifier(runId),
    expectedArtifact = identifier(artifactId);
  if (!["scan-refresh-candidate", "scan-refresh-frozen"].includes(name))
    throw new Error("Unknown artifact purpose");
  if (!/^[0-9a-f]{40}$/.test(head) || !/^sha256:[0-9a-f]{64}$/.test(serviceDigest))
    throw new Error("Invalid custody selector");
  const repo = (value) =>
    value?.id === 1336836161 &&
    value.full_name === "samartomar/aih-scan" &&
    value.owner?.id === 9993940;
  const actor = (value) => value?.id === 333589491 && value.login === "stomar-tech";
  if (
    run.id !== expectedRun ||
    run.run_attempt !== 1 ||
    run.event !== "workflow_dispatch" ||
    run.status !== "completed" ||
    run.conclusion !== "success" ||
    run.head_sha !== head ||
    run.head_branch !== "main" ||
    run.path !== ".github/workflows/scan-report-candidate-upload.yml" ||
    !repo(run.repository) ||
    !repo(run.head_repository) ||
    !actor(run.actor) ||
    !actor(run.triggering_actor)
  )
    throw new Error("Candidate run custody refused");
  if (
    artifacts.total_count !== 1 ||
    !Array.isArray(artifacts.artifacts) ||
    artifacts.artifacts.length !== 1
  )
    throw new Error("Candidate archive set refused");
  const archive = artifacts.artifacts[0];
  if (
    archive.id !== expectedArtifact ||
    archive.name !== name ||
    archive.digest !== serviceDigest ||
    archive.expired !== false ||
    !Number.isSafeInteger(archive.size_in_bytes) ||
    archive.size_in_bytes < 1 ||
    archive.size_in_bytes > archiveCeiling ||
    archive.workflow_run?.id !== expectedRun ||
    archive.workflow_run?.head_sha !== head
  )
    throw new Error("Candidate archive custody refused");
  return {
    event: "scan-refresh-custody.verified",
    phase: "actions-custody",
    runId: expectedRun,
    head,
    artifactId: expectedArtifact,
    serviceDigest,
    archiveBytes: archive.size_in_bytes,
  };
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (![8, 9].includes(process.argv.length))
      throw new Error("Expected run metadata, archives and four selectors with optional purpose");
    const [, , runPath, artifactsPath, ...selectors] = process.argv;
    const result = checkRefreshRun(
      parseJson(readRegular(runPath, 1024 * 1024)),
      parseJson(readRegular(artifactsPath, 1024 * 1024)),
      ...selectors,
    );
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write(
      `${JSON.stringify({ event: "scan-refresh-custody.refused", phase: "actions-custody", reason: "selector-or-run-or-archive-refused" })}\n`,
    );
    process.exitCode = 2;
  }
}
