// Final transport uses the normal maintainer's gh authentication. The operator
// selects custody and an independently prepared reader, before any release write.
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalBytes, object, parseJson, readRegular, sha256 } from "../refresh/contracts.mjs";
import { loadScanner } from "../refresh/scanner.mjs";
import { archiveCeiling, checkRefreshRun } from "./check-refresh-run.mjs";
import { extractFinalZip } from "./extract-final-zip.mjs";
import { ghTransport, publishRelease } from "./publish-refresh-release.mjs";
import { validatePublication } from "./refresh-publication.mjs";

export function checkFinalSelection(value) {
  object(value, [
    "schema",
    "repository",
    "sourceHead",
    "publisherRunId",
    "finalArtifactId",
    "finalArtifactDigest",
    "manifestSha256",
    "selectionSha256",
    "readerInstallationSha256",
  ]);
  if (
    value.schema !== "urn:aihq:scan:final-publication-selection:1.0.0" ||
    value.repository !== "samartomar/aih-scan" ||
    typeof value.sourceHead !== "string" ||
    !/^[0-9a-f]{40}$/.test(value.sourceHead) ||
    typeof value.finalArtifactDigest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(value.finalArtifactDigest)
  )
    throw new Error("Final operator selection refused");
  for (const name of ["publisherRunId", "finalArtifactId"])
    if (
      typeof value[name] !== "string" ||
      !/^[1-9][0-9]{0,15}$/.test(value[name]) ||
      !Number.isSafeInteger(Number(value[name]))
    )
      throw new Error("Final immutable selector refused");
  for (const name of ["manifestSha256", "selectionSha256", "readerInstallationSha256"])
    if (typeof value[name] !== "string" || !/^[0-9a-f]{64}$/.test(value[name]))
      throw new Error("Final independent digest refused");
  return value;
}

export async function publishFinal({ selection, scannerInstall, output, trustBytes, command }) {
  checkFinalSelection(selection);
  const trust = parseJson(trustBytes, 1048576),
    transport = ghTransport({ reviewedHead: selection.sourceHead, command }),
    base = "repos/samartomar/aih-scan";
  await transport.verifyScope();
  const run = transport.api.json(`${base}/actions/runs/${selection.publisherRunId}`),
    artifacts = transport.api.json(
      `${base}/actions/runs/${selection.publisherRunId}/artifacts?per_page=100`,
    );
  const custody = checkRefreshRun(
    run,
    artifacts,
    selection.publisherRunId,
    selection.sourceHead,
    selection.finalArtifactId,
    selection.finalArtifactDigest,
    "scan-refresh-final-publication",
  );
  const archive = transport.api.bytes(
    `${base}/actions/artifacts/${selection.finalArtifactId}/zip`,
    { maximum: archiveCeiling, timeout: 120000 },
  );
  if (
    archive.status !== 200 ||
    archive.bytes.length !== custody.archiveBytes ||
    `sha256:${sha256(archive.bytes)}` !== selection.finalArtifactDigest
  )
    throw new Error("Raw final service archive digest differs");
  mkdirSync(output, { mode: 0o700 });
  const save = (name, bytes) =>
    writeFileSync(join(output, name), bytes, { flag: "wx", mode: 0o600 });
  save("final.zip", archive.bytes);
  save("operator-selection.json", canonicalBytes(selection));
  save("publisher-run.json", canonicalBytes(run));
  save("publisher-artifacts.json", canonicalBytes(artifacts));
  save("independent-trust.json", trustBytes);
  const directory = join(output, "publication"),
    measurement = extractFinalZip(archive.bytes, directory);
  const inventory = await validatePublication({
    directory,
    scannerInstall,
    expectedManifestSha256: selection.manifestSha256,
    expectedSelectionSha256: selection.selectionSha256,
    readerInstallationSha256: selection.readerInstallationSha256,
    trust,
  });
  const manifest = parseJson(readRegular(join(directory, "manifest.json"), 2097152), 2097152, true);
  if (manifest.scanner.sourceCommit !== selection.sourceHead)
    throw new Error("Final reviewed source head differs");
  const reader = await loadScanner(
    join(directory, "scanner.tgz"),
    scannerInstall,
    selection.sourceHead,
  );
  const record = {
    schema: "urn:aihq:scan:final-publication-custody:1.0.0",
    batchId: inventory.batchId,
    selection,
    actionsCustody: custody,
    archiveSha256: sha256(archive.bytes),
    archiveBytes: archive.bytes.length,
    expandedBytes: measurement.expandedBytes,
    receiptSha256: sha256(readRegular(join(directory, "publication.json"), 2097152)),
    independentTrustSha256: sha256(trustBytes),
    consumerLockSha256: sha256(
      readRegular(join(directory, "consumer-package-lock.json"), 8 * 1024 * 1024),
    ),
    reader: {
      scanner: reader.identity,
      runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    },
    producer: { scanner: manifest.scanner, runtime: manifest.runtime },
    authenticatedTargets: inventory.targets.filter((row) => row.authenticity === "authenticated")
      .length,
  };
  const custodyPath = join(output, "publication-custody.json");
  save("publication-custody.json", canonicalBytes(record));
  reader.verifyUnchanged();
  // Recheck operator and current main immediately before mutable transport.
  await transport.verifyScope();
  return {
    ...(await publishRelease({ directory, transport, custodyPath })),
    publisherRunId: custody.runId,
    finalArtifactId: custody.artifactId,
    readerInstallationSha256: reader.identity.installationSha256,
  };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 5)
      throw new Error(
        "Expected selected final custody, prepared reader installation, exclusive output",
      );
    const selection = checkFinalSelection(
        parseJson(readRegular(process.argv[2], 2097152), 2097152, true),
      ),
      root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    const git = (args) => {
      const result = spawnSync("git", args, {
        cwd: root,
        encoding: "buffer",
        timeout: 30000,
        maxBuffer: 2097152,
        windowsHide: true,
      });
      if (result.status !== 0 || result.error) throw new Error("Reviewed local tool scope refused");
      return Buffer.from(result.stdout);
    };
    if (
      git(["rev-parse", "HEAD"]).toString().trim() !== selection.sourceHead ||
      !/^https:\/\/github\.com\/samartomar\/aih-scan(?:\.git)?\s*$/.test(
        git(["remote", "get-url", "origin"]).toString(),
      )
    )
      throw new Error("Reviewed tool checkout identity differs");
    git(["diff", "--quiet", "HEAD", "--", "tools", ".github/scan-report-trust.json"]);
    const trustBytes = git(["show", `${selection.sourceHead}:.github/scan-report-trust.json`]);
    const result = await publishFinal({
      selection,
      scannerInstall: process.argv[3],
      output: process.argv[4],
      trustBytes,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(
      `${JSON.stringify({ event: "scan-refresh-final.refused", phase: "maintainer-final-publication", reason: error.code === "immutable-releases-disabled" ? error.code : "selected-custody-or-reader-or-release-refused" })}\n`,
    );
    process.exitCode = 2;
  }
}
