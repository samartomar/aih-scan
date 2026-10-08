// Maintainer orchestration only. Assessment validation and authentication use the
// exact installed public package; no target code is loaded here or by the signer.
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  canonicalBytes,
  digest,
  object,
  parseJson,
  readRegular,
  schemas,
  sha256,
  targetDirectory,
  validateManifest,
} from "../refresh/contracts.mjs";
import { loadScanner } from "../refresh/scanner.mjs";
import { archiveCeiling } from "./check-refresh-run.mjs";
import { checkStatement } from "./check-statement.mjs";

export const publicationSchemas = Object.freeze({
  custody: "urn:aihq:scan:refresh-custody:1.0.0",
  selection: "urn:aihq:scan:refresh-signing-selection:1.0.0",
  inventory: "urn:aihq:scan:publication-inventory:1.0.0",
});
export const expandedCeiling = 2 * 1024 * 1024 * 1024;
const jsonLimit = 128 * 1024 * 1024;
const equal = (a, b) => canonicalBytes(a).equals(canonicalBytes(b));
const assert = (condition, reason) => {
  if (!condition) throw new Error(reason);
};
const bytesAt = (root, path, maximum) => readRegular(join(root, path), maximum);
const jsonAt = (root, path, maximum = jsonLimit) =>
  parseJson(bytesAt(root, path, maximum), maximum, true);
const write = (root, path, bytes) =>
  writeFileSync(join(root, path), bytes, { flag: "wx", mode: 0o600 });
const writeJson = (root, path, value) => write(root, path, canonicalBytes(value));
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const instant = (value) =>
  typeof value === "string" &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;

// Inspect sizes before allocating file contents. Links, devices, unknown paths,
// hard links and aggregate expansion beyond the independent bound are refused.
export function measureDirectory(root, allowed) {
  const files = [],
    directories = new Set([""]),
    seen = new Set();
  for (const path of allowed) {
    const components = path.split("/");
    components.pop();
    while (components.length) {
      directories.add(components.join("/"));
      components.pop();
    }
  }
  let bytes = 0;
  assert(
    lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink(),
    "Invalid directory root",
  );
  const walk = (relative = "") => {
    for (const name of readdirSync(join(root, relative)).sort()) {
      const path = relative ? `${relative}/${name}` : name,
        stat = lstatSync(join(root, path));
      assert(!stat.isSymbolicLink(), "Links refused");
      if (stat.isDirectory()) {
        assert(directories.has(path), "Unexpected directory");
        walk(path);
      } else {
        assert(stat.isFile() && stat.nlink === 1 && allowed.has(path), "Unexpected or linked file");
        bytes += stat.size;
        assert(
          Number.isSafeInteger(bytes) && bytes <= expandedCeiling,
          "Expanded data budget exceeded",
        );
        files.push({ path, byteLength: stat.size });
        seen.add(path);
      }
    }
  };
  walk();
  assert(seen.size === allowed.size, "Missing retained file");
  return { bytes, files };
}

export async function retainCustody({ candidate, scannerTarball, scannerInstall }) {
  const manifest = validateManifest(jsonAt(candidate, "manifest.json", 2097152));
  const scanner = await loadScanner(scannerTarball, scannerInstall, manifest.scanner.sourceCommit);
  assert(
    equal(scanner.identity, manifest.scanner),
    "Scanner identity differs from frozen manifest",
  );
  const lock = readRegular(join(scannerInstall, "package-lock.json"), 8 * 1024 * 1024);
  const parsedLock = parseJson(lock, 8 * 1024 * 1024);
  assert(
    parsedLock.lockfileVersion === 3 &&
      parsedLock.packages?.["node_modules/@aihq/scan"]?.version === manifest.scanner.version,
    "Consumer dependency lock mismatch",
  );
  const custody = {
    schema: publicationSchemas.custody,
    scanner: manifest.scanner,
    runtime: manifest.runtime,
    consumerLockSha256: sha256(lock),
  };
  const packedBytes = readRegular(scannerTarball, 64 * 1024 * 1024);
  if (existsSync(join(candidate, "scanner.tgz")))
    assert(
      bytesAt(candidate, "scanner.tgz", 64 * 1024 * 1024).equals(packedBytes),
      "Retained package collision",
    );
  else write(candidate, "scanner.tgz", packedBytes);
  write(candidate, "consumer-package-lock.json", lock);
  writeJson(candidate, "custody.json", custody);
  scanner.verifyUnchanged();
  return custody;
}

function checkSelection(selection) {
  object(selection, ["schema", "batchId", "manifestSha256", "targets"]);
  assert(
    selection.schema === publicationSchemas.selection &&
      /^batch:sha256:[0-9a-f]{64}$/.test(selection.batchId),
    "Invalid signing selection",
  );
  digest(selection.manifestSha256);
  assert(
    Array.isArray(selection.targets) && selection.targets.length <= 7,
    "Signing target bound exceeded",
  );
  const names = new Set();
  for (const row of selection.targets) {
    object(row, ["repository", "commit", "scanId", "artifactSha256", "statementSha256"]);
    assert(
      typeof row.repository === "string" &&
        /^[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+$/.test(row.repository) &&
        !names.has(row.repository),
      "Signing repository ambiguity",
    );
    names.add(row.repository);
    assert(
      /^[0-9a-f]{40}$/.test(row.commit) && /^scan:sha256:[0-9a-f]{64}$/.test(row.scanId),
      "Invalid signing identity",
    );
    digest(row.artifactSha256);
    digest(row.statementSha256);
  }
  return selection;
}

export async function validateCandidate({
  candidate,
  scannerInstall,
  expectedManifestSha256,
  expectedSelectionSha256,
  retainedPublication = false,
}) {
  digest(expectedManifestSha256);
  const manifestBytes = bytesAt(candidate, "manifest.json", 2097152);
  assert(sha256(manifestBytes) === expectedManifestSha256, "Frozen manifest digest differs");
  const manifest = validateManifest(parseJson(manifestBytes, 2097152, true));
  const custody = jsonAt(candidate, "custody.json", 2097152);
  object(custody, ["schema", "scanner", "runtime", "consumerLockSha256"]);
  assert(
    custody.schema === publicationSchemas.custody &&
      equal(custody.scanner, manifest.scanner) &&
      equal(custody.runtime, manifest.runtime),
    "Custody attribution mismatch",
  );
  digest(custody.consumerLockSha256);
  const lock = bytesAt(candidate, "consumer-package-lock.json", 8 * 1024 * 1024);
  assert(
    sha256(lock) === custody.consumerLockSha256 &&
      lock.equals(readRegular(join(scannerInstall, "package-lock.json"), 8 * 1024 * 1024)),
    "Installed dependency lock differs",
  );
  const scanner = await loadScanner(
    join(candidate, "scanner.tgz"),
    scannerInstall,
    manifest.scanner.sourceCommit,
  );
  assert(equal(scanner.identity, manifest.scanner), "Installed package differs");
  const inventoryName = retainedPublication ? "producer-inventory.json" : "inventory.json";
  const inventory = jsonAt(candidate, inventoryName);
  object(inventory, [
    "schema",
    "batchId",
    "manifestSha256",
    "createdAt",
    "scanner",
    "runtime",
    "profile",
    "unavailableCoverage",
    "targets",
  ]);
  assert(
    inventory.schema === schemas.inventory &&
      inventory.batchId === manifest.batchId &&
      inventory.manifestSha256 === expectedManifestSha256 &&
      instant(inventory.createdAt) &&
      equal(inventory.scanner, manifest.scanner) &&
      equal(inventory.runtime, manifest.runtime) &&
      inventory.profile === manifest.profile &&
      equal(inventory.unavailableCoverage, manifest.unavailableCoverage) &&
      Array.isArray(inventory.targets) &&
      inventory.targets.length === 7,
    "Incomplete or substituted producer inventory",
  );
  const allowed = new Set([
    "manifest.json",
    inventoryName,
    "scanner.tgz",
    "consumer-package-lock.json",
    "custody.json",
  ]);
  if (retainedPublication) {
    allowed.add("inventory.json");
    allowed.add("selection.json");
    allowed.add("publication.json");
    const published = jsonAt(candidate, "inventory.json");
    assert(
      Array.isArray(published.targets) && published.targets.length === 7,
      "Incomplete publication inventory",
    );
    for (const row of published.targets)
      if (row.authenticity === "authenticated") {
        assert(
          row.authenticatedPath === `targets/${targetDirectory(row.repository)}/authenticated.json`,
          "Invalid authenticated path",
        );
        allowed.add(row.authenticatedPath);
      }
  }
  for (let index = 0; index < 7; index++) {
    const row = inventory.targets[index],
      target = manifest.targets[index],
      directory = `targets/${targetDirectory(target.repository)}`;
    const fields = [
      "repository",
      "commit",
      "status",
      "resultPath",
      "resultSha256",
      "diagnostics",
      "detectors",
      "measurements",
    ];
    const assessmentFields = [
      "scanId",
      "completion",
      "authenticity",
      "artifactPath",
      "artifactSha256",
      "statementPath",
      "statementSha256",
      "candidatePath",
    ];
    assert(
      row.status === "assessment" || row.status === "diagnostic",
      "Invalid terminal source row",
    );
    object(row, row.status === "assessment" ? [...fields, ...assessmentFields] : fields);
    assert(
      row.repository === target.repository &&
        row.commit === target.commit &&
        row.resultPath === `${directory}/result.json`,
      "Source row or result path differs",
    );
    allowed.add(row.resultPath);
    object(row.measurements, [
      "durationMs",
      "sourceEntries",
      "sourceBytes",
      "reportBytes",
      "annexBytes",
      "artifactBytes",
    ]);
    assert(integer(row.measurements.durationMs), "Invalid measured duration");
    digest(row.resultSha256);
    if (row.status === "assessment") {
      assert(
        row.artifactPath === `${directory}/artifact.json` &&
          row.statementPath === `${directory}/statement.json` &&
          row.candidatePath === `${directory}/candidate.json`,
        "Candidate paths differ",
      );
      for (const path of [row.artifactPath, row.statementPath, row.candidatePath])
        allowed.add(path);
    }
  }
  const measurement = measureDirectory(candidate, allowed);
  const selection = {
    schema: publicationSchemas.selection,
    batchId: manifest.batchId,
    manifestSha256: expectedManifestSha256,
    targets: [],
  };
  for (let index = 0; index < 7; index++) {
    const row = inventory.targets[index],
      target = manifest.targets[index];
    const resultBytes = bytesAt(candidate, row.resultPath, jsonLimit),
      result = parseJson(resultBytes, jsonLimit, true);
    assert(
      sha256(resultBytes) === row.resultSha256 &&
        result.schema === "urn:aihq:scan:run-result:1.0.0" &&
        result.status === row.status &&
        equal(row.diagnostics, result.diagnostics),
      "Result binding differs",
    );
    if (row.status === "diagnostic") {
      object(result, ["schema", "status", "phase", "diagnostics"]);
      assert(
        ["request", "capture", "assembly"].includes(result.phase) &&
          Array.isArray(result.diagnostics) &&
          result.diagnostics.length > 0,
        "Invalid diagnostic result",
      );
      assert(
        equal(
          row.detectors,
          target.detectors.map((detector) => ({
            detectorId: detector.detectorId,
            profileId: detector.profileId,
            outcome: "not-run",
            coverage: null,
            diagnostics: result.diagnostics,
          })),
        ),
        "Diagnostic detector accounting differs",
      );
      assert(
        ["sourceEntries", "sourceBytes", "reportBytes", "annexBytes", "artifactBytes"].every(
          (key) => row.measurements[key] === null,
        ),
        "Diagnostic measurements invent capture",
      );
      continue;
    }
    object(result, ["schema", "status", "scanId", "report", "annexes", "diagnostics"]);
    assert(Array.isArray(result.annexes), "Missing original annex data");
    for (const annex of result.annexes) {
      object(annex, ["id", "bytesBase64"]);
      assert(
        typeof annex.bytesBase64 === "string" &&
          Buffer.from(annex.bytesBase64, "base64").toString("base64") === annex.bytesBase64,
        "Noncanonical original annex encoding",
      );
    }
    const prepared = await scanner.host.prepareArtifact({
      report: result.report,
      annexes: result.annexes.map((annex) => ({
        id: annex.id,
        bytes: Buffer.from(annex.bytesBase64, "base64"),
      })),
    });
    const artifactBytes = bytesAt(candidate, row.artifactPath, manifest.limits.maxArtifactBytes),
      statementBytes = bytesAt(candidate, row.statementPath, manifest.limits.maxStatementBytes);
    assert(
      Buffer.from(prepared.bytes).equals(artifactBytes) &&
        canonicalBytes(prepared.statement).equals(statementBytes),
      "Unsigned assessment or detached statement differs",
    );
    const read = await scanner.read.readArtifact(artifactBytes);
    assert(
      read.status === "read" &&
        read.scanId === result.scanId &&
        row.scanId === result.scanId &&
        read.report.source.kind === "git" &&
        read.report.source.repository === target.repositoryUrl &&
        read.report.source.commit === target.commit,
      "Assessment source identity differs",
    );
    const report = read.report;
    assert(equal(report.effectiveLimits, manifest.limits), "Assessment effective limits differ");
    assert(
      report.results.length === 4 &&
        report.requestedDetectors.length === 4 &&
        target.detectors.every((expected) => {
          const actual = report.requestedDetectors.find(
            (item) => item.detectorId === expected.detectorId,
          );
          return (
            actual &&
            equal(
              {
                detectorId: actual.detectorId,
                profileId: actual.profileId,
                configuration: actual.configuration,
              },
              expected,
            )
          );
        }) &&
        equal(report.selection.excludedPaths, target.selection.excludedPaths),
      "Assessment profile or scope differs",
    );
    assert(
      equal(
        report.selection.paths,
        report.source.capture.entries
          .filter((entry) => "sha256" in entry)
          .map((entry) => entry.path)
          .sort(),
      ),
      "Assessment does not cover selected inventory",
    );
    assert(
      row.completion === report.completion &&
        row.authenticity === "unsigned" &&
        row.artifactSha256 === sha256(artifactBytes) &&
        row.statementSha256 === sha256(statementBytes),
      "Candidate digest or completion differs",
    );
    const expectedRows = target.detectors.map((expected) => {
      const actual = report.results.find((item) => item.detectorId === expected.detectorId);
      assert(actual, "Missing detector terminal row");
      return {
        detectorId: actual.detectorId,
        profileId: expected.profileId,
        outcome: actual.outcome,
        coverage: actual.coverage,
        diagnostics: actual.diagnostics,
      };
    });
    assert(equal(row.detectors, expectedRows), "Detector terminal inventory differs");
    const measurements = {
      sourceEntries: report.source.capture.entries.length,
      sourceBytes: report.source.capture.entries
        .filter((entry) => entry.kind === "file")
        .reduce((sum, entry) => sum + entry.byteLength, 0),
      reportBytes: prepared.artifact.report.byteLength,
      annexBytes: prepared.artifact.annexes.reduce((sum, annex) => sum + annex.byteLength, 0),
      artifactBytes: artifactBytes.length,
    };
    assert(
      Object.entries(measurements).every(([key, value]) => row.measurements[key] === value),
      "Resource measurement differs",
    );
    const metadata = jsonAt(candidate, row.candidatePath, 2097152);
    const signingRow = {
      repository: row.repository,
      commit: row.commit,
      scanId: row.scanId,
      artifactSha256: row.artifactSha256,
      statementSha256: row.statementSha256,
    };
    assert(
      equal(metadata, {
        schema: schemas.candidate,
        batchId: manifest.batchId,
        ...signingRow,
        resultSha256: row.resultSha256,
      }),
      "Closed candidate metadata differs",
    );
    selection.targets.push(signingRow);
  }
  scanner.verifyUnchanged();
  checkSelection(selection);
  if (expectedSelectionSha256 !== undefined) {
    digest(expectedSelectionSha256);
    assert(
      sha256(canonicalBytes(selection)) === expectedSelectionSha256,
      "Independent signing selection differs",
    );
  }
  return { manifest, inventory, selection, measurement, scanner, allowed };
}

export async function validatePublication({
  directory,
  scannerInstall,
  expectedManifestSha256,
  expectedSelectionSha256,
  trust,
}) {
  const checked = await validateCandidate({
    candidate: directory,
    scannerInstall,
    expectedManifestSha256,
    expectedSelectionSha256,
    retainedPublication: true,
  });
  const published = jsonAt(directory, "inventory.json");
  const receipt = jsonAt(directory, "publication.json", 2097152);
  assert(
    receipt.schema === "urn:aihq:scan:publication-assets:1.0.0" &&
      receipt.batchId === checked.manifest.batchId,
    "Publication receipt batch differs",
  );
  const expected = {
    schema: publicationSchemas.inventory,
    batchId: checked.manifest.batchId,
    manifestSha256: expectedManifestSha256,
    selectionSha256: expectedSelectionSha256,
    producerInventorySha256: sha256(bytesAt(directory, "producer-inventory.json", jsonLimit)),
    actionsCustody: validateActionsCustody(
      published.actionsCustody,
      checked.manifest.scanner.sourceCommit,
    ),
    scanner: checked.manifest.scanner,
    runtime: checked.manifest.runtime,
    profile: checked.manifest.profile,
    unavailableCoverage: checked.manifest.unavailableCoverage,
    targets: [],
  };
  assert(
    equal(jsonAt(directory, "selection.json", 2097152), checked.selection),
    "Published signing selection differs",
  );
  for (let index = 0; index < 7; index++) {
    const original = checked.inventory.targets[index],
      row = published.targets[index];
    if (row.authenticity === "authenticated") {
      assert(original.status === "assessment", "Diagnostic source cannot be authenticated");
      const authenticatedBytes = bytesAt(
        directory,
        row.authenticatedPath,
        checked.manifest.limits.maxArtifactBytes,
      );
      const authentication = await checked.scanner.host.authenticateArtifact({
        bytes: authenticatedBytes,
        expectedScanId: original.scanId,
        trust,
      });
      assert(
        authentication.status === "authenticated" &&
          sha256(authenticatedBytes) === row.authenticatedSha256,
        "Published artifact authentication refused",
      );
      const authenticatedArtifact = parseJson(
        authenticatedBytes,
        checked.manifest.limits.maxArtifactBytes,
        true,
      );
      const unsignedArtifact = parseJson(
        bytesAt(directory, original.artifactPath, checked.manifest.limits.maxArtifactBytes),
        checked.manifest.limits.maxArtifactBytes,
        true,
      );
      delete authenticatedArtifact.attestation;
      assert(
        equal(authenticatedArtifact, unsignedArtifact),
        "Authenticated bytes differ from selected candidate",
      );
      expected.targets.push({
        ...original,
        authenticity: "authenticated",
        authenticatedPath: row.authenticatedPath,
        authenticatedSha256: row.authenticatedSha256,
        authentication,
      });
    } else expected.targets.push({ ...original });
  }
  assert(equal(published, expected), "Durable discovery inventory differs from checked artifacts");
  checked.scanner.verifyUnchanged();
  return published;
}

export function prepareSigning({ candidate, selection, expectedSelectionSha256, output }) {
  const bytes = canonicalBytes(checkSelection(selection));
  assert(sha256(bytes) === digest(expectedSelectionSha256), "Signing selection digest differs");
  const statements = selection.targets.map((row) => {
    const bytes = bytesAt(
      candidate,
      `targets/${targetDirectory(row.repository)}/statement.json`,
      131072,
    );
    const { statement } = checkStatement(bytes, row.statementSha256);
    assert(statement.predicate.scanId === row.scanId, "Signing Scan ID differs");
    return { bytes, statement };
  });
  mkdirSync(output, { mode: 0o700 });
  write(output, "selection.json", bytes);
  statements.forEach(({ bytes, statement }, index) => {
    write(output, `statement-${index}.json`, bytes);
    writeJson(output, `predicate-${index}.json`, statement.predicate);
  });
  return statements.map(({ statement }) => `sha256:${statement.subject[0].digest.sha256}`);
}

export function recheckSigning({ directory, expectedSelectionSha256 }) {
  const bytes = bytesAt(directory, "selection.json", 2097152);
  assert(sha256(bytes) === digest(expectedSelectionSha256), "Signer selection differs");
  const selection = checkSelection(parseJson(bytes, 2097152, true));
  const allowed = new Set(["selection.json"]);
  const digests = selection.targets.map((row, index) => {
    allowed.add(`statement-${index}.json`);
    allowed.add(`predicate-${index}.json`);
    const { statement } = checkStatement(
      bytesAt(directory, `statement-${index}.json`, 131072),
      row.statementSha256,
    );
    assert(
      statement.predicate.scanId === row.scanId &&
        equal(jsonAt(directory, `predicate-${index}.json`, 131072), statement.predicate),
      "Signer statement binding differs",
    );
    return `sha256:${statement.subject[0].digest.sha256}`;
  });
  measureDirectory(directory, allowed);
  return digests;
}

function validateActionsCustody(value, head) {
  if (value === null) return null;
  object(
    value,
    ["runId", "head", "artifactId", "serviceDigest", "archiveBytes"],
    ["event", "phase"],
  );
  if (value.event !== undefined)
    assert(
      value.event === "scan-refresh-custody.verified" && value.phase === "actions-custody",
      "Unexpected custody boundary event",
    );
  assert(
    Number.isSafeInteger(value.runId) &&
      value.runId > 0 &&
      Number.isSafeInteger(value.artifactId) &&
      value.artifactId > 0 &&
      value.head === head &&
      /^sha256:[0-9a-f]{64}$/.test(value.serviceDigest) &&
      integer(value.archiveBytes) &&
      value.archiveBytes > 0 &&
      value.archiveBytes <= archiveCeiling,
    "Actions custody attribution differs",
  );
  return {
    runId: value.runId,
    head: value.head,
    artifactId: value.artifactId,
    serviceDigest: value.serviceDigest,
    archiveBytes: value.archiveBytes,
  };
}

export async function assemblePublication({
  candidate,
  scannerInstall,
  expectedManifestSha256,
  expectedSelectionSha256,
  bundles,
  trust,
  output,
  actionsCustody = null,
}) {
  const checked = await validateCandidate({
    candidate,
    scannerInstall,
    expectedManifestSha256,
    expectedSelectionSha256,
  });
  actionsCustody = validateActionsCustody(actionsCustody, checked.manifest.scanner.sourceCommit);
  const bundleNames = new Set(checked.selection.targets.map((_, index) => `bundle-${index}.json`));
  for (const name of readdirSync(bundles))
    assert(bundleNames.has(name), "Unexpected attestation bundle");
  const authenticated = new Map();
  for (let index = 0; index < checked.selection.targets.length; index++) {
    const row = checked.selection.targets[index],
      name = `bundle-${index}.json`;
    if (!readdirSync(bundles).includes(name)) continue; // Remains explicitly unsigned in durable inventory.
    const unsigned = bytesAt(
      candidate,
      `targets/${targetDirectory(row.repository)}/artifact.json`,
      checked.manifest.limits.maxArtifactBytes,
    );
    const bundle = parseJson(bytesAt(bundles, name, 1024 * 1024), 1024 * 1024);
    const attached = await checked.scanner.host.attachAttestation({ bytes: unsigned, bundle });
    const result = await checked.scanner.host.authenticateArtifact({
      bytes: attached.bytes,
      expectedScanId: row.scanId,
      trust,
    });
    assert(result.status === "authenticated", "Independent artifact authentication refused");
    authenticated.set(row.repository, {
      bytes: Buffer.from(attached.bytes),
      authentication: result,
    });
  }
  checked.scanner.verifyUnchanged();
  // Authenticate every supplied bundle before exclusive output creation.
  mkdirSync(output, { mode: 0o700 });
  mkdirSync(join(output, "targets"), { mode: 0o700 });
  const inventory = {
    schema: publicationSchemas.inventory,
    batchId: checked.manifest.batchId,
    manifestSha256: expectedManifestSha256,
    selectionSha256: expectedSelectionSha256,
    producerInventorySha256: sha256(bytesAt(candidate, "inventory.json", jsonLimit)),
    actionsCustody,
    scanner: checked.manifest.scanner,
    runtime: checked.manifest.runtime,
    profile: checked.manifest.profile,
    unavailableCoverage: checked.manifest.unavailableCoverage,
    targets: checked.inventory.targets.map((row) => {
      const proof = authenticated.get(row.repository);
      return proof
        ? {
            ...row,
            authenticity: "authenticated",
            authenticatedPath: `targets/${targetDirectory(row.repository)}/authenticated.json`,
            authenticatedSha256: sha256(proof.bytes),
            authentication: proof.authentication,
          }
        : { ...row };
    }),
  };
  for (const target of checked.manifest.targets)
    mkdirSync(join(output, "targets", targetDirectory(target.repository)), { mode: 0o700 });
  for (const path of checked.allowed)
    copyFileSync(
      join(candidate, path),
      join(output, path === "inventory.json" ? "producer-inventory.json" : path),
      1,
    );
  writeJson(output, "selection.json", checked.selection);
  for (const row of inventory.targets) {
    const proof = authenticated.get(row.repository);
    if (proof) write(output, row.authenticatedPath, proof.bytes);
  }
  writeJson(output, "inventory.json", inventory);
  const allowed = new Set([...checked.allowed].filter((path) => path !== "inventory.json"));
  for (const path of ["producer-inventory.json", "selection.json", "inventory.json"])
    allowed.add(path);
  for (const row of inventory.targets)
    if (row.authenticatedPath) allowed.add(row.authenticatedPath);
  const measurement = measureDirectory(output, allowed);
  const assets = measurement.files.map(({ path, byteLength }) => ({
    path,
    name: path.replaceAll("/", "--"),
    byteLength,
    sha256: sha256(bytesAt(output, path, jsonLimit)),
  }));
  const receipt = {
    schema: "urn:aihq:scan:publication-assets:1.0.0",
    batchId: inventory.batchId,
    expandedBytes: measurement.bytes,
    assets,
  };
  writeJson(output, "publication.json", receipt);
  allowed.add("publication.json");
  measureDirectory(output, allowed);
  return inventory;
}

let operationPhase = "arguments";
const actionRunId = () =>
  /^[1-9][0-9]{0,15}$/.test(process.env.GITHUB_RUN_ID ?? "") ? process.env.GITHUB_RUN_ID : null;
const operationEvent = (details = {}) => ({
  event: "scan-refresh-publication.completed",
  phase: operationPhase,
  runId: actionRunId(),
  ...details,
});
async function cli() {
  const [mode, ...args] = process.argv.slice(2);
  let context = {};
  if (
    [
      "retain",
      "check",
      "prepare-signing",
      "recheck-signing",
      "assemble",
      "verify-publication",
    ].includes(mode)
  )
    operationPhase = mode;
  if (mode === "retain" && args.length === 3) {
    await retainCustody({ candidate: args[0], scannerTarball: args[1], scannerInstall: args[2] });
    context = { batchId: jsonAt(args[0], "manifest.json", 2097152).batchId };
  } else if (
    mode === "check" &&
    (args.length === 4 || (args.length === 5 && args[4] === "transport"))
  ) {
    const checked = await validateCandidate({
      candidate: args[0],
      scannerInstall: args[1],
      expectedManifestSha256: args[2],
    });
    // upload-artifact uses compression-level:0. Deliberately conservative ZIP
    // header allowance; actual service size/digest is separately checked later.
    if (args[4] === "transport")
      assert(
        checked.measurement.bytes + checked.measurement.files.length * 1024 + 65536 <=
          archiveCeiling,
        "Uncompressed transport admission budget exceeded",
      );
    writeFileSync(args[3], canonicalBytes(checked.selection), { flag: "wx", mode: 0o600 });
    process.stdout.write(
      `${JSON.stringify(operationEvent({ batchId: checked.manifest.batchId, inputSha256: args[2], selectionSha256: sha256(canonicalBytes(checked.selection)), expandedBytes: checked.measurement.bytes }))}\n`,
    );
  } else if (mode === "prepare-signing" && args.length === 4) {
    const selection = parseJson(readRegular(args[1], 2097152), 2097152, true);
    prepareSigning({
      candidate: args[0],
      selection,
      expectedSelectionSha256: args[2],
      output: args[3],
    });
    context = {
      batchId: selection.batchId,
      inputSha256: selection.manifestSha256,
      statements: selection.targets.length,
    };
  } else if (mode === "recheck-signing" && args.length === 2) {
    const digests = recheckSigning({ directory: args[0], expectedSelectionSha256: args[1] });
    const output = `count=${digests.length}\n${digests.map((digest, index) => `digest_${index}=${digest}`).join("\n")}\n`;
    if (process.env.GITHUB_OUTPUT) writeFileSync(process.env.GITHUB_OUTPUT, output, { flag: "a" });
    else process.stdout.write(output);
    context = {
      batchId: jsonAt(args[0], "selection.json", 2097152).batchId,
      statements: digests.length,
    };
  } else if (mode === "assemble" && [7, 8].includes(args.length)) {
    const inventory = await assemblePublication({
      candidate: args[0],
      scannerInstall: args[1],
      expectedManifestSha256: args[2],
      expectedSelectionSha256: args[3],
      bundles: args[4],
      trust: parseJson(readRegular(args[5], 1024 * 1024)),
      output: args[6],
      actionsCustody: args[7] ? parseJson(readRegular(args[7], 2097152)) : null,
    });
    context = {
      batchId: inventory.batchId,
      inputSha256: args[2],
      targets: inventory.targets.length,
      authenticated: inventory.targets.filter((row) => row.authenticity === "authenticated").length,
    };
  } else if (
    mode === "verify-publication" &&
    (args.length === 5 || (args.length === 6 && args[5] === "transport"))
  ) {
    const inventory = await validatePublication({
      directory: args[0],
      scannerInstall: args[1],
      expectedManifestSha256: args[2],
      expectedSelectionSha256: args[3],
      trust: parseJson(readRegular(args[4], 1024 * 1024)),
    });
    context = {
      batchId: inventory.batchId,
      inputSha256: args[2],
      targets: inventory.targets.length,
    };
    if (args[5] === "transport") {
      const receipt = jsonAt(args[0], "publication.json", 2097152);
      const files = new Set([...receipt.assets.map((asset) => asset.path), "publication.json"]);
      const measured = measureDirectory(args[0], files);
      assert(
        measured.bytes + measured.files.length * 1024 + 65536 <= archiveCeiling,
        "Publication transport admission budget exceeded",
      );
    }
  } else throw new Error("Expected exact refresh publication operation arguments");
  if (mode !== "check") process.stdout.write(`${JSON.stringify(operationEvent(context))}\n`);
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  cli().catch(() => {
    process.stderr.write(
      `${JSON.stringify({ event: "scan-refresh-publication.refused", phase: operationPhase, runId: actionRunId(), reason: "validation-or-custody-refused" })}\n`,
    );
    process.exitCode = 2;
  });
