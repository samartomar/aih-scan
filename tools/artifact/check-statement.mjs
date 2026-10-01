// Trusted signer boundary: consumes a bounded detached statement, never report
// bytes, detector output, target code, a package or an executable from its input.
import { createHash } from "node:crypto";
import { constants as fsConstants, openSync, fstatSync, closeSync, lstatSync, readSync, writeFileSync, appendFileSync } from "node:fs";
import { canonicalBytes, strictParse } from "../../dist/assessment/json.js";
import { object, array, text, digest, integer, validScanId } from "../../dist/artifact/validation.js";

// Exported only for the repository's narrow operator tools.
export function readRegular(path, maxBytes) {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maxBytes) throw new Error("Invalid bounded regular file");
  const fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const first = fstatSync(fd);
    if (first.dev !== before.dev || first.ino !== before.ino || first.nlink !== 1 || !first.isFile() || first.size !== before.size) throw new Error("Unstable input file");
    const bytes = Buffer.alloc(first.size);
    let at = 0;
    while (at < bytes.length) { const read = readSync(fd, bytes, at, bytes.length - at, at); if (read === 0) throw new Error("Short input"); at += read; }
    const after = fstatSync(fd), pathname = lstatSync(path);
    if (after.dev !== first.dev || after.ino !== first.ino || after.size !== first.size || after.mtimeMs !== first.mtimeMs || after.ctimeMs !== first.ctimeMs || pathname.dev !== first.dev || pathname.ino !== first.ino || pathname.isSymbolicLink() || pathname.nlink !== 1) throw new Error("Input changed while reading");
    return bytes;
  } finally { closeSync(fd); }
}
export function checkStatement(bytes, expectedSha256) {
  digest(expectedSha256);
  if (createHash("sha256").update(bytes).digest("hex") !== expectedSha256) throw new Error("Detached statement digest mismatch");
  const statement = object(strictParse(bytes, "detached statement", 128 * 1024), ["_type", "subject", "predicateType", "predicate"]);
  if (statement._type !== "https://in-toto.io/Statement/v1" || statement.predicateType !== "urn:aihq:scan:artifact-attestation:1.0.0") throw new Error("Unsupported statement");
  const subjects = array(statement.subject);
  if (subjects.length !== 1) throw new Error("One subject required");
  const subject = object(subjects[0], ["name", "digest"]);
  if (subject.name !== "scan-report") throw new Error("Invalid subject");
  const reportSha256 = digest(object(subject.digest, ["sha256"]).sha256);
  const predicate = object(statement.predicate, ["scanId", "reportSchema", "reportByteLength", "annexManifestSha256"]);
  validScanId(predicate.scanId); text(predicate.reportSchema);
  if (predicate.reportSchema !== "urn:aihq:scan:report:1.0.0") throw new Error("Unsupported producer report");
  integer(predicate.reportByteLength, 16 * 1024 * 1024); digest(predicate.annexManifestSha256);
  return { reportSha256, predicate, statement };
}
// Main is deliberately explicit so importing the bounded reader has no effects.
if (process.argv[1]?.replaceAll("\\", "/").endsWith("/check-statement.mjs")) {
  try {
    if (process.argv.length !== 5) throw new Error("Usage: check-statement STATEMENT EXPECTED_SHA256 PREDICATE_OUTPUT");
    const checked = checkStatement(readRegular(process.argv[2], 128 * 1024), process.argv[3]);
    writeFileSync(process.argv[4], canonicalBytes(checked.predicate), { flag: "wx", mode: 0o600 });
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `digest=sha256:${checked.reportSha256}\n`);
  } catch { process.stderr.write("Detached statement refused.\n"); process.exitCode = 2; }
}
