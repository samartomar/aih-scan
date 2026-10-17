#!/usr/bin/env node
/**
 * Verifies a genuine capture bundle through the public API and projects the verified
 * facts into the Core-owned organization evidence envelope.
 *
 * Every custody input is supplied by the operator. This script ships no trust root, no
 * expected-claims policy and no evidence; it verifies exactly what it is handed, and it
 * refuses by name when anything is missing or does not bind.
 *
 * A successful run proves that the signature, the claims policy, the candidate and the
 * annex bytes all bind. It is not organization approval, not qualification, and not
 * proof that Core accepted anything.
 *
 * Usage:
 *   node examples/verify-capture-bundle.mjs \
 *     --bundle <capture-bundle-directory> \
 *     --evidence <signed-attestation-envelope.json> \
 *     --roots <trust-roots.json> \
 *     --expected <expected-claims.json> \
 *     [--subject-digest sha256:<64-hex>]
 *
 * `--roots` is `{ "roots": [ { "identity", "class", "keyId", "publicKeySpkiBase64" } ] }`.
 * `--expected` is the claims policy `verifyScanAttestationV2` requires, including `now`
 * and the exact expected `signer`.
 */
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { loadScan } from "./load-scan.mjs";

const USAGE =
  "usage: node examples/verify-capture-bundle.mjs --bundle <dir> --evidence <file> --roots <file> --expected <file> [--subject-digest sha256:<64-hex>]";

function refuse(reason) {
  process.stderr.write(`refused: ${reason}\n`);
  process.exitCode = 2;
  return undefined;
}

function parseArguments(argv) {
  const fields = {
    "--bundle": "bundle",
    "--evidence": "evidence",
    "--roots": "roots",
    "--expected": "expected",
    "--subject-digest": "subjectDigest",
  };
  const parsed = {};
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) return undefined;
  if (argv.length % 2 !== 0) return undefined;
  for (let index = 0; index < argv.length; index += 2) {
    const field = fields[argv[index]];
    const value = argv[index + 1];
    if (field === undefined || !value || parsed[field] !== undefined) return undefined;
    parsed[field] = value;
  }
  for (const required of ["bundle", "evidence", "roots", "expected"])
    if (parsed[required] === undefined) return undefined;
  return parsed;
}

const args = parseArguments(process.argv.slice(2));
if (args === undefined) {
  process.stdout.write(`${USAGE}\n`);
  process.exit(0);
}

const { scan, from } = await loadScan();
process.stdout.write(`loaded ${from}\n`);

const readJson = (path, label) => {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return refuse(`${label} is not readable JSON: ${path}`);
  }
};

const rootsDocument = readJson(args.roots, "trust roots");
if (rootsDocument === undefined) process.exit(2);
if (
  rootsDocument === null ||
  typeof rootsDocument !== "object" ||
  !Array.isArray(rootsDocument.roots) ||
  rootsDocument.roots.length === 0
) {
  refuse("trust roots must be { roots: [ … ] } with at least one operator-supplied root");
  process.exit(2);
}
const roots = [];
for (const [index, root] of rootsDocument.roots.entries()) {
  if (root === null || typeof root !== "object" || Array.isArray(root)) {
    refuse(`trust root ${index} is not an object`);
    process.exit(2);
  }
  let publicKey;
  try {
    if (typeof root.publicKeySpkiBase64 !== "string") throw new TypeError("not a string");
    publicKey = createPublicKey({
      key: Buffer.from(root.publicKeySpkiBase64, "base64"),
      format: "der",
      type: "spki",
    });
  } catch {
    refuse(`trust root ${index} publicKeySpkiBase64 is not a readable SPKI public key`);
    process.exit(2);
  }
  roots.push({ identity: root.identity, class: root.class, keyId: root.keyId, publicKey });
}

const expected = readJson(args.expected, "expected claims policy");
if (expected === undefined) process.exit(2);

let bundle;
try {
  bundle = scan.readScanCaptureBundleV2({ bundleDirectory: args.bundle });
} catch (error) {
  refuse(`the capture bundle did not read: ${error instanceof Error ? error.message : "unknown"}`);
  process.exit(2);
}

let envelope;
try {
  envelope = scan.parseScanAttestationEnvelopeV2Json(readFileSync(args.evidence, "utf8"));
} catch (error) {
  refuse(`the evidence envelope did not parse: ${error instanceof Error ? error.message : "unknown"}`);
  process.exit(2);
}

let verified;
try {
  verified = scan.verifyScanAttestationV2({
    envelope,
    candidate: bundle.candidate,
    annexArtifacts: bundle.annexArtifacts,
    roots,
    expected,
    seenReplayIdentities: [],
  });
} catch (error) {
  refuse(`verification failed: ${error instanceof Error ? error.message : "unknown"}`);
  process.exit(2);
}

// The scanned-content binding comes from the verified attestation, never from a caller.
const binding = scan.readScanResultSubjectBindingV1({ verified });
const record = scan.readScanResultRecordV1({
  verified,
  annexArtifacts: bundle.annexArtifacts,
});
if (record.status !== "available") {
  refuse(`the result record is ${record.status}`);
  process.exit(2);
}
const reread = scan.parseScanResultRecordV1(record.result);
if (reread.status !== "read") {
  refuse(`this build does not read that record: ${reread.reason}`);
  process.exit(2);
}

const findings = scan.readScanFindingsV1({ verified, annexArtifacts: bundle.annexArtifacts });

let projection;
if (args.subjectDigest !== undefined) {
  try {
    const envelopeV1 = scan.projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
      verified,
      subjectDigest: args.subjectDigest,
    });
    projection = {
      organizationEvidenceDigest: scan.coreOrganizationEvidenceEnvelopeDigestV1(envelopeV1),
      byteLength: scan.canonicalCoreOrganizationEvidenceEnvelopeV1Bytes(envelopeV1).byteLength,
    };
  } catch (error) {
    refuse(`projection failed: ${error instanceof Error ? error.message : "unknown"}`);
    process.exit(2);
  }
}

process.stdout.write(
  `${JSON.stringify(
    {
      status: "verified",
      subject: binding,
      coreContract: record.result.coreContract,
      coverage: record.result.coverage,
      detector: record.result.detector.id,
      findings: {
        source: findings.status === "available" ? findings.findings.source : findings.status,
        count: findings.status === "available" ? findings.findings.findings.length : 0,
        gaps:
          findings.status === "available"
            ? findings.findings.gaps.map((gap) => gap.kind)
            : [],
      },
      ...(projection === undefined ? {} : { projection }),
      authority: "none",
      limitation:
        "Signature, claims policy, candidate and annex bytes all bind. That is evidence custody only: it is not organization approval, qualification, installation authority, or proof that Core accepted this evidence.",
    },
    null,
    2,
  )}\n`,
);
