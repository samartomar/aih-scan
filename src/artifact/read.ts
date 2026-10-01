import { canonicalBytes, scanIdFor, sha256, strictParse } from "../assessment/json.js";
import { readReport } from "../assessment/report.js";
import { validateBundle, validateStatement } from "./bundle.js";
import type { AnnexDescriptor, Artifact, ReadArtifactResult, ValidatedArtifact } from "./types.js";
import {
  artifactLimits,
  decoded,
  digest,
  equalBytes,
  integer,
  invalid,
  limited,
  object,
  text,
  unsupported,
  validScanId,
} from "./validation.js";

export async function validateArtifact(bytes: Uint8Array): Promise<ValidatedArtifact> {
  if (!(bytes instanceof Uint8Array)) invalid();
  if (bytes.length > artifactLimits.artifact) limited();
  const raw = object(
    strictParse(bytes, "artifact", artifactLimits.artifact),
    ["schema", "scanId", "report", "annexes"],
    ["attestation"],
  );
  if (raw.schema !== "urn:aihq:scan:artifact:1.0.0") unsupported();
  validScanId(raw.scanId);
  const report = object(raw.report, ["schema", "mediaType", "sha256", "byteLength", "bytesBase64"]);
  text(report.schema);
  if (report.mediaType !== "application/json") invalid();
  digest(report.sha256);
  integer(report.byteLength, artifactLimits.report);
  const reportBytes = decoded(report.bytesBase64, artifactLimits.report);
  if (report.byteLength !== reportBytes.length || report.sha256 !== (await sha256(reportBytes)))
    invalid("byte-mismatch");
  if (raw.scanId !== (await scanIdFor(reportBytes))) invalid("id-mismatch");
  if (!Array.isArray(raw.annexes)) invalid();
  let total = reportBytes.length;
  const descriptors: AnnexDescriptor[] = [];
  let prior = "";
  for (const annex of raw.annexes) {
    const a = object(annex, ["id", "mediaType", "sha256", "byteLength", "bytesBase64"]);
    const id = text(a.id);
    if (!/^annex\.[a-z0-9][a-z0-9.-]*$/.test(id) || id <= prior) invalid();
    prior = id;
    const mediaType = text(a.mediaType);
    digest(a.sha256);
    const byteLength = integer(a.byteLength, artifactLimits.annex);
    total += byteLength;
    if (total > artifactLimits.decoded) limited();
    const annexBytes = decoded(a.bytesBase64, artifactLimits.annex);
    if (byteLength !== annexBytes.length || a.sha256 !== (await sha256(annexBytes)))
      invalid("byte-mismatch");
    descriptors.push({ id, mediaType, sha256: a.sha256 as string, byteLength });
  }
  // Canonical container spelling is part of this transport generation. Payload
  // bytes embedded in the envelope are never replaced by a reserialization.
  if (!equalBytes(bytes, canonicalBytes(raw))) invalid();
  const validated: ValidatedArtifact = {
    artifact: raw as unknown as Artifact,
    reportBytes,
    annexManifestSha256: await sha256(canonicalBytes(descriptors)),
  };
  if (raw.attestation !== undefined) {
    const { payload } = validateBundle(raw.attestation);
    validateStatement(payload, validated);
  }
  return validated;
}

export async function readArtifact(bytes: Uint8Array): Promise<ReadArtifactResult> {
  try {
    const validated = await validateArtifact(bytes);
    const { artifact, reportBytes } = validated;
    const result = await readReport(reportBytes);
    if (result.status === "invalid") return result;
    if (result.status === "unsupported-report") {
      if (result.reportSchema !== artifact.report.schema) invalid("byte-mismatch");
      return {
        status: "unsupported-report",
        scanId: artifact.scanId,
        reportSchema: artifact.report.schema,
      };
    }
    if (result.report.schema !== artifact.report.schema) invalid("byte-mismatch");
    const manifest = artifact.annexes.map(({ bytesBase64: _bytes, ...descriptor }) => descriptor);
    if (!equalBytes(canonicalBytes(result.report.annexes), canonicalBytes(manifest)))
      invalid("byte-mismatch");
    return {
      status: "read",
      scanId: artifact.scanId,
      report: result.report,
      authenticity: "unchecked",
      annexBytes: "checked",
    };
  } catch (error) {
    const code =
      error instanceof Error && "code" in error && error.code === "resource-limit"
        ? "resource-limit"
        : "invalid-artifact";
    return {
      status: "invalid",
      diagnostics: [
        { code, detail: "The artifact could not be read within its declared contract." },
      ],
    };
  }
}
