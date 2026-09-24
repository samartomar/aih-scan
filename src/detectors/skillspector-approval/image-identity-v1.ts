import { z } from "zod";
import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";

/**
 * Approved-image identity for `detector.skillspector`, ported verbatim in
 * behaviour from Core's `src/trust/images.ts`.
 *
 * The engine accepts a local image only when `docker image inspect` ties it to
 * the pinned digest — either `.Id` equals an accepted digest, or a
 * `RepoDigests` entry does. An org approval widens the accepted set only when
 * its `imageTag` and `sourceRevision` equal the pinned ones and its digest is
 * `sha256:<64 lowercase hex>`; anything else is rejected fail-closed. The
 * verified reference (bare digest or `repo@digest`) is what a later
 * `docker run` must name; the tag alone is never run and nothing is pulled in
 * this mode.
 */

export const SKILLSPECTOR_IMAGE_TAG_V1 = "skillspector:aih-2d198ab910ad";
export const SKILLSPECTOR_SOURCE_REVISION_V1 = "2d198ab910add401cad658d1087e7c7ba24fd640";
export const SKILLSPECTOR_IMAGE_DIGEST_V1 =
  "sha256:c5d4a1816419f129ae85ff96b3e366d4a062c1859997e26b7ab87341a43d4800";

const IMAGE_DIGEST_V1 = /^sha256:[0-9a-f]{64}$/;
const SOURCE_REVISION_SHAPE_V1 = /^[0-9a-f]{40}$/;
const MAX_IMAGE_APPROVALS_V1 = 64;
const MAX_APPROVAL_FIELD_LENGTH_V1 = 500;

/** One org-policy approval of a locally built SkillSpector image digest. */
export interface SkillspectorImageApprovalV1 {
  readonly imageTag: string;
  readonly imageDigest: string;
  readonly sourceRevision: string;
}

const approvalSchemaV1 = z.strictObject({
  imageTag: z.string().min(1).max(MAX_APPROVAL_FIELD_LENGTH_V1),
  imageDigest: z.string().regex(IMAGE_DIGEST_V1),
  sourceRevision: z.string().regex(SOURCE_REVISION_SHAPE_V1),
});
const approvalListSchemaV1 = z.array(approvalSchemaV1).max(MAX_IMAGE_APPROVALS_V1);

/**
 * Validates untrusted org-policy approval input at the module boundary.
 * Malformed input throws; it never degrades into a partial approval set.
 */
export function parseSkillspectorImageApprovalsV1(
  value: unknown,
): readonly SkillspectorImageApprovalV1[] {
  const parsed = approvalListSchemaV1.safeParse(value);
  if (!parsed.success) {
    throw new TypeError(
      `invalid SkillSpector image approvals: ${parsed.error.issues[0]?.message ?? "schema"}`,
    );
  }
  return deepFreezeStrictJsonV1(parsed.data) as readonly SkillspectorImageApprovalV1[];
}

/**
 * The accepted digest set: the pinned digest plus every approval whose tag and
 * source revision match the pin and whose digest is well-formed. The filter is
 * applied even to already-validated input, exactly as Core does, so a malformed
 * or misattributed approval can never admit an image.
 */
function approvedSkillspectorImageDigestsV1(
  approvedImages: readonly SkillspectorImageApprovalV1[] = [],
): Set<string> {
  return new Set([
    SKILLSPECTOR_IMAGE_DIGEST_V1,
    ...approvedImages
      .filter(
        (approval) =>
          approval.imageTag === SKILLSPECTOR_IMAGE_TAG_V1 &&
          approval.sourceRevision === SKILLSPECTOR_SOURCE_REVISION_V1 &&
          IMAGE_DIGEST_V1.test(approval.imageDigest),
      )
      .map((approval) => approval.imageDigest),
  ]);
}

function normalizedDigestV1(
  value: unknown,
  approvedImages: readonly SkillspectorImageApprovalV1[] = [],
): string | undefined {
  if (typeof value !== "string") return undefined;
  const allowed = approvedSkillspectorImageDigestsV1(approvedImages);
  if (allowed.has(value)) return value;
  const suffix = value.split("@").at(-1);
  return suffix !== undefined && allowed.has(suffix) ? suffix : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseImageInspectV1(stdout: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(stdout.trim());
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The runnable image reference a `docker image inspect` output proves, or
 * `undefined` when it proves nothing acceptable. Mirrors Core exactly: `.Id`
 * wins when it is an accepted digest; otherwise the first `RepoDigests` entry
 * carrying an accepted digest is returned whole (`repo@sha256:...`), so the
 * result stays an unambiguous content address for `docker run`.
 */
export function verifiedSkillspectorImageReferenceV1(
  stdout: string,
  approvedImages: readonly SkillspectorImageApprovalV1[] = [],
): string | undefined {
  const inspect = parseImageInspectV1(stdout);
  if (inspect === undefined) return undefined;

  // Prefer `.Id`: on image stores where it is the manifest digest (e.g. the
  // containerd snapshotter, or any local build), this is the same identifier
  // it has always been.
  const idMatch = normalizedDigestV1(inspect.Id, approvedImages);
  if (idMatch !== undefined) return idMatch;

  // On other stores (e.g. the legacy graphdriver), `.Id` is a config hash, not
  // the manifest digest — a pulled image still carries the manifest digest in
  // `.RepoDigests`. Accept a match there too, but return the full entry
  // (`repo@sha256:...`) rather than the bare digest, so the result stays a
  // runnable, unambiguous content address for `docker run`.
  const repoDigests = inspect.RepoDigests;
  if (!Array.isArray(repoDigests)) return undefined;
  return repoDigests.find(
    (entry): entry is string =>
      typeof entry === "string" && normalizedDigestV1(entry, approvedImages) !== undefined,
  );
}
