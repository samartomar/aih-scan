/**
 * Local-image identity for `detector.skillspector` under the never-pull
 * `docker-host-local-skillspector-v1` profile (C2a §6.1/§6.2), with Core's
 * accept rule from `src/trust/images.ts`.
 *
 * The engine accepts the local image only when `docker image inspect` of the
 * pinned tag ties it to an allowed digest — the pinned digest plus the
 * caller's `acceptedImageDigests` — either through `.Id` or through a
 * `RepoDigests` entry. The verified reference (bare digest or `repo@digest`)
 * is what `docker run` names; the tag alone is never run and nothing is
 * pulled. Which org-policy approvals become `acceptedImageDigests` (matching
 * tag and source revision) is Core's approval policy, not this module's.
 */

export const SKILLSPECTOR_IMAGE_TAG_V1 = "skillspector:aih-2d198ab910ad";
export const SKILLSPECTOR_SOURCE_REVISION_V1 = "2d198ab910add401cad658d1087e7c7ba24fd640";
export const SKILLSPECTOR_IMAGE_DIGEST_V1 =
  "sha256:c5d4a1816419f129ae85ff96b3e366d4a062c1859997e26b7ab87341a43d4800";

const IMAGE_DIGEST_V1 = /^sha256:[0-9a-f]{64}$/;

/** C2a §6.2: at most this many caller-accepted digests per local-mode request. */
export const SKILLSPECTOR_ACCEPTED_IMAGE_DIGESTS_MAX_LOCAL_V1 = 16;

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

// ---------------------------------------------------------------------------
// C2a §6.1/§6.2: never-pull local mode (docker-host-local-skillspector-v1)
// ---------------------------------------------------------------------------

/**
 * Which local image may run under the `docker-host-local-skillspector-v1`
 * profile, and whose digest admitted it (C2a §6.1 "Recording"): the exact
 * reference passed to `docker run`, the digest that matched (Scan's pinned
 * digest or one the caller accepted), and which of the two it was. This is the
 * engine's `SkillspectorImageMatchV1`-style value; Core records it from the
 * observation.
 */
export interface SkillspectorImageAdmissionV1 {
  /** The exact image reference for `docker run`: a bare digest or `repo@sha256:...`. */
  readonly reference: string;
  /** The allowed digest the inspected image matched. */
  readonly digest: string;
  readonly acceptance: "pinned" | "caller-accepted";
}

/**
 * Why a caller-supplied `acceptedImageDigests` list cannot be used in local
 * mode, or `undefined` when it can (C2a §6.2): each entry must be
 * `sha256:<64 lowercase hex>`, entries are unique, and at most 16 are
 * consulted. The caller wires a non-`undefined` detail to the refusal reason
 * `execution-profile-unavailable`, as Core's
 * `skillspectorAcceptedImageDigestsRefusalV1` does. The field is refused for
 * any other profile; that refusal lives at the request boundary, not here.
 * An empty list is valid and admits only the pinned digest.
 */
export function skillspectorAcceptedImageDigestsRefusalV1(value: unknown): string | undefined {
  if (!Array.isArray(value))
    return "acceptedImageDigests must be an array of sha256:<64 lowercase hex> image digests.";
  if (value.length > SKILLSPECTOR_ACCEPTED_IMAGE_DIGESTS_MAX_LOCAL_V1)
    return `acceptedImageDigests names ${value.length} digests; at most ${SKILLSPECTOR_ACCEPTED_IMAGE_DIGESTS_MAX_LOCAL_V1} are consulted.`;
  const seen = new Set<string>();
  for (const [index, digest] of value.entries()) {
    if (typeof digest !== "string" || !IMAGE_DIGEST_V1.test(digest))
      return `acceptedImageDigests[${index}] is not a sha256:<64 lowercase hex> image digest.`;
    if (seen.has(digest)) return `acceptedImageDigests[${index}] repeats ${digest}.`;
    seen.add(digest);
  }
  return undefined;
}

/**
 * The image admission a `docker image inspect` output proves in local mode, or
 * `undefined` when it proves nothing acceptable. Same accept rule as
 * {@link verifiedSkillspectorImageReferenceV1} (`.Id` first, then a
 * `RepoDigests` entry by whole value or `@` suffix), over the allowed set of
 * the pinned digest plus the caller-accepted digests, but reporting which
 * digest admitted the image and whether it was pinned or caller-accepted.
 */
export function admitLocalSkillspectorImageV1(
  stdout: string,
  acceptedImageDigests: readonly string[] = [],
): SkillspectorImageAdmissionV1 | undefined {
  const inspect = parseImageInspectV1(stdout);
  if (inspect === undefined) return undefined;
  const allowed = new Set([SKILLSPECTOR_IMAGE_DIGEST_V1, ...acceptedImageDigests]);
  const admission = (reference: string, digest: string): SkillspectorImageAdmissionV1 =>
    Object.freeze({
      reference,
      digest,
      acceptance: digest === SKILLSPECTOR_IMAGE_DIGEST_V1 ? "pinned" : "caller-accepted",
    });
  const matched = (value: unknown): string | undefined => {
    if (typeof value !== "string") return undefined;
    if (allowed.has(value)) return value;
    const suffix = value.split("@").at(-1);
    return suffix !== undefined && allowed.has(suffix) ? suffix : undefined;
  };

  const idMatch = matched(inspect.Id);
  if (idMatch !== undefined) return admission(idMatch, idMatch);

  const repoDigests = inspect.RepoDigests;
  if (!Array.isArray(repoDigests)) return undefined;
  for (const entry of repoDigests) {
    const digest = matched(entry);
    if (digest !== undefined && typeof entry === "string") return admission(entry, digest);
  }
  return undefined;
}
