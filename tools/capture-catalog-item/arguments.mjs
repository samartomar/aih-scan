/**
 * Input and argument handling for `tools/capture-catalog-item.mjs`: the usage text,
 * the flag table, the collection and subject defaults, and the grammar each value
 * must satisfy. It reads no file and runs nothing.
 */
import { DETECTOR_ID, refuse } from "./common.mjs";

/** The collection view and subject this helper reads a source closure for. */
const DEFAULT_COLLECTION_ID = "aih-core";
const DEFAULT_SUBJECT_ID = "governance-quality";
const USAGE = `Usage:
  node tools/capture-catalog-item.mjs \\
    --catalog-tarball <@aihq/catalog-*.tgz> \\
    --scan-tarball <aihq-scan-*.tgz> \\
    --output <new-or-empty-directory> \\
    --registration <DetectorRegistrationV1 authoring JSON> \\
    --layout <canonical CiscoOciLayoutV1 JSON> \\
    --image-id <docker image inspect --format '{{.Id}}' output> \\
    --sbom <SPDX JSON> \\
    --provenance <in-toto JSON> \\
    [--detector-id <detector.*>] [--collection-id <id>] [--subject-id <id>]
    [--consumer-root <empty-dir>] [--prepare-only]

  --catalog-tarball  npm pack output of the Catalog commit under test.
  --scan-tarball     npm pack output of the Scan commit under test.
  --output           New or empty run directory. It receives source/ (the complete
                     published closure under its own paths), detector/,
                     capture-request.json, source-closure.json, preflight.json,
                     execution.log and bundle/, plus capture-failure.json whenever
                     the run stops after preparation without a verified bundle.
  --registration     The organization's own DetectorRegistrationV1 authoring document
                     (README "Capture"). Nothing here is derived or defaulted.
  --layout           Canonical CiscoOciLayoutV1 JSON for the loaded detector image,
                     produced by: node tools/verify-cisco-oci-candidate.mjs \\
                       --metadata <buildx metadata> --layout-root <oci layout dir> \\
                       --image-id <config id file> --summary <summary out> \\
                       --canonical-layout <this file>
  --image-id         File holding 'docker image inspect --format {{.Id}} local.invalid/aih-scan/cisco'.
  --sbom             The exact SPDX bytes whose sha256 the registration declares.
  --provenance       The exact in-toto bytes whose sha256 the registration declares.
  --detector-id      Required only when the registration declares more than one entry.
  --collection-id    Collection view the source closure is read from. Default: ${DEFAULT_COLLECTION_ID}.
  --subject-id       Subject whose source closure is read. Default: ${DEFAULT_SUBJECT_ID}.
                     The entry id and every digest come from what the public
                     readCatalogSourceClosureV1 returns for this pair; no entry id
                     is defaulted or supplied by the operator.
  --consumer-root    Fresh install directory. Default: a new mkdtemp under the system temp root.
  --prepare-only     Validate everything, write the request, pass the subject and
                     Docker gates, and stop before capture.

Source selection. The item's original source is read through the installed
package's public readCatalogSourceClosureV1(collectionId, subjectId). Every file of
the returned closure is staged under the path Catalog publishes it at, re-hashed,
and its declared digest verified before it is written. The capture source root is
the 'skill' material root Catalog declares; a closure with no declared skill root,
or with more than one, is refused rather than guessed at, and a nested SKILL.md is
never discovered and never substituted for a declaration. Files outside that root,
such as aih-packs.json, stay outside the mounted root and are recorded as
uncovered: a scan of the skill root does not cover them.

Diagnostic record. source-closure.json records the complete closure, the selected
skill root, every published-to-staged-to-selected path mapping and the files the
mount cannot cover. It is this helper's own diagnostic: not signed evidence, not a
capture bundle and not authority. The capture seal covers the selected paths only
and is never the closure's declaredTreeDigest or the entry's subjectDigest.

Suitability. cisco-oci-v1 loads the skill from the root the broker mounts at
/source, so the mounted root must hold the declared skill's SKILL.md at its top
level. Suitability is read from the staged material, never from the item's Catalog
subject kind label: an item labelled 'agent' may be a skill pack, while
closure.json, profile.json, prose.md and recipe.json are assessment artifacts and
are never staged as a source — Catalog's own source reader refuses a subject whose
material is not source files. A run that reaches the Docker gate records the
accepted skill entry, the covered published paths and the uncovered ones in
preflight.json. A refusal before capture names the reason in execution.log and
leaves the selected root and the covered paths in capture-request.json and
source-closure.json; a failed capture additionally leaves capture-failure.json with
the command, the exit status, the streams that exist, that root and those paths.
findingsProduced stays null — unknown — for any capture that ran and failed or
whose bundle failed validation, because this helper does not inspect detector
output; it is false only when no capture process existed at all. No failed run is
recorded as an empty scan.

Checkouts. This file exists only in some Scan commits. Run it from the checkout
that holds it, at the reviewed helper commit, and record that commit separately
from the two package checkpoint identities. Do not switch, reset or clean that
checkout: packing an older package checkpoint would delete this file. Build each
package checkpoint in its own extraction instead, then pass the two tarballs here:

  git -C <catalog-checkout> archive --format=tar <catalog-commit> | \\
    (mkdir -p /tmp/aih-catalog-build && tar -x -C /tmp/aih-catalog-build)
  cd /tmp/aih-catalog-build && npm ci && npm run build && npm pack

  git -C <scan-checkout> archive --format=tar <scan-commit> | \\
    (mkdir -p /tmp/aih-scan-build && tar -x -C /tmp/aih-scan-build)
  cd /tmp/aih-scan-build && npm ci && npm pack

@aihq/catalog has no prepack script, so its dist/ must be built before packing;
@aihq/scan builds itself in prepack. The produced tarball names carry each
package version, and both tarball hashes plus both installed versions are written
to preflight.json.

Running it here proves preparation only. The detector runs only when all of these
hold: Node reports linux/x64 (OCI amd64), PATH=/usr/bin:/bin reaches
/usr/bin/docker or /bin/docker, that daemon reports Linux amd64 on its default
socket (the broker passes no DOCKER_HOST/DOCKER_CONTEXT), and the image is loaded
under the exact config digest the layout declares.
`;

/** Collection and subject ids are Catalog's own lowercase id grammar. */
const CATALOG_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;

/* ---------- arguments ---------- */

const VALUE_FLAGS = new Map([
  ["--catalog-tarball", "catalogTarball"],
  ["--scan-tarball", "scanTarball"],
  ["--output", "output"],
  ["--registration", "registration"],
  ["--layout", "layout"],
  ["--image-id", "imageId"],
  ["--sbom", "sbom"],
  ["--provenance", "provenance"],
  ["--detector-id", "detectorId"],
  ["--collection-id", "collectionId"],
  ["--subject-id", "subjectId"],
  ["--consumer-root", "consumerRoot"],
]);
const BOOLEAN_FLAGS = new Map([["--prepare-only", "prepareOnly"]]);
const REQUIRED_FLAGS = [
  "--catalog-tarball",
  "--scan-tarball",
  "--output",
  "--registration",
  "--layout",
  "--image-id",
  "--sbom",
  "--provenance",
];

/**
 * Names the producing command for every missing operator input, so an absent
 * detector runtime is never silently replaced by a default.
 */
const ORIGIN_OF_FLAG = {
  "--registration": "the organization's own DetectorRegistrationV1 authoring JSON (README section Capture)",
  "--layout": "node tools/verify-cisco-oci-candidate.mjs ... --canonical-layout <file>",
  "--image-id": "docker image inspect --format '{{.Id}}' local.invalid/aih-scan/cisco > <file>",
  "--sbom": "the SPDX bytes whose sha256 your registration declares",
  "--provenance": "the in-toto bytes whose sha256 your registration declares",
};

export function parseArguments(argv) {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  const values = {};
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (BOOLEAN_FLAGS.has(name)) {
      if (seen.has(name)) refuse(`duplicate argument ${name}`);
      seen.add(name);
      values[BOOLEAN_FLAGS.get(name)] = true;
      continue;
    }
    const key = VALUE_FLAGS.get(name);
    if (key === undefined) refuse(`unknown argument ${name}; run with --help`);
    if (seen.has(name)) refuse(`duplicate argument ${name}`);
    const value = argv[index + 1];
    if (typeof value !== "string" || value.startsWith("--")) refuse(`${name} requires a value`);
    seen.add(name);
    values[key] = value;
    index += 1;
  }
  const missing = REQUIRED_FLAGS.filter((name) => !seen.has(name));
  if (missing.length > 0) {
    const origins = missing
      .filter((name) => ORIGIN_OF_FLAG[name] !== undefined)
      .map((name) => `\n  ${name}: supply ${ORIGIN_OF_FLAG[name]}`)
      .join("");
    refuse(`missing required argument(s) ${missing.join(", ")}; run with --help${origins}`);
  }
  values.collectionId ??= DEFAULT_COLLECTION_ID;
  values.subjectId ??= DEFAULT_SUBJECT_ID;
  if (!CATALOG_ID.test(values.collectionId)) refuse("--collection-id grammar");
  if (!CATALOG_ID.test(values.subjectId)) refuse("--subject-id grammar");
  if (values.detectorId !== undefined && !DETECTOR_ID.test(values.detectorId))
    refuse("--detector-id grammar");
  return values;
}
