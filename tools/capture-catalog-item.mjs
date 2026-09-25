#!/usr/bin/env node
/**
 * Produces real Scanner output for one published Catalog item by running the
 * existing, documented capture command — it adds no scanning API and changes no
 * capture behavior.
 *
 * Fixed order of operations:
 *   1. refuse unless this host is Linux on the Node architecture the adapter
 *      supports (`linux/x64`, which is OCI `linux/amd64`) with the Docker the
 *      broker can reach;
 *   2. install the exact Catalog and Scan tarballs with `--ignore-scripts` into a
 *      fresh consumer outside every Git repository;
 *   3. read the item's original source closure through `@aihq/catalog`'s public
 *      source-closure reader, selected by collection and subject. The entry
 *      identity is the one that reader returns, never a packaged default id;
 *   4. stage every file of that closure under the path Catalog publishes it at and
 *      re-verify every declared sha256, then select the skill material root Catalog
 *      declares and mount that directory as the capture source root;
 *   5. validate the operator's detector registration, canonical OCI layout, local
 *      image identity, SBOM and provenance through the installed package's public
 *      API, and cross-check them against each other;
 *   6. write the capture request the packaged `aih-scan capture` command requires:
 *      `sourceRoot` is the declared skill root and `selectedClosurePaths` are
 *      relative to that root;
 *   7. refuse unless the staged root is a skill root the registered route can load:
 *      the broker mounts the request's `sourceRoot` at `/source`, so its own top
 *      level must hold the item's original `SKILL.md`. Suitability is read from the
 *      staged source material, never from the item's Catalog subject kind label,
 *      and a verified digest proves published bytes, not a skill source;
 *   8. if `--prepare-only` was not given: run the packaged command and keep its
 *      capture bundle. A capture that yields no verified bundle is a failure and is
 *      recorded as one, never as an empty scan.
 *
 * Every value that describes the detector runtime is an operator input. This tool
 * derives none of them and refuses instead: a registration, an OCI layout and its
 * image ID, an SBOM and a provenance document must all be supplied, and each one
 * is checked against the others before anything runs. The built-in `detector.cisco`
 * request is deliberately not offered here: its identity values come from CI
 * context, so a non-CI operator could only produce them by inventing them.
 *
 * Scanner output is evidence only. It is never qualification, approval, admission
 * or an effect. Signing is a separate step and is not performed here.
 *
 * Source selection. The source is not inferred from the item index and never from a
 * packaged default entry id: the helper calls the installed package's public
 * `readCatalogSourceClosureV1({ collectionId, subjectId })` and takes the entry,
 * subject digest, source revision and file list from the closure it returns. Every
 * file of that closure is staged under its published path and re-hashed, so a
 * served byte that does not match its declared sha256 stops the run before it is
 * written. The capture source root is then the `skill` material root Catalog
 * declares — not a directory the helper goes looking for. A closure that declares
 * no skill material root, or more than one, is refused rather than guessed at, and
 * a nested `SKILL.md` is never discovered and never substituted. Files that fall
 * outside the declared skill root stay staged, outside the mounted root, and are
 * recorded as uncovered: a scan of the skill root does not cover them.
 *
 * Diagnostic record. `source-closure.json` records the complete closure, the
 * selected skill root, the mapping from every published path to its staged path
 * and to the path the capture selects, and the files the mount cannot cover. It is
 * a diagnostic record written by this helper: it is not signed evidence, not a
 * capture bundle and not authority. A capture bundle seals the mounted root over
 * the selected paths only; that seal is not the closure's declaredTreeDigest, not
 * the four-file closure and not the entry's subjectDigest.
 *
 * Suitability. The only route this tool runs is `cisco-oci-v1`, which loads the
 * skill from the root the broker mounts at `/source`, so the staged root must be
 * the declared skill root itself, holding its own `SKILL.md` at the top level. An
 * item whose matter is an assessment closure rather than source files is refused
 * by the source reader itself, and its assessment artifacts (`closure.json`,
 * `profile.json`, `prose.md`, `recipe.json`) are never staged as a source. Nothing
 * is renamed, generated or substituted to make a root fit.
 *
 * Failure records. A run that stops after its run directory exists keeps its input
 * records and an explicit `capture-failure.json`: the phase, the reason, the exit
 * status and the streams a capture command actually wrote, the selected source
 * root, and the file paths the capture was asked to cover. Fields the phase never
 * produced stay null and output is never reconstructed. `findingsProduced` is
 * deliberately not `false` for a capture that ran and failed, or for a bundle that
 * failed validation: this helper does not inspect detector output, so it records
 * the answer as unknown. Only a run in which no capture process existed at all
 * records false.
 *
 * This helper belongs to one Scan commit and is not present at every package
 * checkpoint, so it must be run from the checkout that holds it, and the two
 * package checkpoints must be packed in their own `git archive` trees. Switching
 * a shared checkout to a package commit deletes this file; see the Checkouts
 * block in `--help`.
 *
 * `--prepare-only` proves preparation: that the supplied tarballs install, that
 * the item's published bytes verify, that the operator's detector inputs agree and
 * that the staged root is a skill root. It is never evidence that a detector ran.
 * Genuine execution is the capture bundle that only a Linux x64 host with the
 * loaded image can produce; a zero-finding or successfully signed result is not a
 * clean scan by itself.
 *
 * Modules. This file is the thin entry point: it parses arguments, runs the fixed
 * order above and exports the phases a test drives. Each phase lives beside it in
 * `capture-catalog-item/`, which nothing else imports: `arguments.mjs` (input and
 * argument handling), `catalog.mjs` (consumer install and public Catalog reading),
 * `staging.mjs` (staging and coverage diagnostics), `detector-inputs.mjs` (operator
 * detector inputs), `preflight.mjs` (platform, subject and Docker gates),
 * `capture.mjs` (request, gate order and capture invocation), `report.mjs` (run
 * directory, execution log and failure/preflight records) and `common.mjs`.
 */
import { pathToFileURL } from "node:url";
import { parseArguments } from "./capture-catalog-item/arguments.mjs";
import {
  attemptCapture,
  prepareCapture,
  runPreparedCapture,
} from "./capture-catalog-item/capture.mjs";
import { installEnvironment, npmCliPath } from "./capture-catalog-item/catalog.mjs";
import { Refusal, reasonOf } from "./capture-catalog-item/common.mjs";
import { readDetectorInputs } from "./capture-catalog-item/detector-inputs.mjs";
import {
  assertPlatform,
  assertSkillSourceRoot,
  BROKER_DOCKER_EXECUTABLE,
} from "./capture-catalog-item/preflight.mjs";
import { createRunDirectory, recordFailure } from "./capture-catalog-item/report.mjs";
import { readCatalogSourceClosure } from "./capture-catalog-item/staging.mjs";

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const platform = assertPlatform();
  const runRoot = createRunDirectory(options.output);
  const prepared = await recordFailure("preparation", runRoot, undefined, () =>
    prepareCapture(options, runRoot),
  );
  const outcome = await runPreparedCapture(options, runRoot, platform, prepared);
  process.stdout.write(`${JSON.stringify(outcome)}\n`);
}

/* Importable for direct preparation checks; the command runs only as the entry point. */
export {
  assertPlatform,
  assertSkillSourceRoot,
  attemptCapture,
  BROKER_DOCKER_EXECUTABLE,
  createRunDirectory,
  installEnvironment,
  npmCliPath,
  prepareCapture,
  readCatalogSourceClosure,
  readDetectorInputs,
  runPreparedCapture,
};

const isEntryPoint =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntryPoint) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(
      `${error instanceof Refusal ? "refused" : "failed"}: ${reasonOf(error)}\n`,
    );
    process.exitCode = 1;
  }
}
