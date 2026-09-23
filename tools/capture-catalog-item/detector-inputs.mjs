/**
 * Operator detector inputs for `tools/capture-catalog-item.mjs`: the registration,
 * the canonical OCI layout, the image ID and the two annex documents, each validated
 * by the installed package's own rules and cross-checked against the others. It
 * derives and defaults nothing.
 */
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  ADAPTER_CAPABILITY,
  canonicalBytes,
  DIGEST,
  exactKeys,
  jsonFile,
  reasonOf,
  refuse,
  regularBytes,
  sha256Hex,
  textFile,
} from "./common.mjs";
import { log } from "./report.mjs";

const REFERENCE_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";
const MAX_LAYOUT_BYTES = 4 * 1024 * 1024;
const MAX_REGISTRATION_BYTES = 512 * 1024;
const MAX_ANNEX_BYTES = 16 * 1024 * 1024;

/** Computed fields the package returns but never accepts back as input. */
function computedWireFields(document) {
  const found = new Set();
  if (Object.hasOwn(document, "registrationSha256")) found.add("registrationSha256");
  const entries = Array.isArray(document.registrations) ? document.registrations : [];
  for (const entry of entries) {
    if (typeof entry !== "object" || entry === null) continue;
    if (Object.hasOwn(entry, "registrationEntrySha256")) found.add("registrationEntrySha256");
    const detector = entry.detector;
    if (
      typeof detector === "object" &&
      detector !== null &&
      Object.hasOwn(detector, "scannerManifestEntrySha256")
    )
      found.add("scannerManifestEntrySha256");
  }
  return [...found];
}

/**
 * Validates the operator's detector identity against the installed package's own
 * rules and against the other operator inputs. It chooses nothing.
 */
export function readDetectorInputs(reader, options, runRoot) {
  const registrationInput = jsonFile(options.registration, "--registration", 2, MAX_REGISTRATION_BYTES);
  let registration;
  try {
    registration = reader.createDetectorRegistrationV1(registrationInput);
  } catch (error) {
    /*
     * `createDetectorRegistrationV1` input is strict and the CLI revalidates the
     * request's registration with it, so a document carrying computed wire fields
     * cannot be resubmitted. Name them instead of failing later inside capture.
     */
    const wireFields = computedWireFields(registrationInput);
    refuse(
      `--registration is not a valid DetectorRegistrationV1 authoring input: ${reasonOf(error)}` +
        (wireFields.length === 0
          ? ""
          : `. It carries computed field(s) ${wireFields.join(", ")}; supply the authoring document without computed fields (README section Capture)`),
    );
  }
  const entries = registration.registrations;
  let selected;
  if (options.detectorId !== undefined) {
    selected = entries.find((entry) => entry.detector.detectorId === options.detectorId);
    if (selected === undefined) refuse(`--registration declares no ${options.detectorId} entry`);
  } else if (entries.length === 1) {
    selected = entries[0];
  } else {
    refuse(`--detector-id is required because --registration declares ${entries.length} entries`);
  }
  if (
    selected.adapterCapability !== ADAPTER_CAPABILITY ||
    selected.broker.capability !== ADAPTER_CAPABILITY
  )
    refuse(`the only executable capture capability is ${ADAPTER_CAPABILITY}`);
  const detectorId = selected.detector.detectorId;
  const platform = selected.detector.supportedPlatforms[0];
  if (
    selected.detector.supportedPlatforms.length !== 1 ||
    platform.os !== "linux" ||
    platform.architecture !== "amd64"
  )
    refuse("the registered detector must support exactly Linux amd64");
  log(
    `registration    ${detectorId} sha256:${registration.registrationSha256} ` +
      `(${entries.length} entr${entries.length === 1 ? "y" : "ies"})`,
  );

  const layoutInput = jsonFile(options.layout, "--layout", 2, MAX_LAYOUT_BYTES);
  exactKeys(
    layoutInput,
    [
      "protocol",
      "manifestDigestSha256",
      "configDigestSha256",
      "logicalReference",
      "manifestPlatform",
      "manifestDescriptor",
    ],
    "--layout",
  );
  if (layoutInput.protocol !== "CiscoOciLayoutV1") refuse("--layout protocol");
  if (!DIGEST.test(layoutInput.manifestDigestSha256) || !DIGEST.test(layoutInput.configDigestSha256))
    refuse("--layout digests");
  if (layoutInput.manifestDigestSha256 === layoutInput.configDigestSha256)
    refuse("--layout manifest and config digests must differ");
  /*
   * CiscoOciLayoutV1 fixes this image name, so a detector image published under any
   * other name cannot satisfy the canonical layout at all. Refuse it here rather
   * than in the middle of capture.
   */
  if (
    layoutInput.logicalReference !==
    `local.invalid/aih-scan/cisco@${layoutInput.manifestDigestSha256}`
  )
    refuse(
      "--layout logical reference must be 'local.invalid/aih-scan/cisco@<manifestDigestSha256>'; CiscoOciLayoutV1 fixes that image name",
    );
  exactKeys(layoutInput.manifestPlatform, ["architecture", "os"], "--layout manifestPlatform");
  if (
    layoutInput.manifestPlatform.os !== "linux" ||
    layoutInput.manifestPlatform.architecture !== "amd64"
  )
    refuse("--layout manifestPlatform");
  const descriptor = layoutInput.manifestDescriptor;
  exactKeys(
    descriptor,
    ["mediaType", "digest", "size", "platform", "annotations"],
    "--layout manifestDescriptor",
  );
  if (
    descriptor.mediaType !== MANIFEST_MEDIA_TYPE ||
    descriptor.digest !== layoutInput.manifestDigestSha256 ||
    !Number.isSafeInteger(descriptor.size) ||
    descriptor.size < 0
  )
    refuse("--layout manifestDescriptor");
  exactKeys(descriptor.platform, ["architecture", "os"], "--layout descriptor platform");
  if (descriptor.platform.os !== "linux" || descriptor.platform.architecture !== "amd64")
    refuse("--layout descriptor platform");
  exactKeys(
    descriptor.annotations,
    ["org.opencontainers.image.ref.name"],
    "--layout descriptor annotations",
  );
  if (!REFERENCE_NAME.test(descriptor.annotations["org.opencontainers.image.ref.name"]))
    refuse("--layout descriptor annotation name");
  if (layoutInput.logicalReference !== selected.runtime.sourceReference)
    refuse("--layout logical reference does not match the registration runtime source reference");
  if (layoutInput.manifestDigestSha256 !== `sha256:${selected.runtime.sourceSha256}`)
    refuse("--layout manifest digest does not match the registration runtime source digest");
  if (layoutInput.configDigestSha256 !== `sha256:${selected.runtime.configSha256}`)
    refuse("--layout config digest does not match the registration runtime config digest");
  log(`layout          ${layoutInput.logicalReference} config ${layoutInput.configDigestSha256}`);

  const imageId = textFile(options.imageId, "--image-id", 2, 128).trim();
  if (!DIGEST.test(imageId)) refuse("--image-id must hold one 'sha256:<64 hex>' image ID");
  if (imageId !== layoutInput.configDigestSha256)
    refuse("--image-id does not match the config digest the layout declares");

  const annexInputs = [
    {
      flag: "--sbom",
      path: options.sbom,
      descriptorId: "annex.sbom",
      declared: selected.detector.sbom.sha256,
    },
    {
      flag: "--provenance",
      path: options.provenance,
      descriptorId: "annex.provenance",
      declared: selected.detector.provenance.sha256,
    },
  ];
  const annex = annexInputs.map((input) => {
    const bytes = regularBytes(input.path, input.flag, 1, MAX_ANNEX_BYTES);
    const recomputed = sha256Hex(bytes);
    if (recomputed !== input.declared)
      refuse(
        `${input.flag} sha256 ${recomputed} does not match the registered ${input.descriptorId} digest ${input.declared}`,
      );
    return { descriptorId: input.descriptorId, source: input.path, sha256: recomputed };
  });

  const detectorRoot = join(runRoot, "detector");
  mkdirSync(join(detectorRoot, "annex"), { recursive: true });
  writeFileSync(join(detectorRoot, "layout-v1.json"), canonicalBytes(layoutInput));
  writeFileSync(join(detectorRoot, "image-id.txt"), `${imageId}\n`);
  const annexFiles = annex.map((entry) => {
    const target = join(detectorRoot, "annex", `${entry.descriptorId}.bin`);
    copyFileSync(entry.source, target);
    if (sha256Hex(readFileSync(target)) !== entry.sha256)
      refuse(`${entry.descriptorId} copy changed`);
    log(`detector input  ${entry.descriptorId} sha256:${entry.sha256}`);
    return { descriptorId: entry.descriptorId, path: target };
  });
  return {
    /* The request carries the authoring document: the CLI revalidates it strictly. */
    registrationInput,
    registrationRecord: registration,
    detectorId,
    layout: layoutInput,
    annexFiles,
  };
}
