/**
 * Labelled validation fixtures for `tools/capture-catalog-item.mjs`.
 *
 * These are fixtures, not operator inputs. No organization registration, OCI
 * layout, image ID or annex byte exists in this repository, and nothing here is
 * a detector identity, a scan result or a finding. They exist only so the
 * helper's own cross-checks can be exercised while the real operator inputs are
 * absent, and they never reach a detector: every test that uses them stops
 * before the Docker gate and before capture.
 *
 * The fixture is internally consistent by construction (image ID = layout config
 * digest, annex digests = registration digests). A test that wants a specific
 * mismatch rewrites exactly one file.
 */
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CatalogCaptureOptionsV1 } from "../../tools/capture-catalog-item.mjs";

const hex = (digit: string) => digit.repeat(64);
const sha256Hex = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

export const FIXTURE_DETECTOR_ID = "detector.fixture.organization";
/** The collection view and subject a case asks the public reader for. */
export const FIXTURE_COLLECTION_ID = "aih-core";
export const FIXTURE_SUBJECT_ID = "governance-quality";
/** The entry identity the source reader returns for that subject; never a helper default. */
export const FIXTURE_ENTRY_ID = "agent.aih.governance-quality.core-0-6-2";
export const FIXTURE_MANIFEST_SHA256 = hex("a");
export const FIXTURE_CONFIG_SHA256 = hex("b");
export const FIXTURE_LOGICAL_REFERENCE = `local.invalid/aih-scan/cisco@sha256:${FIXTURE_MANIFEST_SHA256}`;

export type DetectorInputFixturePaths = Readonly<{
  directory: string;
  registration: string;
  layout: string;
  imageId: string;
  sbom: string;
  provenance: string;
}>;

export const fixtureSbomBytes = (): Buffer =>
  Buffer.from(`${JSON.stringify({ name: "fixture-annex-sbom", spdxVersion: "SPDX-2.3" })}\n`);
export const fixtureProvenanceBytes = (): Buffer =>
  Buffer.from(
    `${JSON.stringify({ _type: "fixture-in-toto-statement", predicateType: "fixture" })}\n`,
  );

/** A canonical CiscoOciLayoutV1 shape; `--layout` here is a fixture, not a build. */
export const fixtureLayout = (): Record<string, unknown> => ({
  configDigestSha256: `sha256:${FIXTURE_CONFIG_SHA256}`,
  logicalReference: FIXTURE_LOGICAL_REFERENCE,
  manifestDescriptor: {
    annotations: { "org.opencontainers.image.ref.name": "cisco" },
    digest: `sha256:${FIXTURE_MANIFEST_SHA256}`,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    platform: { architecture: "amd64", os: "linux" },
    size: 1024,
  },
  manifestDigestSha256: `sha256:${FIXTURE_MANIFEST_SHA256}`,
  manifestPlatform: { architecture: "amd64", os: "linux" },
  protocol: "CiscoOciLayoutV1",
});

/** A DetectorRegistrationV1 authoring document; computed wire fields are absent. */
export const fixtureRegistration = (): Record<string, unknown> => ({
  protocol: "DetectorRegistrationV1",
  registrations: [
    {
      adapterCapability: "cisco-oci-v1",
      broker: { capability: "cisco-oci-v1", identity: "broker.0123456789ab" },
      detector: {
        adapter: { identity: "adapter.0123456789ab", sha256: hex("c") },
        analyzerIdentity: "native.0123456789ab",
        detectorId: FIXTURE_DETECTOR_ID,
        executionProfileSha256: hex("d"),
        observationConfigurationSha256: hex("e"),
        ociImage: {
          reference: FIXTURE_LOGICAL_REFERENCE,
          sha256: FIXTURE_MANIFEST_SHA256,
        },
        provenance: {
          mediaType: "application/vnd.in-toto+json",
          sha256: sha256Hex(fixtureProvenanceBytes()),
        },
        sbom: { mediaType: "application/spdx+json", sha256: sha256Hex(fixtureSbomBytes()) },
        supportedPlatforms: [{ architecture: "amd64", os: "linux" }],
      },
      runtime: {
        configSha256: FIXTURE_CONFIG_SHA256,
        sourceReference: FIXTURE_LOGICAL_REFERENCE,
        sourceSha256: FIXTURE_MANIFEST_SHA256,
      },
    },
  ],
});

export function writeJsonFixture(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value)}\n`);
}

export function writeDetectorInputFixtures(directory: string): DetectorInputFixturePaths {
  mkdirSync(directory, { recursive: true });
  const paths = {
    directory,
    imageId: join(directory, "fixture-image-id.txt"),
    layout: join(directory, "fixture-layout-v1.json"),
    provenance: join(directory, "fixture-annex.provenance.json"),
    registration: join(directory, "fixture-registration.json"),
    sbom: join(directory, "fixture-annex.sbom.json"),
  };
  writeJsonFixture(paths.registration, fixtureRegistration());
  writeJsonFixture(paths.layout, fixtureLayout());
  writeFileSync(paths.imageId, `sha256:${FIXTURE_CONFIG_SHA256}\n`);
  writeFileSync(paths.sbom, fixtureSbomBytes());
  writeFileSync(paths.provenance, fixtureProvenanceBytes());
  return paths;
}

/**
 * A complete options object for the helper. `catalogTarball`/`scanTarball`
 * default to paths that do not exist: only a caller that supplies real packaged
 * tarballs can reach installation.
 */
export function fixtureOptions(
  directory: string,
  paths: DetectorInputFixturePaths,
  overrides: Partial<CatalogCaptureOptionsV1> = {},
): CatalogCaptureOptionsV1 {
  return {
    catalogTarball: join(directory, "fixture-catalog.tgz"),
    collectionId: FIXTURE_COLLECTION_ID,
    consumerRoot: join(directory, "consumer"),
    imageId: paths.imageId,
    layout: paths.layout,
    output: join(directory, "run"),
    provenance: paths.provenance,
    registration: paths.registration,
    sbom: paths.sbom,
    scanTarball: join(directory, "fixture-scan.tgz"),
    subjectId: FIXTURE_SUBJECT_ID,
    ...overrides,
  };
}
