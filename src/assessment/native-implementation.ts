import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../contract/strict-json-v1.js";
import {
  hashSourceEntriesV1,
  hashSourceTreeV1,
  type SourceHashEntryV1,
  type SourceTreeHashV1,
} from "../observation/source-hash-v1.js";
import { sealSourceObservationV1 } from "../observation/source-observation-seal-v1.js";

/** The existing native identity, separated from unrelated external analyzer runtimes. */
export const BASELINE_NATIVE_ANALYZER_IDENTITY_V1 = `native.${canonicalStrictJsonSha256V1({
  domain: "aih.baseline-native-observation-v1",
  algorithm: "source-hash-v1",
}).slice(0, 12)}`;

/** Preserves the exact native source identity annex and analyzer identity. */
export function runNativeImplementationV1(sourceRoot: string) {
  const source = hashSourceTreeV1(sourceRoot);
  return nativeOutput(source);
}

function nativeOutput(source: SourceTreeHashV1) {
  const bytes = canonicalStrictJsonBytesV1({
    protocol: "BaselineNativeObservationV1",
    sourceTreeSha256: source.treeSha256,
    files: source.files,
  });
  return {
    mediaType: "application/vnd.aih.baseline-native+json" as const,
    bytes,
    analyzerVersion: BASELINE_NATIVE_ANALYZER_IDENTITY_V1,
  };
}

/** Internal callback accepted by the common assessment adapter. */
export function nativeImplementationV1(request: {
  sourceRoot: string;
  selectedClosurePaths: readonly string[];
}) {
  const sealed = sealSourceObservationV1(request);
  // The legacy native runner materializes every captured file link as a regular
  // file before hashing. Derive that same tree from the stable captured entries,
  // retaining the original link identity separately in ObservationInput.
  const entries: SourceHashEntryV1[] = sealed.entries.map((entry) => {
    if (entry.kind === "directory") return { type: "directory", path: entry.path };
    if (entry.kind === "directory-link")
      throw new TypeError("Native observation does not materialize directory links");
    return { type: "file", path: entry.path, bytes: entry.byteLength, sha256: entry.sha256 };
  });
  return nativeOutput(hashSourceEntriesV1(entries));
}
