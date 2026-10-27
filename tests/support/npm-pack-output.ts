export interface PackedPackage {
  readonly filename: string;
  readonly files: readonly { readonly path: string }[];
}

/** Read exactly one package inventory from npm pack --json. */
export function readPackedPackage(output: string): PackedPackage {
  const parsed: unknown = JSON.parse(output);
  // npm 11 returns an array; npm 12 keys the same entries by package name.
  const entries = Array.isArray(parsed)
    ? parsed
    : parsed !== null && typeof parsed === "object"
      ? Object.values(parsed)
      : [];
  if (entries.length !== 1) throw new Error("Expected exactly one packed package");
  const entry: unknown = entries[0];
  if (entry === null || typeof entry !== "object" || Array.isArray(entry))
    throw new Error("Invalid packed package entry");
  const { filename, files } = entry as { filename?: unknown; files?: unknown };
  if (typeof filename !== "string" || !Array.isArray(files))
    throw new Error("Missing packed package filename or files");
  return {
    filename,
    files: files.map((file: unknown) => {
      if (file === null || typeof file !== "object" || Array.isArray(file))
        throw new Error("Invalid packed package file");
      const path = (file as { path?: unknown }).path;
      if (typeof path !== "string") throw new Error("Missing packed package file path");
      return { path };
    }),
  };
}
