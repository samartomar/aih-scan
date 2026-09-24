import { isUtf8 } from "node:buffer";

/** Decoded process output, flagging stdout a lossy decode would have repaired (S2h). */
export function processOutputV1(
  stdout: readonly Buffer[],
  stderr: readonly Buffer[],
): Readonly<{ stdout: string; stderr: string; stdoutMalformedUtf8?: true }> {
  const bytes = Buffer.concat(stdout);
  return {
    stdout: bytes.toString("utf8"),
    stderr: Buffer.concat(stderr).toString("utf8"),
    ...(isUtf8(bytes) ? {} : { stdoutMalformedUtf8: true as const }),
  };
}

/**
 * The stdout of a process as analyzer output text: refused when it was not well-formed UTF-8
 * (S2h), never the lossy decode.
 */
export function analyzerStdoutV1(
  result: Readonly<{ stdout: string; stdoutMalformedUtf8?: true }>,
  label: string,
): string {
  if (result.stdoutMalformedUtf8 === true) throw new TypeError(`${label} is not well-formed UTF-8`);
  return result.stdout;
}
