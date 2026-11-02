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
