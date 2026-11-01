/**
 * Reads a fetch response body as UTF-8 text without holding more than `maximum` bytes: the
 * body is streamed and cancelled as soon as it passes the limit. Portable (no Node globals).
 * Undefined when the body is over the limit, is not a readable stream, is not UTF-8 or the read
 * fails. A response without a stream body (a minimal fetch shim) is refused rather than read
 * unbounded.
 */
export async function readBoundedText(
  response: Pick<Response, "body">,
  maximum: number,
): Promise<string | undefined> {
  const reader = (response.body as ReadableStream<Uint8Array> | null | undefined)?.getReader?.();
  if (reader === undefined) return undefined;
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array) && !ArrayBuffer.isView(value)) return undefined;
      total += value.byteLength;
      if (total > maximum) return undefined;
      chunks.push(value);
    }
  } catch {
    return undefined;
  } finally {
    await Promise.resolve(reader.cancel()).catch(() => {});
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}
