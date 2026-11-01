import { describe, expect, it } from "vitest";
import { SigningError, signDocument } from "../../src/host/sign.js";
import { checkAdvisories } from "../../src/public/read.js";
import { readBoundedText } from "../../src/shared/bounded-response.js";
import { corpusCase } from "../support/scan-v1-corpus.js";
import { FULCIO, REKOR, tokenA } from "../support/sigstore-v1-services.js";

/** A response whose body never ends; records how many bytes were pulled and whether it was cancelled. */
function endless(chunk = 64 * 1024) {
  const state = { pulled: 0, cancelled: false };
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      state.pulled += chunk;
      controller.enqueue(new Uint8Array(chunk).fill(0x20));
    },
    cancel() {
      state.cancelled = true;
    },
  });
  return { response: new Response(body, { status: 200 }), state };
}

describe("readBoundedText", () => {
  it("reads a body within the limit as UTF-8 text", async () => {
    expect(await readBoundedText(new Response("héllo"), 16)).toBe("héllo");
    expect(await readBoundedText(new Response(new Uint8Array([0xff])), 16)).toBeUndefined();
  });

  it("stops and cancels a body as soon as it passes the limit", async () => {
    const { response, state } = endless();
    expect(await readBoundedText(response, 1024 * 1024)).toBeUndefined();
    expect(state.cancelled).toBe(true);
    expect(state.pulled).toBeLessThan(2 * 1024 * 1024);
  });

  it("refuses a response without a stream body instead of reading it unbounded", async () => {
    const shim = { ok: true, text: () => Promise.reject(new Error("unbounded")) };
    expect(await readBoundedText(shim as never, 16)).toBeUndefined();
  });
});

describe("bounded service responses", () => {
  it("checkAdvisories treats an oversized advisory answer as unreachable, without buffering it", async () => {
    const { response, state } = endless(1024 * 1024);
    const result = await checkAdvisories(
      [{ ecosystem: "npm", name: "ws", version: "8.18.0", file: "package.json" }],
      { fetch: async () => response, now: () => new Date("2026-11-01T09:00:00Z") },
    );
    expect(result).toMatchObject({
      status: "ok",
      results: [{ state: "not-checked", reason: "advisory service unreachable" }],
    });
    expect(state.cancelled).toBe(true);
    expect(state.pulled).toBeLessThanOrEqual(34 * 1024 * 1024);
  });

  it("signing refuses an oversized certificate-authority answer", async () => {
    const { response, state } = endless();
    const bytes = new Uint8Array(corpusCase("clean").summary);
    await expect(
      signDocument(bytes, tokenA, {
        fulcioUrl: FULCIO,
        rekorUrl: REKOR,
        fetch: (async () => response) as typeof fetch,
      }),
    ).rejects.toThrow(SigningError);
    expect(state.cancelled).toBe(true);
    expect(state.pulled).toBeLessThan(2 * 1024 * 1024);
  });
});
