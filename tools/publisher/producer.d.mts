import type { ProducerContext } from "./candidate.mjs";
export function validateProducerContext(bytes: Uint8Array, expectedSha256: string): ProducerContext;
export function checkProducerSource(context: ProducerContext, source: string): void;
export function sealProducerContext(bytes: Uint8Array, expectedSha256: string, source: string, consumer: string, tarball: string): ProducerContext;
export function checkProducerContext(bytes: Uint8Array, expectedSha256: string, consumer: string): ProducerContext;
export function buildProducerContext(bytes: Uint8Array, expectedSha256: string, source: string, consumer: string): ProducerContext;
