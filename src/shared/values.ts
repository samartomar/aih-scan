/** Portable value helpers shared by the readers, contracts and trust-lint (no Node globals). */

/** A parsed JSON value. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** True for a non-null, non-array object (a JSON object once parsed). */
export function isRecord<T = unknown>(value: unknown): value is Record<string, T> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The realm's WebCrypto `subtle`; throws a TypeError when the realm has none. */
export function webCryptoSubtle(): SubtleCrypto {
  const value = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (value === undefined) throw new TypeError("WebCrypto is unavailable");
  return value;
}
