import type { Problem } from "../contracts/formats.js";
import { sigstoreTrustedRootText } from "../contracts/sigstore-trusted-root.js";
import { isBytes } from "../contracts/text.js";
import { type Summary, validateWithdrawn, type Withdrawal } from "../contracts/validate.js";
import { type AllowedSigner, defaultSigners } from "../contracts/verification.js";
import { parseJsonBytes, readSummary } from "./read-summary.js";
import { BundleProblem, type KeylessBundle, parseBundle } from "./sigstore/bundle.js";
import { EvidenceError } from "./sigstore/bytes.js";
import { type VerifiedSigner, verifyKeyless } from "./sigstore/evidence.js";
import { parseTrustedRoot, type TrustMaterial, TrustProblem } from "./sigstore/trust.js";
import { fulcioText } from "./sigstore/x509.js";

/** The signer established by a verified signature. `trusted` is true only for a caller-selected
 * (or default) identity whose result is not withdrawn. */
export interface VerifiedSignerInfo {
  readonly identity: string;
  readonly trusted: boolean;
  readonly issuer: string;
  readonly subject: string;
}

/** What happened to one supplied withdrawal. Only `applies` withdraws the summary. */
export interface WithdrawalOutcome {
  readonly status: "applies" | "not-applicable" | "refused" | "invalid" | "unsupported-version";
  readonly reason?: string;
  readonly throughRevision?: number;
}

export type VerifySummaryResult =
  | Readonly<{
      status: "ok";
      verified: true;
      withdrawn: boolean;
      signer: VerifiedSignerInfo;
      summary: Summary;
      signedAt: readonly string[];
      withdrawals: readonly WithdrawalOutcome[];
    }>
  | (Problem & Readonly<{ verified: false; withdrawn: false; signer: null; summary: null }>);

/** Bytes (JSON) or an already parsed object. */
export type JsonInput = Uint8Array | Record<string, unknown>;

export interface VerifySummaryOptions {
  /** A Sigstore trusted root obtained and trusted independently by the caller; replaces the
   * shipped snapshot for this call. `null` selects no trust material. */
  readonly trustedRoot?: JsonInput | null;
  /** `aih-scan-withdrawn/1` bytes (or several), each with its bundle at the same position. */
  readonly withdrawn?: Uint8Array | readonly Uint8Array[];
  readonly withdrawnBundle?: JsonInput | readonly JsonInput[];
}

const notVerified = (problem: Problem): VerifySummaryResult =>
  Object.freeze({
    ...problem,
    verified: false,
    withdrawn: false,
    signer: null,
    summary: null,
  }) as VerifySummaryResult;
const problem = (status: Problem["status"], reason: string, detail: string): Problem =>
  Object.freeze({ status, reason, detail }) as Problem;

let shipped: TrustMaterial | undefined;

function selectTrust(options: VerifySummaryOptions): TrustMaterial | Problem {
  try {
    if (options.trustedRoot === undefined) {
      shipped ??= parseTrustedRoot(JSON.parse(sigstoreTrustedRootText));
      return shipped;
    }
    if (options.trustedRoot === null)
      return problem("refused", "trust-data-unavailable", "no trust material was selected");
    let value: unknown = options.trustedRoot;
    if (isBytes(value)) {
      const parsed = parseJsonBytes(value, "trustedRoot", 4 * 1024 * 1024);
      if (!parsed.ok)
        return problem("invalid", "trusted-root", "trustedRoot is not strict UTF-8 JSON");
      value = parsed.value;
    }
    return parseTrustedRoot(value);
  } catch (error) {
    if (error instanceof TrustProblem) return problem(error.status, error.reason, error.message);
    return problem(
      "refused",
      "trust-data-unavailable",
      "the selected trust material could not be read",
    );
  }
}

function checkSigners(value: unknown): readonly AllowedSigner[] | Problem {
  if (value === undefined) return defaultSigners;
  const bad = problem(
    "invalid",
    "allowedSigners",
    "allowedSigners must be an array of { identity, issuer, subject, extensions? }",
  );
  if (!Array.isArray(value) || value.length > 256) return bad;
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) return bad;
    const { identity, issuer, subject, extensions } = entry as Record<string, unknown>;
    if (typeof identity !== "string" || typeof issuer !== "string" || typeof subject !== "string")
      return bad;
    if (issuer.length === 0 || subject.length === 0) return bad;
    if (extensions !== undefined) {
      if (typeof extensions !== "object" || extensions === null || Array.isArray(extensions))
        return bad;
      for (const [oid, text] of Object.entries(extensions))
        if (!/^\d+(\.\d+)+$/.test(oid) || typeof text !== "string") return bad;
    }
  }
  return value as readonly AllowedSigner[];
}

const matches = (signer: VerifiedSigner, allowed: AllowedSigner) =>
  signer.issuer === allowed.issuer &&
  signer.subject === allowed.subject &&
  Object.entries(allowed.extensions ?? {}).every(
    ([oid, text]) => fulcioText(signer.certificate, oid) === text,
  );

type Verified = { ok: true; signer: VerifiedSigner } | { ok: false; problem: Problem };

async function authenticate(
  bytes: Uint8Array,
  bundleInput: unknown,
  trust: TrustMaterial,
): Promise<Verified> {
  let bundle: KeylessBundle;
  try {
    bundle = parseBundle(bundleInput);
  } catch (error) {
    if (error instanceof BundleProblem)
      return { ok: false, problem: problem(error.status, error.reason, error.message) };
    return { ok: false, problem: problem("invalid", "bundle", "the bundle could not be read") };
  }
  try {
    return { ok: true, signer: await verifyKeyless(bytes, bundle, trust) };
  } catch (error) {
    if (error instanceof EvidenceError)
      return { ok: false, problem: problem("refused", error.reason, error.message) };
    return {
      ok: false,
      problem: problem(
        "refused",
        "invalid-signature",
        "the signature, certificate or proof material does not verify",
      ),
    };
  }
}

const listOf = <T>(value: T | readonly T[] | undefined): readonly T[] =>
  value === undefined ? [] : Array.isArray(value) ? (value as readonly T[]) : [value as T];

async function withdrawalOutcome(
  bytes: unknown,
  bundle: unknown,
  summary: Summary,
  signer: VerifiedSigner,
  trust: TrustMaterial,
  allowed: readonly AllowedSigner[],
): Promise<WithdrawalOutcome> {
  const parsed = parseJsonBytes(bytes, "withdrawn", 1024 * 1024);
  if (!parsed.ok)
    return Object.freeze({ status: parsed.problem.status, reason: parsed.problem.reason });
  const checked = validateWithdrawn(parsed.value);
  if (checked.status !== "ok")
    return Object.freeze({ status: checked.status, reason: checked.reason });
  const withdrawal: Withdrawal = checked.withdrawn;
  const verified = await authenticate(bytes as Uint8Array, bundle, trust);
  if (!verified.ok)
    return Object.freeze({ status: verified.problem.status, reason: verified.problem.reason });
  const through = withdrawal.throughRevision;
  if (withdrawal.scanKey !== summary.scanKey)
    return Object.freeze({
      status: "not-applicable",
      reason: "other-key",
      throughRevision: through,
    });
  const sameSigner =
    verified.signer.issuer === signer.issuer &&
    verified.signer.subject === signer.subject &&
    allowed.every((entry) => !matches(signer, entry) || matches(verified.signer, entry));
  if (!sameSigner)
    return Object.freeze({
      status: "not-applicable",
      reason: "other-signer",
      throughRevision: through,
    });
  if (summary.revision > through)
    return Object.freeze({
      status: "not-applicable",
      reason: "later-revision",
      throughRevision: through,
    });
  return Object.freeze({ status: "applies", throughRevision: through });
}

/**
 * Verifies a summary's Sigstore bundle offline under `aih-sigstore-keyless/1` (see `/contracts`
 * `verification`) and applies signer-specific withdrawals. Resolves asynchronously (WebCrypto)
 * and never throws.
 *
 * - `verified` is the cryptographic result; `signer.trusted` is true only when the issuer and
 *   certificate subject (and any listed extensions) match an entry of `allowedSigners` (default:
 *   `defaultSigners`, the documented Scan publishing workflow) and the result is not withdrawn.
 *   A valid signature by anyone else is "signed, not by a trusted publisher".
 * - Trust comes only from the shipped pinned snapshot or `options.trustedRoot`; certificates in
 *   the bundle never act as trust anchors. No network access.
 * - A withdrawal applies only when it verifies under the same rules, names the same scan key, is
 *   signed by the same signer and its `throughRevision` is at least the summary's revision.
 * - Unreadable summary → its `readSummary` problem; no usable trust → `refused`
 *   `trust-data-unavailable`; malformed trust → `invalid`; another bundle version →
 *   `unsupported-version`; another profile/algorithm → `refused` `unsupported-profile` /
 *   `unsupported-algorithm`; failed signature/chain/SCT/log/time proof → `refused`
 *   `invalid-signature`.
 * - Pass the returned object itself to `matchScan`: only that object carries its signer (a copy
 *   or a hand-built look-alike matches with `signer: null`).
 */
export async function verifySummary(
  bytes: Uint8Array,
  bundle: JsonInput,
  allowedSigners?: readonly AllowedSigner[],
  options: VerifySummaryOptions = {},
): Promise<VerifySummaryResult> {
  const result = await verify(bytes, bundle, allowedSigners, options);
  issued.add(result);
  return result;
}

/**
 * Results this module returned. `matchScan` takes a signer only from one of these exact (frozen)
 * objects, so a look-alike `{ status: "ok", summary, signer }` cannot claim a trusted signer.
 */
const issued = new WeakSet<object>();

/** True only for an object `verifySummary` returned, as returned (not copied or spread). */
export function isVerifySummaryResult(value: unknown): boolean {
  return typeof value === "object" && value !== null && issued.has(value);
}

async function verify(
  bytes: Uint8Array,
  bundle: JsonInput,
  allowedSigners: readonly AllowedSigner[] | undefined,
  options: VerifySummaryOptions,
): Promise<VerifySummaryResult> {
  try {
    const read = readSummary(bytes);
    if (read.status !== "ok") return notVerified(read);
    const allowed = checkSigners(allowedSigners);
    if ("status" in allowed) return notVerified(allowed);
    const trust = selectTrust(options ?? {});
    if ("status" in trust) return notVerified(trust);
    const verified = await authenticate(bytes, bundle, trust);
    if (!verified.ok) return notVerified(verified.problem);
    const withdrawnList = listOf(options?.withdrawn);
    const bundleList = listOf(
      options?.withdrawnBundle as JsonInput | readonly JsonInput[] | undefined,
    );
    if (withdrawnList.length !== bundleList.length || withdrawnList.length > 64)
      return notVerified(
        problem(
          "invalid",
          "withdrawn",
          "each withdrawal needs its bundle at the same position (at most 64)",
        ),
      );
    const withdrawals: WithdrawalOutcome[] = [];
    for (const [index, entry] of withdrawnList.entries())
      withdrawals.push(
        await withdrawalOutcome(
          entry,
          bundleList[index],
          read.summary,
          verified.signer,
          trust,
          allowed,
        ),
      );
    const withdrawn = withdrawals.some((outcome) => outcome.status === "applies");
    const listed = allowed.find((entry) => matches(verified.signer, entry));
    return Object.freeze({
      status: "ok" as const,
      verified: true as const,
      withdrawn,
      signer: Object.freeze({
        identity: listed?.identity ?? verified.signer.subject,
        trusted: listed !== undefined && !withdrawn,
        issuer: verified.signer.issuer,
        subject: verified.signer.subject,
      }),
      summary: read.summary,
      signedAt: Object.freeze(verified.signer.signedAt.map((time) => new Date(time).toISOString())),
      withdrawals: Object.freeze(withdrawals),
    });
  } catch {
    return notVerified(
      problem("refused", "invalid-signature", "the evidence could not be verified"),
    );
  }
}
