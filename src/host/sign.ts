/**
 * `aih-scan sign`: signs the exact bytes of a summary (or withdrawal) with the caller's own
 * OIDC identity through Sigstore keyless signing (Fulcio certificate, Rekor v1 hashedrekord
 * entry) and returns an `aih-sigstore-keyless/1` bundle (v0.3, messageSignature). The private
 * key is ephemeral and never leaves memory. The produced bundle is verified with the portable
 * verifier before it is returned.
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { sigstoreTrustedRootText } from "../contracts/sigstore-trusted-root.js";
import { validateWithdrawn } from "../contracts/validate.js";
import { parseJsonBytes, readSummary } from "../read/read-summary.js";
import { BUNDLE_MEDIA_TYPE, parseBundle } from "../read/sigstore/bundle.js";
import { base64Encode, hexDecode, pemCertificate } from "../read/sigstore/bytes.js";
import { verifyKeyless } from "../read/sigstore/evidence.js";
import { parseTrustedRoot, type TrustMaterial } from "../read/sigstore/trust.js";

export const DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev";
export const DEFAULT_REKOR_URL = "https://rekor.sigstore.dev";

export interface SigningServices {
  readonly fulcioUrl: string;
  readonly rekorUrl: string;
  readonly fetch: typeof fetch;
  readonly timeoutMs?: number;
}

export class SigningError extends Error {}

const MAX_RESPONSE = 1024 * 1024;

async function postJson(
  services: SigningServices,
  url: string,
  body: unknown,
  label: string,
): Promise<unknown> {
  let response: Response;
  try {
    response = await services.fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      redirect: "error",
      credentials: "omit",
      signal: AbortSignal.timeout(services.timeoutMs ?? 60_000),
    });
  } catch {
    throw new SigningError(`${label} could not be reached`);
  }
  const text = await response.text();
  if (text.length > MAX_RESPONSE) throw new SigningError(`${label} returned too much data`);
  if (!response.ok)
    throw new SigningError(`${label} refused the request (HTTP ${response.status})`);
  try {
    return JSON.parse(text);
  } catch {
    throw new SigningError(`${label} returned malformed JSON`);
  }
}

const field = (value: unknown, ...path: (string | number)[]): unknown => {
  let current = value;
  for (const key of path) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string | number, unknown>)[key];
  }
  return current;
};

/** The proof-of-possession challenge Fulcio expects: the token's email for email issuers, else `sub`. */
export function tokenSubject(token: string): string {
  const parts = token.split(".");
  if (parts.length !== 3) throw new SigningError("the identity token is not a JWT");
  let claims: Record<string, unknown>;
  try {
    claims = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8"));
  } catch {
    throw new SigningError("the identity token is not a JWT");
  }
  const email =
    claims.iss === "https://accounts.google.com" ||
    claims.iss === "https://oauth2.sigstore.dev/auth";
  const subject = email ? claims.email : claims.sub;
  if (typeof subject !== "string" || subject.length === 0)
    throw new SigningError("the identity token has no subject");
  return subject;
}

/** Accepts exactly a readable `aih-scan-summary/1` or `aih-scan-withdrawn/1` document. */
export function signableKind(bytes: Uint8Array): "summary" | "withdrawn" | undefined {
  if (readSummary(bytes).status === "ok") return "summary";
  const parsed = parseJsonBytes(bytes, "withdrawn", MAX_RESPONSE);
  if (parsed.ok && validateWithdrawn(parsed.value).status === "ok") return "withdrawn";
  return undefined;
}

let shipped: TrustMaterial | undefined;

/**
 * Signs `bytes` and returns the bundle object plus the certificate identity. `trust` (default:
 * the shipped public snapshot) is used to verify the produced bundle offline.
 */
export async function signDocument(
  bytes: Uint8Array,
  identityToken: string,
  services: SigningServices,
  trust?: TrustMaterial,
): Promise<{ bundle: Record<string, unknown>; issuer: string; subject: string }> {
  if (signableKind(bytes) === undefined)
    throw new SigningError(
      "only an aih-scan-summary/1 or aih-scan-withdrawn/1 document can be signed",
    );
  const challenge = tokenSubject(identityToken);
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const certificateResponse = await postJson(
    services,
    `${services.fulcioUrl.replace(/\/$/, "")}/api/v2/signingCert`,
    {
      credentials: { oidcIdentityToken: identityToken },
      publicKeyRequest: {
        publicKey: {
          algorithm: "ECDSA",
          content: publicKey.export({ type: "spki", format: "pem" }),
        },
        proofOfPossession: sign("sha256", Buffer.from(challenge), privateKey).toString("base64"),
      },
    },
    "the certificate authority",
  );
  const chain = field(certificateResponse, "signedCertificateEmbeddedSct", "chain", "certificates");
  if (!Array.isArray(chain) || typeof chain[0] !== "string")
    throw new SigningError(
      "the certificate authority did not return a certificate with an embedded SCT",
    );
  const leafPem = chain[0];
  const leaf = pemCertificate(leafPem.endsWith("\n") ? leafPem : `${leafPem}\n`);
  if (leaf === undefined)
    throw new SigningError("the certificate authority returned a malformed certificate");

  const signature = sign("sha256", bytes, privateKey);
  const digest = createHash("sha256").update(bytes).digest();
  const entryResponse = await postJson(
    services,
    `${services.rekorUrl.replace(/\/$/, "")}/api/v1/log/entries`,
    {
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: {
        data: { hash: { algorithm: "sha256", value: digest.toString("hex") } },
        signature: {
          content: signature.toString("base64"),
          publicKey: { content: Buffer.from(leafPem).toString("base64") },
        },
      },
    },
    "the transparency log",
  );
  const entries =
    typeof entryResponse === "object" && entryResponse !== null ? Object.values(entryResponse) : [];
  const entry = entries[0];
  const proof = field(entry, "verification", "inclusionProof");
  const hex = (value: unknown) => {
    const decoded = hexDecode(value);
    if (decoded === undefined)
      throw new SigningError("the transparency log returned a malformed entry");
    return base64Encode(decoded);
  };
  const integer = (value: unknown) => {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
      throw new SigningError("the transparency log returned a malformed entry");
    return String(value);
  };
  const checkpoint = field(proof, "checkpoint");
  const hashes = field(proof, "hashes") ?? [];
  if (
    entries.length !== 1 ||
    typeof field(entry, "body") !== "string" ||
    typeof checkpoint !== "string" ||
    !Array.isArray(hashes)
  )
    throw new SigningError("the transparency log returned a malformed entry");
  const bundle = {
    mediaType: BUNDLE_MEDIA_TYPE,
    verificationMaterial: {
      certificate: { rawBytes: base64Encode(leaf) },
      tlogEntries: [
        {
          logIndex: integer(field(entry, "logIndex")),
          logId: { keyId: hex(field(entry, "logID")) },
          kindVersion: { kind: "hashedrekord", version: "0.0.1" },
          integratedTime: integer(field(entry, "integratedTime")),
          inclusionPromise: {
            signedEntryTimestamp: field(entry, "verification", "signedEntryTimestamp"),
          },
          inclusionProof: {
            logIndex: integer(field(proof, "logIndex")),
            rootHash: hex(field(proof, "rootHash")),
            treeSize: integer(field(proof, "treeSize")),
            hashes: hashes.map(hex),
            checkpoint: { envelope: checkpoint },
          },
          canonicalizedBody: field(entry, "body"),
        },
      ],
    },
    messageSignature: {
      messageDigest: { algorithm: "SHA2_256", digest: digest.toString("base64") },
      signature: signature.toString("base64"),
    },
  };
  shipped ??= parseTrustedRoot(JSON.parse(sigstoreTrustedRootText));
  let verified: Awaited<ReturnType<typeof verifyKeyless>>;
  try {
    verified = await verifyKeyless(bytes, parseBundle(bundle), trust ?? shipped);
  } catch (error) {
    throw new SigningError(
      `the produced bundle does not verify under the selected trust material (${error instanceof Error ? error.message : "unknown"})`,
    );
  }
  return { bundle, issuer: verified.issuer, subject: verified.subject };
}

/**
 * The caller's own OIDC token: `SIGSTORE_ID_TOKEN`, else GitHub Actions' ambient token
 * (audience `sigstore`, requires `id-token: write`). No interactive sign-in is offered.
 */
export async function identityToken(
  env: Readonly<Record<string, string | undefined>>,
  fetcher: typeof fetch,
): Promise<string | undefined> {
  const explicit = env.SIGSTORE_ID_TOKEN?.trim();
  if (explicit) return explicit;
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) return undefined;
  let response: Response;
  try {
    const request = new URL(url);
    request.searchParams.set("audience", "sigstore");
    response = await fetcher(request.href, {
      headers: { authorization: `Bearer ${bearer}`, accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new SigningError("the GitHub Actions identity token could not be obtained");
  }
  const value = response.ok
    ? field(await response.json().catch(() => undefined), "value")
    : undefined;
  if (typeof value !== "string")
    throw new SigningError("the GitHub Actions identity token could not be obtained");
  return value;
}
