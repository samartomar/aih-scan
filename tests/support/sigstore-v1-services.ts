import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { expect } from "vitest";
import { signerA, signerB, spkiOf, type Universe } from "./sigstore-v1-universe.js";

/** TEST-ONLY Fulcio and Rekor stand-ins over the synthetic certificate universe. */
export const FULCIO = "https://fulcio.test.invalid";
export const REKOR = "https://rekor.test.invalid";
export const b64url = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
export const jwt = (claims: object) => `${b64url({ alg: "none" })}.${b64url(claims)}.TEST-ONLY`;
export const tokenA = jwt({ iss: signerA.issuer, sub: signerA.subject, aud: "sigstore" });
export const tokenB = jwt({ iss: signerB.issuer, sub: signerB.subject, aud: "sigstore" });
const hexOf = (value: string) => Buffer.from(value, "base64").toString("hex");

/** Controlled Fulcio/Rekor: issue a leaf from the synthetic universe for the token's identity
 * and log the proposed hashedrekord. Records every request; no live service is contacted. */
export function services(world: Universe, options: { otherKey?: boolean } = {}) {
  const calls: { url: string; body: unknown; headers?: unknown }[] = [];
  const fetcher = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
    calls.push({ url, body, headers: init?.headers });
    expect(init?.redirect).toBe("error");
    if (url === `${FULCIO}/api/v2/signingCert`) {
      const token = body.credentials.oidcIdentityToken as string;
      const claims = JSON.parse(
        Buffer.from(token.split(".")[1] as string, "base64url").toString("utf8"),
      );
      const key = createPublicKey(body.publicKeyRequest.publicKey.content);
      const possession = verify(
        "sha256",
        Buffer.from(claims.sub),
        key,
        Buffer.from(body.publicKeyRequest.proofOfPossession, "base64"),
      );
      if (!possession) return new Response("{}", { status: 400 });
      // A key Fulcio did not receive: the certificate cannot verify the signature.
      const leafKey = options.otherKey
        ? generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey
        : key;
      const leaf = world.issueLeaf(spkiOf(leafKey), { issuer: claims.iss, subject: claims.sub });
      return Response.json({
        signedCertificateEmbeddedSct: { chain: { certificates: [world.pem(leaf)] } },
      });
    }
    if (url === `${REKOR}/api/v1/log/entries`) {
      const pem = Buffer.from(body.spec.signature.publicKey.content, "base64").toString("utf8");
      const der = Buffer.from(pem.replace(/-----[A-Z ]+-----|\n/g, ""), "base64");
      const entry = world.logV1(
        world.bodyV1(
          Buffer.from(body.spec.data.hash.value, "hex"),
          Buffer.from(body.spec.signature.content, "base64"),
          der,
        ),
      );
      return Response.json(
        {
          "TEST-ONLY-uuid": {
            body: entry.canonicalizedBody,
            integratedTime: Number(entry.integratedTime),
            logID: hexOf(entry.logId.keyId),
            logIndex: Number(entry.logIndex),
            verification: {
              signedEntryTimestamp: entry.inclusionPromise?.signedEntryTimestamp,
              inclusionProof: {
                checkpoint: entry.inclusionProof?.checkpoint.envelope,
                hashes: entry.inclusionProof?.hashes.map(hexOf),
                logIndex: Number(entry.inclusionProof?.logIndex),
                rootHash: hexOf(entry.inclusionProof?.rootHash as string),
                treeSize: Number(entry.inclusionProof?.treeSize),
              },
            },
          },
        },
        { status: 201 },
      );
    }
    if (url.startsWith("https://actions.test.invalid/token"))
      return Response.json({ value: tokenA });
    throw new Error(`unexpected request ${url}`);
  }) as typeof fetch;
  return { fetcher, calls };
}
