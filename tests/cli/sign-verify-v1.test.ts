import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exitCodes } from "../../src/cli/commands-v1.js";
import { runSignCommand, runVerifyCommand } from "../../src/cli/sign-verify-v1.js";
import { verifySummary } from "../../src/public/read.js";
import { corpusCase } from "../support/scan-v1-corpus.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";
import {
  signerA,
  signerB,
  spkiOf,
  type Universe,
  universe,
} from "../support/sigstore-v1-universe.js";

const FULCIO = "https://fulcio.test.invalid";
const REKOR = "https://rekor.test.invalid";
const b64url = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (claims: object) => `${b64url({ alg: "none" })}.${b64url(claims)}.TEST-ONLY`;
const tokenA = jwt({ iss: signerA.issuer, sub: signerA.subject, aud: "sigstore" });
const tokenB = jwt({ iss: signerB.issuer, sub: signerB.subject, aud: "sigstore" });
const hexOf = (value: string) => Buffer.from(value, "base64").toString("hex");

/** Controlled Fulcio/Rekor: issue a leaf from the synthetic universe for the token's identity
 * and log the proposed hashedrekord. Records every request; no live service is contacted. */
function services(world: Universe, options: { otherKey?: boolean } = {}) {
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

let fixture: FixtureRoot;
let world: Universe;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-sign-");
  world = universe();
  vi.spyOn(globalThis, "fetch").mockImplementation(() => {
    throw new Error("live network is not allowed in tests");
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  fixture.dispose();
});

function capture(extra: object = {}) {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: (t: string) => void out.push(t),
      stderr: (t: string) => void err.push(t),
      cwd: fixture.root,
      ...extra,
    },
    out: () => out.join(""),
    err: () => err.join(""),
  };
}

function setup() {
  const summary = fixture.path("summary.r1.json");
  writeFileSync(summary, corpusCase("clean").summary);
  writeFileSync(fixture.path("root.json"), JSON.stringify(world.trustedRoot()));
  writeFileSync(
    fixture.path("signers.json"),
    JSON.stringify([{ identity: "TEST-ONLY signer A", ...signerA }]),
  );
  return summary;
}

const signArgs = (path: string) => [
  path,
  "--trusted-root",
  "root.json",
  "--fulcio-url",
  FULCIO,
  "--rekor-url",
  REKOR,
];

describe("aih-scan sign and verify (aih-sigstore-keyless/1)", () => {
  it("signs with the caller's identity and the bundle verifies offline under the same profile", async () => {
    const summary = setup();
    const { fetcher, calls } = services(world);
    const signed = capture({ fetch: fetcher, env: { SIGSTORE_ID_TOKEN: tokenA } });
    expect(await runSignCommand(signArgs("summary.r1.json"), signed.io), signed.err()).toBe(
      exitCodes.ok,
    );
    expect(signed.out()).toContain(`signer ${signerA.subject}`);
    expect(calls.map((call) => call.url)).toEqual([
      `${FULCIO}/api/v2/signingCert`,
      `${REKOR}/api/v1/log/entries`,
    ]);
    const bundlePath = fixture.path("summary.r1.sigstore");
    const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
    expect(bundle.mediaType).toBe("application/vnd.dev.sigstore.bundle.v0.3+json");
    expect(bundle.messageSignature.messageDigest.algorithm).toBe("SHA2_256");
    expect(bundle.dsseEnvelope).toBeUndefined();
    expect(JSON.stringify(calls)).not.toContain("PRIVATE KEY");

    // The portable verifier (as /read consumers use it) accepts the exact bytes.
    const result = await verifySummary(
      new Uint8Array(readFileSync(summary)),
      new Uint8Array(readFileSync(bundlePath)),
      [{ identity: "TEST-ONLY signer A", ...signerA }],
      { trustedRoot: world.trustedRoot() },
    );
    expect(result).toMatchObject({
      status: "ok",
      verified: true,
      withdrawn: false,
      signer: { trusted: true },
    });

    const verified = capture();
    expect(
      await runVerifyCommand(
        [
          "summary.r1.json",
          "--bundle",
          "summary.r1.sigstore",
          "--trusted-root",
          "root.json",
          "--signers",
          "signers.json",
        ],
        verified.io,
      ),
    ).toBe(exitCodes.ok);
    expect(verified.out()).toContain("Verified: signed by trusted publisher TEST-ONLY signer A");
    const untrusted = capture();
    expect(
      await runVerifyCommand(
        ["summary.r1.json", "--bundle", "summary.r1.sigstore", "--trusted-root", "root.json"],
        untrusted.io,
      ),
    ).toBe(exitCodes.ok);
    expect(untrusted.out()).toContain("Verified: signed, not by a trusted publisher");
    const shipped = capture();
    expect(
      await runVerifyCommand(["summary.r1.json", "--bundle", "summary.r1.sigstore"], shipped.io),
    ).toBe(exitCodes.input);
    expect(shipped.out()).toContain("Not verified: refused invalid-signature");

    // Exact bytes: any change is refused.
    writeFileSync(summary, `${readFileSync(summary, "utf8")} `);
    const tampered = capture();
    expect(
      await runVerifyCommand(
        [
          "summary.r1.json",
          "--bundle",
          "summary.r1.sigstore",
          "--trusted-root",
          "root.json",
          "--signers",
          "signers.json",
          "--json",
        ],
        tampered.io,
      ),
    ).toBe(exitCodes.input);
    expect(JSON.parse(tampered.out())).toMatchObject({
      status: "refused",
      reason: "invalid-signature",
      verified: false,
      signer: null,
    });
  });

  it("signs a withdrawal that withdraws the same signer's revisions only", async () => {
    setup();
    const scanKey = JSON.parse(new TextDecoder().decode(corpusCase("clean").summary)).scanKey;
    writeFileSync(
      fixture.path("withdrawn.json"),
      `${JSON.stringify({ format: "aih-scan-withdrawn/1", scanKey, throughRevision: 1, at: "2026-11-02T10:00:00Z", reason: "TEST ONLY" })}\n`,
    );
    const a = services(world);
    expect(
      await runSignCommand(
        signArgs("summary.r1.json"),
        capture({ fetch: a.fetcher, env: { SIGSTORE_ID_TOKEN: tokenA } }).io,
      ),
    ).toBe(0);
    const byB = capture({ fetch: services(world).fetcher, env: { SIGSTORE_ID_TOKEN: tokenB } });
    expect(
      await runSignCommand(
        [...signArgs("withdrawn.json"), "--bundle", "withdrawn.b.sigstore"],
        byB.io,
      ),
      byB.err(),
    ).toBe(0);
    const verifyArgs = [
      "summary.r1.json",
      "--bundle",
      "summary.r1.sigstore",
      "--trusted-root",
      "root.json",
      "--signers",
      "signers.json",
    ];
    const other = capture();
    expect(
      await runVerifyCommand(
        [
          ...verifyArgs,
          "--withdrawn",
          "withdrawn.json",
          "--withdrawn-bundle",
          "withdrawn.b.sigstore",
        ],
        other.io,
      ),
    ).toBe(0);
    expect(other.out()).toContain("Verified: signed by trusted publisher");
    expect(other.out()).toContain("withdrawal 1: not-applicable (other-signer)");
    expect(
      await runSignCommand(
        [...signArgs("withdrawn.json"), "--bundle", "withdrawn.a.sigstore"],
        capture({ fetch: services(world).fetcher, env: { SIGSTORE_ID_TOKEN: tokenA } }).io,
      ),
    ).toBe(0);
    const same = capture();
    expect(
      await runVerifyCommand(
        [
          ...verifyArgs,
          "--withdrawn",
          "withdrawn.json",
          "--withdrawn-bundle",
          "withdrawn.a.sigstore",
        ],
        same.io,
      ),
    ).toBe(0);
    expect(same.out()).toContain("Withdrawn:");
    expect(same.out()).toContain("not trusted");
  });

  it("uses the GitHub Actions ambient identity when no token is given", async () => {
    setup();
    const { fetcher, calls } = services(world);
    const env = {
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://actions.test.invalid/token?x=1",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "TEST-ONLY",
    };
    const run = capture({ fetch: fetcher, env });
    expect(await runSignCommand(signArgs("summary.r1.json"), run.io), run.err()).toBe(0);
    expect(calls[0]?.url).toBe("https://actions.test.invalid/token?x=1&audience=sigstore");
  });

  it("refuses without an identity, for other documents, existing output and unverifiable results", async () => {
    setup();
    const none = capture({ fetch: services(world).fetcher, env: {} });
    expect(await runSignCommand(signArgs("summary.r1.json"), none.io)).toBe(exitCodes.input);
    expect(none.err()).toContain("no identity token");

    writeFileSync(fixture.path("other.json"), "{}\n");
    const other = capture({ fetch: services(world).fetcher, env: { SIGSTORE_ID_TOKEN: tokenA } });
    expect(await runSignCommand(signArgs("other.json"), other.io)).toBe(exitCodes.input);
    expect(other.err()).toContain("only an aih-scan-summary/1 or aih-scan-withdrawn/1 document");

    const wrong = services(world, { otherKey: true });
    const mismatched = capture({ fetch: wrong.fetcher, env: { SIGSTORE_ID_TOKEN: tokenA } });
    expect(await runSignCommand(signArgs("summary.r1.json"), mismatched.io)).toBe(exitCodes.input);
    expect(mismatched.err()).toContain("does not verify");
    expect(existsSync(fixture.path("summary.r1.sigstore"))).toBe(false);

    writeFileSync(fixture.path("summary.r1.sigstore"), "x");
    const exists = capture({ fetch: services(world).fetcher, env: { SIGSTORE_ID_TOKEN: tokenA } });
    expect(await runSignCommand(signArgs("summary.r1.json"), exists.io)).toBe(exitCodes.input);
    expect(exists.err()).toContain("already exists");

    const insecure = capture({
      fetch: services(world).fetcher,
      env: { SIGSTORE_ID_TOKEN: tokenA },
    });
    expect(
      await runSignCommand(
        ["summary.r1.json", "--bundle", "x.sigstore", "--fulcio-url", "http://fulcio.test.invalid"],
        insecure.io,
      ),
    ).toBe(exitCodes.input);
  });

  it("verify reports bad input as exit 2", async () => {
    setup();
    const missing = capture();
    expect(await runVerifyCommand(["summary.r1.json"], missing.io)).toBe(exitCodes.input);
    expect(missing.err()).toContain("--bundle is required");
    writeFileSync(fixture.path("bundle.json"), "{");
    const malformed = capture();
    expect(
      await runVerifyCommand(["summary.r1.json", "--bundle", "bundle.json"], malformed.io),
    ).toBe(exitCodes.input);
    expect(malformed.out()).toContain("Not verified: invalid bundle");
  });
});
