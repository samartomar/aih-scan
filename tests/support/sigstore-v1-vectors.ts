// TEST ONLY. The single committed `aih-sigstore-keyless/1` fixture set shared by the host
// verifier tests, the CLI and the browser-like realm: summaries, withdrawals, bundles and trust
// roots built from one synthetic universe, each case with its spec-derived expectation.
// Regenerate: AIH_SCAN_UPDATE_SIGSTORE_VECTORS=1 npx vitest run tests/read-v1/verify-summary.test.ts
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { corpusRoot } from "./scan-v1-corpus.js";
import {
  LEAF_NOT_AFTER,
  LEAF_NOT_BEFORE,
  p256,
  p384,
  REPOSITORY_OID,
  type SignOptions,
  signedBundle,
  signerA,
  signerB,
  universe,
} from "./sigstore-v1-universe.js";

export const vectorsPath = join(
  import.meta.dirname,
  "..",
  "fixtures",
  "sigstore-v1",
  "vectors.json",
);

export interface VectorSigner {
  readonly identity: string;
  readonly issuer: string;
  readonly subject: string;
  readonly extensions?: Record<string, string>;
}

export interface VectorCase {
  readonly name: string;
  /** Base64 of the exact summary bytes. */
  readonly summary: string;
  /** The bundle object, or base64 bytes in `bundleBytes`. */
  readonly bundle?: unknown;
  readonly bundleBytes?: string;
  /** A key of `roots`, "shipped" (no override) or "none" (null). */
  readonly root: string;
  /** Omitted → default signers. */
  readonly signers?: readonly VectorSigner[];
  readonly withdrawn?: readonly { bytes: string; bundle: unknown }[];
  readonly expect: {
    readonly status: string;
    readonly reason?: string;
    readonly verified?: boolean;
    readonly trusted?: boolean;
    readonly withdrawn?: boolean;
    readonly identity?: string;
  };
}

export interface Vectors {
  readonly note: string;
  /** Corpus case whose content the summaries describe (for matchScan). */
  readonly content: string;
  readonly roots: Record<string, unknown>;
  readonly cases: readonly VectorCase[];
}

export const loadVectors = (): Vectors => JSON.parse(readFileSync(vectorsPath, "utf8"));

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const A: VectorSigner = { identity: "TEST-ONLY signer A", ...signerA };
const B: VectorSigner = { identity: "TEST-ONLY signer B", ...signerB };

export function buildVectors(): Vectors {
  const world = universe();
  const stranger = universe();
  const base = readFileSync(join(corpusRoot, "clean", "summary.json"), "utf8");
  const scanKey = JSON.parse(base).scanKey as string;
  const summary = (revision: number) =>
    Buffer.from(base.replace('"revision": 1,', `"revision": ${revision},`));
  const withdrawal = (throughRevision: number, key = scanKey) =>
    Buffer.from(
      `${JSON.stringify({ format: "aih-scan-withdrawn/1", scanKey: key, throughRevision, at: "2026-11-02T10:00:00Z", reason: "TEST ONLY withdrawal" }, null, 2)}\n`,
    );
  const asB = { leaf: { subject: signerB.subject } } satisfies SignOptions;
  const cases: VectorCase[] = [];
  const add = (
    name: string,
    bytes: Uint8Array,
    bundle: unknown,
    expect: VectorCase["expect"],
    extra: Partial<VectorCase> = {},
  ) =>
    cases.push({
      name,
      summary: b64(bytes),
      bundle,
      root: "universe",
      signers: [A, B],
      expect,
      ...extra,
    });
  const ok = (trusted: boolean, identity = A.identity, withdrawn = false) => ({
    status: "ok",
    verified: true,
    trusted,
    withdrawn,
    identity,
  });
  const refused = (reason: string) => ({ status: "refused", reason, verified: false });
  const r1 = summary(1);
  const sign = (bytes: Uint8Array, options?: SignOptions) => signedBundle(world, bytes, options);

  // Valid evidence in each supported log/time form.
  add("valid-rekor-v1-set", r1, sign(r1), ok(true));
  add("valid-rekor-v2-ed25519-rfc3161", r1, sign(r1, { rekor: "v2" }), ok(true));
  add("valid-rekor-v1-set-and-rfc3161", r1, sign(r1, { rekor: "v1+tsa" }), ok(true));
  add(
    "valid-signing-before-leaf-expiry",
    r1,
    sign(r1, { log: { integratedTime: LEAF_NOT_AFTER } }),
    ok(true),
  );
  add(
    "valid-signing-at-leaf-not-before",
    r1,
    sign(r1, { log: { integratedTime: LEAF_NOT_BEFORE } }),
    ok(true),
  );
  // Caller-selected signer trust.
  add("valid-unlisted-signer", r1, sign(r1), ok(false, signerA.subject), { signers: [B] });
  add("valid-default-signers-do-not-list-test-signer", r1, sign(r1), ok(false, signerA.subject), {
    signers: undefined,
  });
  add("valid-empty-signer-list", r1, sign(r1), ok(false, signerA.subject), { signers: [] });
  add("valid-signer-extension-matches", r1, sign(r1), ok(true), {
    signers: [{ ...A, extensions: { [REPOSITORY_OID]: "TEST-ONLY-1" } }],
  });
  add("valid-signer-extension-differs", r1, sign(r1), ok(false, signerA.subject), {
    signers: [{ ...A, extensions: { [REPOSITORY_OID]: "TEST-ONLY-2" } }],
  });
  add(
    "valid-other-issuer-same-subject",
    r1,
    sign(r1, { leaf: { issuer: "https://other-issuer.test.invalid" } }),
    ok(false, signerA.subject),
  );
  // Exact bytes.
  add(
    "tampered-summary-bytes",
    Buffer.concat([r1, Buffer.from("\n")]),
    sign(r1),
    refused("invalid-signature"),
  );
  {
    const bundle = sign(r1);
    const changed = summary(2);
    bundle.messageSignature.messageDigest.digest = b64(
      createHash("sha256").update(changed).digest(),
    );
    add(
      "tampered-summary-with-matching-digest-claim",
      changed,
      bundle,
      refused("invalid-signature"),
    );
  }
  // Trust material.
  add("unknown-root", r1, sign(r1), refused("invalid-signature"), { root: "stranger" });
  add("shipped-public-root-does-not-anchor-test-ca", r1, sign(r1), refused("invalid-signature"), {
    root: "shipped",
  });
  add(
    "leaf-from-unselected-ca",
    r1,
    sign(r1, { leaf: { ca: world.keys.otherCa } }),
    refused("invalid-signature"),
  );
  {
    const bundle = sign(r1) as Record<string, any>;
    bundle.verificationMaterial.x509CertificateChain = {
      certificates: [
        bundle.verificationMaterial.certificate,
        { rawBytes: b64(world.otherCaCertificate) },
      ],
    };
    delete bundle.verificationMaterial.certificate;
    add("bundle-supplied-chain-is-not-an-anchor", r1, bundle, refused("unsupported-profile"));
  }
  add("ca-not-valid-at-signing-time", r1, sign(r1), refused("invalid-signature"), {
    root: "ca-later",
  });
  add("wrong-ct-log-key", r1, sign(r1), refused("invalid-signature"), { root: "wrong-ct" });
  add(
    "sct-signed-by-other-key",
    r1,
    sign(r1, { leaf: { sctKey: p256().privateKey } }),
    refused("invalid-signature"),
  );
  add("sct-missing", r1, sign(r1, { leaf: { noSct: true } }), refused("invalid-signature"));
  add("wrong-rekor-key", r1, sign(r1), refused("invalid-signature"), { root: "wrong-rekor" });
  add(
    "leaf-without-code-signing",
    r1,
    sign(r1, { leaf: { codeSigning: false } }),
    refused("invalid-signature"),
  );
  // Log proofs and bindings.
  add(
    "broken-inclusion-proof",
    r1,
    sign(r1, { log: { badProof: true } }),
    refused("invalid-signature"),
  );
  add(
    "checkpoint-signed-by-other-key",
    r1,
    sign(r1, { log: { badCheckpoint: true } }),
    refused("invalid-signature"),
  );
  add(
    "rekor-v2-checkpoint-signed-by-other-key",
    r1,
    sign(r1, { rekor: "v2", log: { badCheckpoint: true } }),
    refused("invalid-signature"),
  );
  add(
    "missing-inclusion-proof",
    r1,
    sign(r1, { log: { noProof: true } }),
    refused("invalid-signature"),
  );
  add("set-over-other-body", r1, sign(r1, { log: { badSet: true } }), refused("invalid-signature"));
  add(
    "log-body-other-digest",
    r1,
    sign(r1, { body: "other-digest" }),
    refused("invalid-signature"),
  );
  add(
    "log-body-other-certificate",
    r1,
    sign(r1, { body: "other-certificate" }),
    refused("invalid-signature"),
  );
  add(
    "log-body-other-signature",
    r1,
    sign(r1, { body: "other-signature" }),
    refused("invalid-signature"),
  );
  add(
    "rekor-v2-body-other-digest",
    r1,
    sign(r1, { rekor: "v2", body: "other-digest" }),
    refused("invalid-signature"),
  );
  {
    const bundle = sign(r1) as Record<string, any>;
    bundle.verificationMaterial.tlogEntries = [];
    add("no-log-entry", r1, bundle, refused("invalid-signature"));
  }
  // Signing time.
  add(
    "signing-after-leaf-expiry",
    r1,
    sign(r1, { log: { integratedTime: LEAF_NOT_AFTER + 1000 } }),
    refused("invalid-signature"),
  );
  add(
    "signing-before-leaf-validity",
    r1,
    sign(r1, { log: { integratedTime: LEAF_NOT_BEFORE - 1000 } }),
    refused("invalid-signature"),
  );
  add(
    "rekor-v1-without-set-or-timestamp",
    r1,
    sign(r1, { log: { noSet: true } }),
    refused("invalid-signature"),
  );
  add(
    "rfc3161-wrong-imprint",
    r1,
    sign(r1, { rekor: "v2", timestampFor: "other-data" }),
    refused("invalid-signature"),
  );
  add(
    "rfc3161-after-leaf-expiry",
    r1,
    sign(r1, { rekor: "v2", genTime: LEAF_NOT_AFTER + 1000 }),
    refused("invalid-signature"),
  );
  add("rfc3161-tsa-not-selected", r1, sign(r1, { rekor: "v2" }), refused("invalid-signature"), {
    root: "no-tsa",
  });
  // Unsupported evidence.
  {
    const bundle = sign(r1) as Record<string, any>;
    bundle.dsseEnvelope = {
      payloadType: "application/vnd.in-toto+json",
      payload: b64(r1),
      signatures: [{ sig: bundle.messageSignature.signature }],
    };
    delete bundle.messageSignature;
    add("dsse-bundle", r1, bundle, refused("unsupported-profile"));
  }
  {
    const bundle = sign(r1) as Record<string, any>;
    bundle.verificationMaterial.publicKey = { hint: "TEST-ONLY" };
    delete bundle.verificationMaterial.certificate;
    add("bare-public-key-bundle", r1, bundle, refused("unsupported-profile"));
  }
  for (const [version, mediaType] of [
    ["v0.1", "application/vnd.dev.sigstore.bundle+json;version=0.1"],
    ["v0.2", "application/vnd.dev.sigstore.bundle+json;version=0.2"],
    ["v0.4", "application/vnd.dev.sigstore.bundle.v0.4+json"],
  ]) {
    const bundle = sign(r1) as Record<string, any>;
    bundle.mediaType = mediaType;
    add(`unsupported-bundle-version-${version}`, r1, bundle, {
      status: "unsupported-version",
      verified: false,
    });
  }
  {
    const bundle = sign(r1) as Record<string, any>;
    bundle.messageSignature.messageDigest.algorithm = "SHA2_384";
    add("unsupported-digest-algorithm", r1, bundle, refused("unsupported-algorithm"));
  }
  add(
    "unsupported-p384-signing-key",
    r1,
    sign(r1, { key: p384() }),
    refused("unsupported-algorithm"),
  );
  cases.push({
    name: "malformed-bundle-bytes",
    summary: b64(r1),
    bundleBytes: b64(Buffer.from("{")),
    root: "universe",
    signers: [A],
    expect: { status: "invalid", reason: "bundle", verified: false },
  });
  add(
    "malformed-trusted-root",
    r1,
    sign(r1),
    { status: "invalid", reason: "trusted-root", verified: false },
    { root: "malformed" },
  );
  add(
    "malformed-trusted-root-certificate",
    r1,
    sign(r1),
    { status: "invalid", reason: "trusted-root", verified: false },
    { root: "bad-certificate" },
  );
  add("trust-without-certificate-authorities", r1, sign(r1), refused("trust-data-unavailable"), {
    root: "empty",
  });
  add("no-trust-selected", r1, sign(r1), refused("trust-data-unavailable"), { root: "none" });
  add("unreadable-summary", Buffer.from("{"), sign(r1), { status: "invalid", verified: false });

  // Withdrawals: same key, same signer, revisions 1..throughRevision.
  const r3 = summary(3);
  const r4 = summary(4);
  const w = (through: number, options?: SignOptions, key?: string) => {
    const bytes = withdrawal(through, key);
    return { bytes: b64(bytes), bundle: sign(bytes, options) };
  };
  add("withdrawn-at-boundary-revision", r3, sign(r3), ok(false, A.identity, true), {
    withdrawn: [w(3)],
  });
  add("withdrawn-earlier-revision", r1, sign(r1), ok(false, A.identity, true), {
    withdrawn: [w(3)],
  });
  add("not-withdrawn-revision-above-through", r3, sign(r3), ok(true), { withdrawn: [w(2)] });
  add("later-revision-stays-valid", r4, sign(r4), ok(true), { withdrawn: [w(3)] });
  add("later-additional-withdrawal", r4, sign(r4), ok(false, A.identity, true), {
    withdrawn: [w(3), w(4)],
  });
  add("withdrawal-by-other-signer-ignored", r1, sign(r1), ok(true), { withdrawn: [w(5, asB)] });
  add("withdrawal-for-other-key-ignored", r1, sign(r1), ok(true), {
    withdrawn: [w(5, undefined, "git-sha1:0000000000000000000000000000000000000000")],
  });
  {
    const valid = w(5);
    const tampered = Buffer.from(valid.bytes, "base64")
      .toString("utf8")
      .replace('"throughRevision": 5', '"throughRevision": 6');
    add("tampered-withdrawal-ignored", r1, sign(r1), ok(true), {
      withdrawn: [{ bytes: b64(Buffer.from(tampered)), bundle: valid.bundle }],
    });
  }
  add("withdrawal-under-unselected-root-ignored", r1, sign(r1), ok(true), {
    withdrawn: [{ bytes: b64(withdrawal(5)), bundle: signedBundle(stranger, withdrawal(5)) }],
  });
  add("other-signer-revision-unaffected", r1, sign(r1, asB), ok(true, B.identity), {
    withdrawn: [w(5)],
  });
  add("withdrawn-unlisted-signer-is-untrusted", r1, sign(r1), ok(false, signerA.subject, true), {
    signers: [B],
    withdrawn: [w(1)],
  });

  const root = world.trustedRoot();
  const malformed = { ...root, mediaType: "application/json" };
  const badCertificate = world.trustedRoot({
    cas: [
      {
        uri: "https://fulcio.test.invalid",
        certChain: { certificates: [{ rawBytes: b64(Buffer.from("not a certificate")) }] },
        validFor: { start: "2020-01-01T00:00:00Z" },
      },
    ],
  });
  return {
    note: "TEST ONLY synthetic Sigstore universe; never production trust. Generated by tests/support/sigstore-v1-vectors.ts.",
    content: "clean",
    roots: {
      universe: root,
      stranger: stranger.trustedRoot(),
      "ca-later": world.trustedRoot({ caValidFor: { start: "2026-01-01T00:00:00Z" } }),
      "wrong-ct": world.trustedRoot({ ctKey: p256().publicKey }),
      "wrong-rekor": world.trustedRoot({ rekorKey: p256().publicKey }),
      "no-tsa": world.trustedRoot({ noTsa: true }),
      malformed,
      "bad-certificate": badCertificate,
      empty: world.trustedRoot({ cas: [] }),
    },
    cases,
  };
}
