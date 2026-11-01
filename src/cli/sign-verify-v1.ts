import { closeSync, lstatSync, openSync, readFileSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import { limits } from "../contracts/limits.js";
import { sanitizeText } from "../contracts/text.js";
import type { AllowedSigner } from "../contracts/verification.js";
import {
  DEFAULT_FULCIO_URL,
  DEFAULT_REKOR_URL,
  identityToken,
  SigningError,
  signDocument,
} from "../host/sign.js";
import { parseTrustedRoot, TrustProblem } from "../read/sigstore/trust.js";
import { verifySummary } from "../read/verify-summary.js";
import { type CommandIo, exitCodes, parse, single, UsageError } from "./commands-v1.js";

/** Seams for `sign`: the network client and environment (tests never reach live services). */
export interface SigningIo extends CommandIo {
  readonly fetch?: typeof fetch;
  readonly env?: Readonly<Record<string, string | undefined>>;
}

export const signUsage = `${[
  "Usage: aih-scan sign <summary.json | withdrawn.json> [--bundle <new-file>] [--trusted-root <file>]",
  "                     [--fulcio-url <url>] [--rekor-url <url>] [--json]",
  "",
  "Signs the exact bytes with your own identity using Sigstore keyless signing: an ephemeral",
  "P-256 key, a Fulcio certificate for your OIDC token and a Rekor transparency-log entry. The",
  "token comes from SIGSTORE_ID_TOKEN, or from GitHub Actions (id-token: write). The signature,",
  "your certificate identity and the log entry are public. Writes a Sigstore v0.3 bundle",
  "(default: the document path with .sigstore instead of .json) after verifying it offline",
  "against the shipped trust snapshot or --trusted-root.",
].join("\n")}\n`;

export const verifyUsage = `${[
  "Usage: aih-scan verify <summary.json> --bundle <file> [--signers <file>] [--trusted-root <file>]",
  "                       [--withdrawn <file> --withdrawn-bundle <file>]... [--json]",
  "",
  "Verifies offline (aih-sigstore-keyless/1). --signers is a JSON array of",
  "{ identity, issuer, subject, extensions? }; default: the documented Scan publishing workflow.",
  "--trusted-root replaces the shipped Sigstore trust snapshot. Withdrawals apply only to the",
  "same scan key and signer and revisions up to their throughRevision.",
  "",
  "Exit: 0 verified (trusted or not), 2 not verified or bad input.",
].join("\n")}\n`;

/** Summaries and withdrawals are held to the summary limit; bundles and roots to the bundle limit. */
function readFile(path: string, label: string, maximum: number): Uint8Array {
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch {
    throw new UsageError(`${label} could not be read`);
  }
  if (!stat.isFile()) throw new UsageError(`${label} is not a regular file`);
  if (stat.size > maximum) throw new UsageError(`${label} exceeds the size limit`);
  return new Uint8Array(readFileSync(path));
}

function readJson(path: string, label: string): unknown {
  try {
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        readFile(path, label, limits.output.bundleBytes),
      ),
    );
  } catch (error) {
    if (error instanceof UsageError) throw error;
    throw new UsageError(`${label} is not JSON`);
  }
}

function writeNew(path: string, bytes: Uint8Array): void {
  let descriptor: number;
  try {
    descriptor = openSync(path, "wx", 0o644);
  } catch {
    throw new UsageError("the bundle file already exists or cannot be created");
  }
  try {
    writeSync(descriptor, bytes);
  } finally {
    closeSync(descriptor);
  }
}

const httpsUrl = (value: string | undefined, fallback: string, name: string) => {
  const url = value ?? fallback;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new Error();
  } catch {
    throw new UsageError(`${name} must be an https URL without credentials`);
  }
  return url;
};

/** `aih-scan sign <document>`: signs a summary or withdrawal with the caller's own identity. */
export async function runSignCommand(args: readonly string[], io: SigningIo): Promise<number> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    io.stdout(signUsage);
    return exitCodes.ok;
  }
  try {
    const parsed = parse(
      args,
      ["--bundle", "--trusted-root", "--fulcio-url", "--rekor-url"],
      ["--json"],
    );
    if (parsed.positional.length !== 1) throw new UsageError("name one summary or withdrawal file");
    const cwd = io.cwd ?? process.cwd();
    const documentPath = resolve(cwd, parsed.positional[0] as string);
    const bundlePath = resolve(
      cwd,
      single(parsed, "--bundle") ?? `${documentPath.replace(/\.json$/i, "")}.sigstore`,
    );
    const bytes = readFile(documentPath, "the document", limits.output.summaryBytes);
    const rootPath = single(parsed, "--trusted-root");
    let trust: ReturnType<typeof parseTrustedRoot> | undefined;
    if (rootPath !== undefined) {
      try {
        trust = parseTrustedRoot(readJson(resolve(cwd, rootPath), "the trusted root"));
      } catch (error) {
        if (error instanceof TrustProblem)
          throw new UsageError(`the trusted root: ${error.message}`);
        throw error;
      }
    }
    const fetcher = io.fetch ?? globalThis.fetch;
    const services = {
      fulcioUrl: httpsUrl(single(parsed, "--fulcio-url"), DEFAULT_FULCIO_URL, "--fulcio-url"),
      rekorUrl: httpsUrl(single(parsed, "--rekor-url"), DEFAULT_REKOR_URL, "--rekor-url"),
      fetch: fetcher,
    };
    try {
      lstatSync(bundlePath);
      throw new UsageError("the bundle file already exists");
    } catch (error) {
      if (error instanceof UsageError) throw error;
    }
    const token = await identityToken(io.env ?? process.env, fetcher);
    if (token === undefined)
      throw new SigningError(
        "no identity token: set SIGSTORE_ID_TOKEN to an OIDC token for audience sigstore, or run in GitHub Actions with id-token: write",
      );
    const signed = await signDocument(bytes, token, services, trust);
    const output = new TextEncoder().encode(`${JSON.stringify(signed.bundle)}\n`);
    writeNew(bundlePath, output);
    if (parsed.flags.has("--json"))
      io.stdout(
        `${JSON.stringify({ status: "ok", bundle: bundlePath, issuer: signed.issuer, subject: signed.subject })}\n`,
      );
    else
      io.stdout(
        `Signed ${sanitizeText(documentPath, 1024)}\n  bundle ${sanitizeText(bundlePath, 1024)}\n  signer ${sanitizeText(signed.subject, 512)} (${sanitizeText(signed.issuer, 256)})\n`,
      );
    return exitCodes.ok;
  } catch (error) {
    if (error instanceof SigningError) {
      io.stderr(`aih-scan: ${sanitizeText(error.message, 500)}\n`);
      return exitCodes.input;
    }
    io.stderr(
      `aih-scan: ${error instanceof UsageError ? sanitizeText(error.message, 500) : "the document could not be signed"}\n${signUsage}`,
    );
    return exitCodes.input;
  }
}

/** `aih-scan verify <summary.json> --bundle <file>`: offline verification and withdrawals. */
export async function runVerifyCommand(args: readonly string[], io: CommandIo): Promise<number> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    io.stdout(verifyUsage);
    return exitCodes.ok;
  }
  try {
    const parsed = parse(
      args,
      ["--bundle", "--signers", "--trusted-root", "--withdrawn", "--withdrawn-bundle"],
      ["--json"],
    );
    if (parsed.positional.length !== 1) throw new UsageError("name one summary file");
    const cwd = io.cwd ?? process.cwd();
    const bundlePath = single(parsed, "--bundle");
    if (bundlePath === undefined) throw new UsageError("--bundle is required");
    const summary = readFile(
      resolve(cwd, parsed.positional[0] as string),
      "the summary",
      limits.output.summaryBytes,
    );
    const bundle = readFile(resolve(cwd, bundlePath), "the bundle", limits.output.bundleBytes);
    const signersPath = single(parsed, "--signers");
    const signers =
      signersPath === undefined
        ? undefined
        : (readJson(resolve(cwd, signersPath), "the signers file") as AllowedSigner[]);
    const rootPath = single(parsed, "--trusted-root");
    const withdrawn = (parsed.values.get("--withdrawn") ?? []).map((path) =>
      readFile(resolve(cwd, path), "a withdrawal", limits.output.summaryBytes),
    );
    const withdrawnBundle = (parsed.values.get("--withdrawn-bundle") ?? []).map((path) =>
      readFile(resolve(cwd, path), "a withdrawal bundle", limits.output.bundleBytes),
    );
    if (withdrawn.length !== withdrawnBundle.length)
      throw new UsageError("give each --withdrawn its --withdrawn-bundle");
    const result = await verifySummary(summary, bundle, signers, {
      ...(rootPath === undefined
        ? {}
        : {
            trustedRoot: readFile(
              resolve(cwd, rootPath),
              "the trusted root",
              limits.output.bundleBytes,
            ),
          }),
      withdrawn,
      withdrawnBundle,
    });
    if (parsed.flags.has("--json")) {
      const { summary: _summary, ...rest } = result;
      io.stdout(
        `${JSON.stringify({ ...rest, scanKey: result.summary?.scanKey ?? null, revision: result.summary?.revision ?? null }, null, 2)}\n`,
      );
    } else if (result.status === "ok") {
      const who = `${sanitizeText(result.signer.subject, 512)} (${sanitizeText(result.signer.issuer, 256)})`;
      const lines = [
        result.withdrawn
          ? `Withdrawn: signed by ${who}, but its signer withdrew revision ${result.summary.revision}; not trusted`
          : result.signer.trusted
            ? `Verified: signed by trusted publisher ${sanitizeText(result.signer.identity, 256)}`
            : "Verified: signed, not by a trusted publisher",
        `  signer ${who}`,
        `  ${result.summary.scanKey} revision ${result.summary.revision}; signed at ${result.signedAt.join(", ")}`,
        ...result.withdrawals.map(
          (outcome, index) =>
            `  withdrawal ${index + 1}: ${outcome.status}${outcome.reason ? ` (${outcome.reason})` : ""}${outcome.throughRevision ? ` through revision ${outcome.throughRevision}` : ""}`,
        ),
      ];
      io.stdout(`${lines.join("\n")}\n`);
    } else
      io.stdout(
        `Not verified: ${result.status} ${result.reason}${result.detail ? `: ${sanitizeText(result.detail, 300)}` : ""}\n`,
      );
    return result.status === "ok" ? exitCodes.ok : exitCodes.input;
  } catch (error) {
    io.stderr(
      `aih-scan: ${error instanceof UsageError ? sanitizeText(error.message, 500) : "the summary could not be verified"}\n${verifyUsage}`,
    );
    return exitCodes.input;
  }
}
