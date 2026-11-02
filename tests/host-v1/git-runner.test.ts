import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GitContainmentError, runPinnedGit } from "../../src/host/git-runner.js";

/**
 * The hardened Git runner with real Git: the bounded process-tree runner starts the Git helper,
 * which runs `git` with argument arrays only, an allowlisted environment (no inherited GIT_*,
 * proxy or credential variables, a private HOME, no system or global configuration, no askpass,
 * no prompts) and an empty hooks directory. Only local repositories and a local HTTPS answerer
 * are used; nothing is fetched from a live service.
 */
const hasGit = spawnSync("git", ["--version"]).status === 0;
const hasOpenssl = spawnSync("openssl", ["version"]).status === 0;
const roots: string[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function stage() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-git-runner-"));
  roots.push(root);
  const hooks = join(root, "hooks");
  const work = join(root, "work");
  mkdirSync(hooks);
  mkdirSync(work);
  return { root, hooks, work };
}
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe.runIf(hasGit)("runPinnedGit (real Git)", () => {
  it("runs Git in the given folder with no inherited Git or proxy settings and empty hooks", async () => {
    const { root, hooks, work } = stage();
    const elsewhere = join(root, "elsewhere");
    mkdirSync(elsewhere);
    vi.stubEnv("GIT_DIR", join(elsewhere, ".git"));
    vi.stubEnv("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/tmp/attacker'");
    vi.stubEnv("HTTPS_PROXY", "http://attacker.invalid:9000");
    await runPinnedGit(["init", "--quiet", `--template=${hooks}`], work, {}, hooks);
    expect(existsSync(join(work, ".git"))).toBe(true);
    expect(existsSync(join(elsewhere, ".git"))).toBe(false);
    const config = text(await runPinnedGit(["config", "--list", "--show-origin"], work, {}, hooks));
    expect(config).toContain(`core.hookspath=${hooks}`);
    expect(config).toContain("protocol.allow=never");
    expect(config).toContain("http.followredirects=false");
    expect(config).toContain("http.sslverify=true");
    expect(config).not.toContain("attacker");
    expect(config).not.toMatch(/^file:\/(?!.*\.git\/config)/m);
  });

  it("never runs a repository's own hooks", async () => {
    const { root, hooks, work } = stage();
    await runPinnedGit(["init", "--quiet", `--template=${hooks}`], work, {}, hooks);
    const sentinel = join(root, "hook-ran");
    const own = join(work, ".git", "hooks");
    mkdirSync(own, { recursive: true });
    writeFileSync(join(own, "post-checkout"), `#!/bin/sh\ntouch ${sentinel}\n`, { mode: 0o755 });
    writeFileSync(join(work, "a.txt"), "a\n");
    execFileSync("git", ["-C", work, "add", "a.txt"], {
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    });
    await runPinnedGit(
      ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "x"],
      work,
      {},
      hooks,
    );
    await runPinnedGit(["checkout", "-q", "-b", "other"], work, {}, hooks);
    expect(existsSync(sentinel)).toBe(false);
  });

  it("bounds Git's output and fails closed on errors and cancellation", async () => {
    const { hooks, work } = stage();
    await runPinnedGit(["init", "--quiet", `--template=${hooks}`], work, {}, hooks);
    await expect(runPinnedGit(["config", "--list"], work, {}, hooks, 4)).rejects.toThrow(
      /gitStdoutBytes exceeds limit 4|maxStdoutBytes/,
    );
    await expect(runPinnedGit(["rev-parse", "HEAD"], work, {}, hooks)).rejects.toMatchObject({
      code: "git-acquisition-failed",
    });
    await expect(
      runPinnedGit(["config", "--list"], work, { signal: AbortSignal.abort() }, hooks),
    ).rejects.toThrow("cancelled");
    expect(new GitContainmentError().code).toBe("git-containment-failed");
  });
});

describe.runIf(hasGit && hasOpenssl)("runPinnedGit credentials (local HTTPS answerer)", () => {
  it("never sends the operator's .netrc or inherited secrets to a Git host that answers 401", async () => {
    // A local HTTPS "repository" answers 401 Basic and records any Authorization header. The
    // operator's HOME holds a fake .netrc with a matching machine entry and a default entry.
    const { root, hooks, work } = stage();
    execFileSync(
      "openssl",
      [
        ...["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"],
        ...["-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        ...["-keyout", join(root, "key.pem"), "-out", join(root, "cert.pem")],
      ],
      { stdio: "ignore" },
    );
    const seen: (string | null)[] = [];
    const server = createServer(
      { key: readFileSync(join(root, "key.pem")), cert: readFileSync(join(root, "cert.pem")) },
      (request, response) => {
        seen.push(request.headers.authorization ?? null);
        response.writeHead(401, { "WWW-Authenticate": 'Basic realm="fixture"' }).end();
      },
    );
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const home = join(root, "operator-home");
      mkdirSync(join(home, ".config", "git"), { recursive: true });
      writeFileSync(
        join(home, ".netrc"),
        "machine 127.0.0.1 login fixture-user password fixture-secret-NOT-REAL\n" +
          "default login any-user password any-secret-NOT-REAL\n",
        { mode: 0o600 },
      );
      writeFileSync(
        join(home, ".config", "git", "config"),
        "[http]\n\textraHeader = X-Leak: yes\n",
      );
      vi.stubEnv("HOME", home);
      vi.stubEnv("USERPROFILE", home);
      vi.stubEnv("XDG_CONFIG_HOME", join(home, ".config"));
      vi.stubEnv("NETRC", join(home, ".netrc"));
      vi.stubEnv("CURL_HOME", home);
      await runPinnedGit(["init", "--quiet", `--template=${hooks}`], work, {}, hooks);
      await expect(
        runPinnedGit(
          [
            ...["-c", `http.sslCAInfo=${join(root, "cert.pem")}`, "-c", "credential.helper="],
            ...["ls-remote", `https://127.0.0.1:${port}/owner/repo.git`, "HEAD"],
          ],
          work,
          {},
          hooks,
          1 << 20,
        ),
      ).rejects.toMatchObject({ code: "git-acquisition-failed" });
      expect(seen.length).toBeGreaterThan(0);
      expect(seen).toEqual(seen.map(() => null));
    } finally {
      server.close();
    }
  });
});
