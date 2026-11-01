import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import {
  codeForRule,
  codes,
  limits,
  schemas,
  validateRequest,
  validateSource,
  validateWithdrawn,
} from "../../src/public/contracts.js";
import { corpusCase } from "../support/scan-v1-corpus.js";

const compile = (schema: object) => new Ajv({ strict: false }).compile(schema);

describe("request and source validation", () => {
  const base = { format: "aih-scan-request/1", origin: "local" };

  it("accepts the documented request and descriptor shapes", () => {
    const requests = [
      {
        ...base,
        items: [
          {
            path: "stage/brainstorming",
            executable: ["scripts/start-server.sh"],
            label: "brainstorming",
          },
        ],
      },
      {
        format: "aih-scan-request/1",
        source: {
          format: "aih-scan-source/1",
          type: "git",
          repo: "https://github.com/obra/superpowers",
          ref: "5bf4e78011075bcfc0dc295f0724994cd123ee71",
        },
        origin: "published",
        kinds: ["hook", "skill", "rule"],
      },
      {
        ...base,
        source: {
          type: "npm",
          package: "@modelcontextprotocol/server-github",
          version: "2025.4.8",
          kind: "mcp",
        },
        tools: ["skillspector", "cisco"],
        mode: "ai",
      },
      { ...base, source: { type: "npm-file", path: "dl/server-internal-1.4.0.tgz", kind: "mcp" } },
      { ...base, source: { type: "remote", url: "https://mcp.example.com/sse", kind: "mcp" } },
      {
        ...base,
        source: {
          type: "git",
          repo: "https://github.com/o/r",
          ref: "main",
          path: "skills/brainstorming",
          kind: "skill",
        },
      },
      { ...base, source: { type: "folder", path: "C:\\work\\team-skills" } },
    ];
    const ajv = compile(schemas.request);
    for (const request of requests) {
      expect(validateRequest(request)).toMatchObject({ status: "ok" });
      expect(ajv(request)).toBe(true);
    }
  });

  it.each([
    [
      "both source and items",
      { ...base, items: [{ path: "a" }], source: { type: "folder", path: "a" } },
      "invalid",
    ],
    ["neither source nor items", { ...base }, "invalid"],
    ["an unknown kind", { ...base, items: [{ path: "a" }], kinds: ["widget"] }, "invalid"],
    ["an unknown tool", { ...base, items: [{ path: "a" }], tools: ["semgrep"] }, "invalid"],
    ["an unknown origin", { ...base, origin: "trusted", items: [{ path: "a" }] }, "invalid"],
    ["an unknown field", { ...base, items: [{ path: "a" }], catalogId: "x" }, "invalid"],
    [
      "another request version",
      { ...base, format: "aih-scan-request/2", items: [{ path: "a" }] },
      "unsupported-version",
    ],
    [
      "an escaping executable path",
      { ...base, items: [{ path: "a", executable: ["../x"] }] },
      "refused",
    ],
    ["a label with controls", { ...base, items: [{ path: "a", label: "a\u0007" }] }, "invalid"],
    [
      "an http Git repository",
      { ...base, source: { type: "git", repo: "http://github.com/o/r" } },
      "invalid",
    ],
    [
      "credentials in a URL",
      { ...base, source: { type: "git", repo: "https://u:p@github.com/o/r" } },
      "invalid",
    ],
    [
      "an npm range",
      { ...base, source: { type: "npm", package: "x", version: "^1.0.0" } },
      "invalid",
    ],
    [
      "a non-mcp npm kind",
      { ...base, source: { type: "npm", package: "x", version: "1.0.0", kind: "skill" } },
      "invalid",
    ],
    [
      "a malformed remote URL",
      { ...base, source: { type: "remote", url: "not a url" } },
      "invalid",
    ],
    [
      "an unpaired surrogate",
      { ...base, source: { type: "remote", url: "https://x/\uD800" } },
      "invalid",
    ],
  ])("returns a result for %s", (_name, request, status) => {
    expect(validateRequest(request).status).toBe(status);
  });

  it("validates descriptors on their own", () => {
    expect(validateSource({ type: "folder", path: "x" })).toMatchObject({
      status: "ok",
      source: { type: "folder", path: "x" },
    });
    expect(validateSource({ format: "aih-scan-source/7", type: "folder", path: "x" }).status).toBe(
      "unsupported-version",
    );
    expect(validateSource({ type: "ftp", path: "x" }).status).toBe("invalid");
  });

  it("refuses a git kind without a path in the validator and the schema alike", () => {
    const descriptor = { type: "git", repo: "https://github.com/o/r", kind: "skill" };
    expect(validateSource(descriptor)).toMatchObject({ status: "invalid", reason: "schema" });
    expect(validateRequest({ ...base, source: descriptor }).status).toBe("invalid");
    expect(compile(schemas.source)(descriptor)).toBe(false);
    expect(compile(schemas.request)({ ...base, source: descriptor })).toBe(false);
    const named = { ...descriptor, path: "skills/x" };
    expect(validateSource(named).status).toBe("ok");
    expect(compile(schemas.source)(named)).toBe(true);
  });
});

describe("summary and withdrawal schemas", () => {
  it("agree with the corpus summaries", () => {
    const ajv = compile(schemas.summary);
    for (const name of ["risky", "clean", "not-assessed"]) {
      const summary = JSON.parse(new TextDecoder().decode(corpusCase(name).summary));
      expect(ajv(summary), name).toBe(true);
    }
  });

  it("validates withdrawals", () => {
    const withdrawal = {
      format: "aih-scan-withdrawn/1",
      scanKey: "git-sha1:3d8a2369aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      throughRevision: 3,
      at: "2026-11-02T10:00:00Z",
      reason: "example reason",
    };
    expect(validateWithdrawn(withdrawal)).toMatchObject({ status: "ok", withdrawn: withdrawal });
    expect(compile(schemas.withdrawn)(withdrawal)).toBe(true);
    expect(validateWithdrawn({ ...withdrawal, throughRevision: 0 }).status).toBe("invalid");
    expect(validateWithdrawn({ ...withdrawal, format: "aih-scan-withdrawn/2" }).status).toBe(
      "unsupported-version",
    );
  });
});

describe("codes and limits", () => {
  it("maps every tool rule to one code and unmapped rules to trust.unmapped-rule", () => {
    expect(codeForRule("aih-trust-lint", "secrets.plaintext-detected")).toBe(
      "trust.plaintext-secret",
    );
    expect(codeForRule("aih-trust-lint", "mcp.config-invalid")).toBe("trust.unmapped-rule");
    expect(codeForRule("skillspector", "ZZ9")).toBe("trust.unmapped-rule");
    expect(codeForRule("aih-trust-lint", "__proto__")).toBe("trust.unmapped-rule");
    for (const table of Object.values(codes.tools))
      for (const code of Object.values(table)) expect(codes.scan).toContain(code);
    expect(codes.scan).not.toContain("trust.known-vulnerability");
  });

  it("maps SkillSpector rule ids and Cisco categories, never to an advisory code", () => {
    expect(codeForRule("skillspector", "P1")).toBe("trust.prompt-injection");
    expect(codeForRule("skillspector", "SC2")).toBe("trust.malicious-code");
    expect(codeForRule("skillspector", "SC1")).toBe("trust.unpinned-dependency");
    expect(codeForRule("skillspector", "TP1")).toBe("trust.mcp-tool-poisoning");
    expect(codeForRule("skillspector", "SC4")).toBe("trust.unmapped-rule");
    // A rule id wins over a category; a category decides only open-ended rule ids.
    expect(codeForRule("cisco", "YARA_prompt_injection_generic", "prompt_injection")).toBe(
      "trust.prompt-injection",
    );
    expect(codeForRule("cisco", "ANY_RULE", "hardcoded_secrets")).toBe("trust.plaintext-secret");
    expect(codeForRule("cisco", "ANY_RULE", "policy_violation")).toBe("trust.unmapped-rule");
    expect(codeForRule("cisco", "ANY_RULE", "__proto__")).toBe("trust.unmapped-rule");
    expect(codeForRule("skillspector", "P1", "prompt_injection")).toBe("trust.prompt-injection");
    for (const table of Object.values(codes.categories))
      for (const code of Object.values(table)) expect(codes.scan).toContain(code);
  });

  it("publishes the agreed input limits and concrete output bounds", () => {
    expect(limits.input).toEqual({
      sourceBytes: 500 * 1024 * 1024,
      files: 50_000,
      fileBytes: 50 * 1024 * 1024,
      pathLength: 1024,
      depth: 64,
      items: 20_000,
    });
    expect(limits.tool.timeoutMs).toBe(600_000);
    expect(limits.output).toMatchObject({ findingText: 500, findingPath: 1024 });
  });
});
