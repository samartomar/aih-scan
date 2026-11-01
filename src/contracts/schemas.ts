import { formats } from "./formats.js";
import { limits } from "./limits.js";
import { kinds, optionalTools } from "./routing.js";

/**
 * JSON Schemas (draft-07) of the replacement formats. The validators in this entry
 * (`validateRequest`, `validateSource`, `validateSummary`, `validateWithdrawn`) apply these
 * shapes plus the cross-field rules a schema cannot express (exactly-one-of source/items,
 * label consistency, notAnalysed/files agreement, path safety).
 */
const id = (name: string) => `https://github.com/samartomar/aih-scan/schemas/${name}.json`;
const relativePath = {
  type: "string",
  minLength: 1,
  maxLength: limits.input.pathLength * 2,
} as const;
const sha256 = { type: "string", pattern: "^[0-9a-f]{64}$" } as const;
const scanKey = {
  type: "string",
  pattern: "^git-(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$",
} as const;
const timestamp = {
  type: "string",
  pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$",
} as const;
const kind = { enum: [...kinds] } as const;

const source = {
  $id: id("aih-scan-source-1"),
  $schema: "http://json-schema.org/draft-07/schema#",
  title: formats.source,
  oneOf: [
    {
      type: "object",
      additionalProperties: false,
      required: ["type", "path"],
      properties: {
        format: { const: formats.source },
        type: { const: "folder" },
        path: { type: "string", minLength: 1 },
      },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["type", "repo"],
      properties: {
        format: { const: formats.source },
        type: { const: "git" },
        repo: { type: "string", pattern: "^https://" },
        ref: { type: "string", minLength: 1, maxLength: 255 },
        path: relativePath,
        kind,
      },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["type", "package", "version"],
      properties: {
        format: { const: formats.source },
        type: { const: "npm" },
        package: { type: "string", minLength: 1, maxLength: 214 },
        version: { type: "string", minLength: 1 },
        kind: { const: "mcp" },
      },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["type", "path"],
      properties: {
        format: { const: formats.source },
        type: { const: "npm-file" },
        path: { type: "string", minLength: 1 },
        kind: { const: "mcp" },
      },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["type", "url"],
      properties: {
        format: { const: formats.source },
        type: { const: "remote" },
        url: { type: "string", pattern: "^https?://" },
        kind: { const: "mcp" },
      },
    },
  ],
} as const;

const request = {
  $id: id("aih-scan-request-1"),
  $schema: "http://json-schema.org/draft-07/schema#",
  title: formats.request,
  type: "object",
  additionalProperties: false,
  required: ["format", "origin"],
  oneOf: [{ required: ["source"] }, { required: ["items"] }],
  properties: {
    format: { const: formats.request },
    source,
    items: {
      type: "array",
      minItems: 1,
      maxItems: limits.input.items,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path"],
        properties: {
          path: { type: "string", minLength: 1 },
          executable: { type: "array", uniqueItems: true, items: relativePath },
          label: { type: "string", minLength: 1, maxLength: limits.output.label * 2 },
        },
      },
    },
    origin: { enum: ["published", "local"] },
    kinds: { type: "array", minItems: 1, uniqueItems: true, items: kind },
    tools: { type: "array", uniqueItems: true, items: { enum: [...optionalTools] } },
    mode: { enum: ["static", "ai"] },
  },
} as const;

const summary = {
  $id: id("aih-scan-summary-1"),
  $schema: "http://json-schema.org/draft-07/schema#",
  title: formats.summary,
  type: "object",
  additionalProperties: false,
  required: [
    "format",
    "scanKey",
    "revision",
    "origin",
    "scannedAt",
    "scanner",
    "routing",
    "scoring",
    "score",
    "label",
    "coverage",
    "files",
    "tools",
    "notAnalysed",
    "sarif",
    "dependencies",
  ],
  properties: {
    format: { const: formats.summary },
    scanKey,
    revision: { type: "integer", minimum: 1 },
    origin: { enum: ["published", "local"] },
    scannedAt: timestamp,
    scanner: { type: "string", minLength: 1 },
    routing: { const: formats.routing },
    scoring: { const: formats.scoring },
    score: { type: "integer", minimum: 0, maximum: 100 },
    label: { enum: ["SAFE", "CAUTION", "DO NOT INSTALL", "NOT ASSESSED"] },
    coverage: { enum: ["complete", "partial"] },
    reason: { type: "string", minLength: 1 },
    files: {
      type: "array",
      maxItems: limits.input.files,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path", "mode", "part", "sha256"],
        properties: {
          path: relativePath,
          mode: { enum: ["100644", "100755"] },
          part: { enum: ["config", "dependencies", "code", "text", "none"] },
          sha256,
        },
      },
    },
    tools: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["tool", "version", "mode", "result", "counts"],
        properties: {
          tool: { type: "string", minLength: 1 },
          version: { type: "string", minLength: 1 },
          mode: { enum: ["static", "ai"] },
          ai: {
            type: "object",
            additionalProperties: false,
            required: ["via", "provider", "model"],
            properties: {
              via: { enum: ["cli", "local", "provider"] },
              provider: { type: "string", minLength: 1 },
              model: { type: "string", minLength: 1 },
            },
          },
          result: { enum: ["pass", "warn", "fail", "not-run", "not-applicable"] },
          reason: { type: "string", minLength: 1 },
          counts: {
            type: "object",
            additionalProperties: false,
            properties: Object.fromEntries(
              ["critical", "high", "medium", "low", "info"].map((key) => [
                key,
                { type: "integer", minimum: 1 },
              ]),
            ),
          },
          suppressed: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["count", "reason"],
              properties: {
                count: { type: "integer", minimum: 1 },
                reason: { type: "string", minLength: 1 },
              },
            },
          },
        },
      },
    },
    notAnalysed: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path", "secretsChecked"],
        properties: { path: relativePath, secretsChecked: { type: "boolean" } },
      },
    },
    sarif: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path", "sha256"],
        properties: { path: relativePath, sha256 },
      },
    },
    dependencies: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["ecosystem", "name", "version", "file"],
        properties: {
          ecosystem: { enum: ["npm", "pypi"] },
          name: { type: "string", minLength: 1 },
          version: { type: ["string", "null"] },
          file: relativePath,
        },
      },
    },
  },
} as const;

const withdrawn = {
  $id: id("aih-scan-withdrawn-1"),
  $schema: "http://json-schema.org/draft-07/schema#",
  title: formats.withdrawn,
  type: "object",
  additionalProperties: false,
  required: ["format", "scanKey", "throughRevision", "at", "reason"],
  properties: {
    format: { const: formats.withdrawn },
    scanKey,
    throughRevision: { type: "integer", minimum: 1 },
    at: timestamp,
    reason: { type: "string", minLength: 1 },
  },
} as const;

export const schemas = Object.freeze({ request, source, summary, withdrawn });
