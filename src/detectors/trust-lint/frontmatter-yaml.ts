/**
 * Minimal YAML parser for trust frontmatter, replacing Core's `yaml` package
 * dependency (`yaml` is not a Scan dependency). It accepts exactly the
 * frontmatter shapes the trust manifest checks consume:
 *
 * - a top-level block mapping with plain keys;
 * - scalar values: plain, single/double-quoted, `true`/`false`/`null`/`~`,
 *   integers and decimals;
 * - flow sequences/maps on one line (`[Read, Bash(*)]`, `{a: 1}`);
 * - block sequences (`- item`) and one-level nested block maps;
 * - literal/folded block scalars (`|`, `>`, with `-`/`+` chomping);
 * - comments and blank lines.
 *
 * Anything outside that subset — anchors, aliases, tags, directives, document
 * markers, multi-line flow collections, deeper nesting, tabs in indentation,
 * duplicate keys — throws, so the caller fails closed with the same
 * "unparseable YAML frontmatter" finding Core emits for YAML errors (including
 * unresolved aliases and alias-expansion bombs, which Core's `yaml` rejects).
 * A whole-document non-mapping scalar parses to a string so callers see
 * Core's `doc.toJS()` "not a record" outcome instead of a parse failure.
 */

export class FrontmatterYamlErrorV1 extends TypeError {
  constructor(message: string) {
    super(`trust-lint frontmatter YAML: ${message}`);
    this.name = "FrontmatterYamlErrorV1";
  }
}

function fail(message: string): never {
  throw new FrontmatterYamlErrorV1(message);
}

const KEY_PATTERN = /^[A-Za-z0-9_.-]+$/;

interface Line {
  indent: number;
  text: string;
}

function toLines(source: string): Line[] {
  return source.split("\n").map((raw) => {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    const indent = line.length - line.trimStart().length;
    if (line.slice(0, indent).includes("\t")) fail("tab in indentation");
    return { indent, text: line.trimStart() };
  });
}

function stripComment(text: string): string {
  // A `#` starts a comment only at the start or after whitespace.
  for (let index = 0; index < text.length; index++) {
    if (text[index] === "#" && (index === 0 || /\s/.test(text[index - 1] ?? ""))) {
      return text.slice(0, index).trimEnd();
    }
  }
  return text;
}

function expectNothingAfter(rest: string, what: string): void {
  if (stripComment(rest.trimStart()).length > 0) fail(`trailing content after ${what}`);
}

function parseSingleQuoted(text: string): string {
  let value = "";
  let index = 1;
  for (;;) {
    const ch = text[index];
    if (ch === undefined) fail("unterminated single-quoted scalar");
    if (ch === "'") {
      if (text[index + 1] === "'") {
        value += "'";
        index += 2;
        continue;
      }
      expectNothingAfter(text.slice(index + 1), "single-quoted scalar");
      return value;
    }
    value += ch;
    index++;
  }
}

function parseDoubleQuoted(text: string): string {
  let value = "";
  let index = 1;
  for (;;) {
    const ch = text[index];
    if (ch === undefined) fail("unterminated double-quoted scalar");
    if (ch === '"') {
      expectNothingAfter(text.slice(index + 1), "double-quoted scalar");
      return value;
    }
    if (ch === "\\") {
      const escaped = text[index + 1];
      if (escaped === undefined) fail("unterminated escape in double-quoted scalar");
      if (escaped === "x" || escaped === "u" || escaped === "U") {
        const length = escaped === "x" ? 2 : escaped === "u" ? 4 : 8;
        const hex = text.slice(index + 2, index + 2 + length);
        if (hex.length !== length || !/^[0-9A-Fa-f]+$/.test(hex)) fail("invalid unicode escape");
        value += String.fromCodePoint(Number.parseInt(hex, 16));
        index += 2 + length;
        continue;
      }
      const simple: Record<string, number> = {
        "0": 0x00,
        a: 0x07,
        b: 0x08,
        t: 0x09,
        n: 0x0a,
        v: 0x0b,
        f: 0x0c,
        r: 0x0d,
        e: 0x1b,
        '"': 0x22,
        "/": 0x2f,
        "\\": 0x5c,
        _: 0xa0,
        N: 0x85,
        L: 0x2028,
        P: 0x2029,
      };
      const mapped = simple[escaped];
      if (mapped === undefined) fail(`unsupported escape \\${escaped}`);
      value += String.fromCodePoint(mapped);
      index += 2;
      continue;
    }
    value += ch;
    index++;
  }
}

function parsePlainScalar(text: string): unknown {
  const value = stripComment(text).trim();
  if (value.length === 0) return null;
  const first = value[0] as string;
  if ("&*!|>@`%".includes(first)) fail(`unsupported indicator ${first}`);
  if (/:($|\s)/.test(value)) fail("mapping shape inside plain scalar");
  if (value === "null" || value === "~") return null;
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^[-+]?\d+$/.test(value)) return Number.parseInt(value, 10);
  if (/^[-+]?(?:\d+\.\d*|\.\d+)$/.test(value)) return Number.parseFloat(value);
  return value;
}

function splitFlowItems(inner: string): string[] {
  const items: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < inner.length; index++) {
    const ch = inner[index] as string;
    if (quote === "'") {
      current += ch;
      if (ch === "'") {
        if (inner[index + 1] === "'") {
          current += "'";
          index++;
        } else {
          quote = undefined;
        }
      }
      continue;
    }
    if (quote === '"') {
      current += ch;
      if (ch === "\\") {
        const next = inner[index + 1];
        if (next === undefined) fail("unterminated escape in flow scalar");
        current += next;
        index++;
      } else if (ch === '"') {
        quote = undefined;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "[" || ch === "]" || ch === "{" || ch === "}") fail("nested flow collection");
    if (ch === ",") {
      items.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (quote !== undefined) fail("unterminated quoted scalar in flow collection");
  items.push(current);
  return items;
}

function parseFlowScalar(item: string): unknown {
  const trimmed = item.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.startsWith("'")) {
    const value = parseSingleQuoted(trimmed);
    return value;
  }
  if (trimmed.startsWith('"')) return parseDoubleQuoted(trimmed);
  return parsePlainScalar(trimmed);
}

function parseFlowSequence(text: string): unknown[] {
  const stripped = stripComment(text);
  if (!stripped.endsWith("]")) fail("unterminated flow sequence");
  const body = stripped.slice(1, -1).trim();
  if (body.length === 0) return [];
  return splitFlowItems(body).map(parseFlowScalar);
}

function parseFlowMap(text: string): Record<string, unknown> {
  const stripped = stripComment(text);
  if (!stripped.endsWith("}")) fail("unterminated flow map");
  const body = stripped.slice(1, -1).trim();
  const out: Record<string, unknown> = {};
  if (body.length === 0) return out;
  for (const item of splitFlowItems(body)) {
    const match = /^([^:]+?)\s*:\s*([\s\S]*)$/.exec(item);
    if (match === null) fail("flow map entry without a colon");
    const key = parseFlowScalar(match[1] as string);
    if (typeof key !== "string") fail("flow map key must be a string");
    if (Object.hasOwn(out, key)) fail(`duplicate key ${JSON.stringify(key)}`);
    out[key] = parseFlowScalar(match[2] as string);
  }
  return out;
}

function parseInlineValue(text: string): unknown {
  if (text.startsWith("[")) return parseFlowSequence(text);
  if (text.startsWith("{")) return parseFlowMap(text);
  if (text.startsWith("'")) return parseSingleQuoted(text);
  if (text.startsWith('"')) return parseDoubleQuoted(text);
  return parsePlainScalar(text);
}

function childLines(lines: Line[], start: number, parentIndent: number): [Line[], number] {
  const collected: Line[] = [];
  let index = start;
  while (index < lines.length) {
    const line = lines[index] as Line;
    if (line.text.length > 0 && line.indent <= parentIndent) break;
    collected.push(line);
    index++;
  }
  return [collected, index];
}

function parseBlockScalar(lines: Line[], marker: string): string {
  const folded = marker.startsWith(">");
  const chomp = marker.includes("-") ? "strip" : marker.includes("+") ? "keep" : "clip";
  const content = lines.filter((line) => line.text.length > 0);
  if (content.length === 0) return chomp === "keep" ? "" : "";
  const cut = Math.min(...content.map((line) => line.indent));
  const raw = lines.map((line) =>
    line.text.length === 0 ? "" : " ".repeat(Math.max(0, line.indent - cut)) + line.text,
  );
  let body: string;
  if (folded) {
    body = "";
    for (let index = 0; index < raw.length; index++) {
      const line = raw[index] as string;
      body += line;
      if (index + 1 < raw.length) {
        const next = raw[index + 1] as string;
        body += line.length === 0 || next.length === 0 ? "\n" : " ";
      }
    }
  } else {
    body = raw.join("\n");
  }
  if (chomp === "strip") return body.replace(/\n+$/, "");
  if (chomp === "keep") return `${body}\n`;
  return `${body.replace(/\n+$/, "")}\n`;
}

function meaningful(lines: Line[]): Line[] {
  return lines.filter((line) => line.text.length > 0 && !line.text.startsWith("#"));
}

function parseBlockSequence(lines: Line[], indent: number): unknown[] {
  const items: unknown[] = [];
  for (const line of meaningful(lines)) {
    if (line.indent !== indent || !line.text.startsWith("-")) fail("ragged block sequence");
    const rest = line.text.slice(1);
    if (rest.length > 0 && !/^\s/.test(rest)) fail("sequence dash must be followed by space");
    items.push(parseFlowScalar(stripComment(rest)));
  }
  return items;
}

function parseNestedMap(lines: Line[], indent: number): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const line of meaningful(lines)) {
    if (line.indent !== indent) fail("ragged nested mapping");
    const colon = line.text.indexOf(":");
    if (colon <= 0) fail("nested line is not a mapping entry");
    const key = line.text.slice(0, colon).trim();
    if (Object.hasOwn(out, key)) fail(`duplicate key ${JSON.stringify(key)}`);
    const after = line.text.slice(colon + 1);
    if (after.length > 0 && !/^\s/.test(after)) fail("mapping colon must be followed by space");
    const inline = stripComment(after).trim();
    out[key] = inline.length > 0 ? parseInlineValue(inline) : null;
  }
  return out;
}

function parseMapEntries(lines: Line[], indent: number): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let index = 0;
  while (index < lines.length) {
    const line = lines[index] as Line;
    if (line.text.length === 0 || line.text.startsWith("#")) {
      index++;
      continue;
    }
    if (line.indent !== indent) fail("ragged mapping indentation");
    const colon = line.text.indexOf(":");
    if (colon <= 0) fail(`line ${JSON.stringify(line.text)} is not a mapping entry`);
    const key = line.text.slice(0, colon).trim();
    if (!KEY_PATTERN.test(key)) fail(`unsupported mapping key ${JSON.stringify(key)}`);
    if (Object.hasOwn(out, key)) fail(`duplicate key ${JSON.stringify(key)}`);
    const after = line.text.slice(colon + 1);
    if (after.length > 0 && !/^\s/.test(after)) fail("mapping colon must be followed by space");
    const inline = stripComment(after).trim();
    if (inline.length > 0) {
      if (inline.startsWith("|") || inline.startsWith(">")) {
        if (!/^[|>][+-]?\d?$/.test(inline) && !/^[|>]\d?[+-]?$/.test(inline))
          fail(`unsupported block scalar header ${JSON.stringify(inline)}`);
        const [children, next] = childLines(lines, index + 1, indent);
        out[key] = parseBlockScalar(children, inline);
        index = next;
        continue;
      }
      out[key] = parseInlineValue(inline);
      index++;
      continue;
    }
    const [children, next] = childLines(lines, index + 1, indent);
    const nested = meaningful(children);
    if (nested.length === 0) {
      out[key] = null;
    } else {
      const childIndent = (nested[0] as Line).indent;
      if ((nested[0] as Line).text.startsWith("-")) {
        out[key] = parseBlockSequence(children, childIndent);
      } else if ((nested[0] as Line).text.includes(":")) {
        out[key] = parseNestedMap(children, childIndent);
      } else {
        // A multi-line plain scalar continuation folds to single spaces.
        out[key] = nested.map((child) => stripComment(child.text).trim()).join(" ");
      }
    }
    index = next;
  }
  return out;
}

/**
 * Parses leading-frontmatter YAML. Throws `FrontmatterYamlErrorV1` for any
 * shape outside the supported subset (fail closed); returns the parsed value
 * otherwise (`undefined` for an empty document, like Core's `doc.toJS()`).
 */
export function parseFrontmatterYamlV1(source: string): unknown {
  if (source.trim().length === 0) return undefined;
  const lines = toLines(source);
  const entries = meaningful(lines);
  if (entries.length === 0) return undefined;
  for (const line of entries) {
    if (line.text === "---" || line.text === "...") fail("document marker inside frontmatter");
  }
  const first = entries[0] as Line;
  const colon = first.text.indexOf(":");
  const looksLikeMap =
    first.indent === 0 &&
    colon > 0 &&
    KEY_PATTERN.test(first.text.slice(0, colon).trim()) &&
    (first.text.length === colon + 1 || /^\s/.test(first.text.slice(colon + 1)));
  if (!looksLikeMap) {
    if (entries.length === 1 && first.indent === 0) return parsePlainScalar(first.text);
    fail("frontmatter is not a block mapping");
  }
  return parseMapEntries(lines, 0);
}
