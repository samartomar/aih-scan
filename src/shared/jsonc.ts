/**
 * Strict JSON plus the two JSONC extensions editors accept in config files: `//` and `/* *\/`
 * comments and trailing commas. Comments become spaces (newlines are kept, so line numbers do
 * not move), trailing commas are removed, and the result goes through `JSON.parse`, so keys such
 * as `__proto__` stay plain own data. Portable: no host modules. Throws a SyntaxError when the
 * text is not JSONC.
 */
export function parseJsonc(text: string): unknown {
  let out = "";
  let index = 0;
  // Index in `out` of a comma that may still turn out to be trailing.
  let pendingComma = -1;
  while (index < text.length) {
    const char = text[index] as string;
    const next = text[index + 1];
    if (char === '"') {
      const start = index;
      index += 1;
      while (index < text.length && text[index] !== '"') index += text[index] === "\\" ? 2 : 1;
      if (index >= text.length) throw new SyntaxError("unterminated string");
      index += 1;
      out += text.slice(start, index);
      pendingComma = -1;
    } else if (char === "/" && next === "/") {
      while (index < text.length && text[index] !== "\n") {
        out += text[index] === "\r" ? "\r" : " ";
        index += 1;
      }
    } else if (char === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      if (end < 0) throw new SyntaxError("unterminated comment");
      out += text.slice(index, end + 2).replace(/[^\r\n]/g, " ");
      index = end + 2;
    } else {
      if ((char === "}" || char === "]") && pendingComma >= 0)
        out = `${out.slice(0, pendingComma)} ${out.slice(pendingComma + 1)}`;
      if (char === ",") pendingComma = out.length;
      else if (!/\s/.test(char)) pendingComma = -1;
      out += char;
      index += 1;
    }
  }
  return JSON.parse(out);
}
