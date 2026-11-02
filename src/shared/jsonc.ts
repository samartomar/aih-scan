/**
 * Whitespace editors skip between JSONC tokens beyond JSON's own (space, tab, CR, LF): vertical
 * tab, form feed, NBSP, U+1680, U+2000-U+200B, U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF.
 * jsonc-parser recovers past them and keeps the entries around them, so Scan reads them as
 * whitespace too rather than seeing nothing.
 */
function isExtraWhitespace(code: number): boolean {
  return (
    code === 0x0b ||
    code === 0x0c ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200b) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000 ||
    code === 0xfeff
  );
}

/**
 * Strict JSON plus the two JSONC extensions editors accept in config files: `//` and `/* *\/`
 * comments and trailing commas. A line comment ends at CR or LF, as in jsonc-parser. Comments
 * and the extra whitespace above become spaces (line breaks are kept, so line numbers do not
 * move), trailing commas are removed, and the result goes through `JSON.parse`, so keys such as
 * `__proto__` stay plain own data. One linear pass. Portable: no host modules. Throws a
 * SyntaxError when the text is not JSONC, including a comma with no value before it (`[,]`,
 * `{,}`, `,,`) and anything else an editor would only recover from.
 */
export function parseJsonc(text: string): unknown {
  const out: string[] = [];
  let index = 0;
  // Slot in `out` of a comma that may still turn out to be trailing.
  let pendingComma = -1;
  // The last token outside strings and comments: a structural character, or "v" for a value.
  let last = "";
  while (index < text.length) {
    const char = text[index] as string;
    const next = text[index + 1];
    if (char === '"') {
      const start = index;
      index += 1;
      while (index < text.length && text[index] !== '"') index += text[index] === "\\" ? 2 : 1;
      if (index >= text.length) throw new SyntaxError("unterminated string");
      index += 1;
      out.push(text.slice(start, index));
      pendingComma = -1;
      last = "v";
    } else if (char === "/" && next === "/") {
      const start = index;
      while (index < text.length && text[index] !== "\n" && text[index] !== "\r") index += 1;
      out.push(" ".repeat(index - start));
    } else if (char === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      if (end < 0) throw new SyntaxError("unterminated comment");
      out.push(text.slice(index, end + 2).replace(/[^\r\n]/g, " "));
      index = end + 2;
    } else if (char === " " || char === "\t" || char === "\n" || char === "\r") {
      out.push(char);
      index += 1;
    } else if (isExtraWhitespace(char.charCodeAt(0))) {
      out.push(" ");
      index += 1;
    } else {
      if (char === ",") {
        if (last === "" || last === "," || last === "[" || last === "{" || last === ":")
          throw new SyntaxError("a comma must follow a value");
        pendingComma = out.length;
      } else {
        if ((char === "}" || char === "]") && pendingComma >= 0) out[pendingComma] = " ";
        pendingComma = -1;
      }
      last = ",[]{}:".includes(char) ? (char === "]" || char === "}" ? "v" : char) : "v";
      out.push(char);
      index += 1;
    }
  }
  return JSON.parse(out.join(""));
}
