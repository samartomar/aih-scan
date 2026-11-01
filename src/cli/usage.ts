/**
 * The top-level help, composed from each command's own usage so the two cannot drift: the
 * usage lines of every command (its first paragraph), then where to find each one's options.
 */
export function commandsUsage(usages: readonly string[]): string {
  const lines: string[] = [];
  for (const usage of usages) {
    const head = usage.split("\n\n")[0]?.trimEnd() ?? "";
    for (const line of head.split("\n"))
      lines.push(line.startsWith("Usage: ") ? `  ${line.slice(7)}` : line.replace(/^ {5}/, ""));
  }
  return `Usage:\n${lines.join("\n")}\nRun \`aih-scan <command> --help\` for a command's options.\n`;
}
