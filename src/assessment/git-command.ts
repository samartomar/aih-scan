/** Internal binary Git transport, always launched under Scan's bounded process-tree runner. */
import { spawn } from "node:child_process";

const argv: unknown = JSON.parse(process.argv[2] ?? "null"),
  maximum = Number(process.argv[3]);
if (
  !Array.isArray(argv) ||
  !argv.every((arg) => typeof arg === "string") ||
  !Number.isSafeInteger(maximum) ||
  maximum < 0
)
  process.exit(1);
const child = spawn("git", argv, {
  env: process.env,
  windowsHide: true,
  shell: false,
  stdio: ["ignore", "pipe", "pipe"],
});
const chunks: Buffer[] = [];
let length = 0,
  stderrLength = 0;
child.stdout.on("data", (chunk: Buffer) => {
  length += chunk.length;
  if (length > maximum) process.exit(1);
  chunks.push(chunk);
});
child.stderr.on("data", (chunk: Buffer) => {
  stderrLength += chunk.length;
  if (stderrLength > 65536) process.exit(1);
});
child.once("error", () => process.exit(1));
child.once("close", (code) => {
  if (code !== 0) process.exit(1);
  process.stdout.write(JSON.stringify({ bytesBase64: Buffer.concat(chunks).toString("base64") }));
});
