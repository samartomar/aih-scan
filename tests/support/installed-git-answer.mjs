// TEST-ONLY stand-in for Scan's Git helper (see installed-fixture-preload.mjs). Same argv
// (`<git argv JSON> <max bytes>`) and the same stdout contract (`{"bytesBase64": ...}`).
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";

const argv = JSON.parse(process.argv[2] ?? "null");
const fixture = process.env.AIH_SCAN_TEST_GIT_FIXTURE;
if (!Array.isArray(argv) || fixture === undefined) process.exit(1);
if (process.env.AIH_SCAN_TEST_GIT_LOG !== undefined)
  appendFileSync(process.env.AIH_SCAN_TEST_GIT_LOG, `${JSON.stringify(argv)}\n`);
const operations = ["init", "fetch", "ls-remote", "rev-parse", "rev-list", "ls-tree", "cat-file"];
const tail = argv.slice(argv.findIndex((arg) => operations.includes(arg)));
const bytes =
  tail[0] === "init" || tail[0] === "fetch"
    ? Buffer.alloc(0)
    : execFileSync(
        "git",
        tail.map((arg) => (arg.startsWith("https://") ? fixture : arg)),
        {
          cwd: fixture,
          env: { PATH: process.env.PATH ?? "", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", HOME: fixture },
          maxBuffer: 256 * 1024 * 1024,
        },
      );
process.stdout.write(JSON.stringify({ bytesBase64: bytes.toString("base64") }));
