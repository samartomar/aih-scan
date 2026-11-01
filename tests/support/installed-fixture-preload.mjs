// TEST-ONLY `node --import` preload for running the INSTALLED `aih-scan` CLI against local
// fixture services. It is never part of the package.
//
// - AIH_SCAN_TEST_REDIRECTS: JSON object mapping an https origin (for example
//   "https://registry.npmjs.org") to a loopback base URL ("http://127.0.0.1:<port>"). A fetch
//   to a mapped origin goes to the loopback service with the same path; every other fetch
//   fails, so no live service is ever contacted.
// - AIH_SCAN_TEST_GIT_FIXTURE: a local Git repository. Scan's hardened Git helper
//   (`dist/host/git-command.js`) is replaced, under the same bounded process-tree runner, by
//   tests/support/installed-git-answer.mjs, which answers each Git subcommand from that
//   repository (transport subcommands answer empty because the fixture already holds the
//   objects) and logs the hardened argv to AIH_SCAN_TEST_GIT_LOG.
import { createRequire, syncBuiltinESMExports } from "node:module";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const redirects = JSON.parse(process.env.AIH_SCAN_TEST_REDIRECTS ?? "{}");
for (const target of Object.values(redirects))
  if (typeof target !== "string" || !target.startsWith("http://127.0.0.1:"))
    throw new Error("AIH_SCAN_TEST_REDIRECTS must name loopback services");
const real = globalThis.fetch.bind(globalThis);
globalThis.fetch = (input, init) => {
  const url = String(input instanceof Request ? input.url : input);
  for (const [origin, target] of Object.entries(redirects))
    if (url === origin || url.startsWith(`${origin}/`))
      return real(`${target}${url.slice(origin.length)}`, init);
  return Promise.reject(new Error(`unexpected fetch ${url}`));
};

if (process.env.AIH_SCAN_TEST_GIT_FIXTURE !== undefined) {
  const answer = join(dirname(fileURLToPath(import.meta.url)), "installed-git-answer.mjs");
  const childProcess = createRequire(import.meta.url)("node:child_process");
  const spawn = childProcess.spawn;
  childProcess.spawn = function (command, args, options) {
    if (
      command === process.execPath &&
      Array.isArray(args) &&
      typeof args[0] === "string" &&
      basename(args[0]) === "git-command.js" &&
      basename(dirname(args[0])) === "host"
    )
      return spawn.call(this, command, [answer, ...args.slice(1)], options);
    return spawn.call(this, command, args, options);
  };
  syncBuiltinESMExports();
}
