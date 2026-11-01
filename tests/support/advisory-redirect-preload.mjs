// TEST-ONLY preload for running a built or installed `aih-scan advisories` against a controlled
// local advisory service: `node --import <this file> <cli.js> advisories ...` with
// AIH_SCAN_TEST_ADVISORY_ENDPOINT=http://127.0.0.1:<port>. Requests to the public OSV endpoint
// are sent to that service instead; every other fetch fails, so no live service is contacted.
const target = process.env.AIH_SCAN_TEST_ADVISORY_ENDPOINT;
if (target === undefined || !target.startsWith("http://127.0.0.1:"))
  throw new Error("AIH_SCAN_TEST_ADVISORY_ENDPOINT must name a loopback service");
const real = globalThis.fetch.bind(globalThis);
globalThis.fetch = (input, init) => {
  const url = String(input instanceof Request ? input.url : input);
  if (!url.startsWith("https://api.osv.dev/"))
    return Promise.reject(new Error(`unexpected fetch ${url}`));
  return real(`${target}${url.slice("https://api.osv.dev".length)}`, init);
};
