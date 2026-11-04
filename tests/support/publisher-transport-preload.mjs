// Test-only external-network adapter: exercise the real publisher URL/DNS/request path
// against a disposable loopback service. Never included in the installed package.
import { createRequire, syncBuiltinESMExports } from "node:module";
const require = createRequire(import.meta.url);
const dns = require("node:dns"), https = require("node:https"), http = require("node:http");
const base = new URL(process.env.AIH_SCAN_TEST_PUBLISHER_SERVICE);
if (base.protocol !== "http:" || base.hostname !== "127.0.0.1") throw new Error("Fixture must be loopback");
dns.lookup = (host, _options, callback) => callback(null, [{ address: host === process.env.AIH_SCAN_TEST_PRIVATE_DNS_HOST ? "127.0.0.1" : "93.184.216.34", family: 4 }]);
https.request = (url, options, callback) => {
  const child = http.request(new URL(url.pathname + url.search, base), { headers: { ...options.headers, "x-fixture-host": url.hostname }, timeout: options.timeout }, callback);
  const end = child.end.bind(child);
  child.end = () => { options.lookup(url.hostname, { all: true }, (error) => error ? child.destroy(error) : end()); return child; };
  return child;
};
syncBuiltinESMExports();
