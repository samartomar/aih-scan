// Verify a signed summary offline with @aihq/scan/read and match it to a folder.
// Usage: node examples/verify-summary.mjs <summary.json> <bundle.sigstore> <item-folder>
// Uses the default trusted publisher and the pinned Sigstore trust snapshot.
import { readFileSync } from "node:fs";
import { matchScan } from "@aihq/scan/host";
import { verifySummary } from "@aihq/scan/read";

const [summaryPath, bundlePath, folder] = process.argv.slice(2);
const verified = await verifySummary(
  new Uint8Array(readFileSync(summaryPath)),
  new Uint8Array(readFileSync(bundlePath)),
);
if (verified.status !== "ok") {
  console.log(`not verified: ${verified.status} ${verified.reason}`);
  process.exit(2);
}
console.log(
  verified.withdrawn
    ? "withdrawn by its signer; not trusted"
    : verified.signer.trusted
      ? `signed by trusted publisher ${verified.signer.identity}`
      : "signed, not by a trusted publisher",
);
const match = await matchScan(verified, folder);
console.log(`matches: ${match.matches} coverage: ${match.coverage} trusted: ${match.signer?.trusted}`);
