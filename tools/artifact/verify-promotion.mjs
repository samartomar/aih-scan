// Trusted final assembly, independently selected trust, and promotion only after
// offline consumer authentication. This tool never signs or makes network calls.
import { writeFileSync } from "node:fs";
import { attachAttestation, authenticateArtifact } from "../../dist/public/host.js";
import { strictParse } from "../../dist/assessment/json.js";
import { readRegular } from "./check-statement.mjs";

try {
  if (process.argv.length !== 7) throw new Error("Expected unsigned artifact, bundle, trust, expected ID and new output path");
  const [, , unsignedPath, bundlePath, trustPath, expectedScanId, outputPath] = process.argv;
  const bytes = readRegular(unsignedPath, 96 * 1024 * 1024);
  const bundle = strictParse(readRegular(bundlePath, 1024 * 1024), "bundle", 1024 * 1024);
  const trust = strictParse(readRegular(trustPath, 1024 * 1024), "independent trust", 1024 * 1024);
  const attached = await attachAttestation({ bytes, bundle });
  const result = await authenticateArtifact({ bytes: attached.bytes, expectedScanId, trust });
  if (result.status !== "authenticated") throw new Error("Independent authentication refused");
  writeFileSync(outputPath, attached.bytes, { flag: "wx", mode: 0o600 });
  process.stdout.write(JSON.stringify(result) + "\n");
} catch { process.stderr.write("Artifact promotion refused; no authenticated output written.\n"); process.exitCode = 2; }
