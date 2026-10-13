import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { runScan } from "@aihq/scan/host";

const rules = readFileSync(new URL("./rules.yaml", import.meta.url));
const definition = JSON.parse(readFileSync(new URL("./definition.json", import.meta.url), "utf8"));
if (createHash("sha256").update(rules).digest("hex") !== definition.rules.sha256)
  throw new Error("Example rule bytes no longer match definition.json");
const result = await runScan({
  schema: "urn:aihq:scan:request:1.0.0",
  source: { kind: "local", path: process.argv[2] },
  selection: { paths: "all", excludedPaths: [] },
  detectors: [{ detectorId: definition.detectorId, profileId: definition.profileId, configuration: {} }],
}, { detectorDefinitions: [{ definition, rules }] });
console.log(JSON.stringify(result, null, 2));
