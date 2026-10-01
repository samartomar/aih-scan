// Explicit unsigned candidate preparation. Input is a retained run-result JSON;
// detector execution and signing are separate operations.
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync, linkSync, unlinkSync, lstatSync, rmSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { prepareArtifact } from "../../dist/public/host.js";
import { base64Decode, canonicalBytes, strictParse } from "../../dist/assessment/json.js";
import { object, array } from "../../dist/artifact/validation.js";
import { readRegular } from "./check-statement.mjs";

let stage;
let ownsStage = false;
try {
  if (process.argv.length !== 4) throw new Error("Expected retained run result and new output directory");
  const result = object(strictParse(readRegular(process.argv[2], 96 * 1024 * 1024), "run result", 96 * 1024 * 1024), ["schema", "status", "scanId", "report", "annexes", "diagnostics"]);
  if (result.schema !== "urn:aihq:scan:run-result:1.0.0" || result.status !== "assessment") throw new Error("Assessment required");
  const annexes = array(result.annexes).map(value => { const annex = object(value, ["id", "bytesBase64"]); return { id: annex.id, bytes: base64Decode(annex.bytesBase64, 16 * 1024 * 1024) }; });
  const prepared = await prepareArtifact({ report: result.report, annexes });
  if (prepared.scanId !== result.scanId) throw new Error("Run result Scan ID mismatch");
  const output = resolve(process.argv[3]);
  try { lstatSync(output); throw new Error("Output already exists"); } catch (error) { if (error.code !== "ENOENT") throw error; }
  stage = join(dirname(output), `.scan-candidate-${randomUUID()}`);
  mkdirSync(stage, { mode: 0o700 });
  ownsStage = true;
  const statement = canonicalBytes(prepared.statement);
  writeFileSync(join(stage, "artifact.json"), prepared.bytes, { flag: "wx", mode: 0o600 });
  writeFileSync(join(stage, "statement.json"), statement, { flag: "wx", mode: 0o600 });
  const manifest = { scanId: prepared.scanId, statementSha256: createHash("sha256").update(statement).digest("hex"), artifactSha256: createHash("sha256").update(prepared.bytes).digest("hex"), nonemptyAnnexes: prepared.artifact.annexes.filter(a => a.byteLength > 0).length };
  writeFileSync(join(stage, "candidate.json"), canonicalBytes(manifest), { flag: "wx", mode: 0o600 });
  // Exclusively claim the destination after staging. A directory rename can
  // replace a concurrently created empty destination on POSIX; mkdir cannot.
  // Moving each staged file via link/unlink also refuses any existing filename.
  mkdirSync(output, { mode: 0o700 });
  for (const name of ["artifact.json", "statement.json", "candidate.json"]) {
    linkSync(join(stage, name), join(output, name));
    unlinkSync(join(stage, name));
  }
  rmSync(stage, { recursive: true }); ownsStage = false; stage = undefined;
  process.stdout.write(JSON.stringify(manifest) + "\n");
} catch { process.stderr.write("Unsigned candidate preparation refused.\n"); process.exitCode = 2; }
finally { if (stage && ownsStage) rmSync(stage, { recursive: true }); }
