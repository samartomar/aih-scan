import { describe, expect, it } from "vitest";
import * as contracts from "../src/public/contracts.js";
import * as host from "../src/public/host.js";
import * as read from "../src/public/read.js";

describe("replacement public entries", () => {
  it("expose exactly the replacement host and read functions", () => {
    expect(Object.keys(host).sort()).toEqual(["matchScan", "scan"]);
    expect(Object.keys(read).sort()).toEqual([
      "FINDINGS_MISMATCH_MESSAGE",
      "matchScan",
      "readFindings",
      "readSummary",
    ]);
  });

  it("expose contract data and validators from /contracts", () => {
    expect(Object.keys(contracts).sort()).toEqual([
      "SCAN_KEY_PATTERN",
      "advisoryCodes",
      "algorithmOfKey",
      "codeForRule",
      "codes",
      "displayLabel",
      "failAtReached",
      "formats",
      "isScanCode",
      "keyFolderName",
      "kinds",
      "limits",
      "optionalTools",
      "packageIdentity",
      "pathProblem",
      "riskLabelForScore",
      "routeFile",
      "routing",
      "sanitizeText",
      "scanCodes",
      "scanKeyOf",
      "schemas",
      "scoreFindings",
      "scoring",
      "severityOf",
      "sha256Hex",
      "storedLabel",
      "toolCategoryCodes",
      "toolRuleCodes",
      "toolsForPart",
      "validateRequest",
      "validateSource",
      "validateSummary",
      "validateWithdrawn",
    ]);
    for (const value of [
      contracts.formats,
      contracts.limits,
      contracts.routing,
      contracts.scoring,
      contracts.codes,
      contracts.schemas,
    ])
      expect(Object.isFrozen(value)).toBe(true);
  });

  it("carry none of the retired V2 operations", () => {
    for (const name of [
      "runScan",
      "prepareArtifact",
      "signArtifact",
      "authenticateArtifact",
      "deliverMaterialChange",
      "createRetainedObservationsV1",
    ])
      expect(host).not.toHaveProperty(name);
    for (const name of [
      "readArtifact",
      "readReport",
      "recordItems",
      "summariseItem",
      "readContentCoverage",
      "selectAssessments",
    ])
      expect(read).not.toHaveProperty(name);
    for (const name of ["contractSupport", "contractSupport11", "entrySupport"])
      expect(contracts).not.toHaveProperty(name);
  });
});
