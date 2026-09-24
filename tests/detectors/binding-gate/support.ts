import {
  type BindingGateDimensionReportV1,
  bindingGateSelectionViewV1,
  inspectBindingGateTreeV1,
} from "../../../src/detectors/binding-gate/index.js";
import {
  buildTrustLintTreeV1,
  type TrustLintTreeV1,
} from "../../../src/detectors/trust-lint/index.js";

/**
 * Test stand-in for the subject Core declares to `detector.aih-binding-gate`
 * (C2a decision 1): Core's binding inventory, `buildTrustFileInventory` with
 * `BINDING_SCAN_SKIP_DIRS = {".git"}` — every listed file with no `.git`
 * directory segment, in the tree's localeCompare order.
 */
export function coreBindingInventoryV1(tree: TrustLintTreeV1): string[] {
  return tree.files
    .map((entry) => entry.relativePath)
    .filter((rel) =>
      rel
        .split("/")
        .slice(0, -1)
        .every((segment) => segment !== ".git"),
    );
}

/** Core's `inspectTree(dir)` over the declared binding inventory. */
export function inspectCoreTreeV1(dir: string): BindingGateDimensionReportV1[] {
  const tree = buildTrustLintTreeV1(dir);
  return inspectBindingGateTreeV1(bindingGateSelectionViewV1(tree, coreBindingInventoryV1(tree)));
}
