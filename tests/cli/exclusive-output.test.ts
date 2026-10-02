import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "vitest";
import {
  assertOutputAbsent,
  ExclusiveOutputError,
  safeOutputParents,
  writeNewSafeOutput,
} from "../../src/cli/exclusive-output.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
/** A disposable real directory. The real path keeps expectations independent of tmpdir links. */
function fixture(): string {
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), "aih-scan-exclusive-output-")));
  roots.push(root);
  return root;
}
const policy = { label: "projection output", maximumBytes: 8 };
const bytes = new TextEncoder().encode("content");

/** The refusal an exclusive write raises, or undefined when it is not an ExclusiveOutputError. */
function refusal(action: () => void): ExclusiveOutputError {
  try {
    action();
  } catch (error) {
    if (error instanceof ExclusiveOutputError) return error;
    throw error;
  }
  throw new Error("expected the write to be refused");
}

test("creates a new file holding exactly the bytes, readable by its owner only", () => {
  const directory = fixture();
  const path = join(directory, "new.json");
  writeNewSafeOutput(path, bytes, policy);
  expect(readFileSync(path)).toEqual(Buffer.from(bytes));
  if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
});

test.each([
  ["an empty output", new Uint8Array(), "projection output bounds"],
  ["an output over the maximum", new Uint8Array(9), "projection output bounds"],
])("refuses %s as a bounds problem named by the label", (_name, content, message) => {
  const directory = fixture();
  const error = refusal(() => writeNewSafeOutput(join(directory, "new.json"), content, policy));
  expect(error).toMatchObject({ problem: "bounds", message });
  expect(readdirSync(directory)).toEqual([]);
});

test("accepts an output of exactly the maximum", () => {
  const directory = fixture();
  writeNewSafeOutput(join(directory, "new.json"), new Uint8Array(8).fill(1), policy);
  expect(statSync(join(directory, "new.json")).size).toBe(8);
});

test("refuses an existing path and leaves it unchanged", () => {
  const directory = fixture();
  const path = join(directory, "existing.json");
  writeFileSync(path, "keep\n");
  const error = refusal(() => writeNewSafeOutput(path, bytes, policy));
  expect(error).toMatchObject({ problem: "exists", message: "projection output already exists" });
  expect(readFileSync(path, "utf8")).toBe("keep\n");
});

test("names the output by the label it is given", () => {
  const directory = fixture();
  writeFileSync(join(directory, "existing.json"), "keep\n");
  const error = refusal(() =>
    writeNewSafeOutput(join(directory, "existing.json"), bytes, { ...policy, label: "artifact" }),
  );
  expect(error.message).toBe("artifact already exists");
});

test("refuses a linked parent directory before creating anything", (context) => {
  const directory = fixture();
  mkdirSync(join(directory, "real"));
  try {
    symlinkSync(join(directory, "real"), join(directory, "linked"), "junction");
  } catch {
    return context.skip();
  }
  const error = refusal(() =>
    writeNewSafeOutput(join(directory, "linked", "new.json"), bytes, policy),
  );
  expect(error).toMatchObject({
    problem: "linked-parent",
    message: "output parent link or reparse",
  });
  expect(readdirSync(join(directory, "real"))).toEqual([]);
});

test("a missing parent directory raises the file system error, not a refusal", () => {
  const directory = fixture();
  expect(() => writeNewSafeOutput(join(directory, "missing", "new.json"), bytes, policy)).toThrow(
    /ENOENT/,
  );
  expect(() => safeOutputParents(join(directory, "missing", "new.json"))).toThrow(/ENOENT/);
});

test("assertOutputAbsent accepts an absent path and refuses a present one", () => {
  const directory = fixture();
  expect(() => assertOutputAbsent(join(directory, "absent.json"), "artifact")).not.toThrow();
  expect(refusal(() => assertOutputAbsent(directory, "artifact"))).toMatchObject({
    problem: "exists",
    message: "artifact already exists",
  });
});
