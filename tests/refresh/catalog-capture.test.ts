import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

test("independent Catalog batches admit bounded keyed subsets without inventing repositories", async () => {
  const { validateInput, ceilings } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const target = {
    repository: "samartomar/aih-catalog",
    ref: "a".repeat(40),
    selection: { paths: "all", excludedPaths: [] },
    trustLint: { internalScopes: [], mcpConfigPaths: [] },
    capture: {
      releaseId: "1",
      assetId: "2",
      sha256: "b".repeat(64),
      byteLength: 1000,
      inventory: { path: "inventory.json", sha256: "c".repeat(64), byteLength: 100 },
    },
  };
  const input = {
    schema: "urn:aihq:scan:catalog-capture-batch-input:1.0.0",
    scannerSourceCommit: "d".repeat(40),
    runtime: { node: process.version, platform: "linux", architecture: "x64" },
    profile: "independent-linux-v1",
    limits: ceilings,
    batchLimits: {
      maxInputBytes: 2000,
      maxSourceBytes: 2000,
      maxSourceEntries: 100,
      maxDurationMs: 60000,
    },
    targets: [
      { ...target, captureId: "default" },
      {
        ...target,
        captureId: "ecc",
        capture: { ...target.capture, assetId: "3", releaseId: "4", sha256: "e".repeat(64) },
      },
    ],
  };
  expect(validateInput(input)).toEqual(input);
  expect(validateInput({ ...input, targets: [input.targets[1]] }).targets).toHaveLength(1);
  for (const targets of [
    [],
    Array(8).fill(input.targets[0]),
    [input.targets[0], input.targets[0]],
    [{ ...input.targets[0], captureId: "../escape" }],
    [{ ...input.targets[0], repository: "invented/catalog-ecc" }],
    [input.targets[0], { ...input.targets[1], capture: target.capture }],
  ])
    expect(() => validateInput({ ...input, targets })).toThrow();
  for (const batchLimits of [
    { ...input.batchLimits, maxInputBytes: 1999 },
    { ...input.batchLimits, maxDurationMs: 5400001 },
  ])
    expect(() => validateInput({ ...input, batchLimits })).toThrow();
});

test("immutable Catalog acquisition binds actual material closure before assessment", async () => {
  const { acquireCatalogCapture } = await import(
    new URL("../../tools/refresh/catalog-capture.mjs", import.meta.url).href
  );
  const { canonicalBytes, sha256, ceilings } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const recipe = Buffer.from('{"instructions":"Read only"}\n');
  const recipeDescriptor = {
    path: "recipes/example.json",
    sha256: sha256(recipe),
    byteLength: recipe.length,
  };
  const inventory = Buffer.from(
    canonicalBytes({
      schema: "urn:aihq:catalog:content-inventory:1.0.0",
      projection: "urn:aihq:catalog:release-content:1.0.0",
      release: {
        schema: "urn:aihq:catalog:release:1.5.0",
        package: { name: "@aihq/catalog", version: "0.3.0" },
        sources: [],
        items: [{ recipe: recipeDescriptor, materials: [] }],
      },
    }).toString() + "\n",
  );
  const inventoryDescriptor = {
    path: "release/content-inventory.json",
    sha256: sha256(inventory),
    byteLength: inventory.length,
  };
  const files = [
    { ...recipeDescriptor, bytesBase64: recipe.toString("base64") },
    { ...inventoryDescriptor, bytesBase64: inventory.toString("base64") },
  ];
  const bytes = canonicalBytes({
    schema: "urn:aihq:scan:catalog-capture:1.0.0",
    inventory: inventoryDescriptor,
    files,
  });
  const selector = {
    releaseId: "11",
    assetId: "12",
    sha256: sha256(bytes),
    byteLength: bytes.length,
    inventory: inventoryDescriptor,
  };
  let immutable = true;
  const target = { commit: "b".repeat(40), capture: selector };
  const transport = {
    json: (path: string): unknown =>
      path === "repos/samartomar/aih-catalog"
        ? {
            full_name: "samartomar/aih-catalog",
            private: false,
            archived: false,
            owner: { id: 9993940 },
          }
        : path.includes("/git/ref/")
          ? {
              ref: "refs/tags/catalog-capture-" + selector.sha256,
              object: { type: "commit", sha: target.commit },
            }
          : path.endsWith("/11")
            ? {
                id: 11,
                immutable,
                draft: false,
                tag_name: "catalog-capture-" + selector.sha256,
                target_commitish: target.commit,
              }
            : [
                {
                  id: 12,
                  name: "catalog-capture.json",
                  state: "uploaded",
                  size: bytes.length,
                  digest: "sha256:" + sha256(bytes),
                  url: "https://api.github.com/repos/samartomar/aih-catalog/releases/assets/12",
                },
              ],
    bytes: () => ({ status: 200, bytes }),
  };
  const capture = await acquireCatalogCapture(target, ceilings, transport);
  expect(capture.files).toEqual([recipeDescriptor, inventoryDescriptor]);
  immutable = false;
  await expect(acquireCatalogCapture(target, ceilings, transport)).rejects.toThrow();
  immutable = true;
  await expect(
    acquireCatalogCapture(
      { ...target, capture: { ...selector, sha256: "0".repeat(64) } },
      ceilings,
      transport,
    ),
  ).rejects.toThrow();
  const missing = canonicalBytes({
    schema: "urn:aihq:scan:catalog-capture:1.0.0",
    inventory: inventoryDescriptor,
    files: [files[1]],
  });
  await expect(
    acquireCatalogCapture(
      { ...target, capture: { ...selector, sha256: sha256(missing), byteLength: missing.length } },
      ceilings,
      {
        json: (path: string) =>
          path.includes("/assets?")
            ? [
                {
                  id: 12,
                  name: "catalog-capture.json",
                  state: "uploaded",
                  size: missing.length,
                  digest: "sha256:" + sha256(missing),
                  url: "https://api.github.com/repos/samartomar/aih-catalog/releases/assets/12",
                },
              ]
            : path.includes("/git/ref/")
              ? {
                  ref: "refs/tags/catalog-capture-" + sha256(missing),
                  object: { type: "commit", sha: target.commit },
                }
              : path.endsWith("/11")
                ? {
                    id: 11,
                    immutable,
                    draft: false,
                    tag_name: "catalog-capture-" + sha256(missing),
                    target_commitish: target.commit,
                  }
                : transport.json(path),
        bytes: () => ({ status: 200, bytes: missing }),
      },
    ),
  ).rejects.toThrow();
});

// Maintainer boundary uses packed Scan in operation.test.ts; this first slice
// exercises the explicit input admission before acquisition has any effects.
test("Catalog capture is an explicit singleton mode with immutable selectors", async () => {
  const { validateInput, ceilings } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const hash = createHash("sha256").update("inventory\n").digest("hex");
  const input = {
    schema: "urn:aihq:scan:catalog-capture-input:1.0.0",
    scannerSourceCommit: "a".repeat(40),
    runtime: { node: process.version, platform: "linux", architecture: "x64" },
    profile: "independent-linux-v1",
    limits: ceilings,
    targets: [
      {
        repository: "samartomar/aih-catalog",
        ref: "b".repeat(40),
        selection: { paths: "all", excludedPaths: [] },
        trustLint: { internalScopes: [], mcpConfigPaths: [] },
        capture: {
          releaseId: "11",
          assetId: "12",
          sha256: "c".repeat(64),
          byteLength: 4096,
          inventory: { path: "release/content-inventory.json", sha256: hash, byteLength: 10 },
        },
      },
    ],
  };
  expect(validateInput(input)).toEqual(input);
  expect(() => validateInput({ ...input, targets: [] })).toThrow();
  expect(() =>
    validateInput({ ...input, targets: [{ ...input.targets[0], ref: "refs/heads/main" }] }),
  ).toThrow();
  expect(() =>
    validateInput({ ...input, targets: [{ ...input.targets[0], repository: "other/repo" }] }),
  ).toThrow();
  for (const change of [
    { assetId: "../12" },
    { releaseId: "0" },
    { url: "https://example.invalid/capture" },
    { byteLength: 64 * 1024 * 1024 + 1 },
    { inventory: { ...input.targets[0]?.capture.inventory, path: "../inventory" } },
  ])
    expect(() =>
      validateInput({
        ...input,
        targets: [{ ...input.targets[0], capture: { ...input.targets[0]?.capture, ...change } }],
      }),
    ).toThrow();
});

test("offline input preparation keeps binary bytes and authored numbers, and refuses unsafe or changed staged material", async () => {
  const { prepareCatalogCapture } = await import(
    new URL("../../tools/refresh/catalog-capture.mjs", import.meta.url).href
  );
  const { sha256, canonicalBytes } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const root = mkdtempSync(join(tmpdir(), "scan-input-preparation-"));
  try {
    mkdirSync(join(root, "recipes"));
    const material = Buffer.from([0, 255, 1, 128]);
    const member = { path: "recipes/blob.bin", sha256: sha256(material), byteLength: 4 };
    const base = {
      schema: "urn:aihq:catalog:content-inventory:1.0.0",
      projection: "urn:aihq:catalog:release-content:1.0.0",
      release: {
        schema: "urn:aihq:catalog:release:1.5.0",
        package: { name: "@aihq/catalog", version: "0.3.0" },
        sources: [],
        items: [{ recipe: member, materials: [] }],
        metadata: { score: 0 },
      },
    };
    // Canonical metadata from Catalog can contain authored fractions/negatives.
    const inventory = Buffer.from(
      `${canonicalBytes(base).toString().replace('"score":0', '"score":-0.5')}\n`,
    );
    writeFileSync(join(root, "inventory.json"), inventory);
    writeFileSync(join(root, member.path), material);
    const args = { root, inventoryPath: "inventory.json", inventorySha256: sha256(inventory) };
    const bytes = prepareCatalogCapture(args);
    expect(prepareCatalogCapture(args)).toEqual(bytes);
    expect(JSON.parse(bytes.toString()).files[1].bytesBase64).toBe("AP8BgA==");
    writeFileSync(join(root, member.path), "changed");
    expect(() => prepareCatalogCapture(args)).toThrow();
    unlinkSync(join(root, member.path));
    // Directory junction requires no Windows developer-mode symlink privilege.
    const linked = join(root, "linked");
    symlinkSync(join(root, "recipes"), linked, process.platform === "win32" ? "junction" : "dir");
    expect(() => prepareCatalogCapture({ ...args, root: linked })).toThrow();
    for (const path of [
      "../escape",
      "recipes/../escape",
      "C:/escape",
      ".git/config",
      "CON.txt",
      "trail.",
      "bad\\name",
    ])
      expect(() => prepareCatalogCapture({ ...args, inventoryPath: path })).toThrow();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("frozen capture rejects namespace aliases, links, duplicate/extra fields and source budgets", async () => {
  const { validateFrozenCapture, ceilings } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const file = { path: "A/file", sha256: "a".repeat(64), byteLength: 1 };
  const frozen = {
    releaseId: "11",
    assetId: "12",
    sha256: "b".repeat(64),
    byteLength: 1000,
    inventory: file,
    files: [file],
  };
  expect(validateFrozenCapture(frozen, ceilings)).toEqual(frozen);
  for (const files of [
    [file, file],
    [file, { ...file, path: "a/other" }],
    [{ ...file, kind: "file-link", target: "other" }],
    [{ ...file, path: "A" }, file],
    [{ ...file, byteLength: 2 }],
    [],
  ])
    expect(() => validateFrozenCapture({ ...frozen, files }, ceilings)).toThrow();
  expect(() => validateFrozenCapture(frozen, { ...ceilings, maxSourceEntries: 1 })).toThrow();
  expect(() => validateFrozenCapture(frozen, { ...ceilings, maxSourceBytes: 0 })).toThrow();
});

test("deep immutable input refuses at its source entry budget within a bounded heap", () => {
  const directory = mkdtempSync(join(tmpdir(), "scan-capture-entry-bound-"));
  try {
    const driver = join(directory, "input.mjs");
    writeFileSync(
      driver,
      `
import {acquireCatalogCapture} from ${JSON.stringify(new URL("../../tools/refresh/catalog-capture.mjs", import.meta.url).href)};
import {canonicalBytes,sha256,ceilings} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
const inventory={path:'inventory.json',sha256:sha256(Buffer.from('{}')),byteLength:2};
const files=Array.from({length:500},(_,i)=>({path:'a'+String(i).padStart(3,'0')+'/'+Array(400).fill('abcd').join('/'),sha256:sha256(Buffer.alloc(0)),byteLength:0,bytesBase64:''}));
files.push({...inventory,bytesBase64:'e30='});
const bytes=canonicalBytes({schema:'urn:aihq:scan:catalog-capture:1.0.0',inventory,files}),hash=sha256(bytes),commit='a'.repeat(40);
const target={commit,capture:{releaseId:'1',assetId:'2',sha256:hash,byteLength:bytes.length,inventory}};
const api={json:path=>path==='repos/samartomar/aih-catalog'?{full_name:'samartomar/aih-catalog',private:false,archived:false,owner:{id:9993940}}:path.includes('/git/ref/')?{ref:'refs/tags/catalog-capture-'+hash,object:{type:'commit',sha:commit}}:path.endsWith('/1')?{id:1,immutable:true,draft:false,tag_name:'catalog-capture-'+hash,target_commitish:commit}:[{id:2,name:'catalog-capture.json',state:'uploaded',size:bytes.length,digest:'sha256:'+hash,url:'https://api.github.com/repos/samartomar/aih-catalog/releases/assets/2'}],bytes:()=>({status:200,bytes})};
try{await acquireCatalogCapture(target,{...ceilings,maxSourceEntries:1000},api);process.exitCode=1;}catch(error){if(!/Capture entry bound exceeded/.test(error.message))throw error;process.stdout.write('bounded-input-refusal');}
`,
    );
    const result = spawnSync(process.execPath, ["--max-old-space-size=64", driver], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 15000,
      maxBuffer: 1024 * 1024,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("bounded-input-refusal");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// Real Catalog producer output: release 1.7.0 in content-inventory/projection 1.2.0,
// copied with its exact member bytes from public samartomar/aih-catalog d86c678.
const current = new URL("../fixtures/catalog-capture-1.7/", import.meta.url);
const inventoryPath = "release/baselines/project-basics/content-inventory.json";

test("current Catalog 1.7 inventories prepare exact, deterministic byte closure", async () => {
  const { prepareCatalogCapture, acquireCatalogCapture } = await import(
    new URL("../../tools/refresh/catalog-capture.mjs", import.meta.url).href
  );
  const { sha256, ceilings } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const root = mkdtempSync(join(tmpdir(), "scan-catalog-17-"));
  try {
    cpSync(new URL("project-basics", current), root, { recursive: true });
    const inventory = readFileSync(join(root, inventoryPath));
    expect(sha256(inventory)).toBe(
      "f651b20122911118657941b0b514fa609a8754ac7c8ae9e203d19e557c85544f",
    );
    const args = { root, inventoryPath, inventorySha256: sha256(inventory) };
    const bytes = prepareCatalogCapture(args);
    expect(prepareCatalogCapture(args)).toEqual(bytes);
    expect(sha256(bytes)).toBe("7a4e886527b7c816389ff1e9c0e28551bd08fd4adf49b26b28de22ceb5e6b33b");
    const envelope = JSON.parse(bytes.toString());
    // Every recipe, behaviour file and content material by package path, plus the inventory.
    expect(envelope.files.map((file: { path: string }) => file.path)).toEqual([
      inventoryPath,
      "release/items/project-basics.router/aih-behaviour.json",
      "release/items/project-basics.shared-block/aih-behaviour.json",
      "release/items/project-basics.working-rules/aih-behaviour.json",
      "release/materials/project-basics/RULE_ROUTER.md",
      "release/materials/project-basics/rules/agent-behavior-core.md",
      "release/materials/project-basics/shared-block.md",
      "release/recipes/project-basics.router.json",
      "release/recipes/project-basics.shared-block.json",
      "release/recipes/project-basics.working-rules.json",
    ]);
    const selector = {
      releaseId: "11",
      assetId: "12",
      sha256: sha256(bytes),
      byteLength: bytes.length,
      inventory: { path: inventoryPath, sha256: sha256(inventory), byteLength: inventory.length },
    };
    const target = { commit: "b".repeat(40), capture: selector };
    const frozen = await acquireCatalogCapture(target, ceilings, fixtureTransport(target, bytes));
    expect(frozen.files).toEqual(
      envelope.files.map(({ bytesBase64: _, ...entry }: { bytesBase64: string }) => entry),
    );
    // Frozen manifests reacquire against the same descriptor set.
    expect(
      await acquireCatalogCapture(
        { ...target, capture: frozen },
        ceilings,
        fixtureTransport(target, bytes),
      ),
    ).toEqual(frozen);
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("../../tools/refresh/catalog-capture.mjs", import.meta.url)),
        root,
        inventoryPath,
        sha256(inventory),
        join(root, "..", `${basename(root)}.capture.json`),
      ],
      { encoding: "utf8", windowsHide: true, timeout: 15000 },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      event: "scan-catalog-capture.prepared",
      sha256: sha256(bytes),
    });
    expect(readFileSync(join(root, "..", `${basename(root)}.capture.json`))).toEqual(bytes);
  } finally {
    rmSync(join(root, "..", `${basename(root)}.capture.json`), { force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test("Catalog 1.7 closure covers recipe maps and refuses unsupported, ambiguous or unsafe declarations", async () => {
  const { prepareCatalogCapture } = await import(
    new URL("../../tools/refresh/catalog-capture.mjs", import.meta.url).href
  );
  const { sha256, canonicalBytes } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const root = mkdtempSync(join(tmpdir(), "scan-catalog-17-shapes-"));
  try {
    cpSync(new URL("project-basics", current), root, { recursive: true });
    // Parsed Catalog JSON: shapes are deliberately mutated, including into invalid ones.
    type Json = ReturnType<typeof JSON.parse>;
    const real: Json = JSON.parse(readFileSync(join(root, inventoryPath), "utf8"));
    const prepare = (value: Json) => {
      const bytes = Buffer.from(`${canonicalBytes(value)}\n`);
      writeFileSync(join(root, "release/inventory.json"), bytes);
      return prepareCatalogCapture({
        root,
        inventoryPath: "release/inventory.json",
        inventorySha256: sha256(bytes),
      });
    };
    const variant = (change: (item: Json, inventory: Json) => void) => {
      const inventory = structuredClone(real);
      change(inventory.release.items[0], inventory);
      return inventory;
    };
    const paths = (bytes: Buffer) =>
      JSON.parse(bytes.toString()).files.map((file: { path: string }) => file.path);
    expect(paths(prepare(real))).toHaveLength(10);

    // A transition recipe map: every client recipe is a closure member.
    const kiro = Buffer.from('{"kiro":true}\n');
    writeFileSync(join(root, "release/recipes/kiro.json"), kiro);
    const mapped = (item: Json) => {
      const content = item.materials
        .filter((member: Json) => member.role !== "behaviour")
        .map((member: Json) => member.id);
      item.recipes = {
        "claude-code": { ...item.recipe, inputs: [], materials: content },
        "kiro-ide": {
          ...item.recipe,
          path: "release/recipes/kiro.json",
          sha256: sha256(kiro),
          byteLength: kiro.length,
          inputs: [],
          materials: content,
        },
      };
      delete item.recipe;
    };
    const withMap = paths(prepare(variant(mapped)));
    expect(withMap).toContain("release/recipes/kiro.json");
    expect(withMap).toContain("release/recipes/project-basics.router.json");
    // Legacy `path` materials remain package members in 1.7.
    expect(
      paths(
        prepare(
          variant((item) => {
            const { packagePath, relPath, executable, sourceId, sourcePath, role, ...rest } =
              item.materials[0];
            item.materials[0] = { ...rest, path: packagePath };
          }),
        ),
      ),
    ).toHaveLength(10);

    for (const refused of [
      // Unsupported or mismatched document formats.
      variant((_, inventory) => {
        inventory.schema = "urn:aihq:catalog:content-inventory:1.0.0";
      }),
      variant((_, inventory) => {
        inventory.projection = "urn:aihq:catalog:release-content:1.0.0";
      }),
      variant((_, inventory) => {
        inventory.release.schema = "urn:aihq:catalog:release:1.5.0";
      }),
      variant((_, inventory) => {
        inventory.schema = "urn:aihq:catalog:content-inventory:1.1.0";
        inventory.projection = "urn:aihq:catalog:release-content:1.1.0";
        inventory.release.schema = "urn:aihq:catalog:release:1.6.0";
      }),
      variant((_, inventory) => {
        inventory.release.schema = "urn:aihq:catalog:release:1.8.0";
      }),
      variant((_, inventory) => {
        inventory.release.baseline = {};
      }),
      variant((_, inventory) => {
        inventory.release.package.name = "@other/catalog";
      }),
      // Recipe declarations: exactly one of recipe or a nonempty map.
      variant((item) => {
        mapped(item);
        item.recipe = real.release.items[0].recipe;
      }),
      variant((item) => {
        delete item.recipe;
      }),
      variant((item) => {
        delete item.recipe;
        item.recipes = {};
      }),
      variant((item) => {
        mapped(item);
        item.recipes["kiro-ide"].materials = ["undeclared"];
      }),
      variant((item) => {
        mapped(item);
        item.recipes["kiro-ide"].materials = ["behaviour"];
      }),
      variant((item) => {
        mapped(item);
        item.recipes["kiro-ide"].path = "release/recipes/missing.json";
      }),
      // Materials: one package path each, safe and consistent.
      variant((item) => {
        item.materials[0].path = item.materials[0].packagePath;
      }),
      variant((item) => {
        delete item.materials[0].packagePath;
      }),
      variant((item) => {
        item.materials[0].packagePath = "../escape.md";
      }),
      variant((item) => {
        item.materials[0].packagePath = ".git/config";
      }),
      variant((item) => {
        item.materials[0].packagePath = "release/items/project-basics.router/AIH-BEHAVIOUR.JSON";
      }),
      variant((item) => {
        item.materials[0].sha256 = "0".repeat(64);
      }),
      variant((item, inventory) => {
        inventory.release.items[1].materials[0].packagePath = item.materials[0].packagePath;
      }),
      variant((item) => {
        item.materials[0].byteLength += 1;
      }),
    ])
      expect(() => prepare(refused)).toThrow();

    // Exact canonical bytes and reviewed digest; changed staged material refuses.
    const canonical = Buffer.from(`${canonicalBytes(real)}\n`);
    const pretty = Buffer.from(`${JSON.stringify(real, null, 1)}\n`);
    writeFileSync(join(root, "release/pretty.json"), pretty);
    expect(() =>
      prepareCatalogCapture({
        root,
        inventoryPath: "release/pretty.json",
        inventorySha256: sha256(pretty),
      }),
    ).toThrow();
    expect(() =>
      prepareCatalogCapture({ root, inventoryPath, inventorySha256: sha256(Buffer.from("x")) }),
    ).toThrow();
    expect(prepare(real)).toEqual(prepare(JSON.parse(canonical.toString())));
    writeFileSync(join(root, "release/materials/project-basics/shared-block.md"), "tampered\n");
    expect(() => prepare(real)).toThrow();
    unlinkSync(join(root, "release/materials/project-basics/shared-block.md"));
    expect(() => prepare(real)).toThrow();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("acquired Catalog 1.7 envelopes refuse missing, extra and substituted members", async () => {
  const { prepareCatalogCapture, acquireCatalogCapture } = await import(
    new URL("../../tools/refresh/catalog-capture.mjs", import.meta.url).href
  );
  const { sha256, canonicalBytes, ceilings } = await import(
    new URL("../../tools/refresh/contracts.mjs", import.meta.url).href
  );
  const root = mkdtempSync(join(tmpdir(), "scan-catalog-17-envelope-"));
  try {
    cpSync(new URL("project-basics", current), root, { recursive: true });
    const inventory = readFileSync(join(root, inventoryPath));
    const bytes = prepareCatalogCapture({
      root,
      inventoryPath,
      inventorySha256: sha256(inventory),
    });
    const envelope = JSON.parse(bytes.toString());
    const acquire = (files: Record<string, unknown>[]) => {
      const changed = canonicalBytes({ ...envelope, files });
      const target = {
        commit: "b".repeat(40),
        capture: {
          releaseId: "11",
          assetId: "12",
          sha256: sha256(changed),
          byteLength: changed.length,
          inventory: envelope.inventory,
        },
      };
      return acquireCatalogCapture(target, ceilings, fixtureTransport(target, changed));
    };
    await expect(acquire(envelope.files)).resolves.toMatchObject({ files: expect.any(Array) });
    const extra = Buffer.from("extra\n");
    const substitute = Buffer.from("substituted\n");
    const behaviour = "release/items/project-basics.router/aih-behaviour.json";
    for (const files of [
      envelope.files.filter((file: { path: string }) => file.path !== behaviour),
      [
        ...envelope.files,
        {
          path: "release/zz-extra.txt",
          sha256: sha256(extra),
          byteLength: extra.length,
          bytesBase64: extra.toString("base64"),
        },
      ],
      envelope.files.map((file: { path: string }) =>
        file.path === behaviour
          ? {
              path: behaviour,
              sha256: sha256(substitute),
              byteLength: substitute.length,
              bytesBase64: substitute.toString("base64"),
            }
          : file,
      ),
    ])
      await expect(acquire(files)).rejects.toThrow();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function fixtureTransport(
  target: { commit: string; capture: { releaseId: string; assetId: string; sha256: string } },
  bytes: Buffer,
) {
  const { releaseId, assetId, sha256 } = target.capture;
  const tag = `catalog-capture-${sha256}`;
  return {
    json: (path: string): unknown =>
      path === "repos/samartomar/aih-catalog"
        ? {
            full_name: "samartomar/aih-catalog",
            private: false,
            archived: false,
            owner: { id: 9993940 },
          }
        : path.includes("/git/ref/")
          ? { ref: `refs/tags/${tag}`, object: { type: "commit", sha: target.commit } }
          : path.endsWith(`/releases/${releaseId}`)
            ? {
                id: Number(releaseId),
                immutable: true,
                draft: false,
                tag_name: tag,
                target_commitish: target.commit,
              }
            : [
                {
                  id: Number(assetId),
                  name: "catalog-capture.json",
                  state: "uploaded",
                  size: bytes.length,
                  digest: `sha256:${sha256}`,
                  url: `https://api.github.com/repos/samartomar/aih-catalog/releases/assets/${assetId}`,
                },
              ],
    bytes: () => ({ status: 200, bytes }),
  };
}
