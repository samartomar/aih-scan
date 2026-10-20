import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";

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
