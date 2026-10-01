import { execFileSync } from "node:child_process";
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import type { ScanRunResult } from "../../src/public/host.js";

type Assessment = Extract<ScanRunResult, { status: "assessment" }> & { preloadMarker?: string };

function npmCliPath(): string {
  const configured = process.env.npm_execpath;
  if (
    configured &&
    isAbsolute(configured) &&
    basename(configured) === "npm-cli.js" &&
    existsSync(configured)
  )
    return configured;
  const nodeDirectory = dirname(process.execPath);
  for (const candidate of [
    join(nodeDirectory, "node_modules/npm/bin/npm-cli.js"),
    resolve(nodeDirectory, "../lib/node_modules/npm/bin/npm-cli.js"),
  ])
    if (existsSync(candidate)) return candidate;
  throw new Error("npm CLI entrypoint unavailable");
}

let templateRoot: string | undefined;
let installationTemplate: string | undefined;
let casesDirectory: string | undefined;

function removeTemporaryFixture(root: string): void {
  const path = relative(resolve(tmpdir()), resolve(root));
  if (
    !path ||
    isAbsolute(path) ||
    path === ".." ||
    path.startsWith("../") ||
    path.startsWith("..\\") ||
    !basename(root).startsWith("aih-dependency-reuse-")
  )
    throw new Error("Fixture cleanup must stay within its owned temporary root");
  rmSync(root, { recursive: true, force: true });
}

beforeAll(() => {
  templateRoot = mkdtempSync(join(tmpdir(), "aih-dependency-reuse-template-"));
  const first = join(templateRoot, "installation"),
    built = join(first, "dist");
  mkdirSync(first);
  execFileSync(
    process.execPath,
    [resolve("node_modules/typescript/bin/tsc"), "-p", "tsconfig.build.json", "--outDir", built],
    { stdio: "pipe" },
  );

  cpSync(resolve("package.json"), join(first, "package.json"));
  cpSync(resolve("tools/baseline-analyzers"), join(first, "tools/baseline-analyzers"), {
    recursive: true,
  });
  const packages = execFileSync(
    process.execPath,
    [npmCliPath(), "ls", "--omit=dev", "--all", "--parseable"],
    { encoding: "utf8" },
  )
    .trim()
    .split(/\r?\n/)
    .slice(1);
  for (const packageRoot of packages) {
    const path = relative(resolve("."), packageRoot);
    if (path.startsWith("..") || !path.startsWith("node_modules"))
      throw new Error("Fixture dependency must belong to its selected checkout");
    const destination = join(templateRoot, path);
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(packageRoot, destination, { recursive: true });
  }

  // Compiled modules and common package files remain immutable after setup.
  // Case installations resolve unchanged packages through this real ancestor tree.
  installationTemplate = first;
  casesDirectory = join(templateRoot, "cases");
  mkdirSync(casesDirectory);
}, 30000);

afterAll(() => {
  if (templateRoot) removeTemporaryFixture(templateRoot);
});

function installedFixture(
  change: (installation: string) => void,
  verify: (current: Assessment, original: Assessment) => void,
  startupFlags: string[] = [],
  preparePreload?: (installation: string) => string[],
  launchFromInstallation = false,
): void {
  if (!casesDirectory || !templateRoot)
    throw new Error("Installed fixture template is unavailable");
  const root = mkdtempSync(join(casesDirectory, "aih-dependency-reuse-test-"));
  try {
    if (!installationTemplate) throw new Error("Installed fixture template is unavailable");
    const first = join(root, "first"),
      second = join(root, "second");
    cpSync(installationTemplate, first, { recursive: true });
    cpSync(installationTemplate, second, { recursive: true });
    // YAML is the only package mutated by these cases. Both processes get distinct
    // regular-file copies, while every other installed dependency stays immutable.
    for (const installation of [first, second]) {
      mkdirSync(join(installation, "node_modules"));
      cpSync(join(templateRoot, "node_modules/yaml"), join(installation, "node_modules/yaml"), {
        recursive: true,
      });
    }
    const firstFlags = preparePreload?.(first) ?? [];
    const secondFlags = preparePreload?.(second) ?? startupFlags;
    const source = join(root, "source");
    mkdirSync(source);
    writeFileSync(
      join(source, "SKILL.md"),
      "---\nname: parser-fixture\n---\n# Dependency fixture\n",
    );
    const request = {
      schema: "urn:aihq:scan:request:1.0.0",
      source: { kind: "local", path: source },
      selection: { paths: ["SKILL.md"], excludedPaths: [] },
      detectors: [
        { detectorId: "detector.aih-native", configuration: {} },
        { detectorId: "detector.aih-binding-gate", configuration: {} },
        {
          detectorId: "detector.aih-trust-lint",
          configuration: { internalScopes: [], mcpConfigPaths: [] },
        },
      ],
    };
    const priorPath = join(root, "prior.json"),
      trustPath = join(root, "trust.json"),
      firstScript = join(root, "first.mjs");
    writeFileSync(
      firstScript,
      `
import {createHash, generateKeyPairSync} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {runScan, signArtifact} from ${JSON.stringify(pathToFileURL(join(first, "dist/public/host.js")).href)};
await globalThis.__aihPreloadReady;
const result = await runScan(${JSON.stringify(request)});
if(result.status !== 'assessment') throw new Error('Fixture assessment required');
const {privateKey, publicKey} = generateKeyPairSync('ed25519');
const spki = publicKey.export({type:'spki', format:'der'});
const keyId = 'ed25519:' + createHash('sha256').update(spki).digest('hex');
const artifact = await signArtifact({report:result.report, annexes:result.annexes.map(({id,bytesBase64})=>({id,bytes:Buffer.from(bytesBase64,'base64')})), signer:{keyId,privateKey}});
writeFileSync(${JSON.stringify(priorPath)}, artifact.bytes);
writeFileSync(${JSON.stringify(trustPath)}, JSON.stringify({keys:[{identity:'independent-dependency-fixture', keyId, publicKeySpkiBase64:spki.toString('base64')}],publishers:[]}));
process.stdout.write(JSON.stringify({...result, preloadMarker:globalThis.__aihPreloadMarker}));
`,
    );
    const original = JSON.parse(
      execFileSync(process.execPath, [...firstFlags, firstScript], {
        cwd: launchFromInstallation ? first : undefined,
        encoding: "utf8",
        maxBuffer: 2 * 1024 * 1024,
      }),
    );
    change(second);
    const currentScript = join(root, "second.mjs");
    writeFileSync(
      currentScript,
      `
import {readFileSync} from 'node:fs';
import {runScan} from ${JSON.stringify(pathToFileURL(join(second, "dist/public/host.js")).href)};
await globalThis.__aihPreloadReady;
const result = await runScan({...${JSON.stringify(request)}, priorArtifacts:[{scanId:${JSON.stringify(original.scanId)},location:{kind:'file',path:${JSON.stringify(priorPath)}}}]}, {reuseTrust:JSON.parse(readFileSync(${JSON.stringify(trustPath)},'utf8'))});
process.stdout.write(JSON.stringify({...result, preloadMarker:globalThis.__aihPreloadMarker}));
`,
    );
    const current = JSON.parse(
      execFileSync(process.execPath, [...secondFlags, currentScript], {
        cwd: launchFromInstallation ? second : undefined,
        encoding: "utf8",
        maxBuffer: 2 * 1024 * 1024,
      }),
    );
    if (preparePreload === undefined)
      expect(original).toMatchObject({
        status: "assessment",
        report: {
          results: [{ outcome: "succeeded" }, { outcome: "succeeded" }, { outcome: "succeeded" }],
        },
      });
    verify(current, original);
  } finally {
    removeTemporaryFixture(root);
  }
}

test("an installed YAML parser change reruns trust while unrelated native and binding work remains reusable", () => {
  installedFixture(
    (installation) =>
      appendFileSync(
        join(installation, "node_modules/yaml/dist/parse/parser.js"),
        "\n// changed independently installed parser implementation\n",
      ),
    (current, original) => {
      expect(current).toMatchObject({
        status: "assessment",
        report: {
          results: [
            { detectorId: "detector.aih-binding-gate", observations: [{ origin: "reused" }] },
            { detectorId: "detector.aih-native", observations: [{ origin: "reused" }] },
            { detectorId: "detector.aih-trust-lint", observations: [{ origin: "fresh" }] },
          ],
        },
      });
      expect(current.report.results[2]?.observations[0]?.body.input.rulesSha256).not.toBe(
        original.report.results[2]?.observations[0]?.body.input.rulesSha256,
      );
      for (const index of [0, 1])
        expect(current.report.results[index]?.observations[0]?.body).toEqual(
          original.report.results[index]?.observations[0]?.body,
        );
    },
  );
}, 30000);

test("an unresolved installed runtime dependency refuses its detector while unrelated observations remain reusable", () => {
  installedFixture(
    (installation) => {
      const path = join(installation, "node_modules/yaml/package.json");
      const manifest = JSON.parse(readFileSync(path, "utf8"));
      manifest.dependencies = { ...manifest.dependencies, "missing-scan-fixture-package": "1.0.0" };
      writeFileSync(path, JSON.stringify(manifest));
    },
    (current) =>
      expect(current).toMatchObject({
        status: "assessment",
        report: {
          completion: "partial",
          results: [
            { detectorId: "detector.aih-binding-gate", observations: [{ origin: "reused" }] },
            { detectorId: "detector.aih-native", observations: [{ origin: "reused" }] },
            {
              detectorId: "detector.aih-trust-lint",
              outcome: "refused",
              observations: [],
              coverage: { uncoveredPaths: ["SKILL.md"], complete: false },
              diagnostics: [{ code: "implementation-material-unavailable" }],
            },
          ],
        },
      }),
  );
}, 30000);

test("changed Node startup conditions cannot admit observations from another execution condition", () => {
  installedFixture(
    () => {},
    (current) =>
      expect(current).toMatchObject({
        status: "assessment",
        report: {
          results: [
            { detectorId: "detector.aih-binding-gate", observations: [{ origin: "fresh" }] },
            { detectorId: "detector.aih-native", observations: [{ origin: "fresh" }] },
            { detectorId: "detector.aih-trust-lint", observations: [{ origin: "fresh" }] },
          ],
        },
      }),
    ["--conditions=aih-independent-fixture"],
  );
}, 30000);

test.each([
  ["quote-prefixed computed", "require('./' + 'actual.cjs');\n"],
  ["require alias", "const load = require; load('./actual.cjs');\n"],
])(
  "a %s preload dependency is refused instead of admitting stale signed observations",
  (_kind, entry) => {
    installedFixture(
      (installation) =>
        writeFileSync(
          join(installation, "preload/actual.cjs"),
          "globalThis.__aihPreloadMarker = 'changed';\n",
        ),
      (current, original) => {
        expect(original.preloadMarker).toBe("original");
        expect(current.preloadMarker).toBe("changed");
        expect(current).toMatchObject({
          status: "assessment",
          report: {
            completion: "partial",
            results: [
              "detector.aih-binding-gate",
              "detector.aih-native",
              "detector.aih-trust-lint",
            ].map((detectorId) => ({
              detectorId,
              outcome: "refused",
              observations: [],
              coverage: { uncoveredPaths: ["SKILL.md"], complete: false },
              diagnostics: [{ code: "implementation-material-unavailable" }],
            })),
          },
        });
      },
      [],
      (installation) => {
        const directory = join(installation, "preload");
        mkdirSync(directory);
        writeFileSync(join(directory, "entry.cjs"), entry);
        writeFileSync(join(directory, "index.js"), "// unchanged unused resolution fallback\n");
        writeFileSync(
          join(directory, "actual.cjs"),
          "globalThis.__aihPreloadMarker = 'original';\n",
        );
        return ["--require", join(directory, "entry.cjs")];
      },
    );
  },
  30000,
);

test("relative startup preloads resolve from each Node launch working directory", () => {
  installedFixture(
    () => {},
    (current, original) => {
      expect(original.preloadMarker).toBe("relative-preload");
      expect(current.preloadMarker).toBe("relative-preload");
      expect(original.report.results.map((result) => result.outcome)).toEqual([
        "succeeded",
        "succeeded",
        "succeeded",
      ]);
      expect(current).toMatchObject({
        status: "assessment",
        report: {
          results: [
            "detector.aih-binding-gate",
            "detector.aih-native",
            "detector.aih-trust-lint",
          ].map((detectorId) => ({
            detectorId,
            outcome: "succeeded",
            observations: [{ origin: "reused" }],
          })),
        },
      });
    },
    [],
    (installation) => {
      const directory = join(installation, "preload");
      mkdirSync(directory);
      writeFileSync(join(directory, "entry.cjs"), "require('./actual.cjs');\n");
      writeFileSync(
        join(directory, "actual.cjs"),
        "globalThis.__aihPreloadMarker = 'relative-preload';\n",
      );
      return ["-r", "./preload/entry.cjs"];
    },
    true,
  );
}, 30000);

test.each([
  ["commented literal", "require /* acquisition comment */ ('./actual.cjs');\n"],
  ["escaped literal and identifier", "requ\\u0069re('.\\x2factual.cjs');\n"],
  [
    "JavaScript relational expression",
    "globalThis.__aihPreloadReady = new Promise(resolve => { globalThis.__aihResolvePreload = resolve; });\nconst a=0,b=0; a < typeof import('./actual.cjs') > (b);\n",
  ],
])(
  "a %s preload call binds the dependency actually executed by Node",
  (_kind, entry) => {
    installedFixture(
      (installation) =>
        writeFileSync(
          join(installation, "preload/actual.cjs"),
          "globalThis.__aihPreloadMarker = 'changed'; globalThis.__aihResolvePreload?.();\n",
        ),
      (current, original) => {
        expect(original.preloadMarker).toBe("original");
        expect(current.preloadMarker).toBe("changed");
        expect(original.report.results.map((result) => result.outcome)).toEqual([
          "succeeded",
          "succeeded",
          "succeeded",
        ]);
        expect(current).toMatchObject({
          status: "assessment",
          report: {
            results: [
              "detector.aih-binding-gate",
              "detector.aih-native",
              "detector.aih-trust-lint",
            ].map((detectorId) => ({
              detectorId,
              outcome: "succeeded",
              observations: [{ origin: "fresh" }],
            })),
          },
        });
        for (const index of [0, 1, 2])
          expect(current.report.results[index]?.observations[0]?.body.input.adapterSha256).not.toBe(
            original.report.results[index]?.observations[0]?.body.input.adapterSha256,
          );
      },
      [],
      (installation) => {
        const directory = join(installation, "preload");
        mkdirSync(directory);
        writeFileSync(join(directory, "entry.cjs"), entry);
        writeFileSync(
          join(directory, "actual.cjs"),
          "globalThis.__aihPreloadMarker = 'original'; globalThis.__aihResolvePreload?.();\n",
        );
        return ["--require", join(directory, "entry.cjs")];
      },
    );
  },
  30000,
);
