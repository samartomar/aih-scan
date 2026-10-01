import { createHash } from "node:crypto";
import {
  type BigIntStats,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
} from "node:fs";
import { createRequire, isBuiltin } from "node:module";
import { dirname, extname, isAbsolute, join, relative, resolve } from "node:path";
import { parse } from "@babel/parser";

/** A fresh, bounded installation snapshot shared only by one assessment. */
export interface ImplementationDigester {
  digest(...entries: string[]): Promise<string>;
  assertUnchanged(): void;
}

const caps = { files: 20_000, bytes: 256 * 1024 * 1024, packages: 256, depth: 64 };
function unavailable(): never {
  throw new Error("Complete installed implementation material is unavailable");
}
const hash = (bytes: Uint8Array | string): string =>
  createHash("sha256").update(bytes).digest("hex");
const same = (a: BigIntStats, b: BigIntStats): boolean =>
  a.dev === b.dev &&
  a.ino === b.ino &&
  a.size === b.size &&
  a.mtimeNs === b.mtimeNs &&
  a.ctimeNs === b.ctimeNs &&
  a.mode === b.mode &&
  a.nlink === b.nlink;
const within = (root: string, path: string): boolean => {
  const name = relative(root, path);
  return (
    name === "" ||
    (!isAbsolute(name) && name !== ".." && !name.startsWith(`..\\`) && !name.startsWith("../"))
  );
};
const portable = (root: string, path: string): string => relative(root, path).replaceAll("\\", "/");
type PackageManifest = {
  name?: unknown;
  version?: unknown;
  dependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  peerDependenciesMeta?: Record<string, { optional?: unknown }>;
};
type PackageNode = {
  root: string;
  name: string;
  version: string;
  files: { path: string; sha256: string }[];
  edges: { name: string; target: string | null }[];
};

/**
 * Local runtime imports select exact module closures. A resolved external package is a
 * conservative unit: bind its complete tree and installed runtime/optional/peer graph,
 * rather than guessing which conditional entry or dynamic internal import it executes.
 * Installations must remain immutable for the life of the process that loaded them.
 */
export function createImplementationDigester(options: {
  moduleRoot: string;
  extension: string;
}): ImplementationDigester {
  const root = resolve(options.moduleRoot);
  const bindingWorkingDirectory = process.cwd();
  const startup = (): string =>
    JSON.stringify({ argv: process.execArgv, nodeOptions: process.env.NODE_OPTIONS ?? "" });
  const startupIdentity = startup();
  const snapshots = new Map<string, BigIntStats>();
  const contents = new Map<string, { bytes: Buffer; sha256: string }>();
  const packages = new Map<string, PackageNode>();
  let totalBytes = 0;
  const absent: { name: string; parent: string }[] = [];
  const stat = (path: string): BigIntStats => lstatSync(path, { bigint: true });
  const remember = (path: string, value: BigIntStats): void => {
    const previous = snapshots.get(path);
    if (previous && !same(previous, value)) unavailable();
    if (!previous && snapshots.size >= caps.files * 2) unavailable();
    snapshots.set(path, value);
  };
  const read = (path: string): { bytes: Buffer; sha256: string } => {
    const cached = contents.get(path);
    if (cached) {
      const before = snapshots.get(path);
      if (!before || !same(before, stat(path))) unavailable();
      return cached;
    }
    if (contents.size >= caps.files) unavailable();
    const before = stat(path);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) unavailable();
    if (before.size > BigInt(caps.bytes - totalBytes)) unavailable();
    const fd = openSync(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    try {
      if (!same(before, fstatSync(fd, { bigint: true }))) unavailable();
      const bytes = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < bytes.length) {
        const count = readSync(
          fd,
          bytes,
          offset,
          Math.min(64 * 1024, bytes.length - offset),
          offset,
        );
        if (count === 0) unavailable();
        offset += count;
      }
      if (!same(before, fstatSync(fd, { bigint: true })) || !same(before, stat(path)))
        unavailable();
      totalBytes += bytes.length;
      remember(path, before);
      const value = { bytes, sha256: hash(bytes) };
      contents.set(path, value);
      return value;
    } finally {
      closeSync(fd);
    }
  };
  const directory = (path: string): string[] => {
    const before = stat(path);
    if (!before.isDirectory() || before.isSymbolicLink()) unavailable();
    const names = readdirSync(path).sort();
    if (names.length > caps.files) unavailable();
    if (!same(before, stat(path))) unavailable();
    remember(path, before);
    return names;
  };
  const manifest = (path: string): PackageManifest => {
    const parsed: unknown = JSON.parse(read(path).bytes.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) unavailable();
    return parsed as PackageManifest;
  };
  const resolvePackage = (specifier: string, parent: string): string => {
    if (
      specifier.startsWith("#") ||
      specifier.includes(":") ||
      specifier.startsWith("/") ||
      specifier.startsWith("\\")
    )
      unavailable();
    const resolved = createRequire(parent).resolve(specifier);
    let current = dirname(resolved);
    for (let depth = 0; depth < caps.depth; depth++) {
      const names = directory(current);
      if (names.includes("package.json")) {
        const value = manifest(join(current, "package.json"));
        if (typeof value.name === "string" && typeof value.version === "string") return current;
      }
      const next = dirname(current);
      if (next === current) break;
      current = next;
    }
    return unavailable();
  };
  const packageNode = (packageRoot: string, depth = 0): PackageNode => {
    const cached = packages.get(packageRoot);
    if (cached) return cached;
    if (depth >= caps.depth || packages.size >= caps.packages) unavailable();
    const value = manifest(join(packageRoot, "package.json"));
    if (typeof value.name !== "string" || typeof value.version !== "string") unavailable();
    const node: PackageNode = {
      root: packageRoot,
      name: value.name,
      version: value.version,
      files: [],
      edges: [],
    };
    packages.set(packageRoot, node);
    const walk = (path: string, level: number): void => {
      if (level >= caps.depth) unavailable();
      for (const name of directory(path)) {
        // Runtime dependencies are separate resolved nodes, never an ambient node_modules sweep.
        if (name === "node_modules") continue;
        const file = join(path, name),
          entry = stat(file);
        if (entry.isDirectory() && !entry.isSymbolicLink()) walk(file, level + 1);
        else node.files.push({ path: portable(packageRoot, file), sha256: read(file).sha256 });
      }
    };
    walk(packageRoot, 0);
    node.files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    const requirements = new Map<string, boolean>();
    for (const [field, optional] of [
      [value.dependencies, false],
      [value.peerDependencies, false],
      [value.optionalDependencies, true],
    ] as const) {
      if (field !== undefined && (!field || typeof field !== "object" || Array.isArray(field)))
        unavailable();
      for (const name of Object.keys(field ?? {}).sort()) {
        if (typeof field?.[name] !== "string") unavailable();
        requirements.set(
          name,
          optional ||
            (value.peerDependenciesMeta?.[name]?.optional === true &&
              field === value.peerDependencies),
        );
      }
    }
    for (const [name, optional] of [...requirements].sort(([a], [b]) => (a < b ? -1 : 1))) {
      let target: string;
      try {
        target = resolvePackage(name, join(packageRoot, "package.json"));
      } catch (error) {
        if (optional && (error as NodeJS.ErrnoException).code === "MODULE_NOT_FOUND") {
          absent.push({ name, parent: join(packageRoot, "package.json") });
          node.edges.push({ name, target: null });
          continue;
        }
        throw error;
      }
      node.edges.push({ name, target });
      packageNode(target, depth + 1);
    }
    return node;
  };
  const boundArguments: string[] = [];
  const preloadFiles: string[] = [];
  let startupUnsupported = startupIdentity.length > 64 * 1024;
  for (let index = 0; index < process.execArgv.length; index++) {
    const argument = process.execArgv[index] ?? "";
    if (argument === "--require" || argument === "-r" || argument.startsWith("--require=")) {
      const preload = argument.startsWith("--require=")
        ? argument.slice(10)
        : process.execArgv[++index];
      try {
        if (!preload) unavailable();
        // Node resolves command-line preloads from its launch cwd. The current
        // cwd alone cannot prove that history: require a matching already-loaded
        // startup module, otherwise refuse rather than bind an unexecuted file.
        const startupRequire = createRequire(join(bindingWorkingDirectory, ".aih-preload.cjs"));
        const file = startupRequire.resolve(preload);
        const loaded = startupRequire.cache[file];
        if (!loaded?.loaded || loaded.parent?.id !== "internal/preload") unavailable();
        boundArguments.push("--require", `preload:${preloadFiles.length}`);
        preloadFiles.push(file);
      } catch {
        startupUnsupported = true;
      }
    } else boundArguments.push(argument);
  }
  startupUnsupported ||=
    /--(?:experimental-)?loader(?:=|\s|$)|--import(?:=|\s|$)|--require(?:=|\s|$)|(?:^|\s)-r/.test(
      [
        ...boundArguments.filter((argument) => argument !== "--require"),
        process.env.NODE_OPTIONS ?? "",
      ].join(" "),
    );
  const boundStartup = JSON.stringify({
    argv: boundArguments,
    nodeOptions: process.env.NODE_OPTIONS ?? "",
  });
  const extractedImports = new Map<Buffer, string[]>();
  const runtimeImports = (bytes: Buffer, file: string): string[] => {
    const cached = extractedImports.get(bytes);
    if (cached) return cached;
    // Bound allocation before parsing, then bound the syntax traversal independently.
    if (bytes.length > 1024 * 1024) unavailable();
    const ast = parse(bytes.toString("utf8"), {
      sourceType: "unambiguous",
      plugins: [".ts", ".mts", ".cts"].includes(extname(file)) ? ["typescript"] : [],
      createImportExpressions: true,
      attachComment: false,
      allowReturnOutsideFunction: true,
    });
    type SyntaxNode = { type: string; [key: string]: unknown };
    const node = (value: unknown): SyntaxNode | undefined =>
      value !== null &&
      typeof value === "object" &&
      "type" in value &&
      typeof value.type === "string"
        ? (value as SyntaxNode)
        : undefined;
    const literal = (value: unknown): string => {
      const argument = node(value);
      if (argument?.type !== "StringLiteral" || typeof argument.value !== "string") unavailable();
      return argument.value;
    };
    const imports = new Set<string>();
    const pending: { value: SyntaxNode; parent?: SyntaxNode; key?: string; depth: number }[] = [
      { value: ast as unknown as SyntaxNode, depth: 0 },
    ];
    const typeOnly = new Set([
      "TSImportType",
      "TSTypeAnnotation",
      "TSTypeAliasDeclaration",
      "TSInterfaceDeclaration",
      "TSTypeParameterDeclaration",
      "TSTypeParameterInstantiation",
      "TSDeclareFunction",
    ]);
    const unsupported = new Set([
      "eval",
      "Function",
      "createRequire",
      "_load",
      "register",
      "registerHooks",
    ]);
    let visited = 0;
    while (pending.length) {
      const item = pending.pop();
      if (!item || ++visited > 100_000 || item.depth >= caps.depth) unavailable();
      const value = item.value;
      if (typeOnly.has(value.type) || value.declare === true) continue;
      if (value.importKind === "type" || value.exportKind === "type") continue;
      if (value.type === "TSImportEqualsDeclaration") unavailable();
      if (
        value.type === "ImportDeclaration" ||
        value.type === "ExportNamedDeclaration" ||
        value.type === "ExportAllDeclaration"
      ) {
        const specifiers = Array.isArray(value.specifiers) ? value.specifiers : [];
        if (
          specifiers.length > 0 &&
          specifiers.every((specifier) => {
            const part = node(specifier);
            return part?.importKind === "type" || part?.exportKind === "type";
          })
        )
          continue;
        if (value.source) imports.add(literal(value.source));
      }
      if (value.type === "ImportExpression") {
        if (value.options != null) unavailable();
        imports.add(literal(value.source));
      }
      if (
        value.type === "CallExpression" &&
        node(value.callee)?.type === "Identifier" &&
        node(value.callee)?.name === "require"
      ) {
        if (!Array.isArray(value.arguments) || value.arguments.length !== 1) unavailable();
        imports.add(literal(value.arguments[0]));
      }
      if (value.type === "Identifier" && value.name === "require") {
        // A reference used to construct an alias or alternate require API is unknown.
        if (
          item.key !== "callee" ||
          item.parent?.type !== "CallExpression" ||
          item.parent.callee !== value
        )
          unavailable();
      }
      if (
        value.type === "Identifier" &&
        typeof value.name === "string" &&
        unsupported.has(value.name)
      )
        unavailable();
      if (
        (value.type === "MemberExpression" || value.type === "OptionalMemberExpression") &&
        value.computed === true
      ) {
        const property = node(value.property);
        if (
          property?.type === "StringLiteral" &&
          typeof property.value === "string" &&
          (unsupported.has(property.value) || property.value === "require")
        )
          unavailable();
      }
      for (const [key, child] of Object.entries(value)) {
        if (
          [
            "loc",
            "extra",
            "comments",
            "leadingComments",
            "innerComments",
            "trailingComments",
            "typeAnnotation",
            "typeParameters",
            "returnType",
            "superTypeParameters",
            "implements",
          ].includes(key)
        )
          continue;
        for (const candidate of Array.isArray(child) ? child : [child]) {
          const nested = node(candidate);
          if (nested) pending.push({ value: nested, parent: value, key, depth: item.depth + 1 });
        }
      }
    }
    if (imports.has("vm") || imports.has("node:vm")) unavailable();
    const result = [...imports].sort();
    extractedImports.set(bytes, result);
    return result;
  };
  const assertUnchanged = (): void => {
    // Conditional exports and Node startup flags select runtime behavior.
    if (startup() !== startupIdentity) unavailable();
    if (preloadFiles.length > 0 && process.cwd() !== bindingWorkingDirectory) unavailable();
    for (const { name, parent } of absent) {
      try {
        createRequire(parent).resolve(name);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "MODULE_NOT_FOUND") continue;
      }
      unavailable();
    }
    for (const [path, before] of snapshots) if (!same(before, stat(path))) unavailable();
  };
  return {
    assertUnchanged,
    async digest(...entries) {
      try {
        if (startupUnsupported) unavailable();
        assertUnchanged();
        const pending = entries.map((entry) => resolve(root, `${entry}${options.extension}`));
        const local = new Map<string, string>();
        const roots: { from: string; specifier: string; target: string }[] = [];
        while (pending.length) {
          const file = pending.pop();
          if (file === undefined) unavailable();
          if (!within(root, file)) unavailable();
          if (local.has(file)) continue;
          const content = read(file);
          local.set(file, content.sha256);
          for (const specifier of runtimeImports(content.bytes, file)) {
            if (isBuiltin(specifier)) continue;
            if (specifier.startsWith("."))
              pending.push(resolve(dirname(file), specifier.replace(/\.js$/, options.extension)));
            else {
              const target = resolvePackage(specifier, file);
              packageNode(target);
              if (roots.length >= caps.files) unavailable();
              roots.push({ from: portable(root, file), specifier, target });
            }
          }
        }
        const preloads: {
          sha256: string;
          imports: { specifier: string; local?: number; package?: string }[];
        }[][] = [];
        for (const [preloadIndex, entry] of preloadFiles.entries()) {
          const files: {
            sha256: string;
            imports: { specifier: string; local?: number; package?: string }[];
          }[] = [];
          const seen = new Map<string, number>();
          const visitFile = (file: string, depth: number): number => {
            const existing = seen.get(file);
            if (existing !== undefined) return existing;
            if (depth >= caps.depth) unavailable();
            const id = files.length;
            seen.set(file, id);
            const content = read(file);
            const node = {
              sha256: content.sha256,
              imports: [] as { specifier: string; local?: number; package?: string }[],
            };
            files.push(node);
            const imports = runtimeImports(content.bytes, file);
            for (const specifier of imports) {
              if (isBuiltin(specifier)) continue;
              if (specifier.startsWith(".")) {
                const imported = createRequire(file).resolve(specifier);
                node.imports.push({ specifier, local: visitFile(imported, depth + 1) });
              } else {
                const target = resolvePackage(specifier, file);
                packageNode(target);
                if (roots.length >= caps.files) unavailable();
                roots.push({ from: `preload:${preloadIndex}:${id}`, specifier, target });
                node.imports.push({ specifier, package: target });
              }
            }
            return id;
          };
          visitFile(entry, 0);
          preloads.push(files);
        }
        roots.sort((a, b) =>
          a.from < b.from ? -1 : a.from > b.from ? 1 : a.specifier < b.specifier ? -1 : 1,
        );
        const ordered: PackageNode[] = [];
        const ids = new Map<string, number>();
        const visit = (path: string): number => {
          const existing = ids.get(path);
          if (existing !== undefined) return existing;
          const index = ordered.length;
          ids.set(path, index);
          const node = packages.get(path);
          if (!node) unavailable();
          ordered.push(node);
          for (const edge of node.edges) if (edge.target !== null) visit(edge.target);
          return index;
        };
        for (const edge of roots) visit(edge.target);
        const result = hash(
          JSON.stringify({
            startupSha256: hash(boundStartup),
            preloads: preloads.map((files) =>
              files.map((file) => ({
                sha256: file.sha256,
                imports: file.imports.map((edge) => ({
                  specifier: edge.specifier,
                  ...(edge.local === undefined
                    ? { package: ids.get(edge.package ?? "") }
                    : { local: edge.local }),
                })),
              })),
            ),
            local: [...local]
              .map(([path, sha256]) => ({ path: portable(root, path), sha256 }))
              .sort((a, b) => (a.path < b.path ? -1 : 1)),
            roots: roots.map((edge) => ({
              from: edge.from,
              specifier: edge.specifier,
              target: ids.get(edge.target),
            })),
            packages: ordered.map((node) => ({
              name: node.name,
              version: node.version,
              files: node.files,
              edges: node.edges.map((edge) => ({
                name: edge.name,
                target: edge.target === null ? null : ids.get(edge.target),
              })),
            })),
          }),
        );
        assertUnchanged();
        return result;
      } catch (error) {
        // Never reuse a partially populated package node after unsupported resolution.
        // Stable byte snapshots remain useful to unrelated detector closures.
        packages.clear();
        throw error;
      }
    },
  };
}
