import type { Kind } from "../contracts/routing.js";
import type { SnapshotFile } from "./snapshot.js";

/** One item found on the `source` route: its own folder, keyed exactly as if handed over. */
export interface DiscoveredItem {
  readonly kind: Kind;
  /** The item's source-relative path: a folder (skill, hooks folder) or a single file. */
  readonly path: string;
  /** The item's files with item-relative paths (a single-file item is a one-file folder). */
  readonly files: readonly SnapshotFile[];
}

export interface Discovery {
  /** Items sorted by source-relative path. */
  readonly items: readonly DiscoveredItem[];
  /** Files that belong to no item, with their source-relative paths. */
  readonly remaining: readonly SnapshotFile[];
}

const parentOf = (path: string) => {
  const slash = path.lastIndexOf("/");
  return slash < 0 ? "" : path.slice(0, slash);
};
const nameOf = (path: string) => path.slice(path.lastIndexOf("/") + 1);
const extensionOf = (path: string) => {
  const name = nameOf(path).toLowerCase();
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1) : "";
};
const inside = (path: string, folder: string) => folder === "" || path.startsWith(`${folder}/`);
const codeUnit = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** Outermost folders only: a folder inside another listed folder is dropped. */
function outermost(folders: Iterable<string>): string[] {
  const sorted = [...new Set(folders)].sort(
    (a, b) => a.split("/").length - b.split("/").length || codeUnit(a, b),
  );
  const kept: string[] = [];
  for (const folder of sorted)
    if (!kept.some((outer) => outer === "" || folder === outer || inside(folder, outer)))
      kept.push(folder);
  return kept;
}

/**
 * The single-file layout a source-relative path matches, if any. Names of the config files
 * come first, then rules (a file under a folder named `rules` at any depth, `.kiro/steering/*.md`),
 * then agents (`.md`, `.json` or `.toml` directly under a folder named `agents`) and commands
 * (`.md` directly under a folder named `commands`). Folder and file names compare exactly;
 * extensions ignore ASCII case.
 */
export function singleFileKind(path: string): Kind | undefined {
  const name = nameOf(path);
  const folders = parentOf(path) === "" ? [] : parentOf(path).split("/");
  const parent = folders.at(-1);
  const extension = extensionOf(path);
  if (name === "hooks.json") return "hook";
  if (name === ".mcp.json" || name === "mcp.json") return "mcp";
  if (folders.includes("rules")) return "rule";
  if (parent === "steering" && folders.at(-2) === ".kiro" && extension === "md") return "rule";
  if (parent === "agents" && ["md", "json", "toml"].includes(extension)) return "agent";
  if (parent === "commands" && extension === "md") return "command";
  return undefined;
}

function rebase(files: readonly SnapshotFile[], folder: string): SnapshotFile[] {
  const prefix = folder === "" ? 0 : folder.length + 1;
  return files.map((file) => Object.freeze({ ...file, path: file.path.slice(prefix) }));
}

/**
 * Finds items by the `aih-scan-routing/1` layouts anywhere in a source inventory. Each file
 * belongs to one item only: the outermost folder holding `SKILL.md` owns everything inside it
 * (nested skills included), then a folder named `hooks` holding `hooks.json` (the whole folder),
 * then single files. Everything else is the remaining files. The result depends only on the
 * inventory's paths, not on the order it was read.
 */
export function discoverItems(files: readonly SnapshotFile[]): Discovery {
  const ordered = [...files].sort((a, b) => codeUnit(a.path, b.path));
  const skills = outermost(
    ordered.filter((file) => nameOf(file.path) === "SKILL.md").map((file) => parentOf(file.path)),
  );
  const ownedBy = (path: string, folders: readonly string[]) =>
    folders.find((folder) => inside(path, folder));
  const hooks = outermost(
    ordered
      .filter(
        (file) =>
          nameOf(file.path) === "hooks.json" &&
          nameOf(parentOf(file.path)) === "hooks" &&
          parentOf(file.path) !== "" &&
          ownedBy(file.path, skills) === undefined,
      )
      .map((file) => parentOf(file.path)),
  );
  const folderFiles = new Map<string, SnapshotFile[]>();
  const items: DiscoveredItem[] = [];
  const remaining: SnapshotFile[] = [];
  for (const file of ordered) {
    const folder = ownedBy(file.path, skills) ?? ownedBy(file.path, hooks);
    if (folder !== undefined) {
      const list = folderFiles.get(folder) ?? [];
      list.push(file);
      folderFiles.set(folder, list);
      continue;
    }
    const kind = singleFileKind(file.path);
    if (kind === undefined) remaining.push(file);
    else
      items.push(
        Object.freeze({ kind, path: file.path, files: rebase([file], parentOf(file.path)) }),
      );
  }
  for (const folder of skills)
    items.push(
      Object.freeze({
        kind: "skill" as const,
        path: folder === "" ? "." : folder,
        files: Object.freeze(rebase(folderFiles.get(folder) ?? [], folder)),
      }),
    );
  for (const folder of hooks)
    items.push(
      Object.freeze({
        kind: "hook" as const,
        path: folder,
        files: Object.freeze(rebase(folderFiles.get(folder) ?? [], folder)),
      }),
    );
  items.sort((a, b) => codeUnit(a.path, b.path));
  return Object.freeze({ items: Object.freeze(items), remaining: Object.freeze(remaining) });
}
