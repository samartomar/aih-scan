import type { ChildProcess, SpawnOptions } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";

// [DEBUG-retro-linux] Temporary failure evidence. Never reads argv or environment values.
function state(pid: number) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const close = stat.lastIndexOf(")");
    const fields = stat
      .slice(close + 1)
      .trim()
      .split(/\s+/u);
    return {
      pid,
      name: stat.slice(stat.indexOf("(") + 1, close).slice(0, 64),
      state: fields[0],
      parent: Number(fields[1]),
      group: Number(fields[2]),
      session: Number(fields[3]),
    };
  } catch (error) {
    return { pid, state: "unreadable", error: (error as NodeJS.ErrnoException).code };
  }
}

export function linuxPidEvidence(pids: readonly number[]) {
  return process.platform === "linux" ? pids.map(state) : { platform: process.platform };
}

/** Observes only the detached Git helper spawned in one disposable fixture's exact cwd. */
export function observeLinuxGitGroups(cwd: string) {
  const groups = new Set<number>();
  const childProcess = createRequire(import.meta.url)(
    "node:child_process",
  ) as typeof import("node:child_process");
  const original = childProcess.spawn;
  if (process.platform === "linux") {
    Object.defineProperty(childProcess, "spawn", {
      value: (...values: unknown[]) => {
        const [command, argv, options] = values as [string, string[], SpawnOptions];
        const child = Reflect.apply(original, childProcess, values) as ChildProcess;
        if (
          command === process.execPath &&
          Array.isArray(argv) &&
          /[/\\]git-command\.[jt]s$/u.test(argv[0] ?? "") &&
          options?.cwd === cwd &&
          options.detached === true &&
          child.pid !== undefined
        )
          groups.add(child.pid);
        return child;
      },
    });
    syncBuiltinESMExports();
  }
  return {
    snapshot() {
      if (process.platform !== "linux") return { platform: process.platform };
      const members = readdirSync("/proc")
        .filter((name) => /^\d+$/u.test(name))
        .slice(0, 4096)
        .map((name) => state(Number(name)))
        .filter((entry) => typeof entry.group === "number" && groups.has(entry.group))
        .slice(0, 128);
      return { leaders: [...groups].map(state), members };
    },
    dispose() {
      if (process.platform !== "linux") return;
      Object.defineProperty(childProcess, "spawn", { value: original });
      syncBuiltinESMExports();
    },
  };
}
