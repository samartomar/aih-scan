import { randomUUID } from "node:crypto";
import { SKILLSPECTOR_IMAGE_TAG_V1 } from "./image-identity-v1.js";

/**
 * argv planning for `detector.skillspector`, ported verbatim in behaviour from
 * Core's `src/trust/detectors.ts` (`skillspectorDockerRunArgv`, the cleanup
 * argv) with Core's `dockerBindMountArg` and `execArgv` inlined so the module
 * stands alone. No function here spawns anything; the runtime supplies the
 * runner.
 *
 * `docker` is not one of the Windows `.cmd` shims, so `execArgvV1` leaves every
 * argv below unchanged on every platform; the shim logic is retained so the
 * planning stays byte-identical to Core's if a shimmed executable is ever
 * planned through it.
 */

export type SkillspectorPlatformV1 = "windows" | "darwin" | "linux";

const WIN_CMD_SHIMS_V1 = new Set(["claude", "npm", "npx", "pnpm", "scoop", "yarn"]);

/**
 * cmd.exe command-injection / expansion metacharacters: chaining (`&` `|`),
 * redirection (`<` `>`), escape (`^`), quote-breaking (`"`), variable expansion
 * (`%VAR%`) and delayed expansion (`!VAR!`), and newlines.
 */
const CMD_INJECTION_V1 = /[&|<>^%!\r\n"]/;

function assertNoCmdInjectionV1(value: string, label: string): void {
  if (CMD_INJECTION_V1.test(value)) {
    throw new TypeError(
      `${label} contains a shell metacharacter (one of & | < > ^ % ! " or a newline) that is ` +
        `unsafe for a Windows cmd launcher: ${JSON.stringify(value)}`,
    );
  }
}

/**
 * Windows can't `execFile` a `.cmd` shim directly, so those route through
 * `cmd /c`. Every argv this engine plans starts with `docker`, which is not a
 * shim, so the returned argv equals the input on all platforms.
 */
export function execArgvV1(platform: SkillspectorPlatformV1, argv: string[]): string[] {
  if (platform !== "windows" || argv[0] === undefined || !WIN_CMD_SHIMS_V1.has(argv[0]))
    return argv;
  for (const [index, arg] of argv.entries()) {
    assertNoCmdInjectionV1(arg, `Windows ${argv[0]} shim argv[${index}]`);
  }
  return ["cmd", "/c", ...argv];
}

function hasUnsupportedMountSourceCharV1(value: string): boolean {
  return [...value].some((char) => {
    const code = char.charCodeAt(0);
    return char === "," || code <= 0x1f || code === 0x7f;
  });
}

/**
 * Whether a bind-mount source path is representable at all (C2a §6.3: a comma
 * or control character is refused before spawning). Exported so the run layer
 * can refuse with a typed outcome instead of catching the argv builder's throw.
 */
export function hasUnsupportedDockerMountSourceCharV1(value: string): boolean {
  return hasUnsupportedMountSourceCharV1(value);
}

/** A Docker bind-mount specification; rejects paths a mount spec cannot represent. */
export function skillspectorDockerBindMountArgV1(source: string, target: string): string {
  if (hasUnsupportedMountSourceCharV1(source)) {
    throw new TypeError("unsupported Docker bind mount source path: comma/control characters");
  }
  return `type=bind,source=${source},target=${target},readonly`;
}

export function skillspectorDockerVersionArgvV1(platform: SkillspectorPlatformV1): string[] {
  return execArgvV1(platform, ["docker", "--version"]);
}

export function skillspectorImageInspectArgvV1(platform: SkillspectorPlatformV1): string[] {
  return execArgvV1(platform, [
    "docker",
    "image",
    "inspect",
    SKILLSPECTOR_IMAGE_TAG_V1,
    "--format",
    "{{json .}}",
  ]);
}

export function skillspectorDockerRunArgvV1(
  platform: SkillspectorPlatformV1,
  tree: string,
  image: string = SKILLSPECTOR_IMAGE_TAG_V1,
  containerName = `aih-skillspector-${randomUUID()}`,
): string[] {
  // Native Windows Docker bind mounts can reject drive-letter paths; that fails safe to skip.
  return execArgvV1(platform, [
    "docker",
    "run",
    "--rm",
    "--name",
    containerName,
    "--network",
    "none",
    "--cpus",
    "2",
    "--memory",
    "4g",
    "--memory-swap",
    "4g",
    "--pids-limit",
    "256",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "DAC_OVERRIDE",
    "--security-opt",
    "no-new-privileges",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=64m",
    "--mount",
    skillspectorDockerBindMountArgV1(tree, "/scan"),
    image,
    "scan",
    "/scan",
    "--no-llm",
    "--format",
    "sarif",
  ]);
}

/** Force-removes a bounded scan container after a spawn error or truncated output. */
export function skillspectorDockerCleanupArgvV1(
  platform: SkillspectorPlatformV1,
  containerName: string,
): string[] {
  return execArgvV1(platform, ["docker", "rm", "--force", "--volumes", containerName]);
}
