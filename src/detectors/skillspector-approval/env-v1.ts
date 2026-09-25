/**
 * Child-environment scrubbing for `detector.skillspector`, ported verbatim in
 * behaviour from Core's `src/trust/fetch.ts` (`scrubFetchEnv` /
 * `scrubDockerClientEnv`). A Docker client spawn inherits only allow-listed,
 * non-secret variables, plus the two Linux session variables Docker needs to
 * reach its socket.
 */

const SAFE_ENV_KEYS_V1 = new Set([
  "ALLUSERSPROFILE",
  "APPDATA",
  "COMSPEC",
  "HOME",
  "HOMEDRIVE",
  "HOMEPATH",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "LANG",
  "LOCALAPPDATA",
  "NO_PROXY",
  "NODE_EXTRA_CA_CERTS",
  "PATH",
  "PATHEXT",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USERPROFILE",
  "UV_CACHE_DIR",
  "WINDIR",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
]);

function isSecretEnvKeyV1(key: string): boolean {
  const upper = key.toUpperCase();
  return (
    upper.includes("TOKEN") ||
    upper.includes("SECRET") ||
    upper.includes("PASSWORD") ||
    upper.endsWith("_KEY") ||
    upper.endsWith("_CREDENTIALS") ||
    upper.startsWith("AWS_") ||
    upper.startsWith("GITHUB_") ||
    upper.startsWith("ANTHROPIC_") ||
    upper.startsWith("OPENAI_")
  );
}

export function scrubFetchEnvV1(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || isSecretEnvKeyV1(key)) continue;
    if (SAFE_ENV_KEYS_V1.has(key.toUpperCase())) out[key] = value;
  }
  return out;
}

export function scrubDockerClientEnvV1(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out = scrubFetchEnvV1(env);
  const dbus = env.DBUS_SESSION_BUS_ADDRESS;
  if (typeof dbus === "string" && dbus.length > 0) {
    out.DBUS_SESSION_BUS_ADDRESS = dbus;
  }
  const xdgRuntimeDir = env.XDG_RUNTIME_DIR;
  if (typeof xdgRuntimeDir === "string" && xdgRuntimeDir.length > 0) {
    out.XDG_RUNTIME_DIR = xdgRuntimeDir;
  }
  return out;
}
