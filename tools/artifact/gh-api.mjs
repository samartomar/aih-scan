// Normal gh CLI authentication only. No token extraction/export and no shell.
import { spawnSync } from "node:child_process";
import { parseJson } from "../refresh/contracts.mjs";

export function ghApi({ command = spawnSync } = {}) {
  function bytes(
    path,
    {
      method = "GET",
      body,
      maximum = 2097152,
      accept = "application/vnd.github+json",
      timeout = 30000,
    } = {},
  ) {
    const args = [
      "api",
      path,
      "--method",
      method,
      "--include",
      "-H",
      `Accept: ${accept}`,
      "-H",
      "X-GitHub-Api-Version: 2022-11-28",
    ];
    if (body !== undefined)
      args.push(
        "--input",
        "-",
        "-H",
        `Content-Type: ${accept === "application/octet-stream" ? "application/octet-stream" : "application/json"}`,
      );
    const result = command("gh", args, {
      input:
        body === undefined
          ? undefined
          : Buffer.isBuffer(body)
            ? body
            : Buffer.from(JSON.stringify(body)),
      encoding: "buffer",
      maxBuffer: maximum + 65536,
      timeout,
      windowsHide: true,
    });
    if (result.error) throw new Error("Normal gh command failed or exceeded bound");
    const output = Buffer.from(result.stdout ?? []);
    let end = output.indexOf("\r\n\r\n"),
      separator = 4;
    if (end < 0) {
      end = output.indexOf("\n\n");
      separator = 2;
    }
    if (end < 0 || end > 65536) throw new Error("Normal gh HTTP status unavailable");
    const status = Number(
      /^HTTP\/[^ ]+ (\d{3})/.exec(output.subarray(0, end).toString("ascii"))?.[1],
    );
    const response = output.subarray(end + separator);
    if (response.length > maximum || !Number.isInteger(status))
      throw new Error("Normal gh response bound exceeded");
    if (result.status !== 0 && status < 400) throw new Error("Normal gh request failed");
    return { status, bytes: response };
  }
  const json = (path, options) => {
    const response = bytes(path, options);
    if (response.status === 404) return null;
    if (response.status < 200 || response.status >= 300)
      throw new Error("Normal gh API permission or response refused");
    return parseJson(response.bytes, options?.maximum ?? 2097152);
  };
  return { bytes, json };
}
