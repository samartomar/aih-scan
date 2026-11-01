import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

export interface TarEntry {
  readonly path: string;
  readonly text?: string | Uint8Array;
  readonly mode?: number;
  /** ustar type flag: 0 file, 1 hard link, 2 symbolic link, 3 character device, 5 folder. */
  readonly type?: string;
  readonly link?: string;
}

/** A gzipped ustar archive built byte by byte, so hostile entries can be expressed. */
export function npmTarball(entries: readonly TarEntry[]): Uint8Array {
  const expanded: TarEntry[] = [];
  for (const entry of entries) {
    if (Buffer.byteLength(entry.path) > 99) {
      // A PAX extended header carries a long path; the ustar name field holds a placeholder.
      const body = ` path=${entry.path}\n`;
      let length = body.length + 1;
      while (`${length}${body}`.length !== length) length += 1;
      expanded.push({ path: "PaxHeader/long", type: "x", text: `${length}${body}` });
      expanded.push({ ...entry, path: "placeholder" });
    } else expanded.push(entry);
  }
  const blocks: Buffer[] = [];
  for (const { path, text = "", mode = 0o644, type = "0", link = "" } of expanded) {
    const data = Buffer.from(text);
    const header = Buffer.alloc(512);
    header.write(path, 0, 100, "utf8");
    for (const [offset, length, value] of [
      [100, 8, mode],
      [108, 8, 0],
      [116, 8, 0],
      [124, 12, type === "0" || type === "x" ? data.length : 0],
      [136, 12, 0],
    ] as const)
      header.write(`${value.toString(8).padStart(length - 1, "0")}\0`, offset, length, "ascii");
    header.fill(32, 148, 156);
    header.write(type, 156);
    header.write(link, 157, 100);
    header.write("ustar\0", 257);
    header.write("00", 263);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8);
    blocks.push(header);
    if (type === "0" || type === "x")
      blocks.push(data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  return new Uint8Array(gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)])));
}

export const integrityOf = (bytes: Uint8Array) =>
  `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
export const sha256Of = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

export interface RegistryCall {
  readonly url: string;
  readonly init: RequestInit;
}

/**
 * A local stand-in for the public npm registry: answers exact-version metadata and the tarball
 * it names, records every request and never touches the network.
 */
export function registryStub(
  packages: Readonly<
    Record<string, Readonly<{ tarball: Uint8Array; integrity?: string; name?: string }>>
  >,
) {
  const calls: RegistryCall[] = [];
  const fetch = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    for (const [spec, entry] of Object.entries(packages)) {
      const at = spec.lastIndexOf("@");
      const name = spec.slice(0, at);
      const version = spec.slice(at + 1);
      const tarballUrl = `https://registry.example.invalid/${encodeURIComponent(name)}-${version}.tgz`;
      if (url === `https://registry.npmjs.org/${name.replace("/", "%2f")}/${version}`)
        return new Response(
          JSON.stringify({
            name: entry.name ?? name,
            version,
            dist: { tarball: tarballUrl, integrity: entry.integrity ?? integrityOf(entry.tarball) },
          }),
        );
      if (url === tarballUrl) return new Response(entry.tarball);
    }
    return new Response("not found", { status: 404 });
  };
  return { fetch, calls };
}
