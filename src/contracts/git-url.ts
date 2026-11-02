/** Spelled shape of a supported repository URL: https, a host, an optional path, nothing else. */
export const GIT_REPOSITORY_URL_PATTERN =
  "^https://[^/@?#\\s\\u0000-\\u001f\\u007f]+(?:/[^?#\\s\\u0000-\\u001f\\u007f]*)?$";
const shape = new RegExp(GIT_REPOSITORY_URL_PATTERN);

/**
 * A credential-free `https://` repository URL of at most 2048 UTF-8 bytes, with no query,
 * fragment, controls or spaces: the one rule shared by `validateSource` and the CLI, so a token
 * in a query can never reach a recorded pin. Loopback, link-local and private hosts are not
 * refused here; reaching them is left to the operator's network isolation.
 */
export function isSupportedRepositoryUrl(spelling: string): boolean {
  if (new TextEncoder().encode(spelling).length > 2048 || !shape.test(spelling)) return false;
  if ([...spelling].some((c) => c.charCodeAt(0) <= 32 || c.charCodeAt(0) === 127)) return false;
  let url: URL;
  try {
    url = new URL(spelling);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.username === "" &&
    url.password === "" &&
    url.hash === "" &&
    url.search === "" &&
    url.hostname !== ""
  );
}
