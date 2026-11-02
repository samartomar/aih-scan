/** npm naming rules shared by the request validator, the CLI and the advisory reader. */
const SEGMENT = "[a-z0-9][a-z0-9._~-]*";

/** An npm scope as an internal-scope option takes it: `@scope`. */
export const NPM_SCOPE_PATTERN = new RegExp(`^@${SEGMENT}$`);

/** An npm package name, scoped or not. */
export const NPM_NAME_PATTERN = new RegExp(`^(?:@${SEGMENT}/)?${SEGMENT}$`);
