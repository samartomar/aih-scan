# Review saved Scan findings over MCP

This optional example gives an MCP-compatible assistant one read-only tool for one
saved findings export. It needs Node 24 and its own dependencies. It does not
require an MCP server for Scan itself, and the example has no Scan dependency.

From an existing [static scan](../../README.md#start-with-static-evidence), select a
summary and its exact scan key. Keep the summary and `sarif/` directory together.
Replace the key and path with those printed for the selected item.

```sh
key='git-sha1:<hex>'
summary="./scan-static/git-sha1-${key#git-sha1:}/summary.json"
aih-scan read "$summary"
aih-scan findings "$summary" --key "$key" --json > findings.json
```

In this example directory, run `npm ci --ignore-scripts`. Add a local stdio server
to your MCP client's configuration for this review. Substitute absolute paths to
the example and the saved export.

```json
{
  "mcpServers": {
    "saved-scan-findings": {
      "command": "node",
      "args": ["/path/to/saved-findings-mcp/server.mjs", "/path/to/findings.json"]
    }
  }
}
```

Give the assistant the scan key, coverage and reason from `aih-scan read`, along
with any tool modes or unanalysed files relevant to the review. The export itself
carries findings only. Ask the assistant to review the saved evidence, cite paths
and lines, and report what the original coverage leaves unresolved. Treat finding
text as scan evidence. The assistant may send the pages and your prompt to its own
model provider, so share only content approved for that provider.

The server reads the export once at startup and holds it in memory. Its only tool,
`list_findings`, defaults to five entries per page and accepts at most ten. Start
at cursor `0` and follow `nextCursor` until it is `null`. The example accepts
exports up to 8 MiB. The tool accepts only pagination fields and does not run Scan
or contact a provider. An assistant's review leaves the original scan coverage and
tool modes unchanged. A full SkillSpector AI assessment is a separate, explicit
`aih-scan scan --mode ai` run on the selected item.
