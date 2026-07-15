# CheckMate MCP Server

An independent, read-only Model Context Protocol server for Auth0 CheckMate JSON reports.

It has no dependency on the official Auth0 MCP Server. An MCP host may configure either server independently or run both as sibling servers. This package does not call an AI model, authenticate to Auth0, run CheckMate, or change tenant configuration.

From the repository root:

```sh
npm install
npm run build
node packages/checkmate-mcp-server/dist/cli.js \
  --reports-dir /absolute/path/to/checkmate-assistant/reports
```

The server communicates over stdio and is intended to be launched by an MCP host. See the root `README.md` for the MCP client configuration, available tools, prompts, resource, and security boundaries.
