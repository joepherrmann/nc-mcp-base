# @hejguide/mcp-base

Shared scaffolding for hejGuide MCP servers. Provides:

- **Transport** — stdio (Claude Desktop) + Streamable HTTP (remote / containerised)
- **Health endpoint** — `/health` for Docker + Traefik
- **Nextcloud OIDC auth** — turn any MCP into one that can be added as a custom connector in Claude Desktop, authenticated via your existing Nextcloud account

Designed for single-user or small-team self-hosted deployments. Each MCP that needs to be reachable from Anthropic's cloud (Cowork in Claude Desktop) wraps `runMcpServer()` + `nextcloudOAuth()` and gets a working OAuth flow without writing a line of auth code itself.

## Install

```bash
npm install github:joepherrmann/hejguide-mcp-base#main
```

Pin to a tag in production:

```json
"dependencies": {
  "@hejguide/mcp-base": "github:joepherrmann/hejguide-mcp-base#v0.1.0"
}
```

## Quickstart

```ts
// src/index.ts
import { runMcpServer, nextcloudOAuth } from "@hejguide/mcp-base";
import { createMyServer } from "./server.js"; // your createServer() factory

await runMcpServer({
  name: "hejguide-imap",
  version: "0.4.0",
  createServer: createMyServer,
  publicUrl: process.env.PUBLIC_URL, // e.g. https://imap-mcp.joepherrmann.com
  healthExtras: () => ({ accounts: ["support", "meubelmakerij"] }),
  auth: nextcloudOAuth({
    nextcloudUrl: "https://nextcloud.joepherrmann.com",
    allowedUserIds: ["joepherrmann"], // optional — restrict to specific NC users
  }),
});
```

With `TRANSPORT=http`, the server exposes:

| Endpoint | Purpose |
|---|---|
| `GET /health` | Health check (no auth) |
| `GET /.well-known/oauth-protected-resource` | OAuth discovery (RFC 9728) |
| `GET /.well-known/oauth-authorization-server` | OAuth server metadata (RFC 8414) |
| `POST /oauth/register` | Dynamic client registration (RFC 7591) |
| `GET /oauth/authorize` | Start OAuth flow — redirects user to NC login |
| `GET /oauth/wait` | HTML wait page (handles NC login completion) |
| `GET /oauth/wait/status` | JSON polling endpoint for the wait page |
| `POST /oauth/token` | Exchange code for access token (NC app password) |
| `POST/GET/DELETE /mcp` | MCP Streamable HTTP transport (Bearer-protected) |

## TRANSPORT env var

| Value | Behaviour |
|---|---|
| `stdio` (default) | Stdio transport — for local Claude Desktop. No HTTP server, no auth. |
| `http` | Streamable HTTP on `PORT` (default 8001) — for containers + Cowork. Auth is wired in if `opts.auth` is set. |

## Building MCPs that use this base

See the [Building MCPs](https://nextcloud.joepherrmann.com/apps/collectives/hejGuide/Infrastructure/Building+MCPs) page in the hejGuide Collective for the architecture rationale, per-MCP exposure choices, and example deployments.

In short: write your tools in a `createServer()` factory, hand it to `runMcpServer()`, and you're done. Each MCP becomes ~100 lines of code (plus the integration-specific tool implementations).

## Status

- **0.1.0** — Initial release. Transport + NC OIDC auth + dynamic client registration + PKCE.
