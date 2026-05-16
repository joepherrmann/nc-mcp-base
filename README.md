# nc-mcp-base

Nextcloud-OIDC auth + transport scaffolding for self-hosted MCP servers.

Drop-in package that gives any MCP server:

- **Transport** — stdio (Claude Desktop) + Streamable HTTP (remote / containerised)
- **Health endpoint** — `/health` for Docker + Traefik
- **Nextcloud OIDC auth** — OAuth 2.0 + PKCE flow wrapping the standard Nextcloud `login/v2/flow` mechanism. Lets you add the MCP as a custom connector in Claude Desktop, authenticated with the same Nextcloud account you already log into.

Designed for single-user or small-team self-hosted deployments. Each MCP that needs to be reachable from Anthropic's cloud (custom connectors in Claude Desktop) wraps `runMcpServer()` + `nextcloudOAuth()` and gets a working OAuth flow without writing a line of auth code itself.

## Install

```bash
npm install github:joepherrmann/nc-mcp-base#main
```

Or pin to a tag:

```json
"dependencies": {
  "nc-mcp-base": "github:joepherrmann/nc-mcp-base#v0.1.0"
}
```

The `prepare` script runs `tsc` automatically when installed via git URL, so `dist/` is populated for consumers.

## Quickstart

```ts
// src/index.ts
import { runMcpServer, nextcloudOAuth } from "nc-mcp-base";
import { createMyServer } from "./server.js"; // your createServer() factory

await runMcpServer({
  name: "my-mcp",
  version: "1.0.0",
  createServer: createMyServer,
  publicUrl: process.env.PUBLIC_URL, // e.g. https://my-mcp.example.com
  auth: nextcloudOAuth({
    nextcloudUrl: process.env.NEXTCLOUD_URL!,        // e.g. https://nextcloud.example.com
    allowedUserIds: process.env.ALLOWED_USER_IDS
      ?.split(",")
      .map((s) => s.trim()),                          // optional, restrict to specific NC users
  }),
});
```

That's it. With `TRANSPORT=http`, the server exposes:

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

## How the auth flow works

```
Claude Desktop                  Your MCP                       Nextcloud
     │                            │                              │
     │  /.well-known/oauth-*      │                              │
     │ ─────────────────────────►                              │
     │ ◄─────── metadata          │                              │
     │                            │                              │
     │  POST /oauth/register      │                              │
     │ ─────────────────────────►                              │
     │ ◄─────── client_id         │                              │
     │                            │                              │
     │  User opens browser at     │                              │
     │  /oauth/authorize?...      │                              │
     │ ─────────────────────────►  POST /index.php/login/v2    │
     │                            │ ─────────────────────────────►
     │                            │ ◄── { poll, login_url }      │
     │                            │                              │
     │ ◄── 302 /oauth/wait?...    │                              │
     │                            │                              │
     │  Wait page (HTML+JS):      │                              │
     │  - opens NC login_url      │                              │
     │  - polls /oauth/wait/status│                              │
     │                            │                              │
     │                            │  Background: poll NC endpoint│
     │                            │ ─────────────────────────────►
     │                            │ ◄── { loginName, appPassword}│
     │                            │  (when user has signed in)   │
     │                            │                              │
     │  Wait page redirects to    │                              │
     │  redirect_uri?code=...     │                              │
     │                            │                              │
     │  POST /oauth/token         │                              │
     │   (code, code_verifier)    │                              │
     │ ─────────────────────────►                              │
     │ ◄── access_token (base64   │                              │
     │     of loginName:appPwd)   │                              │
     │                            │                              │
     │  POST /mcp                 │                              │
     │   Authorization: Bearer X  │                              │
     │ ─────────────────────────►  GET /ocs/v2.php/cloud/user  │
     │                            │   with Authorization: Basic X│
     │                            │ ─────────────────────────────►
     │                            │ ◄── user info                │
     │                            │                              │
     │  (tool call proxies)       │                              │
```

Notes:

- The `access_token` issued to the client is just `base64("loginName:appPassword")`. The MCP forwards it as the credential in an HTTP Basic auth header when validating with NC. There's no real OAuth bearer-token concept on the NC side — we're wrapping the long-lived app password.
- Uses **PKCE (S256)** for the OAuth code exchange — required by the MCP spec and a sensible default.
- Token validation results are cached (default 60s) to avoid hitting NC on every single MCP request. Configurable via `validationCacheMs`.
- `pendingFlowTtlMs` (default 10 min) controls how long an in-progress login is kept alive.

## Public API

```ts
runMcpServer(opts: RunOptions): Promise<void>;
nextcloudOAuth(opts: NextcloudOAuthOptions): AuthConfig;
```

Full type definitions in `src/types.ts` and `src/auth/nextcloud.ts`. JSDoc on every public field.

## TRANSPORT env var

| Value | Behaviour |
|---|---|
| `stdio` (default) | Stdio transport — for local Claude Desktop. No HTTP server, no auth. |
| `http` | Streamable HTTP on `PORT` (default 8001) — for containers and remote use. Auth is wired in if `opts.auth` is set. |

## Skipping auth for internal-only MCPs

If your MCP only needs to be called from inside your network (e.g. via n8n on the same host), skip `opts.auth` entirely. The MCP will run without OAuth, on plain HTTP, and you rely on network isolation (VPN, firewall, internal DNS) instead. This is appropriate for monitoring / scheduled-agent MCPs that never need to be reachable from Anthropic's cloud.

## Status

- **0.1.0** — Initial release. Transport (stdio + Streamable HTTP), Nextcloud OAuth flow with PKCE + dynamic client registration, Bearer middleware, optional user-allowlist.

## Known limitations

- Single-process in-memory state for pending OAuth flows + token cache. Fine for one container; would need Redis or similar for multi-instance HA deploys.
- No token revocation endpoint yet (NC app passwords can be revoked at the NC side via Settings → Security → Devices & sessions; cached tokens invalidate within `validationCacheMs`).
- Wait page requires JavaScript in the browser. Acceptable for the user-facing OAuth flow, which always happens in a browser anyway.

## Origin

Extracted from a multi-MCP self-hosted setup. Originally built to give a small set of MCP servers (mail, monitoring, integration adapters) a consistent transport + auth layer without writing OAuth boilerplate per MCP. Generic enough that anyone running a Nextcloud instance can use it for their own MCPs.

## License

MIT.
