/**
 * @hejguide/mcp-base — shared scaffolding for hejGuide MCP servers.
 *
 * Public exports:
 *   - runMcpServer    — boot an MCP server (stdio or HTTP)
 *   - nextcloudOAuth  — auth config factory for Nextcloud OIDC
 *   - types
 */

export { runMcpServer } from "./transport.js";
export { nextcloudOAuth } from "./auth/nextcloud.js";
export type { AuthConfig, RunOptions } from "./types.js";
export type { NextcloudOAuthOptions } from "./auth/nextcloud.js";
