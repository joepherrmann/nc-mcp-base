/**
 * Public types for @hejguide/mcp-base.
 */

import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Express, NextFunction, Request, Response } from "express";

/**
 * Auth configuration produced by `nextcloudOAuth()` (or future auth factories).
 *
 * Consumed internally by `runMcpServer()`. You usually don't construct this
 * type by hand — call one of the factory functions (e.g. `nextcloudOAuth()`)
 * and pass the result to `runMcpServer({ auth })`.
 */
export interface AuthConfig {
  /**
   * Express middleware that validates the incoming Authorization header on
   * /mcp requests. Should respond 401 if the token is invalid.
   */
  middleware: (req: Request, res: Response, next: NextFunction) => void | Promise<void>;

  /**
   * Mount the OAuth metadata + flow endpoints on the Express app
   * (e.g. /.well-known/oauth-protected-resource, /oauth/authorize, /oauth/token).
   * Called once during server startup.
   */
  registerEndpoints?: (app: Express, opts: { publicUrl: string }) => void;
}

/**
 * Options for `runMcpServer()`.
 */
export interface RunOptions {
  /** Server name, e.g. "hejguide-imap". Reported in /health and in MCP serverInfo. */
  name: string;

  /** Semver, e.g. "0.4.0". Reported in /health and in MCP serverInfo. */
  version: string;

  /**
   * Factory function that returns a new MCP `Server` instance with tools and
   * request handlers registered.
   *
   * In HTTP mode this is called once per new client session — each session
   * gets its own Server + Transport pair, but all sessions share the same
   * backing logic (which lives in your tool implementations, closures, etc.).
   *
   * In stdio mode it's called exactly once at startup.
   */
  createServer: () => Server;

  /** HTTP listen port (HTTP mode only). Default: PORT env var or 8001. */
  port?: number;

  /** HTTP bind host (HTTP mode only). Default: HOST env var or "0.0.0.0". */
  host?: string;

  /**
   * Optional extra JSON fields to include in /health responses. Called on
   * each request, so keep it cheap. Useful for surfacing configured-account
   * names, integration version, etc.
   */
  healthExtras?: () => Record<string, unknown>;

  /**
   * Optional Bearer-token auth. Skip entirely for internal-only MCPs that
   * rely on network isolation. Required for MCPs reachable from Anthropic's
   * cloud (custom connectors in Claude Desktop).
   */
  auth?: AuthConfig;

  /**
   * Public URL of this MCP, e.g. "https://imap-mcp.joepherrmann.com".
   * Required when `auth` is set — used in OAuth metadata to advertise
   * issuer / endpoints. Falls back to PUBLIC_URL env var.
   */
  publicUrl?: string;
}
