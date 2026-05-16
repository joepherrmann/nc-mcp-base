/**
 * Transport scaffolding for MCP servers.
 *
 * `runMcpServer(opts)` boots the server in stdio or HTTP mode based on the
 * TRANSPORT env var. HTTP mode uses the MCP Streamable HTTP transport
 * (POST/GET/DELETE /mcp), plus a /health endpoint and (optionally) OAuth
 * metadata + flow endpoints.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, { type Request, type Response } from "express";
import { randomUUID } from "node:crypto";
import type { RunOptions } from "./types.js";

function isInitializeRequest(body: unknown): boolean {
  return (
    !!body &&
    typeof body === "object" &&
    "method" in body &&
    (body as { method: unknown }).method === "initialize"
  );
}

async function runStdio(opts: RunOptions): Promise<void> {
  const server = opts.createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`${opts.name} v${opts.version} started on stdio.`);
}

async function runHttp(opts: RunOptions): Promise<void> {
  const port = opts.port ?? parseInt(process.env.PORT ?? "8001");
  const host = opts.host ?? process.env.HOST ?? "0.0.0.0";
  const publicUrl =
    opts.publicUrl ?? process.env.PUBLIC_URL ?? `http://${host}:${port}`;

  if (opts.auth && !opts.publicUrl && !process.env.PUBLIC_URL) {
    console.error(
      `Warning: ${opts.name} has auth enabled but no publicUrl / PUBLIC_URL set. OAuth metadata will advertise ${publicUrl}, which may not be reachable by clients.`,
    );
  }

  const app = express();
  app.use(express.json({ limit: "4mb" }));

  // ----- /health (always public, no auth) ---------------------------------
  app.get("/health", (_req, res) => {
    res.json({
      ok: true,
      service: opts.name,
      version: opts.version,
      ...(opts.healthExtras?.() ?? {}),
    });
  });

  // ----- Auth: register OAuth metadata + flow endpoints (if configured) ----
  if (opts.auth?.registerEndpoints) {
    opts.auth.registerEndpoints(app, { publicUrl });
  }

  // ----- /mcp: the Streamable HTTP transport ------------------------------
  const mcpRouter = express.Router();
  if (opts.auth?.middleware) {
    mcpRouter.use(opts.auth.middleware);
  }

  // Map session ID → transport. Sessions are created on initialize, removed
  // when the transport closes.
  const transports: Record<string, StreamableHTTPServerTransport> = {};

  mcpRouter.post("/", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports[sessionId]) {
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          transports[id] = transport;
        },
      });

      transport.onclose = () => {
        if (transport.sessionId) {
          delete transports[transport.sessionId];
        }
      };

      const server = opts.createServer();
      await server.connect(transport);
    } else {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32600,
          message: "Bad Request: missing or invalid session ID",
        },
        id: null,
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  });

  mcpRouter.get("/", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send("Invalid or missing session ID");
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  });

  mcpRouter.delete("/", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send("Invalid or missing session ID");
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  });

  app.use("/mcp", mcpRouter);

  app.listen(port, host, () => {
    console.error(
      `${opts.name} v${opts.version} listening on http://${host}:${port}/mcp` +
        (opts.auth ? " (auth: enabled)" : ""),
    );
  });
}

/**
 * Boot an MCP server. Reads TRANSPORT env var to decide between stdio and
 * HTTP. In HTTP mode also serves a /health endpoint, and optionally OAuth
 * metadata + Bearer-token middleware when `opts.auth` is supplied.
 */
export async function runMcpServer(opts: RunOptions): Promise<void> {
  const transportType = (process.env.TRANSPORT ?? "stdio").toLowerCase();
  switch (transportType) {
    case "stdio":
      await runStdio(opts);
      break;
    case "http":
      await runHttp(opts);
      break;
    default:
      console.error(
        `Unknown TRANSPORT: ${transportType}. Use "stdio" or "http".`,
      );
      process.exit(1);
  }
}
