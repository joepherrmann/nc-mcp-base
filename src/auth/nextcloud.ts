/**
 * Nextcloud OIDC auth for MCP servers.
 *
 * Implements the OAuth 2.0 Authorization Code flow with PKCE on top of
 * Nextcloud's `login/v2/flow` mechanism. The result is a Bearer token
 * (actually a Nextcloud app password) that the MCP validates on each request
 * by calling Nextcloud's user endpoint.
 *
 * Flow overview:
 *  1. Client (Claude Desktop) discovers OAuth metadata via /.well-known/*
 *  2. Client POSTs to /oauth/register (dynamic client registration)
 *  3. Client opens user's browser at /oauth/authorize?...
 *  4. MCP starts NC login/v2 flow, gets poll info + login URL
 *  5. MCP redirects user to /oauth/wait page that:
 *     - Auto-opens NC login URL in new tab
 *     - Polls our /oauth/wait/status until NC completes
 *     - Redirects to client's redirect_uri with code
 *  6. Client POSTs to /oauth/token with code + PKCE verifier
 *  7. MCP returns NC app password as access_token
 *  8. Subsequent /mcp requests: Bearer middleware validates via NC userinfo
 *
 * Single-user / single-process design — uses in-memory state, no Redis.
 * Sufficient for personal MCP servers with one (or a handful of) users.
 */

import { createHash, randomBytes } from "node:crypto";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { AuthConfig } from "../types.js";

// ============================================================
// Public factory
// ============================================================

export interface NextcloudOAuthOptions {
  /** Base URL of the Nextcloud instance, e.g. "https://nextcloud.joepherrmann.com" */
  nextcloudUrl: string;

  /**
   * If set, only these Nextcloud user IDs are accepted. Tokens from other
   * users return 403. Useful for single-user MCPs.
   */
  allowedUserIds?: string[];

  /**
   * How long to cache successful token validations (ms). Default 60_000 (1 min).
   * Setting to 0 disables caching (validates every request).
   */
  validationCacheMs?: number;

  /**
   * How long pending OAuth flows are kept in memory before being garbage
   * collected (ms). Default 600_000 (10 min). After this, /oauth/token
   * returns "code expired".
   */
  pendingFlowTtlMs?: number;
}

export function nextcloudOAuth(opts: NextcloudOAuthOptions): AuthConfig {
  const nextcloudUrl = opts.nextcloudUrl.replace(/\/$/, "");
  const validationCacheMs = opts.validationCacheMs ?? 60_000;
  const pendingFlowTtlMs = opts.pendingFlowTtlMs ?? 600_000;

  // In-memory state. Single-process, single-user system.
  const pendingFlows = new Map<string, PendingFlow>();
  const issuedCodes = new Map<string, IssuedCode>();
  const tokenCache = new Map<string, TokenCacheEntry>();
  const clients = new Map<string, RegisteredClient>();

  // Periodic GC of expired entries
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of pendingFlows) {
      if (entry.expiresAt < now) pendingFlows.delete(key);
    }
    for (const [key, entry] of issuedCodes) {
      if (entry.expiresAt < now) issuedCodes.delete(key);
    }
    for (const [key, entry] of tokenCache) {
      if (entry.expiresAt < now) tokenCache.delete(key);
    }
  }, 60_000).unref();

  const middleware = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) {
      sendUnauthorized(res, "missing_token");
      return;
    }
    const token = auth.slice("Bearer ".length).trim();
    if (!token) {
      sendUnauthorized(res, "missing_token");
      return;
    }

    // Cache lookup
    const cached = tokenCache.get(token);
    if (cached && cached.expiresAt > Date.now()) {
      (req as RequestWithAuth).auth = { userId: cached.userId };
      next();
      return;
    }

    // Validate against Nextcloud
    try {
      const userId = await validateTokenWithNextcloud(nextcloudUrl, token);
      if (!userId) {
        sendUnauthorized(res, "invalid_token");
        return;
      }
      if (opts.allowedUserIds && !opts.allowedUserIds.includes(userId)) {
        res.status(403).json({
          error: "insufficient_scope",
          error_description: `User "${userId}" is not in the allowed list.`,
        });
        return;
      }

      if (validationCacheMs > 0) {
        tokenCache.set(token, {
          userId,
          expiresAt: Date.now() + validationCacheMs,
        });
      }

      (req as RequestWithAuth).auth = { userId };
      next();
    } catch (err) {
      console.error("Token validation failed:", err);
      sendUnauthorized(res, "invalid_token");
    }
  };

  const registerEndpoints = (
    app: Express,
    { publicUrl: rawPublicUrl }: { publicUrl: string },
  ): void => {
    const publicUrl = rawPublicUrl.replace(/\/$/, "");

    // ----- Discovery: protected resource metadata -----
    // RFC 9728: tells clients which authorization servers protect this resource.
    app.get("/.well-known/oauth-protected-resource", (_req, res) => {
      res.json({
        resource: publicUrl,
        authorization_servers: [publicUrl],
        bearer_methods_supported: ["header"],
      });
    });

    // ----- Discovery: authorization server metadata -----
    // RFC 8414: how this auth server works.
    app.get("/.well-known/oauth-authorization-server", (_req, res) => {
      res.json({
        issuer: publicUrl,
        authorization_endpoint: `${publicUrl}/oauth/authorize`,
        token_endpoint: `${publicUrl}/oauth/token`,
        registration_endpoint: `${publicUrl}/oauth/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["mcp"],
      });
    });

    // ----- Dynamic client registration (RFC 7591) -----
    app.post("/oauth/register", express.json(), (req, res) => {
      const body = req.body ?? {};
      const clientId = randomToken(16);
      const redirectUris: string[] = Array.isArray(body.redirect_uris)
        ? body.redirect_uris
        : [];
      if (redirectUris.length === 0) {
        res.status(400).json({
          error: "invalid_client_metadata",
          error_description: "redirect_uris is required",
        });
        return;
      }
      const client: RegisteredClient = {
        clientId,
        redirectUris,
        clientName: body.client_name ?? "unnamed",
        createdAt: Date.now(),
      };
      clients.set(clientId, client);
      res.status(201).json({
        client_id: clientId,
        redirect_uris: redirectUris,
        client_name: client.clientName,
        token_endpoint_auth_method: "none",
      });
    });

    // ----- Authorization endpoint -----
    // Starts NC login/v2 flow, redirects user to a wait page.
    app.get("/oauth/authorize", async (req, res) => {
      const params = req.query as Record<string, string | undefined>;
      const error = validateAuthorizeParams(params, clients);
      if (error) {
        res.status(400).type("text/plain").send(error);
        return;
      }

      // Start NC login flow
      let ncFlow: NcLoginFlow;
      try {
        ncFlow = await startNcLoginFlow(nextcloudUrl);
      } catch (err: any) {
        console.error("Failed to start NC login flow:", err);
        res
          .status(502)
          .type("text/plain")
          .send(`Failed to reach Nextcloud at ${nextcloudUrl}: ${err?.message ?? err}`);
        return;
      }

      const flowId = randomToken(24);
      const pending: PendingFlow = {
        flowId,
        clientId: params.client_id!,
        redirectUri: params.redirect_uri!,
        state: params.state ?? "",
        codeChallenge: params.code_challenge!,
        codeChallengeMethod: params.code_challenge_method!,
        ncPollToken: ncFlow.pollToken,
        ncPollEndpoint: ncFlow.pollEndpoint,
        ncLoginUrl: ncFlow.loginUrl,
        appPassword: undefined,
        userId: undefined,
        polling: false,
        completed: false,
        error: undefined,
        expiresAt: Date.now() + pendingFlowTtlMs,
      };
      pendingFlows.set(flowId, pending);

      // Kick off background polling of NC
      pollNcInBackground(pending).catch((err) => {
        console.error(`[flow ${flowId}] NC polling crashed:`, err);
        pending.error = err?.message ?? String(err);
      });

      // Redirect user to wait page (HTML page that polls our status endpoint)
      res.redirect(302, `/oauth/wait?flow=${encodeURIComponent(flowId)}`);
    });

    // ----- Wait page (HTML) -----
    app.get("/oauth/wait", (req, res) => {
      const flowId = (req.query.flow as string | undefined) ?? "";
      const flow = pendingFlows.get(flowId);
      if (!flow) {
        res.status(404).type("text/plain").send("Flow not found or expired.");
        return;
      }
      res.type("text/html").send(renderWaitPage(flow));
    });

    // ----- Wait status (JSON, polled by the wait page) -----
    app.get("/oauth/wait/status", (req, res) => {
      const flowId = (req.query.flow as string | undefined) ?? "";
      const flow = pendingFlows.get(flowId);
      if (!flow) {
        res.status(404).json({ status: "expired" });
        return;
      }
      if (flow.error) {
        res.json({ status: "error", message: flow.error });
        return;
      }
      if (!flow.completed) {
        res.json({ status: "pending" });
        return;
      }

      // NC flow done — issue an authorization code, return redirect target.
      const code = randomToken(32);
      issuedCodes.set(code, {
        flowId,
        appPassword: flow.appPassword!,
        userId: flow.userId!,
        clientId: flow.clientId,
        redirectUri: flow.redirectUri,
        codeChallenge: flow.codeChallenge,
        codeChallengeMethod: flow.codeChallengeMethod,
        used: false,
        expiresAt: Date.now() + 5 * 60_000, // 5 min to exchange
      });

      const redirectUrl = new URL(flow.redirectUri);
      redirectUrl.searchParams.set("code", code);
      if (flow.state) redirectUrl.searchParams.set("state", flow.state);

      // Don't delete the flow yet — wait page might re-poll. Mark it done.
      res.json({
        status: "done",
        redirect: redirectUrl.toString(),
      });
    });

    // ----- Token endpoint -----
    app.post(
      "/oauth/token",
      express.urlencoded({ extended: false }),
      express.json(),
      (req, res) => {
        const body = { ...(req.body ?? {}) };
        const grantType = body.grant_type;
        if (grantType !== "authorization_code") {
          res.status(400).json({
            error: "unsupported_grant_type",
            error_description: `Only authorization_code is supported, got: ${grantType}`,
          });
          return;
        }

        const code = body.code as string | undefined;
        const codeVerifier = body.code_verifier as string | undefined;
        const redirectUri = body.redirect_uri as string | undefined;
        const clientId = body.client_id as string | undefined;

        if (!code || !codeVerifier || !redirectUri || !clientId) {
          res.status(400).json({
            error: "invalid_request",
            error_description:
              "code, code_verifier, redirect_uri, and client_id are required",
          });
          return;
        }

        const issued = issuedCodes.get(code);
        if (!issued) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "code not found or already used",
          });
          return;
        }
        if (issued.used) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "code already used",
          });
          return;
        }
        if (issued.expiresAt < Date.now()) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "code expired",
          });
          return;
        }
        if (issued.clientId !== clientId) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "client_id mismatch",
          });
          return;
        }
        if (issued.redirectUri !== redirectUri) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "redirect_uri mismatch",
          });
          return;
        }

        // PKCE verification (S256)
        if (issued.codeChallengeMethod === "S256") {
          const expected = base64UrlEncode(
            createHash("sha256").update(codeVerifier).digest(),
          );
          if (expected !== issued.codeChallenge) {
            res.status(400).json({
              error: "invalid_grant",
              error_description: "PKCE verification failed",
            });
            return;
          }
        } else {
          res.status(400).json({
            error: "invalid_grant",
            error_description: `Unsupported code_challenge_method: ${issued.codeChallengeMethod}`,
          });
          return;
        }

        issued.used = true;

        res.json({
          access_token: issued.appPassword,
          token_type: "Bearer",
          // App password doesn't expire — we'd reissue if revoked at NC side.
        });
      },
    );
  };

  return { middleware, registerEndpoints };
}

// ============================================================
// Internal types & helpers
// ============================================================

interface PendingFlow {
  flowId: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  ncPollToken: string;
  ncPollEndpoint: string;
  ncLoginUrl: string;
  appPassword?: string;
  userId?: string;
  polling: boolean;
  completed: boolean;
  error?: string;
  expiresAt: number;
}

interface IssuedCode {
  flowId: string;
  appPassword: string;
  userId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  used: boolean;
  expiresAt: number;
}

interface TokenCacheEntry {
  userId: string;
  expiresAt: number;
}

interface RegisteredClient {
  clientId: string;
  redirectUris: string[];
  clientName: string;
  createdAt: number;
}

interface NcLoginFlow {
  pollToken: string;
  pollEndpoint: string;
  loginUrl: string;
}

interface RequestWithAuth extends Request {
  auth?: { userId: string };
}

function sendUnauthorized(res: Response, reason: string): void {
  res.set(
    "WWW-Authenticate",
    `Bearer error="${reason}", resource_metadata="${"/.well-known/oauth-protected-resource"}"`,
  );
  res.status(401).json({ error: reason });
}

function validateAuthorizeParams(
  params: Record<string, string | undefined>,
  clients: Map<string, RegisteredClient>,
): string | null {
  if (params.response_type !== "code") {
    return "response_type must be 'code'";
  }
  if (!params.client_id) {
    return "client_id is required";
  }
  const client = clients.get(params.client_id);
  if (!client) {
    return `unknown client_id: ${params.client_id}`;
  }
  if (!params.redirect_uri) {
    return "redirect_uri is required";
  }
  if (!client.redirectUris.includes(params.redirect_uri)) {
    return `redirect_uri not registered for this client`;
  }
  if (!params.code_challenge) {
    return "code_challenge is required (PKCE)";
  }
  if (params.code_challenge_method !== "S256") {
    return "code_challenge_method must be S256";
  }
  return null;
}

async function startNcLoginFlow(nextcloudUrl: string): Promise<NcLoginFlow> {
  const resp = await fetch(`${nextcloudUrl}/index.php/login/v2`, {
    method: "POST",
    headers: { "User-Agent": "hejguide-mcp-base/0.1.0" },
  });
  if (!resp.ok) {
    throw new Error(`NC login/v2 returned ${resp.status} ${resp.statusText}`);
  }
  const data = (await resp.json()) as {
    poll: { token: string; endpoint: string };
    login: string;
  };
  return {
    pollToken: data.poll.token,
    pollEndpoint: data.poll.endpoint,
    loginUrl: data.login,
  };
}

async function pollNcInBackground(flow: PendingFlow): Promise<void> {
  flow.polling = true;
  const startedAt = Date.now();
  const deadline = flow.expiresAt;

  while (Date.now() < deadline && !flow.completed && !flow.error) {
    try {
      const resp = await fetch(flow.ncPollEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `token=${encodeURIComponent(flow.ncPollToken)}`,
      });

      if (resp.status === 200) {
        const data = (await resp.json()) as {
          server: string;
          loginName: string;
          appPassword: string;
        };
        // Encode loginName:appPassword as base64 so the single "access_token"
        // we return to the OAuth client is sufficient for Basic auth to NC.
        // NC's OCS endpoints don't accept Bearer; the app password must be
        // sent as the Basic-auth password alongside the login name.
        const basicCred = Buffer.from(
          `${data.loginName}:${data.appPassword}`,
        ).toString("base64");
        flow.appPassword = basicCred;
        flow.userId = data.loginName;
        flow.completed = true;
        console.error(
          `[flow ${flow.flowId}] NC login completed for user "${data.loginName}" after ${Date.now() - startedAt}ms`,
        );
        return;
      }

      // 404 = still waiting, anything else = problem
      if (resp.status !== 404) {
        flow.error = `NC poll returned ${resp.status}`;
        return;
      }
    } catch (err: any) {
      flow.error = `NC poll failed: ${err?.message ?? err}`;
      return;
    }

    await sleep(2000);
  }

  if (!flow.completed && !flow.error) {
    flow.error = "Login flow timed out";
  }
}

async function validateTokenWithNextcloud(
  nextcloudUrl: string,
  token: string,
): Promise<string | null> {
  // The token from our /oauth/token endpoint is already a base64-encoded
  // "loginName:appPassword" pair. We forward it as the credential in a
  // Basic auth header — exactly what NC's OCS endpoints expect.
  const resp = await fetch(
    `${nextcloudUrl}/ocs/v2.php/cloud/user?format=json`,
    {
      headers: {
        Authorization: `Basic ${token}`,
        "OCS-APIRequest": "true",
        Accept: "application/json",
      },
    },
  );

  if (!resp.ok) {
    return null;
  }
  const data = (await resp.json()) as {
    ocs?: { data?: { id?: string } };
  };
  return data?.ocs?.data?.id ?? null;
}

function randomToken(bytes: number): string {
  return base64UrlEncode(randomBytes(bytes));
}

function base64UrlEncode(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================
// HTML wait page (rendered server-side)
// ============================================================

function renderWaitPage(flow: PendingFlow): string {
  const flowId = flow.flowId;
  const loginUrl = flow.ncLoginUrl;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sign in with Nextcloud</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; max-width: 480px; margin: 4rem auto; padding: 2rem; color: #333; }
    h1 { font-size: 1.3rem; margin-bottom: 1rem; }
    p { line-height: 1.5; }
    .btn { display: inline-block; background: #0082c9; color: white; padding: 0.7rem 1.4rem; border-radius: 4px; text-decoration: none; font-weight: 500; margin-top: 1rem; }
    .btn:hover { background: #006aa3; }
    .status { margin-top: 1.5rem; padding: 0.8rem 1rem; border-radius: 4px; background: #f0f0f0; font-size: 0.9rem; }
    .status.error { background: #fee; color: #c00; }
    .status.done { background: #efe; color: #060; }
  </style>
</head>
<body>
  <h1>Sign in with Nextcloud</h1>
  <p>
    To finish connecting this MCP, sign in to your Nextcloud account in the
    new tab that just opened. After approving the access request, this page
    will close itself.
  </p>
  <p>
    Didn't open?
    <a class="btn" href="${escapeHtml(loginUrl)}" target="_blank" rel="noopener">Open Nextcloud login</a>
  </p>
  <div id="status" class="status">Waiting for sign-in…</div>

  <script>
    const flowId = ${JSON.stringify(flowId)};
    const loginUrl = ${JSON.stringify(loginUrl)};
    const statusEl = document.getElementById('status');

    // Auto-open the NC login window
    window.open(loginUrl, '_blank', 'noopener,noreferrer');

    let stopped = false;
    async function poll() {
      if (stopped) return;
      try {
        const resp = await fetch('/oauth/wait/status?flow=' + encodeURIComponent(flowId));
        const data = await resp.json();
        if (data.status === 'done') {
          stopped = true;
          statusEl.textContent = 'Signed in. Returning to the app…';
          statusEl.className = 'status done';
          window.location.replace(data.redirect);
          return;
        }
        if (data.status === 'error') {
          stopped = true;
          statusEl.textContent = 'Error: ' + (data.message || 'unknown');
          statusEl.className = 'status error';
          return;
        }
        if (data.status === 'expired') {
          stopped = true;
          statusEl.textContent = 'This sign-in attempt expired. Reload the connector in your app to start again.';
          statusEl.className = 'status error';
          return;
        }
        setTimeout(poll, 2000);
      } catch (err) {
        statusEl.textContent = 'Polling error — retrying…';
        setTimeout(poll, 4000);
      }
    }
    poll();
  </script>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
