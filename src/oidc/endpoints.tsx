/* src/oidc/endpoints.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { TTL, issuer, now, type AppContext, type AppEnv } from "../env";
import { audit } from "../lib/audit";
import { b64url, randomToken, sha256, sha256Hex, timingSafeEqualStr } from "../lib/crypto";
import { form } from "../lib/http";
import { clientAllows, getClient, verifyClientSecret, type Client } from "../data/clients";
import { publicJwks } from "../data/keys";
import { endSession } from "../data/sessions";
import { getUser, groupsFor } from "../data/users";
import { render } from "../views/layout";
import { Csrf, Icon } from "../views/ui";
import {
  SUPPORTED_CLAIMS,
  SUPPORTED_SCOPES,
  issueTokens,
  parseScope,
  userClaims,
  verifyAccessToken,
  verifyIdTokenHint,
} from "./tokens";

export const oidc = new Hono<AppEnv>();

// Machine-to-machine endpoints are called from other origins (including SPAs),
// carry no cookies, and so are safe to open to any origin.
const openCors = cors({
  origin: "*",
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Authorization", "Content-Type"],
  maxAge: 86400,
});
for (const path of ["/.well-known/*", "/token", "/userinfo", "/revoke"]) {
  oidc.use(path, openCors);
}

// --- discovery ----------------------------------------------------------------------

oidc.get("/.well-known/openid-configuration", (c) => {
  const iss = issuer(c.env);
  c.header("Cache-Control", "public, max-age=300");
  return c.json({
    issuer: iss,
    authorization_endpoint: `${iss}/authorize`,
    token_endpoint: `${iss}/token`,
    userinfo_endpoint: `${iss}/userinfo`,
    jwks_uri: `${iss}/.well-known/jwks.json`,
    end_session_endpoint: `${iss}/end-session`,
    revocation_endpoint: `${iss}/revoke`,
    scopes_supported: SUPPORTED_SCOPES,
    claims_supported: SUPPORTED_CLAIMS,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported: ["S256"],
    prompt_values_supported: ["none", "login"],
    authorization_response_iss_parameter_supported: true,
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
  });
});

oidc.get("/.well-known/jwks.json", async (c) => {
  c.header("Cache-Control", "public, max-age=300");
  return c.json(await publicJwks(c.env));
});

// --- authorize ------------------------------------------------------------------------

function errorPage(c: AppContext, title: string, text: string, status: 400 | 403 = 400) {
  return render(
    c,
    { title, narrow: true, status },
    <div class="card">
      <h1>{title}</h1>
      <p class="muted">{text}</p>
    </div>,
  );
}

async function authorizeParams(c: AppContext): Promise<Record<string, string>> {
  if (c.req.method === "POST") return form(c);
  const out: Record<string, string> = {};
  for (const [k, v] of new URL(c.req.url).searchParams) if (!(k in out)) out[k] = v;
  return out;
}

async function authorize(c: AppContext) {
  const params = await authorizeParams(c);
  const iss = issuer(c.env);

  // Until client and redirect_uri are both trusted, errors can only be shown
  // here: redirecting to an unverified URI would make this an open redirector.
  if (!params.client_id || !params.redirect_uri) {
    return errorPage(c, "Incomplete sign-in request", "The app didn't say who it is or where to send you back to.");
  }
  const client = await getClient(c.env, params.client_id);
  if (!client) {
    return errorPage(c, "Unknown application", "The app that sent you here isn't registered with this server.");
  }
  if (!client.redirectUris.includes(params.redirect_uri)) {
    return errorPage(c, "Unregistered redirect", `${client.name} asked to send you somewhere it isn't allowed to.`);
  }

  const back = (values: Record<string, string>) => {
    const url = new URL(params.redirect_uri!);
    for (const [k, v] of Object.entries(values)) url.searchParams.set(k, v);
    if (params.state !== undefined) url.searchParams.set("state", params.state);
    url.searchParams.set("iss", iss);
    return c.redirect(url.toString());
  };
  const fail = (error: string, description: string) => back({ error, error_description: description });

  if (params.request || params.request_uri) {
    return fail(params.request ? "request_not_supported" : "request_uri_not_supported", "Request objects aren't supported.");
  }
  if (params.response_type !== "code") return fail("unsupported_response_type", "Only response_type=code is supported.");
  if (params.response_mode && params.response_mode !== "query") {
    return fail("invalid_request", "Only response_mode=query is supported.");
  }

  const scopes = parseScope(params.scope);
  if (!scopes.includes("openid")) return fail("invalid_scope", "The openid scope is required.");

  const challenge = params.code_challenge;
  if (challenge) {
    if (params.code_challenge_method !== "S256") return fail("invalid_request", "code_challenge_method must be S256.");
    if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) return fail("invalid_request", "Malformed code_challenge.");
  } else if (client.isPublic) {
    return fail("invalid_request", "Public clients must use PKCE (S256).");
  }
  if (params.nonce && params.nonce.length > 512) return fail("invalid_request", "nonce is too long.");

  const prompts = (params.prompt ?? "").split(" ").filter(Boolean);
  if (prompts.includes("none") && prompts.length > 1) {
    return fail("invalid_request", "prompt=none can't be combined with other values.");
  }
  let maxAge: number | null = null;
  if (params.max_age !== undefined) {
    maxAge = Number(params.max_age);
    if (!Number.isInteger(maxAge) || maxAge < 0) return fail("invalid_request", "max_age must be a non-negative integer.");
  }

  // `_fresh` is added by us when bouncing through /login: a session that
  // authenticated at or after that moment satisfies prompt=login / max_age.
  const session = c.get("session");
  const fresh = Number(params._fresh) || 0;
  let needLogin = !session;
  if (session && !(fresh && session.authTime >= fresh)) {
    if (prompts.includes("login")) needLogin = true;
    if (maxAge !== null && now() - session.authTime > maxAge) needLogin = true;
  }

  if (needLogin) {
    if (prompts.includes("none")) return fail("login_required", "The user isn't signed in.");
    const again = new URLSearchParams(params);
    again.set("_fresh", String(now()));
    const loginParams = new URLSearchParams({ return: `/authorize?${again}` });
    if (session) loginParams.set("reauth", "1");
    return c.redirect(`/login?${loginParams}`);
  }

  const user = await getUser(c.env, session!.userId);
  if (!user || user.disabled) {
    await endSession(c);
    return fail("login_required", "The user isn't signed in.");
  }

  if (!clientAllows(client, await groupsFor(c.env, user.id))) {
    await audit(c, "oidc.access_denied", { target: client.id });
    if (prompts.includes("none")) return fail("access_denied", "This account isn't allowed to use this application.");
    const denied = new URL(params.redirect_uri);
    denied.searchParams.set("error", "access_denied");
    if (params.state !== undefined) denied.searchParams.set("state", params.state);
    denied.searchParams.set("iss", iss);
    return render(
      c,
      { title: "No access", narrow: true, status: 403 },
      <div class="card">
        <h1>No access to {client.name}</h1>
        <p class="muted">
          You're signed in as <strong>@{user.username}</strong>, which isn't allowed to use {client.name}. If you think it should be, ask an admin.
        </p>
        <form method="post" action="/logout" class="stack">
          <Csrf token={session!.csrf} />
          <button type="submit" class="wide">Sign in as someone else</button>
        </form>
        <p class="small">
          <a class="btn wide" href={denied.toString()}>Back to {client.name}</a>
        </p>
      </div>,
    );
  }

  const code = randomToken(32);
  await c.env.DB.prepare(
    `INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, amr, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      await sha256Hex(code),
      client.id,
      user.id,
      params.redirect_uri,
      scopes.join(" "),
      params.nonce ?? null,
      challenge ?? null,
      session!.authTime,
      JSON.stringify(session!.amr),
      now() + TTL.authCode,
    )
    .run();

  return back({ code });
}

oidc.get("/authorize", authorize);
oidc.post("/authorize", authorize);

// --- token --------------------------------------------------------------------------

function tokenError(c: AppContext, error: string, description: string, status: 400 | 401 = 400) {
  c.header("Cache-Control", "no-store");
  if (status === 401) c.header("WWW-Authenticate", 'Basic realm="token"');
  return c.json({ error, error_description: description }, status);
}

type ClientAuth = { ok: true; client: Client } | { ok: false; response: Response };

/** RFC 6749 §2.3: client_secret_basic, client_secret_post, or none for public clients. */
async function authenticateClient(c: AppContext, body: Record<string, string>): Promise<ClientAuth> {
  const failed = (description: string, status: 400 | 401 = 401): ClientAuth => ({
    ok: false,
    response: tokenError(c, status === 401 ? "invalid_client" : "invalid_request", description, status),
  });

  let clientId = body.client_id;
  let secret: string | undefined;
  const header = c.req.header("authorization");

  if (header?.startsWith("Basic ")) {
    if (body.client_secret) return failed("Use only one client authentication method.", 400);
    let decoded: string;
    try {
      decoded = atob(header.slice(6).trim());
    } catch {
      return failed("Malformed Basic credentials.");
    }
    const idx = decoded.indexOf(":");
    if (idx === -1) return failed("Malformed Basic credentials.");
    const formDecode = (v: string) => decodeURIComponent(v.replace(/\+/g, " "));
    try {
      const basicId = formDecode(decoded.slice(0, idx));
      if (clientId && clientId !== basicId) return failed("client_id doesn't match the credentials.", 400);
      clientId = basicId;
      secret = formDecode(decoded.slice(idx + 1));
    } catch {
      return failed("Malformed Basic credentials.");
    }
  } else if (body.client_secret !== undefined) {
    secret = body.client_secret;
  }

  if (!clientId) return failed("Client authentication is required.");
  const client = await getClient(c.env, clientId);
  if (!client) return failed("Unknown client.");

  if (client.isPublic) {
    if (secret) return failed("Public clients don't use a secret.");
    return { ok: true, client };
  }
  if (!secret || !(await verifyClientSecret(client, secret))) return failed("Client authentication failed.");
  return { ok: true, client };
}

oidc.post("/token", async (c) => {
  const body = await form(c);
  const auth = await authenticateClient(c, body);
  if (!auth.ok) return auth.response;
  const { client } = auth;

  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");

  if (body.grant_type === "authorization_code") {
    if (!body.code || !body.redirect_uri) return tokenError(c, "invalid_request", "code and redirect_uri are required.");

    // DELETE … RETURNING makes the code single-use even under concurrent redemption.
    const row = await c.env.DB.prepare("DELETE FROM auth_codes WHERE code_hash = ? RETURNING *")
      .bind(await sha256Hex(body.code))
      .first<{
        client_id: string;
        user_id: string;
        redirect_uri: string;
        scope: string;
        nonce: string | null;
        code_challenge: string | null;
        auth_time: number;
        amr: string;
        expires_at: number;
      }>();
    if (!row || row.expires_at <= now() || row.client_id !== client.id || row.redirect_uri !== body.redirect_uri) {
      return tokenError(c, "invalid_grant", "The authorization code is invalid or expired.");
    }

    if (row.code_challenge) {
      const verifier = body.code_verifier ?? "";
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return tokenError(c, "invalid_grant", "code_verifier is missing or malformed.");
      if (!timingSafeEqualStr(b64url(await sha256(verifier)), row.code_challenge)) {
        return tokenError(c, "invalid_grant", "code_verifier doesn't match.");
      }
    } else if (body.code_verifier) {
      return tokenError(c, "invalid_grant", "No code_challenge was sent for this code.");
    }

    const user = await getUser(c.env, row.user_id);
    if (!user || user.disabled || !clientAllows(client, await groupsFor(c.env, user.id))) {
      return tokenError(c, "invalid_grant", "The account can no longer use this application.");
    }

    const scopes = row.scope.split(" ");
    const tokens = await issueTokens(
      c.env,
      { clientId: client.id, user, scopes, authTime: row.auth_time, amr: JSON.parse(row.amr) as string[], nonce: row.nonce },
      { familyId: randomToken(16) },
    );
    await audit(c, "oidc.token_issued", { actor: user.id, target: client.id });
    return c.json(tokens);
  }

  if (body.grant_type === "refresh_token") {
    if (!body.refresh_token) return tokenError(c, "invalid_request", "refresh_token is required.");
    const hash = await sha256Hex(body.refresh_token);
    const row = await c.env.DB.prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?")
      .bind(hash)
      .first<{
        family_id: string;
        client_id: string;
        user_id: string;
        scope: string;
        auth_time: number;
        amr: string;
        expires_at: number;
        used_at: number | null;
        revoked_at: number | null;
      }>();
    const invalid = () => tokenError(c, "invalid_grant", "The refresh token is invalid, expired or revoked.");
    if (!row || row.client_id !== client.id || row.revoked_at || row.expires_at <= now()) return invalid();

    // Rotation: each refresh token works once. Seeing one again means it was
    // copied, so the whole family is shut down — unless it's within a short
    // grace period of its first use. Apps running on many instances (Workers,
    // eventually-consistent storage) can legitimately race two refreshes with
    // the same token; each racer gets its own valid successor.
    const claimed = await c.env.DB.prepare(
      "UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
    )
      .bind(now(), hash)
      .run();
    // If our read saw it unused but the claim lost, another request used it just now.
    const usedAt = row.used_at ?? now();
    if (claimed.meta.changes !== 1 && now() - usedAt > TTL.refreshReuseGrace) {
      await c.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL")
        .bind(now(), row.family_id)
        .run();
      await audit(c, "oidc.refresh_reuse", { actor: row.user_id, target: client.id });
      return invalid();
    }

    const granted = row.scope.split(" ");
    let scopes = granted;
    if (body.scope) {
      scopes = parseScope(body.scope);
      if (!scopes.includes("openid") || scopes.some((s) => !granted.includes(s))) {
        return tokenError(c, "invalid_scope", "Requested scope exceeds the original grant.");
      }
    }

    const user = await getUser(c.env, row.user_id);
    if (!user || user.disabled || !clientAllows(client, await groupsFor(c.env, user.id))) return invalid();

    const tokens = await issueTokens(
      c.env,
      { clientId: client.id, user, scopes, authTime: row.auth_time, amr: JSON.parse(row.amr) as string[] },
      { familyId: row.family_id },
    );
    return c.json(tokens);
  }

  return tokenError(c, "unsupported_grant_type", "Supported grants: authorization_code, refresh_token.");
});

// --- userinfo -------------------------------------------------------------------------

async function userinfo(c: AppContext) {
  const header = c.req.header("authorization");
  let token = header?.startsWith("Bearer ") ? header.slice(7).trim() : undefined;
  if (!token && c.req.method === "POST") token = (await form(c)).access_token;

  const reject = (error: string) => {
    c.header("WWW-Authenticate", `Bearer error="${error}"`);
    return c.json({ error }, 401);
  };
  if (!token) return reject("invalid_request");

  const claims = await verifyAccessToken(c.env, token);
  if (!claims || !claims.scopes.includes("openid")) return reject("invalid_token");

  const [user, client] = await Promise.all([getUser(c.env, claims.sub), getClient(c.env, claims.clientId)]);
  if (!user || user.disabled || !client) return reject("invalid_token");

  c.header("Cache-Control", "no-store");
  return c.json(await userClaims(c.env, user, claims.scopes));
}

oidc.get("/userinfo", userinfo);
oidc.post("/userinfo", userinfo);

// --- revocation (RFC 7009) ------------------------------------------------------------

oidc.post("/revoke", async (c) => {
  const body = await form(c);
  const auth = await authenticateClient(c, body);
  if (!auth.ok) return auth.response;

  // Access tokens are short-lived JWTs and can't be recalled; per the RFC an
  // unknown or unsupported token still gets a 200.
  if (body.token) {
    const row = await c.env.DB.prepare("SELECT family_id, client_id FROM refresh_tokens WHERE token_hash = ?")
      .bind(await sha256Hex(body.token))
      .first<{ family_id: string; client_id: string }>();
    if (row && row.client_id === auth.client.id) {
      await c.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL")
        .bind(now(), row.family_id)
        .run();
    }
  }
  return c.body(null, 200);
});

// --- RP-initiated logout ------------------------------------------------------------

type LogoutTarget = { ok: true; client: Client | null; returnTo: string | null } | { ok: false; response: Promise<Response> };

/** Validates client_id / post_logout_redirect_uri exactly against the registration. */
async function logoutTarget(c: AppContext, clientId: string | undefined, uri: string | undefined, state: string | undefined): Promise<LogoutTarget> {
  const client = clientId ? await getClient(c.env, clientId) : null;
  if (!uri) return { ok: true, client, returnTo: null };
  if (!client || !client.postLogoutRedirectUris.includes(uri)) {
    return {
      ok: false,
      response: errorPage(c, "Sign-out failed", "The app asked to send you somewhere it isn't allowed to after signing out."),
    };
  }
  const url = new URL(uri);
  if (state) url.searchParams.set("state", state);
  return { ok: true, client, returnTo: url.toString() };
}

async function endSessionRequest(c: AppContext) {
  const params = c.req.method === "POST" ? await form(c) : Object.fromEntries(new URL(c.req.url).searchParams);

  const hint = params.id_token_hint ? await verifyIdTokenHint(c.env, params.id_token_hint) : null;
  if (params.id_token_hint && !hint) {
    return errorPage(c, "Sign-out failed", "The app sent a sign-out request this server couldn't verify.");
  }

  let clientId = params.client_id;
  if (hint) {
    if (clientId && !hint.aud.includes(clientId)) {
      return errorPage(c, "Sign-out failed", "The sign-out request doesn't match the app that sent it.");
    }
    clientId ??= hint.aud[0];
  }

  const target = await logoutTarget(c, clientId, params.post_logout_redirect_uri, params.state);
  if (!target.ok) return target.response;
  const { client, returnTo } = target;

  const session = c.get("session");
  const user = c.get("user");
  // A logout request without proof it came from the app is just a link anyone
  // could send, so it gets a confirmation step instead of acting straight away.
  if (session && user && !(hint && hint.sub === user.id)) {
    return render(
      c,
      { title: "Sign out", narrow: true },
      <div class="card">
        <h1>Sign out?</h1>
        <p class="muted">
          {client ? `${client.name} wants to sign you out` : "Sign out"} of @{user.username} on this server.
        </p>
        <form method="post" action="/end-session/confirm" class="stack">
          <Csrf token={session.csrf} />
          <input type="hidden" name="client_id" value={clientId ?? ""} />
          <input type="hidden" name="post_logout_redirect_uri" value={params.post_logout_redirect_uri ?? ""} />
          <input type="hidden" name="state" value={params.state ?? ""} />
          <button type="submit" class="primary wide">
            <Icon name="logout" />
            Sign out
          </button>
        </form>
        {returnTo && (
          <p class="small">
            <a class="btn wide" href={returnTo}>Stay signed in and go back</a>
          </p>
        )}
      </div>,
    );
  }

  if (session) {
    await audit(c, "logout.rp", { target: client?.id ?? null });
    await endSession(c);
  }
  return c.redirect(returnTo ?? "/login?m=signed-out");
}

oidc.get("/end-session", endSessionRequest);
oidc.post("/end-session", endSessionRequest);

oidc.post("/end-session/confirm", async (c) => {
  const session = c.get("session");
  const body = await form(c);
  if (session) {
    if (!body._csrf || !timingSafeEqualStr(body._csrf, session.csrf)) {
      return c.text("This form is out of date. Go back, reload the page and try again.", 403);
    }
  }

  const target = await logoutTarget(c, body.client_id || undefined, body.post_logout_redirect_uri || undefined, body.state || undefined);
  if (!target.ok) return target.response;

  if (session) {
    await audit(c, "logout.rp", { target: target.client?.id ?? null });
    await endSession(c);
  }
  return c.redirect(target.returnTo ?? "/login?m=signed-out");
});
