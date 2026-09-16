/* src/main.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { Hono } from "hono";
import { isSecure, issuerOrigin, type AppEnv, type Env } from "./env";
import { loadSession } from "./data/sessions";
import { sweepExpired } from "./data/cleanup";
import { oidc } from "./oidc/endpoints";
import { login } from "./routes/login";
import { setup } from "./routes/setup";
import { account } from "./routes/account";
import { admin } from "./routes/admin";

const app = new Hono<AppEnv>();

// Protocol endpoints that other sites legitimately POST to. They don't act on
// the browser's session cookie (or, for /end-session, confirm first).
const CROSS_ORIGIN_POSTS = new Set(["/token", "/revoke", "/userinfo", "/end-session", "/authorize"]);

app.use("*", async (c, next) => {
  const url = new URL(c.req.url);
  const origin = issuerOrigin(c.env);

  // Passkeys and cookies are bound to the issuer's hostname, so anything
  // arriving on another host (e.g. the workers.dev URL) is sent there.
  if (url.origin !== origin) {
    if (c.req.method === "GET" || c.req.method === "HEAD") {
      return c.redirect(origin + url.pathname + url.search, 308);
    }
    return c.text("Use " + origin, 421);
  }

  // CSRF, layer one: browsers label every cross-site request with Origin or
  // Sec-Fetch-Site, so state-changing requests from elsewhere are refused.
  // Session-bound forms additionally carry a CSRF token (lib/guards).
  const safe = c.req.method === "GET" || c.req.method === "HEAD" || c.req.method === "OPTIONS";
  if (!safe && !CROSS_ORIGIN_POSTS.has(url.pathname)) {
    const sentOrigin = c.req.header("origin");
    const site = c.req.header("sec-fetch-site");
    if (sentOrigin ? sentOrigin !== origin : site && site !== "same-origin" && site !== "none") {
      return c.text("Cross-site request refused.", 403);
    }
  }

  await loadSession(c);
  await next();

  const h = c.res.headers;
  h.set(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  h.set("X-Frame-Options", "DENY");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "same-origin");
  h.set("Permissions-Policy", "publickey-credentials-get=(self), publickey-credentials-create=(self)");
  h.set("Cross-Origin-Opener-Policy", "same-origin");
  if (isSecure(c.env)) h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  if (!h.has("Cache-Control")) h.set("Cache-Control", "no-store");
});

app.get("/", (c) => c.redirect(c.get("user") ? "/account" : "/login"));

app.route("/", oidc);
app.route("/", login);
app.route("/", setup);
app.route("/", account);
app.route("/", admin);

app.notFound((c) => c.text("Not found", 404));

app.onError((err, c) => {
  console.error("[error]", c.req.method, new URL(c.req.url).pathname, err);
  return c.text("Something went wrong on our side. Please try again.", 500);
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(sweepExpired(env));
  },
} satisfies ExportedHandler<Env>;
