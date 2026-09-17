/* src/lib/guards.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { createMiddleware } from "hono/factory";
import { TTL, issuerOrigin, now, type AppContext, type AppEnv } from "../env";
import { timingSafeEqualStr } from "./crypto";
import { form, safeReturn } from "./http";
import { render } from "../views/layout";
import { Icon } from "../views/ui";

function wantsJson(c: AppContext): boolean {
  return (c.req.header("content-type") ?? "").includes("application/json");
}

function loginUrl(returnTo: string, reauth = false): string {
  const params = new URLSearchParams({ return: returnTo });
  if (reauth) params.set("reauth", "1");
  return `/login?${params}`;
}

/** Where to come back to after signing in: the page, or for a POST, the page it came from. */
function returnTarget(c: AppContext, fallback: string): string {
  if (c.req.method === "GET") {
    const url = new URL(c.req.url);
    return url.pathname + url.search;
  }
  // Referrer-Policy is same-origin, so a Referer here is one of our own pages.
  try {
    const referer = new URL(c.req.header("referer") ?? "");
    if (referer.origin === issuerOrigin(c.env)) return safeReturn(referer.pathname + referer.search, fallback);
  } catch {
    // no usable referer
  }
  return fallback;
}

export const requireUser = createMiddleware<AppEnv>(async (c, next) => {
  if (!c.get("user")) {
    if (wantsJson(c)) return c.json({ error: "Your session ended. Sign in again." }, 401);
    return c.redirect(loginUrl(returnTarget(c, "/account")));
  }
  await next();
});

export const requireAdmin = createMiddleware<AppEnv>(async (c, next) => {
  if (!c.get("user")?.isAdmin) {
    return render(
      c,
      { title: "Not allowed", narrow: true, status: 403 },
      <div class="card">
        <h1>Admins only</h1>
        <p class="muted">Your account isn't in the admin group for this server.</p>
        <p>
          <a class="btn primary" href="/account">
            <Icon name="arrow-left" />
            Back to your account
          </a>
        </p>
      </div>,
    );
  }
  await next();
});

/**
 * Every state-changing request from a signed-in page carries the session's
 * CSRF token, either as a `_csrf` form field or an `x-csrf-token` header.
 */
export const requireCsrf = createMiddleware<AppEnv>(async (c, next) => {
  if (c.req.method === "POST") {
    const session = c.get("session");
    const sent = wantsJson(c) ? c.req.header("x-csrf-token") : (await form(c))._csrf;
    if (!session || !sent || !timingSafeEqualStr(sent, session.csrf)) {
      if (wantsJson(c)) return c.json({ error: "This page is out of date. Reload and try again." }, 403);
      return c.text("This form is out of date. Go back, reload the page and try again.", 403);
    }
  }
  await next();
});

/**
 * Changing how an account signs in (or anything in /admin) needs a recent
 * sign-in, so a session lifted from an unlocked machine can't be used to lock
 * the owner out.
 */
export function recentAuthRedirect(c: AppContext, returnTo: string): Response | null {
  const session = c.get("session");
  if (session && now() - session.authTime <= TTL.recentAuth) return null;
  const url = loginUrl(returnTarget(c, returnTo), true);
  if (wantsJson(c)) return c.json({ error: "Please confirm it's you.", reauth: url }, 401);
  return c.redirect(url);
}

export const requireRecentAuthForPosts = (returnTo: string) =>
  createMiddleware<AppEnv>(async (c, next) => {
    if (c.req.method === "POST") {
      const redirect = recentAuthRedirect(c, returnTo);
      if (redirect) return redirect;
    }
    await next();
  });
