/* src/routes/login.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { Hono } from "hono";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import type { AppContext, AppEnv } from "../env";
import { audit } from "../lib/audit";
import { decrypt, timingSafeEqualStr } from "../lib/crypto";
import { clientIp, form, readJson, safeReturn } from "../lib/http";
import { burnPasswordCheck, hashPassword, needsRehash, verifyPassword } from "../lib/password";
import { attempt, clearAttempts } from "../lib/ratelimit";
import { verifyTotp } from "../lib/totp";
import { normaliseUsername } from "../lib/validate";
import { authenticationOptions, finishAuthentication } from "../data/passkeys";
import { consumeLoginLink, peekLoginLink } from "../data/links";
import {
  endSession,
  finishPendingLogin,
  peekPendingLogin,
  spendPendingAttempt,
  startPendingLogin,
  startSession,
} from "../data/sessions";
import { claimTotpStep, countUsers, getUser, getUserByUsername, setPasswordHash } from "../data/users";
import { render } from "../views/layout";
import { ErrorNote, Field, Flash, Icon } from "../views/ui";

const WINDOW = 15 * 60;
const USER_LIMIT = 10;
const IP_LIMIT = 50;
const TOTP_ATTEMPTS = 5;
const GENERIC_FAILURE = "That username and password don't match.";

export const login = new Hono<AppEnv>();

interface LoginPageOptions {
  returnTo: string;
  reauth: boolean;
  username?: string;
  error?: string;
  message?: string;
  status?: 401 | 429;
}

function loginPage(c: AppContext, opts: LoginPageOptions) {
  const user = c.get("user");
  const username = opts.username ?? (opts.reauth ? user?.username : undefined);
  return render(
    c,
    { title: "Sign in", page: "login", narrow: true, status: opts.status },
    <div class="card" id="login" data-return={opts.returnTo}>
      <h1>{opts.reauth ? "Confirm it's you" : "Sign in"}</h1>
      {opts.reauth && (
        <p class="muted">This needs a fresh sign-in. It only takes a moment.</p>
      )}
      <Flash code={opts.message} />
      <ErrorNote error={opts.error} />
      <p class="notice error hidden" id="passkey-error" role="alert"></p>

      <button type="button" class="primary wide" id="passkey-signin">
        <Icon name="key" />
        Sign in with a passkey
      </button>

      <div class="divider">
        <span>or use a password</span>
      </div>

      <form method="post" action="/login/password" class="stack">
        <input type="hidden" name="return" value={opts.returnTo} />
        {opts.reauth && <input type="hidden" name="reauth" value="1" />}
        <Field
          label="Username"
          name="username"
          value={username}
          required
          autocomplete="username webauthn"
          autofocus={!username}
          maxlength={64}
        />
        <Field
          label="Password"
          name="password"
          type="password"
          required
          autocomplete="current-password"
          autofocus={Boolean(username)}
          maxlength={512}
        />
        <button type="submit" class="wide">
          Sign in
        </button>
      </form>
    </div>,
  );
}

login.get("/login", async (c) => {
  const returnTo = safeReturn(c.req.query("return"));
  const reauth = c.req.query("reauth") === "1";
  if (c.get("user") && !reauth) return c.redirect(returnTo);
  if ((await countUsers(c.env)) === 0) return c.redirect("/setup");
  return loginPage(c, { returnTo, reauth, message: c.req.query("m") });
});

login.post("/login/password", async (c) => {
  const body = await form(c);
  const returnTo = safeReturn(body.return);
  const reauth = body.reauth === "1";
  const username = normaliseUsername(body.username).slice(0, 64);
  const password = (body.password ?? "").slice(0, 512);

  const ipOk = await attempt(c.env, `login-ip:${clientIp(c)}`, IP_LIMIT, WINDOW);
  const userOk = await attempt(c.env, `login-user:${username}`, USER_LIMIT, WINDOW);
  if (!ipOk || !userOk) {
    await audit(c, "login.rate_limited", { actor: null, target: username });
    return loginPage(c, {
      returnTo,
      reauth,
      username,
      status: 429,
      error: "Too many sign-in attempts. Wait a few minutes and try again.",
    });
  }

  const user = username ? await getUserByUsername(c.env, username) : null;
  if (!user || !user.password_hash || user.disabled) {
    await burnPasswordCheck(password);
    await audit(c, "login.failed", { actor: null, target: username, detail: "password" });
    return loginPage(c, { returnTo, reauth, username, status: 401, error: GENERIC_FAILURE });
  }

  if (!(await verifyPassword(password, user.password_hash))) {
    await audit(c, "login.failed", { actor: user.id, target: user.username, detail: "password" });
    return loginPage(c, { returnTo, reauth, username, status: 401, error: GENERIC_FAILURE });
  }

  await clearAttempts(c.env, `login-user:${username}`);
  if (needsRehash(user.password_hash)) {
    await setPasswordHash(c.env, user.id, await hashPassword(password));
  }

  if (user.totp_secret) {
    await startPendingLogin(c, user.id, returnTo);
    return c.redirect("/login/totp");
  }

  await startSession(c, user.id, ["pwd"]);
  await audit(c, "login.password", { actor: user.id, target: user.username });
  return c.redirect(returnTo);
});

function totpPage(c: AppContext, error?: string) {
  return render(
    c,
    { title: "Two-factor code", narrow: true, status: error ? 401 : 200 },
    <div class="card">
      <h1>Enter your code</h1>
      <p class="muted">Open your authenticator app and enter the 6-digit code for this account.</p>
      <ErrorNote error={error} />
      <form method="post" action="/login/totp" class="stack">
        <Field
          label="Code"
          name="code"
          required
          autocomplete="one-time-code"
          inputmode="numeric"
          pattern="[0-9 ]{6,7}"
          maxlength={7}
          autofocus
        />
        <button type="submit" class="primary wide">
          <Icon name="login" />
          Continue
        </button>
      </form>
      <p class="muted small">
        <a class="btn wide" href="/login">Start over</a>
      </p>
    </div>,
  );
}

login.get("/login/totp", async (c) => {
  if (!(await peekPendingLogin(c))) return c.redirect("/login");
  return totpPage(c);
});

login.post("/login/totp", async (c) => {
  const body = await form(c);
  const pending = await spendPendingAttempt(c, TOTP_ATTEMPTS);
  if (!pending) return c.redirect("/login");

  const user = await getUser(c.env, pending.user_id);
  if (!user || user.disabled || !user.totp_secret) {
    await finishPendingLogin(c, pending.id_hash);
    return c.redirect("/login");
  }

  const secret = await decrypt(c.env.KEY_ENCRYPTION_KEY, user.totp_secret);
  const step = await verifyTotp(secret, body.code ?? "", user.totp_last_step);
  if (step === null || !(await claimTotpStep(c.env, user.id, step))) {
    await audit(c, "login.failed", { actor: user.id, target: user.username, detail: "totp" });
    const left = TOTP_ATTEMPTS - pending.attempts;
    if (left <= 0) {
      await finishPendingLogin(c, pending.id_hash);
      return c.redirect("/login");
    }
    return totpPage(c, `That code didn't work. ${left} ${left === 1 ? "try" : "tries"} left.`);
  }

  await finishPendingLogin(c, pending.id_hash);
  await startSession(c, user.id, ["pwd", "otp", "mfa"]);
  await audit(c, "login.password_totp", { actor: user.id, target: user.username });
  return c.redirect(safeReturn(pending.return_to));
});

login.post("/login/passkey/options", async (c) => {
  if (!(await attempt(c.env, `passkey-ip:${clientIp(c)}`, 120, WINDOW))) {
    return c.json({ error: "Too many sign-in attempts. Wait a few minutes and try again." }, 429);
  }
  return c.json(await authenticationOptions(c.env));
});

login.post("/login/passkey/verify", async (c) => {
  const body = await readJson<{ id?: string; response?: AuthenticationResponseJSON; return?: string }>(c);
  if (!body?.id || !body.response) return c.json({ error: "Malformed request." }, 400);

  const result = await finishAuthentication(c.env, body.id, body.response);
  if (!result.ok) {
    await audit(c, "login.failed", { actor: null, detail: "passkey" });
    return c.json({ error: result.error }, 401);
  }

  const user = await getUser(c.env, result.userId);
  if (!user || user.disabled) return c.json({ error: "This account is disabled." }, 403);

  await startSession(c, user.id, result.amr);
  await audit(c, "login.passkey", { actor: user.id, target: user.username });
  return c.json({ redirect: safeReturn(body.return) });
});

login.get("/login/link/:token", async (c) => {
  const target = await peekLoginLink(c.env, c.req.param("token"));
  if (!target) {
    return render(
      c,
      { title: "Link expired", narrow: true, status: 410 },
      <div class="card">
        <h1>This link can't be used</h1>
        <p class="muted">It has expired, was already used, or was replaced by a newer one. Ask an admin for a new link.</p>
      </div>,
    );
  }

  const current = c.get("user");
  // Link scanners follow GETs, so using the link takes a deliberate POST.
  return render(
    c,
    { title: "Sign in", narrow: true },
    <div class="card">
      <h1>Sign in as {target.name ?? target.username}</h1>
      <p class="muted">
        This one-time link signs you in as <strong>@{target.username}</strong>. It stops working once it's used.
      </p>
      {current && current.id !== target.user_id && (
        <p class="notice">You'll be signed out of @{current.username} on this browser.</p>
      )}
      <form method="post" action={`/login/link/${c.req.param("token")}`}>
        <button type="submit" class="primary wide">
          <Icon name="login" />
          Continue
        </button>
      </form>
    </div>,
  );
});

login.post("/login/link/:token", async (c) => {
  if (!(await attempt(c.env, `link-ip:${clientIp(c)}`, 30, WINDOW))) {
    return c.text("Too many attempts. Wait a few minutes and try again.", 429);
  }
  const userId = await consumeLoginLink(c.env, c.req.param("token"));
  if (!userId) return c.redirect(`/login/link/${encodeURIComponent(c.req.param("token"))}`);

  await startSession(c, userId, ["link"]);
  await audit(c, "login.link", { actor: userId, target: userId });
  return c.redirect("/account?m=link-welcome");
});

login.post("/logout", async (c) => {
  const session = c.get("session");
  if (session) {
    const body = await form(c);
    if (!body._csrf || !timingSafeEqualStr(body._csrf, session.csrf)) {
      return c.text("This form is out of date. Go back, reload the page and try again.", 403);
    }
    await audit(c, "logout");
    await endSession(c);
  }
  return c.redirect("/login?m=signed-out");
});
