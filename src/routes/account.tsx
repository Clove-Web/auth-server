/* src/routes/account.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { Hono } from "hono";
import { Key, Save, Shield } from "pixelarticons/react";
import { renderSVG } from "uqr";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { TTL, now, siteName, type AppContext, type AppEnv } from "../env";
import { audit } from "../lib/audit";
import { decrypt, encrypt } from "../lib/crypto";
import { form, readJson } from "../lib/http";
import { recentAuthRedirect, requireCsrf, requireUser } from "../lib/guards";
import { hashPassword, passwordProblem, PASSWORD_MIN } from "../lib/password";
import { generateTotpSecret, otpauthUri, verifyTotp } from "../lib/totp";
import { cleanText, emailProblem, pictureProblem } from "../lib/validate";
import {
  countPasskeys,
  deletePasskey,
  finishRegistration,
  listPasskeys,
  registrationOptions,
  renamePasskey,
} from "../data/passkeys";
import { endSession, listSessions, revokeOtherSessions, revokeSession } from "../data/sessions";
import {
  claimTotpStep,
  disableTotp,
  enableTotp,
  getUser,
  setPasswordHash,
  setTotpPending,
  updateProfile,
  type UserRow,
} from "../data/users";
import { render } from "../views/layout";
import { Csrf, ErrorNote, Field, Flash, Section, date, describeAgent, relative } from "../views/ui";

export const account = new Hono<AppEnv>();

account.use("/account", requireUser);
account.use("/account/*", requireUser, requireCsrf);

async function me(c: AppContext): Promise<UserRow> {
  const user = await getUser(c.env, c.get("user")!.id);
  if (!user) throw new Error("session user vanished");
  return user;
}

function amrLabel(amr: string): string {
  const list = JSON.parse(amr) as string[];
  if (list.includes("swk") || list.includes("hwk")) return "passkey";
  if (list.includes("otp") && list.includes("pwd")) return "password + code";
  if (list.includes("pwd")) return "password";
  if (list.includes("link")) return "sign-in link";
  if (list.includes("setup")) return "setup";
  return "unknown";
}

async function accountPage(c: AppContext, opts: { error?: string; status?: 400 } = {}) {
  const user = await me(c);
  const session = c.get("session")!;
  const [passkeys, sessions] = await Promise.all([listPasskeys(c.env, user.id), listSessions(c.env, user.id)]);
  const csrf = session.csrf;
  const stale = now() - session.authTime > TTL.recentAuth;

  return render(
    c,
    { title: "Your account", page: "account", status: opts.status },
    <>
      <h1>Hi, {user.name ?? user.username}</h1>
      <Flash code={c.req.query("m")} />
      <ErrorNote error={opts.error} />
      <p class="notice error hidden" id="passkey-error" role="alert"></p>
      {stale && (
        <p class="notice">
          You signed in {relative(session.authTime)}. Changing how you sign in will ask you to confirm it's you first.
        </p>
      )}

      <Section title="Profile" description="Shared with the apps you sign in to.">
        <form method="post" action="/account/profile" class="stack">
          <Csrf token={csrf} />
          <label class="field">
            <span>Username</span>
            <input type="text" value={user.username} disabled />
            <small class="muted">Only an admin can change this.</small>
          </label>
          <Field label="Display name" name="name" value={user.name} autocomplete="name" maxlength={100} />
          <Field
            label="Email"
            name="email"
            type="email"
            value={user.email}
            autocomplete="email"
            maxlength={254}
            hint={user.email ? (user.email_verified ? "Verified." : "Not verified.") : undefined}
          />
          <Field label="Picture URL" name="picture" type="url" value={user.picture} maxlength={2048} placeholder="https://…" />
          <div>
            <button type="submit">
              <Save class="icon" aria-hidden="true" />
              Save profile
            </button>
          </div>
        </form>
      </Section>

      <Section title="Passkeys" description="The quickest and safest way to sign in: your device unlocks with a fingerprint, face or PIN.">
        {passkeys.length === 0 ? (
          <p class="muted">No passkeys yet.</p>
        ) : (
          <ul class="rows">
            {passkeys.map((p) => (
              <li>
                <div class="grow">
                  <form method="post" action={`/account/passkeys/${encodeURIComponent(p.id)}/rename`} class="inline-edit">
                    <Csrf token={csrf} />
                    <input type="text" name="name" value={p.name} maxlength={60} aria-label="Passkey name" required />
                    <button type="submit" class="small">Rename</button>
                  </form>
                  <small class="muted">
                    {p.device_type === "multiDevice" ? "Synced" : "This device only"} · added {date(p.created_at)} · last used{" "}
                    {relative(p.last_used_at)}
                  </small>
                </div>
                <form
                  method="post"
                  action={`/account/passkeys/${encodeURIComponent(p.id)}/delete`}
                  data-confirm={`Remove the passkey "${p.name}"?`}
                >
                  <Csrf token={csrf} />
                  <button type="submit" class="danger small">Remove</button>
                </form>
              </li>
            ))}
          </ul>
        )}
        <form id="passkey-add" class="inline-edit">
          <input type="text" name="name" placeholder="Name, e.g. Phone" maxlength={60} aria-label="New passkey name" />
          <button type="submit" class="primary">
            <Key class="icon" aria-hidden="true" />
            Add a passkey
          </button>
        </form>
      </Section>

      <Section title="Password">
        <p class="muted">
          {user.password_hash
            ? "You can sign in with a password."
            : "No password set. Add one as a fallback for devices without your passkeys."}
        </p>
        <form method="post" action="/account/password" class="stack">
          <Csrf token={csrf} />
          <input type="text" name="username" value={user.username} autocomplete="username" hidden />
          <Field
            label={user.password_hash ? "New password" : "Password"}
            name="password"
            type="password"
            required
            autocomplete="new-password"
            maxlength={512}
            hint={`At least ${PASSWORD_MIN} characters. A long phrase beats a short tricky one.`}
          />
          <Field label="Confirm password" name="confirm" type="password" required autocomplete="new-password" maxlength={512} />
          <div>
            <button type="submit">{user.password_hash ? "Change password" : "Set password"}</button>
          </div>
        </form>
        {user.password_hash && (
          <form method="post" action="/account/password/remove" data-confirm="Remove your password? You'll only be able to sign in with a passkey.">
            <Csrf token={csrf} />
            <button type="submit" class="danger small" disabled={passkeys.length === 0}>
              Remove password
            </button>
            {passkeys.length === 0 && <small class="muted"> Add a passkey first.</small>}
          </form>
        )}
      </Section>

      <Section title="Two-factor codes" description="Asks for a code from an authenticator app after your password. Passkey sign-ins don't need it.">
        {!user.password_hash ? (
          <p class="muted">Set a password first.</p>
        ) : user.totp_secret ? (
          <form method="post" action="/account/totp/disable" class="inline-edit">
            <Csrf token={csrf} />
            <span class="badge ok">On</span>
            <input
              type="text"
              name="code"
              placeholder="Current code"
              inputmode="numeric"
              autocomplete="one-time-code"
              maxlength={7}
              required
              aria-label="Current code"
            />
            <button type="submit" class="danger">Turn off</button>
          </form>
        ) : (
          <form method="post" action="/account/totp/start">
            <Csrf token={csrf} />
            <button type="submit">Set up an authenticator app</button>
          </form>
        )}
      </Section>

      <Section title="Sessions" description="Browsers signed in to this server. Apps you've signed in to keep their own sessions.">
        <ul class="rows">
          {sessions.map((s) => (
            <li>
              <div class="grow">
                <strong>{describeAgent(s.user_agent)}</strong>
                {s.id_hash === session.idHash && <span class="badge">This browser</span>}
                <br />
                <small class="muted">
                  {s.ip ?? "unknown IP"} · via {amrLabel(s.amr)} · signed in {date(s.created_at)} · active {relative(s.last_seen_at)}
                </small>
              </div>
              <form method="post" action={`/account/sessions/${s.id_hash}/revoke`}>
                <Csrf token={csrf} />
                <button type="submit" class="small">Sign out</button>
              </form>
            </li>
          ))}
        </ul>
        {sessions.length > 1 && (
          <form method="post" action="/account/sessions/revoke-others">
            <Csrf token={csrf} />
            <button type="submit" class="danger small">Sign out everywhere else</button>
          </form>
        )}
      </Section>
    </>,
  );
}

account.get("/account", (c) => accountPage(c));

account.post("/account/profile", async (c) => {
  const body = await form(c);
  const update = {
    name: cleanText(body.name, 100),
    email: cleanText(body.email, 254),
    picture: cleanText(body.picture, 2048),
  };
  const problem = emailProblem(update.email) ?? pictureProblem(update.picture);
  if (problem) return accountPage(c, { error: problem, status: 400 });

  await updateProfile(c.env, await me(c), update);
  await audit(c, "account.profile");
  return c.redirect("/account?m=profile-saved");
});

// --- passkeys --------------------------------------------------------------------

account.post("/account/passkeys/options", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;
  return c.json(await registrationOptions(c.env, await me(c)));
});

account.post("/account/passkeys/verify", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;

  const body = await readJson<{ id?: string; response?: RegistrationResponseJSON; name?: string }>(c);
  if (!body?.id || !body.response) return c.json({ error: "Malformed request." }, 400);

  const name = cleanText(body.name, 60) ?? "Passkey";
  const result = await finishRegistration(c.env, await me(c), body.id, body.response, name);
  if (!result.ok) return c.json({ error: result.error }, 400);

  await audit(c, "account.passkey_added", { detail: name });
  return c.json({ redirect: "/account?m=passkey-added" });
});

account.post("/account/passkeys/:id/rename", async (c) => {
  const body = await form(c);
  const name = cleanText(body.name, 60);
  if (!name) return accountPage(c, { error: "Passkeys need a name.", status: 400 });
  await renamePasskey(c.env, c.get("user")!.id, c.req.param("id"), name);
  return c.redirect("/account?m=passkey-renamed");
});

account.post("/account/passkeys/:id/delete", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;

  const user = await me(c);
  if (!user.password_hash && (await countPasskeys(c.env, user.id)) <= 1) {
    return accountPage(c, {
      error: "That's your only way to sign in. Add another passkey or a password before removing it.",
      status: 400,
    });
  }
  await deletePasskey(c.env, user.id, c.req.param("id"));
  await audit(c, "account.passkey_removed");
  return c.redirect("/account?m=passkey-removed");
});

// --- password ------------------------------------------------------------------

account.post("/account/password", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;

  const user = await me(c);
  const body = await form(c);
  const password = body.password ?? "";
  const problem =
    passwordProblem(password, user.username) ??
    (password !== body.confirm ? "The two passwords don't match." : null);
  if (problem) return accountPage(c, { error: problem, status: 400 });

  await setPasswordHash(c.env, user.id, await hashPassword(password));
  await revokeOtherSessions(c.env, user.id, c.get("session")!.idHash);
  await audit(c, "account.password_set");
  return c.redirect("/account?m=password-set");
});

account.post("/account/password/remove", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;

  const user = await me(c);
  if ((await countPasskeys(c.env, user.id)) === 0) {
    return accountPage(c, { error: "Add a passkey before removing your password.", status: 400 });
  }
  await setPasswordHash(c.env, user.id, null);
  await audit(c, "account.password_removed");
  return c.redirect("/account?m=password-removed");
});

// --- TOTP ----------------------------------------------------------------------

account.post("/account/totp/start", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;

  const user = await me(c);
  if (!user.password_hash) return c.redirect("/account");
  if (user.totp_secret) return c.redirect("/account");
  await setTotpPending(c.env, user.id, await encrypt(c.env.KEY_ENCRYPTION_KEY, generateTotpSecret()));
  return c.redirect("/account/totp");
});

async function totpSetupPage(c: AppContext, error?: string) {
  const user = await me(c);
  if (!user.totp_pending || user.totp_secret) return c.redirect("/account");

  const secret = await decrypt(c.env.KEY_ENCRYPTION_KEY, user.totp_pending);
  const uri = otpauthUri(secret, siteName(c.env), user.username);
  const svg = renderSVG(uri, { border: 2 });
  const qr = `data:image/svg+xml,${encodeURIComponent(svg)}`;

  return render(
    c,
    { title: "Set up two-factor codes", narrow: true, status: error ? 400 : 200 },
    <div class="card">
      <h1>Scan this code</h1>
      <p class="muted">Use any authenticator app (1Password, Aegis, Google Authenticator…), then enter the code it shows.</p>
      <ErrorNote error={error} />
      <img class="qr" src={qr} alt="QR code for your authenticator app" width="220" height="220" />
      <details>
        <summary>Can't scan it?</summary>
        <p>Enter this key instead:</p>
        <p class="secret">
          <code>{secret.match(/.{1,4}/g)?.join(" ")}</code>
        </p>
      </details>
      <form method="post" action="/account/totp/confirm" class="stack">
        <Csrf token={c.get("session")!.csrf} />
        <Field label="Code" name="code" required inputmode="numeric" autocomplete="one-time-code" maxlength={7} autofocus />
        <button type="submit" class="primary wide">
          <Shield class="icon" aria-hidden="true" />
          Turn on
        </button>
      </form>
      <p class="small">
        <a class="btn wide" href="/account">Cancel</a>
      </p>
    </div>,
  );
}

account.get("/account/totp", (c) => totpSetupPage(c));

account.post("/account/totp/confirm", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;

  const user = await me(c);
  if (!user.totp_pending) return c.redirect("/account");

  const secret = await decrypt(c.env.KEY_ENCRYPTION_KEY, user.totp_pending);
  const step = await verifyTotp(secret, (await form(c)).code ?? "", 0);
  if (step === null) return totpSetupPage(c, "That code didn't match. Check your device's clock and try the next one.");

  await enableTotp(c.env, user.id, user.totp_pending, step);
  await audit(c, "account.totp_enabled");
  return c.redirect("/account?m=totp-enabled");
});

account.post("/account/totp/disable", async (c) => {
  const reauth = recentAuthRedirect(c, "/account");
  if (reauth) return reauth;

  const user = await me(c);
  if (!user.totp_secret) return c.redirect("/account");

  const secret = await decrypt(c.env.KEY_ENCRYPTION_KEY, user.totp_secret);
  const step = await verifyTotp(secret, (await form(c)).code ?? "", user.totp_last_step);
  if (step === null || !(await claimTotpStep(c.env, user.id, step))) {
    return accountPage(c, { error: "That code didn't work, so two-factor codes are still on.", status: 400 });
  }
  await disableTotp(c.env, user.id);
  await audit(c, "account.totp_disabled");
  return c.redirect("/account?m=totp-disabled");
});

// --- sessions ------------------------------------------------------------------

account.post("/account/sessions/revoke-others", async (c) => {
  await revokeOtherSessions(c.env, c.get("user")!.id, c.get("session")!.idHash);
  await audit(c, "account.sessions_revoked");
  return c.redirect("/account?m=sessions-revoked");
});

account.post("/account/sessions/:id/revoke", async (c) => {
  const id = c.req.param("id");
  if (id === c.get("session")!.idHash) {
    await endSession(c);
    return c.redirect("/login?m=signed-out");
  }
  await revokeSession(c.env, c.get("user")!.id, id);
  return c.redirect("/account?m=session-revoked");
});
