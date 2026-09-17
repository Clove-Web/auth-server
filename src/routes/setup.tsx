/* src/routes/setup.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { Hono } from "hono";
import { Login, UserPlus } from "pixelarticons/react";
import type { AppContext, AppEnv } from "../env";
import { audit } from "../lib/audit";
import { timingSafeEqualStr } from "../lib/crypto";
import { clientIp, form } from "../lib/http";
import { attempt } from "../lib/ratelimit";
import { cleanText, emailProblem, normaliseUsername, usernameProblem } from "../lib/validate";
import { startSession } from "../data/sessions";
import { countUsers, createFirstAdmin } from "../data/users";
import { render } from "../views/layout";
import { ErrorNote, Field } from "../views/ui";

export const setup = new Hono<AppEnv>();

function closed(c: AppContext) {
  return render(
    c,
    { title: "Setup", narrow: true, status: 404 },
    <div class="card">
      <h1>Setup is done</h1>
      <p class="muted">This server already has accounts.</p>
      <p>
        <a class="btn primary" href="/login">
          <Login class="icon" aria-hidden="true" />
          Sign in
        </a>
      </p>
    </div>,
  );
}

function setupPage(c: AppContext, values: Record<string, string> = {}, error?: string) {
  if (!c.env.SETUP_TOKEN) {
    return render(
      c,
      { title: "Setup", narrow: true, status: 503 },
      <div class="card">
        <h1>Almost there</h1>
        <p>
          Set a <code>SETUP_TOKEN</code> secret (<code>wrangler secret put SETUP_TOKEN</code>, or{" "}
          <code>.dev.vars</code> locally), then reload this page to create the first admin.
        </p>
      </div>,
    );
  }
  return render(
    c,
    { title: "Setup", narrow: true, status: error ? 400 : 200 },
    <div class="card">
      <h1>Create the first admin</h1>
      <p class="muted">
        This page only works while the server has no accounts. You'll add a passkey or password straight after.
      </p>
      <ErrorNote error={error} />
      <form method="post" action="/setup" class="stack">
        <Field label="Setup token" name="token" type="password" required autocomplete="off" hint="The SETUP_TOKEN secret." />
        <Field label="Username" name="username" value={values.username} required autocomplete="username" maxlength={32} />
        <Field label="Display name" name="name" value={values.name} autocomplete="name" maxlength={100} />
        <Field label="Email" name="email" type="email" value={values.email} autocomplete="email" maxlength={254} />
        <button type="submit" class="primary wide">
          <UserPlus class="icon" aria-hidden="true" />
          Create admin account
        </button>
      </form>
    </div>,
  );
}

setup.get("/setup", async (c) => {
  if ((await countUsers(c.env)) > 0) return closed(c);
  return setupPage(c);
});

setup.post("/setup", async (c) => {
  if ((await countUsers(c.env)) > 0 || !c.env.SETUP_TOKEN) return closed(c);

  if (!(await attempt(c.env, `setup-ip:${clientIp(c)}`, 10, 60 * 60))) {
    return c.text("Too many attempts. Try again later.", 429);
  }

  const body = await form(c);
  if (!timingSafeEqualStr(body.token ?? "", c.env.SETUP_TOKEN)) {
    await audit(c, "setup.bad_token", { actor: null });
    return setupPage(c, body, "That setup token is wrong.");
  }

  const username = normaliseUsername(body.username);
  const email = cleanText(body.email, 254);
  const problem = usernameProblem(username) ?? emailProblem(email);
  if (problem) return setupPage(c, body, problem);

  const id = await createFirstAdmin(c.env, {
    username,
    name: cleanText(body.name, 100),
    email,
    emailVerified: false,
  });
  if (!id) return closed(c);

  await startSession(c, id, ["setup"]);
  await audit(c, "setup.complete", { actor: id, target: username });
  return c.redirect("/account?m=setup-done");
});
