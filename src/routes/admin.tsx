/* src/routes/admin.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { Hono } from "hono";
import type { Child } from "hono/jsx";
import { AppWindows, Link, Save, UserPlus, Users } from "pixelarticons/react";
import { ADMIN_GROUP, issuer, type AppContext, type AppEnv } from "../env";
import { audit, recentAudit } from "../lib/audit";
import { form, formAll, lines } from "../lib/http";
import { requireAdmin, requireCsrf, requireRecentAuthForPosts, requireUser } from "../lib/guards";
import {
  cleanText,
  clientIdProblem,
  emailProblem,
  groupProblem,
  normaliseUsername,
  pictureProblem,
  redirectUriProblem,
  subjectProblem,
  usernameProblem,
} from "../lib/validate";
import {
  createClient,
  deleteClient,
  getClient,
  listClients,
  makeClientPublic,
  rotateClientSecret,
  updateClient,
  type Client,
  type ClientInput,
} from "../data/clients";
import { createGroup, deleteGroup, listGroups, updateGroup, type GroupRow } from "../data/groups";
import { listKeys, rotateKeys } from "../data/keys";
import { createLoginLink, hasOpenLoginLink, revokeLoginLinks } from "../data/links";
import { deletePasskey, listPasskeys } from "../data/passkeys";
import { listSessions } from "../data/sessions";
import {
  adminUpdateUser,
  createUser,
  deleteUser,
  disableTotp,
  getUser,
  groupsFor,
  listUsers,
  revokeAllStatements,
  setDisabled,
  setPasswordHash,
  setUserGroups,
} from "../data/users";
import { render } from "../views/layout";
import { Csrf, ErrorNote, Field, Flash, Section, date, relative } from "../views/ui";

export const admin = new Hono<AppEnv>();

admin.use("/admin", requireUser, requireAdmin);
admin.use("/admin/*", requireUser, requireAdmin, requireCsrf, requireRecentAuthForPosts("/admin"));

admin.get("/admin", (c) => c.redirect("/admin/users"));

const TABS = [
  ["/admin/users", "Users"],
  ["/admin/groups", "Groups"],
  ["/admin/clients", "Applications"],
  ["/admin/keys", "Signing keys"],
  ["/admin/audit", "Audit log"],
] as const;

function adminPage(
  c: AppContext,
  opts: { title: string; tab: string; error?: string | null; status?: 400 | 404 },
  body: Child,
) {
  return render(
    c,
    { title: opts.title, page: "admin", status: opts.status },
    <>
      <nav class="tabs">
        {TABS.map(([href, label]) => (
          <a href={href} class={opts.tab === href ? "active" : undefined}>
            {label}
          </a>
        ))}
      </nav>
      <Flash code={c.req.query("m")} />
      <ErrorNote error={opts.error} />
      {body}
    </>,
  );
}

function csrf(c: AppContext): string {
  return c.get("session")!.csrf;
}

function GroupChecks(props: { groups: GroupRow[]; selected: string[]; name?: string }) {
  if (props.groups.length === 0) return <p class="muted">No groups yet.</p>;
  return (
    <div class="checks">
      {props.groups.map((g) => (
        <label class="check">
          <input type="checkbox" name={props.name ?? "groups"} value={g.name} checked={props.selected.includes(g.name)} />
          <span>
            {g.name}
            {g.description && <small class="muted"> — {g.description}</small>}
          </span>
        </label>
      ))}
    </div>
  );
}

function notFound(c: AppContext, what: string) {
  return adminPage(
    c,
    { title: "Not found", tab: "", status: 404 },
    <p>
      That {what} doesn't exist. <a class="btn small" href="/admin">Back</a>
    </p>,
  );
}

// --- users -----------------------------------------------------------------------

async function usersPage(c: AppContext, error?: string, values: Record<string, string> = {}, chosen: string[] = []) {
  const [users, groups] = await Promise.all([listUsers(c.env), listGroups(c.env)]);
  return adminPage(
    c,
    { title: "Users", tab: "/admin/users", error, status: error ? 400 : undefined },
    <>
      <Section title={`Users (${users.length})`}>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Groups</th>
                <th>Sign-in methods</th>
                <th>Last sign-in</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr>
                  <td>
                    <a class="btn small" href={`/admin/users/${encodeURIComponent(u.id)}`}>
                      {u.name ?? u.username}
                    </a>
                    <br />
                    <small class="muted">@{u.username}</small>
                    {u.disabled ? <span class="badge danger">disabled</span> : null}
                  </td>
                  <td>{u.groups.length ? u.groups.map((g) => <span class="badge">{g}</span>) : <span class="muted">—</span>}</td>
                  <td>
                    {u.passkey_count > 0 && <span class="badge">{u.passkey_count} passkey{u.passkey_count === 1 ? "" : "s"}</span>}
                    {u.password_hash && <span class="badge">password{u.totp_secret ? " + 2FA" : ""}</span>}
                    {!u.passkey_count && !u.password_hash && <span class="muted">none</span>}
                  </td>
                  <td>{relative(u.last_login_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Add a user" description="They'll need a sign-in link from their page to set up a passkey or password.">
        <form method="post" action="/admin/users" class="stack">
          <Csrf token={csrf(c)} />
          <div class="grid2">
            <Field label="Username" name="username" value={values.username} required maxlength={32} autocomplete="off" />
            <Field label="Display name" name="name" value={values.name} maxlength={100} autocomplete="off" />
            <Field label="Email" name="email" type="email" value={values.email} maxlength={254} autocomplete="off" />
            <label class="check">
              <input type="checkbox" name="email_verified" value="1" checked={values.email_verified === "1"} />
              <span>Email is verified</span>
            </label>
          </div>
          <fieldset>
            <legend>Groups</legend>
            <GroupChecks groups={groups} selected={chosen} />
          </fieldset>
          <details>
            <summary>Advanced</summary>
            <Field
              label="Subject id"
              name="subject"
              value={values.subject}
              maxlength={64}
              autocomplete="off"
              hint="The permanent `sub` apps see. Leave blank for a random UUID. Set it to carry an account over from another identity provider without apps treating it as a new person."
            />
          </details>
          <div>
            <button type="submit" class="primary">
              <UserPlus class="icon" aria-hidden="true" />
              Create user
            </button>
          </div>
        </form>
      </Section>
    </>,
  );
}

admin.get("/admin/users", (c) => usersPage(c));

admin.post("/admin/users", async (c) => {
  const body = await form(c);
  const groups = await formAll(c, "groups");
  const username = normaliseUsername(body.username);
  const email = cleanText(body.email, 254);
  const subject = cleanText(body.subject, 64);
  const problem =
    usernameProblem(username) ?? emailProblem(email) ?? (subject ? subjectProblem(subject) : null);
  if (problem) return usersPage(c, problem, body, groups);

  const result = await createUser(c.env, {
    id: subject ?? undefined,
    username,
    name: cleanText(body.name, 100),
    email,
    emailVerified: body.email_verified === "1",
  });
  if (!result.ok) return usersPage(c, result.error, body, groups);

  await setUserGroups(c.env, result.id, groups);
  await audit(c, "admin.user_created", { target: username, detail: groups.join(",") });
  return c.redirect(`/admin/users/${encodeURIComponent(result.id)}?m=user-created`);
});

async function userPage(
  c: AppContext,
  id: string,
  opts: { error?: string; link?: { url: string; expiresAt: number } } = {},
) {
  const user = await getUser(c.env, id);
  if (!user) return notFound(c, "user");

  const [groups, allGroups, passkeys, sessions, openLink] = await Promise.all([
    groupsFor(c.env, id),
    listGroups(c.env),
    listPasskeys(c.env, id),
    listSessions(c.env, id),
    hasOpenLoginLink(c.env, id),
  ]);
  const base = `/admin/users/${encodeURIComponent(id)}`;
  const token = csrf(c);
  const self = c.get("user")!.id === id;

  return adminPage(
    c,
    { title: `@${user.username}`, tab: "/admin/users", error: opts.error, status: opts.error ? 400 : undefined },
    <>
      <p>
        <a class="btn small" href="/admin/users">← All users</a>
      </p>
      <h1>
        {user.name ?? user.username} <small class="muted">@{user.username}</small>
        {user.disabled ? <span class="badge danger">disabled</span> : null}
      </h1>
      <p class="muted">
        Subject <code>{user.id}</code> · created {date(user.created_at)} · last sign-in {relative(user.last_login_at)}
      </p>

      {opts.link && (
        <div class="notice ok">
          <p>
            <strong>Sign-in link</strong> — send this to @{user.username}. It works once and expires{" "}
            {relative(opts.link.expiresAt)}. It won't be shown again.
          </p>
          <p class="copyrow">
            <input type="text" readonly value={opts.link.url} aria-label="Sign-in link" />
            <button type="button" data-copy={opts.link.url}>Copy</button>
          </p>
        </div>
      )}

      <Section title="Profile">
        <form method="post" action={`${base}/profile`} class="stack">
          <Csrf token={token} />
          <div class="grid2">
            <Field label="Username" name="username" value={user.username} required maxlength={32} autocomplete="off" hint="Apps may use this as a mailbox or URL; changing it can break things there." />
            <Field label="Display name" name="name" value={user.name} maxlength={100} autocomplete="off" />
            <Field label="Email" name="email" type="email" value={user.email} maxlength={254} autocomplete="off" />
            <Field label="Picture URL" name="picture" type="url" value={user.picture} maxlength={2048} autocomplete="off" />
            <label class="check">
              <input type="checkbox" name="email_verified" value="1" checked={user.email_verified === 1} />
              <span>Email is verified</span>
            </label>
          </div>
          <div>
            <button type="submit">
              <Save class="icon" aria-hidden="true" />
              Save profile
            </button>
          </div>
        </form>
      </Section>

      <Section title="Groups" description="Sent to apps in the `groups` claim, and used to limit who can open each application.">
        <form method="post" action={`${base}/groups`} class="stack">
          <Csrf token={token} />
          <GroupChecks groups={allGroups} selected={groups} />
          <div>
            <button type="submit">
              <Save class="icon" aria-hidden="true" />
              Save groups
            </button>
          </div>
        </form>
      </Section>

      <Section title="Sign-in link" description="A one-time link that signs this person in so they can add a passkey or password. Use it for new accounts and lost devices.">
        {openLink && (
          <form method="post" action={`${base}/link/revoke`} class="inline-edit">
            <Csrf token={token} />
            <span>An unused link expires {relative(openLink)}.</span>
            <button type="submit" class="small">Revoke it</button>
          </form>
        )}
        <form method="post" action={`${base}/link`} class="inline-edit">
          <Csrf token={token} />
          <label>
            Valid for{" "}
            <select name="ttl">
              <option value="900">15 minutes</option>
              <option value="3600" selected>1 hour</option>
              <option value="86400">1 day</option>
              <option value="604800">7 days</option>
            </select>
          </label>
          <button type="submit" class="primary">
            <Link class="icon" aria-hidden="true" />
            {openLink ? "Replace link" : "Create link"}
          </button>
        </form>
      </Section>

      <Section title="Sign-in methods">
        <ul class="rows">
          {passkeys.map((p) => (
            <li>
              <div class="grow">
                <strong>Passkey: {p.name}</strong>
                <br />
                <small class="muted">added {date(p.created_at)} · last used {relative(p.last_used_at)}</small>
              </div>
              <form method="post" action={`${base}/passkeys/${encodeURIComponent(p.id)}/delete`} data-confirm={`Remove the passkey "${p.name}"?`}>
                <Csrf token={token} />
                <button type="submit" class="danger small">Remove</button>
              </form>
            </li>
          ))}
          {user.password_hash && (
            <li>
              <div class="grow">
                <strong>Password</strong>
              </div>
              <form method="post" action={`${base}/password/remove`} data-confirm="Remove this password (and any two-factor setup)?">
                <Csrf token={token} />
                <button type="submit" class="danger small">Remove</button>
              </form>
            </li>
          )}
          {user.totp_secret && (
            <li>
              <div class="grow">
                <strong>Two-factor codes</strong>
              </div>
              <form method="post" action={`${base}/totp/reset`} data-confirm="Turn off two-factor codes for this account?">
                <Csrf token={token} />
                <button type="submit" class="danger small">Turn off</button>
              </form>
            </li>
          )}
          {!passkeys.length && !user.password_hash && <li class="muted">None. Send a sign-in link so they can add one.</li>}
        </ul>
      </Section>

      <Section title="Access">
        <p class="muted">
          {sessions.length} active browser session{sessions.length === 1 ? "" : "s"} on this server.
        </p>
        <div class="buttons">
          <form method="post" action={`${base}/signout`} data-confirm="Sign this account out of every browser and application?">
            <Csrf token={token} />
            <button type="submit">Sign out everywhere</button>
          </form>
          {!self &&
            (user.disabled ? (
              <form method="post" action={`${base}/enable`}>
                <Csrf token={token} />
                <button type="submit">Enable account</button>
              </form>
            ) : (
              <form method="post" action={`${base}/disable`} data-confirm="Disable this account? They'll be signed out everywhere.">
                <Csrf token={token} />
                <button type="submit" class="danger">Disable account</button>
              </form>
            ))}
        </div>
      </Section>

      {!self && (
        <Section title="Delete account" description="Permanent. Apps keep whatever they stored about this person; a new account will get a new subject id.">
          <form method="post" action={`${base}/delete`} class="inline-edit">
            <Csrf token={token} />
            <input type="text" name="confirm" placeholder={`Type ${user.username} to confirm`} required autocomplete="off" aria-label="Confirm username" />
            <button type="submit" class="danger">Delete</button>
          </form>
        </Section>
      )}
    </>,
  );
}

admin.get("/admin/users/:id", (c) => userPage(c, c.req.param("id")));

admin.post("/admin/users/:id/profile", async (c) => {
  const id = c.req.param("id");
  const body = await form(c);
  const update = {
    username: normaliseUsername(body.username),
    name: cleanText(body.name, 100),
    email: cleanText(body.email, 254),
    picture: cleanText(body.picture, 2048),
    emailVerified: body.email_verified === "1",
  };
  const problem = usernameProblem(update.username) ?? emailProblem(update.email) ?? pictureProblem(update.picture);
  if (problem) return userPage(c, id, { error: problem });

  const error = await adminUpdateUser(c.env, id, update);
  if (error) return userPage(c, id, { error });
  await audit(c, "admin.user_updated", { target: id });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=user-saved`);
});

admin.post("/admin/users/:id/groups", async (c) => {
  const id = c.req.param("id");
  const groups = await formAll(c, "groups");
  if (id === c.get("user")!.id && !groups.includes(ADMIN_GROUP)) {
    return userPage(c, id, { error: `You can't remove yourself from ${ADMIN_GROUP}. Ask another admin.` });
  }
  await setUserGroups(c.env, id, groups);
  await audit(c, "admin.user_groups", { target: id, detail: groups.join(",") });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=groups-saved`);
});

const LINK_TTLS = new Set([900, 3600, 86400, 604800]);

admin.post("/admin/users/:id/link", async (c) => {
  const id = c.req.param("id");
  const user = await getUser(c.env, id);
  if (!user) return notFound(c, "user");
  if (user.disabled) return userPage(c, id, { error: "Enable the account before sending a sign-in link." });

  const ttl = Number((await form(c)).ttl);
  const link = await createLoginLink(c.env, id, c.get("user")!.id, LINK_TTLS.has(ttl) ? ttl : 3600);
  await audit(c, "admin.link_created", { target: id, detail: `ttl=${ttl}` });
  return userPage(c, id, { link });
});

admin.post("/admin/users/:id/link/revoke", async (c) => {
  const id = c.req.param("id");
  await revokeLoginLinks(c.env, id);
  await audit(c, "admin.link_revoked", { target: id });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=link-revoked`);
});

admin.post("/admin/users/:id/passkeys/:pid/delete", async (c) => {
  const id = c.req.param("id");
  await deletePasskey(c.env, id, c.req.param("pid"));
  await audit(c, "admin.passkey_removed", { target: id });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=credential-removed`);
});

admin.post("/admin/users/:id/password/remove", async (c) => {
  const id = c.req.param("id");
  await setPasswordHash(c.env, id, null);
  await audit(c, "admin.password_removed", { target: id });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=credential-removed`);
});

admin.post("/admin/users/:id/totp/reset", async (c) => {
  const id = c.req.param("id");
  await disableTotp(c.env, id);
  await audit(c, "admin.totp_reset", { target: id });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=credential-removed`);
});

admin.post("/admin/users/:id/signout", async (c) => {
  const id = c.req.param("id");
  await c.env.DB.batch(revokeAllStatements(c.env, id));
  await audit(c, "admin.user_signed_out", { target: id });
  if (id === c.get("user")!.id) return c.redirect("/login?m=signed-out");
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=user-signed-out`);
});

admin.post("/admin/users/:id/disable", async (c) => {
  const id = c.req.param("id");
  if (id === c.get("user")!.id) return userPage(c, id, { error: "You can't disable your own account." });
  await setDisabled(c.env, id, true);
  await revokeLoginLinks(c.env, id);
  await audit(c, "admin.user_disabled", { target: id });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=user-disabled`);
});

admin.post("/admin/users/:id/enable", async (c) => {
  const id = c.req.param("id");
  await setDisabled(c.env, id, false);
  await audit(c, "admin.user_enabled", { target: id });
  return c.redirect(`/admin/users/${encodeURIComponent(id)}?m=user-enabled`);
});

admin.post("/admin/users/:id/delete", async (c) => {
  const id = c.req.param("id");
  const user = await getUser(c.env, id);
  if (!user) return notFound(c, "user");
  if (id === c.get("user")!.id) return userPage(c, id, { error: "You can't delete your own account." });
  if (normaliseUsername((await form(c)).confirm) !== user.username) {
    return userPage(c, id, { error: "Type the username exactly to delete the account." });
  }
  await deleteUser(c.env, id);
  await audit(c, "admin.user_deleted", { target: `${user.username} (${id})` });
  return c.redirect("/admin/users?m=user-deleted");
});

// --- groups ----------------------------------------------------------------------

async function groupsPage(c: AppContext, error?: string) {
  const groups = await listGroups(c.env);
  const token = csrf(c);
  return adminPage(
    c,
    { title: "Groups", tab: "/admin/groups", error, status: error ? 400 : undefined },
    <>
      <Section title="Groups" description="Apps receive group names in the `groups` claim. Name them after what they allow, e.g. system-owner or inbox-admin.">
        <ul class="rows">
          {groups.map((g) => (
            <li>
              <div class="grow">
                <strong>{g.name}</strong> <small class="muted">{g.member_count} member{g.member_count === 1 ? "" : "s"}</small>
                <form method="post" action={`/admin/groups/${encodeURIComponent(g.name)}`} class="inline-edit">
                  <Csrf token={token} />
                  <input type="text" name="description" value={g.description} maxlength={200} placeholder="Description" aria-label={`Description of ${g.name}`} />
                  <button type="submit" class="small">
                    <Save class="icon" aria-hidden="true" />
                    Save
                  </button>
                </form>
              </div>
              {g.name !== ADMIN_GROUP && (
                <form method="post" action={`/admin/groups/${encodeURIComponent(g.name)}/delete`} data-confirm={`Delete the group "${g.name}"? Members lose it immediately.`}>
                  <Csrf token={token} />
                  <button type="submit" class="danger small">Delete</button>
                </form>
              )}
            </li>
          ))}
        </ul>
      </Section>
      <Section title="New group">
        <form method="post" action="/admin/groups" class="stack">
          <Csrf token={token} />
          <div class="grid2">
            <Field label="Name" name="name" required maxlength={64} autocomplete="off" />
            <Field label="Description" name="description" maxlength={200} autocomplete="off" />
          </div>
          <div>
            <button type="submit" class="primary">
              <Users class="icon" aria-hidden="true" />
              Create group
            </button>
          </div>
        </form>
      </Section>
    </>,
  );
}

admin.get("/admin/groups", (c) => groupsPage(c));

admin.post("/admin/groups", async (c) => {
  const body = await form(c);
  const name = (body.name ?? "").trim().toLowerCase();
  const problem = groupProblem(name);
  if (problem) return groupsPage(c, problem);
  if (!(await createGroup(c.env, name, cleanText(body.description, 200) ?? ""))) {
    return groupsPage(c, "A group with that name already exists.");
  }
  await audit(c, "admin.group_created", { target: name });
  return c.redirect("/admin/groups?m=group-created");
});

admin.post("/admin/groups/:name", async (c) => {
  const body = await form(c);
  await updateGroup(c.env, c.req.param("name"), cleanText(body.description, 200) ?? "");
  return c.redirect("/admin/groups?m=group-saved");
});

admin.post("/admin/groups/:name/delete", async (c) => {
  const name = c.req.param("name");
  if (name === ADMIN_GROUP) return groupsPage(c, `${ADMIN_GROUP} can't be deleted.`);
  await deleteGroup(c.env, name);
  await audit(c, "admin.group_deleted", { target: name });
  return c.redirect("/admin/groups?m=group-deleted");
});

// --- clients -----------------------------------------------------------------------

interface ClientForm {
  input: ClientInput;
  raw: Record<string, string>;
}

async function readClientForm(c: AppContext): Promise<ClientForm | { error: string; raw: Record<string, string>; groups: string[] }> {
  const raw = await form(c);
  const chosen = await formAll(c, "allowed_groups");
  const known = new Set((await listGroups(c.env)).map((g) => g.name));
  const name = cleanText(raw.name, 100);
  const redirectUris = lines(raw.redirect_uris);
  const postLogoutRedirectUris = lines(raw.post_logout_redirect_uris);

  const fail = (error: string) => ({ error, raw, groups: chosen });
  if (!name) return fail("Applications need a name.");
  if (redirectUris.length === 0) return fail("Add at least one redirect URI.");
  if (redirectUris.length + postLogoutRedirectUris.length > 40) return fail("That's too many URIs.");
  for (const uri of [...redirectUris, ...postLogoutRedirectUris]) {
    const problem = redirectUriProblem(uri);
    if (problem) return fail(problem);
  }
  return {
    raw,
    input: {
      name,
      redirectUris: [...new Set(redirectUris)],
      postLogoutRedirectUris: [...new Set(postLogoutRedirectUris)],
      allowedGroups: chosen.filter((g) => known.has(g)),
    },
  };
}

function ClientFields(props: { groups: GroupRow[]; name?: string; redirects?: string; postLogout?: string; allowed: string[] }) {
  return (
    <>
      <Field label="Name" name="name" value={props.name} required maxlength={100} autocomplete="off" hint="Shown to people when they're asked to sign in." />
      <label class="field">
        <span>Redirect URIs</span>
        <textarea name="redirect_uris" rows={3} required placeholder="https://app.example.com/auth/callback">
          {props.redirects ?? ""}
        </textarea>
        <small class="muted">One per line, matched exactly.</small>
      </label>
      <label class="field">
        <span>Post-logout redirect URIs</span>
        <textarea name="post_logout_redirect_uris" rows={2} placeholder="https://app.example.com/">
          {props.postLogout ?? ""}
        </textarea>
        <small class="muted">Optional. Where the app may send people after signing out here.</small>
      </label>
      <fieldset>
        <legend>Who can use it</legend>
        <p class="muted small">Leave everything unticked to allow every account.</p>
        <GroupChecks groups={props.groups} selected={props.allowed} name="allowed_groups" />
      </fieldset>
    </>
  );
}

async function clientsPage(c: AppContext, error?: string, raw: Record<string, string> = {}, allowed: string[] = []) {
  const [clients, groups] = await Promise.all([listClients(c.env), listGroups(c.env)]);
  return adminPage(
    c,
    { title: "Applications", tab: "/admin/clients", error, status: error ? 400 : undefined },
    <>
      <Section title="Applications" description="Each app that signs people in through this server is an OpenID Connect client.">
        {clients.length === 0 ? (
          <p class="muted">No applications yet.</p>
        ) : (
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Client id</th>
                  <th>Type</th>
                  <th>Allowed</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((cl) => (
                  <tr>
                    <td>
                      <a class="btn small" href={`/admin/clients/${encodeURIComponent(cl.id)}`}>
                        {cl.name}
                      </a>
                    </td>
                    <td>
                      <code>{cl.id}</code>
                    </td>
                    <td>{cl.isPublic ? "public (PKCE)" : "confidential"}</td>
                    <td>{cl.allowedGroups.length ? cl.allowedGroups.map((g) => <span class="badge">{g}</span>) : "everyone"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Add an application">
        <form method="post" action="/admin/clients" class="stack">
          <Csrf token={csrf(c)} />
          <ClientFields groups={groups} name={raw.name} redirects={raw.redirect_uris} postLogout={raw.post_logout_redirect_uris} allowed={allowed} />
          <fieldset>
            <legend>Type</legend>
            <label class="check">
              <input type="radio" name="type" value="confidential" checked={raw.type !== "public"} />
              <span>
                Confidential <small class="muted">— has a server that can keep a client secret (dough-git, inbox).</small>
              </span>
            </label>
            <label class="check">
              <input type="radio" name="type" value="public" checked={raw.type === "public"} />
              <span>
                Public <small class="muted">— runs entirely in the browser or on a device; uses PKCE and no secret.</small>
              </span>
            </label>
          </fieldset>
          <details>
            <summary>Advanced</summary>
            <Field
              label="Client id"
              name="client_id"
              value={raw.client_id}
              maxlength={128}
              autocomplete="off"
              hint="Leave blank for a random id. Set it to keep an app's existing client id when moving it over from another provider."
            />
          </details>
          <div>
            <button type="submit" class="primary">
              <AppWindows class="icon" aria-hidden="true" />
              Create application
            </button>
          </div>
        </form>
      </Section>
    </>,
  );
}

admin.get("/admin/clients", (c) => clientsPage(c));

admin.post("/admin/clients", async (c) => {
  const parsed = await readClientForm(c);
  if ("error" in parsed) return clientsPage(c, parsed.error, parsed.raw, parsed.groups);

  const id = cleanText(parsed.raw.client_id, 128) ?? crypto.randomUUID();
  const idProblem = clientIdProblem(id);
  if (idProblem) return clientsPage(c, idProblem, parsed.raw, parsed.input.allowedGroups);

  const result = await createClient(c.env, id, parsed.raw.type !== "public", parsed.input);
  if (!result.ok) return clientsPage(c, result.error, parsed.raw, parsed.input.allowedGroups);

  await audit(c, "admin.client_created", { target: id });
  return clientPage(c, id, { secret: result.secret });
});

function Integration(props: { c: AppContext; client: Client }) {
  const iss = issuer(props.c.env);
  const rows: [string, string][] = [
    ["Issuer", iss],
    ["Discovery", `${iss}/.well-known/openid-configuration`],
    ["Client id", props.client.id],
    ["Token auth", props.client.isPublic ? "none (PKCE)" : "client_secret_basic or client_secret_post"],
    ["Scopes", "openid profile email groups (+ offline_access for refresh tokens)"],
  ];
  return (
    <dl class="kv">
      {rows.map(([k, v]) => (
        <>
          <dt>{k}</dt>
          <dd>
            <code>{v}</code>
          </dd>
        </>
      ))}
    </dl>
  );
}

async function clientPage(c: AppContext, id: string, opts: { error?: string; secret?: string | null } = {}) {
  const client = await getClient(c.env, id);
  if (!client) return notFound(c, "application");
  const groups = await listGroups(c.env);
  const base = `/admin/clients/${encodeURIComponent(id)}`;
  const token = csrf(c);

  return adminPage(
    c,
    { title: client.name, tab: "/admin/clients", error: opts.error, status: opts.error ? 400 : undefined },
    <>
      <p>
        <a class="btn small" href="/admin/clients">← All applications</a>
      </p>
      <h1>{client.name}</h1>

      {opts.secret && (
        <div class="notice ok">
          <p>
            <strong>Client secret</strong> — copy it into the app's configuration now. It won't be shown again.
          </p>
          <p class="copyrow">
            <input type="text" readonly value={opts.secret} aria-label="Client secret" />
            <button type="button" data-copy={opts.secret}>Copy</button>
          </p>
        </div>
      )}

      <Section title="Connecting the app">
        <Integration c={c} client={client} />
      </Section>

      <Section title="Settings">
        <form method="post" action={base} class="stack">
          <Csrf token={token} />
          <ClientFields
            groups={groups}
            name={client.name}
            redirects={client.redirectUris.join("\n")}
            postLogout={client.postLogoutRedirectUris.join("\n")}
            allowed={client.allowedGroups}
          />
          <div>
            <button type="submit">
              <Save class="icon" aria-hidden="true" />
              Save
            </button>
          </div>
        </form>
      </Section>

      <Section title="Client secret">
        <p class="muted">
          {client.isPublic
            ? "This is a public client: it has no secret and must use PKCE."
            : "Rotating the secret breaks the app until it's given the new one."}
        </p>
        <div class="buttons">
          <form method="post" action={`${base}/secret`} data-confirm={client.isPublic ? "Give this app a secret and make it confidential?" : "Replace the secret? The old one stops working immediately."}>
            <Csrf token={token} />
            <button type="submit">{client.isPublic ? "Create a secret" : "Rotate secret"}</button>
          </form>
          {!client.isPublic && (
            <form method="post" action={`${base}/public`} data-confirm="Remove the secret and make this a public PKCE client?">
              <Csrf token={token} />
              <button type="submit" class="danger">Make public</button>
            </form>
          )}
        </div>
      </Section>

      <Section title="Delete application" description="Its refresh tokens stop working immediately; issued access tokens are refused by /userinfo.">
        <form method="post" action={`${base}/delete`} data-confirm={`Delete ${client.name}? People won't be able to sign in to it.`}>
          <Csrf token={token} />
          <button type="submit" class="danger">Delete</button>
        </form>
      </Section>
    </>,
  );
}

admin.get("/admin/clients/:id", (c) => clientPage(c, c.req.param("id")));

admin.post("/admin/clients/:id", async (c) => {
  const id = c.req.param("id");
  if (!(await getClient(c.env, id))) return notFound(c, "application");
  const parsed = await readClientForm(c);
  if ("error" in parsed) return clientPage(c, id, { error: parsed.error });
  await updateClient(c.env, id, parsed.input);
  await audit(c, "admin.client_updated", { target: id });
  return c.redirect(`/admin/clients/${encodeURIComponent(id)}?m=client-saved`);
});

admin.post("/admin/clients/:id/secret", async (c) => {
  const id = c.req.param("id");
  if (!(await getClient(c.env, id))) return notFound(c, "application");
  const secret = await rotateClientSecret(c.env, id);
  await audit(c, "admin.client_secret_rotated", { target: id });
  return clientPage(c, id, { secret });
});

admin.post("/admin/clients/:id/public", async (c) => {
  const id = c.req.param("id");
  await makeClientPublic(c.env, id);
  await audit(c, "admin.client_made_public", { target: id });
  return c.redirect(`/admin/clients/${encodeURIComponent(id)}?m=client-public`);
});

admin.post("/admin/clients/:id/delete", async (c) => {
  const id = c.req.param("id");
  await deleteClient(c.env, id);
  await audit(c, "admin.client_deleted", { target: id });
  return c.redirect("/admin/clients?m=client-deleted");
});

// --- keys + audit ------------------------------------------------------------------

admin.get("/admin/keys", async (c) => {
  const keys = await listKeys(c.env);
  return adminPage(
    c,
    { title: "Signing keys", tab: "/admin/keys" },
    <Section title="Signing keys" description="Tokens are signed with the newest active key. Apps pick up new keys from the JWKS automatically. A key is created on first use.">
      <ul class="rows">
        {keys.map((k) => (
          <li>
            <div class="grow">
              <code>{k.kid}</code> <span class={`badge ${k.retired_at ? "" : "ok"}`}>{k.retired_at ? "retired" : "active"}</span>
              <br />
              <small class="muted">
                {k.alg} · created {date(k.created_at)}
                {k.retired_at ? ` · retired ${date(k.retired_at)}` : ""}
              </small>
            </div>
          </li>
        ))}
      </ul>
      <form method="post" action="/admin/keys/rotate" data-confirm="Rotate the signing key?">
        <Csrf token={csrf(c)} />
        <button type="submit">Rotate now</button>
      </form>
    </Section>,
  );
});

admin.post("/admin/keys/rotate", async (c) => {
  const kid = await rotateKeys(c.env);
  await audit(c, "admin.keys_rotated", { target: kid });
  return c.redirect("/admin/keys?m=keys-rotated");
});

admin.get("/admin/audit", async (c) => {
  const entries = await recentAudit(c);
  return adminPage(
    c,
    { title: "Audit log", tab: "/admin/audit" },
    <Section title="Recent activity" description="The latest 200 events. Kept for 180 days.">
      <div class="table-wrap">
        <table class="compact">
          <thead>
            <tr>
              <th>When</th>
              <th>Who</th>
              <th>What</th>
              <th>Target</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr>
                <td title={date(e.at)}>{relative(e.at)}</td>
                <td>{e.actor_username ? `@${e.actor_username}` : <span class="muted">—</span>}</td>
                <td>
                  <code>{e.action}</code>
                  {e.detail && <small class="muted"> {e.detail}</small>}
                </td>
                <td>{e.target ?? ""}</td>
                <td>{e.ip ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>,
  );
});
