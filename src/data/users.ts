/* src/data/users.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { ADMIN_GROUP, now, type Env } from "../env";

export interface UserRow {
  id: string;
  username: string;
  name: string | null;
  email: string | null;
  email_verified: number;
  picture: string | null;
  password_hash: string | null;
  totp_secret: string | null;
  totp_pending: string | null;
  totp_last_step: number;
  disabled: number;
  created_at: number;
  updated_at: number;
  last_login_at: number | null;
}

export interface UserSummary extends UserRow {
  groups: string[];
  passkey_count: number;
}

export async function getUser(env: Env, id: string): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
}

export async function getUserByUsername(env: Env, username: string): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first<UserRow>();
}

export async function countUsers(env: Env): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
  return row?.n ?? 0;
}

export async function groupsFor(env: Env, userId: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT group_name FROM user_groups WHERE user_id = ? ORDER BY group_name",
  )
    .bind(userId)
    .all<{ group_name: string }>();
  return results.map((r) => r.group_name);
}

export async function listUsers(env: Env): Promise<UserSummary[]> {
  const { results } = await env.DB.prepare(
    `SELECT u.*,
       (SELECT COUNT(*) FROM passkeys p WHERE p.user_id = u.id) AS passkey_count,
       (SELECT json_group_array(group_name) FROM
          (SELECT group_name FROM user_groups g WHERE g.user_id = u.id ORDER BY group_name)
       ) AS groups_json
     FROM users u ORDER BY u.username`,
  ).all<UserRow & { passkey_count: number; groups_json: string }>();
  return results.map(({ groups_json, ...row }) => ({
    ...row,
    groups: JSON.parse(groups_json) as string[],
  }));
}

export interface NewUser {
  id?: string;
  username: string;
  name: string | null;
  email: string | null;
  emailVerified: boolean;
}

export type CreateResult = { ok: true; id: string } | { ok: false; error: string };

export async function createUser(env: Env, input: NewUser): Promise<CreateResult> {
  const id = input.id || crypto.randomUUID();
  const ts = now();
  try {
    await env.DB.prepare(
      `INSERT INTO users (id, username, name, email, email_verified, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(id, input.username, input.name, input.email, input.emailVerified ? 1 : 0, ts, ts)
      .run();
    return { ok: true, id };
  } catch (err) {
    if (String(err).includes("UNIQUE")) {
      return { ok: false, error: "That username or subject id is already taken." };
    }
    throw err;
  }
}

/**
 * Creates the very first account as an admin. The insert only happens while
 * the users table is empty, so two racing /setup submissions can't both win.
 */
export async function createFirstAdmin(env: Env, input: NewUser): Promise<string | null> {
  const id = crypto.randomUUID();
  const ts = now();
  const [inserted] = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO users (id, username, name, email, email_verified, created_at, updated_at)
       SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`,
    ).bind(id, input.username, input.name, input.email, input.emailVerified ? 1 : 0, ts, ts),
    env.DB.prepare(
      "INSERT OR IGNORE INTO groups (name, description, created_at) VALUES (?, ?, ?)",
    ).bind(ADMIN_GROUP, "Can manage users, groups and applications on this server.", ts),
    env.DB.prepare(
      "INSERT OR IGNORE INTO user_groups (user_id, group_name) SELECT id, ? FROM users WHERE id = ?",
    ).bind(ADMIN_GROUP, id),
  ]);
  return inserted?.meta.changes === 1 ? id : null;
}

export interface ProfileUpdate {
  name: string | null;
  email: string | null;
  picture: string | null;
}

export async function updateProfile(env: Env, user: UserRow, update: ProfileUpdate): Promise<void> {
  // Changing the address un-verifies it; keeping it keeps whatever it was.
  const verified = update.email !== null && update.email === user.email ? user.email_verified : 0;
  await env.DB.prepare(
    "UPDATE users SET name = ?, email = ?, email_verified = ?, picture = ?, updated_at = ? WHERE id = ?",
  )
    .bind(update.name, update.email, verified, update.picture, now(), user.id)
    .run();
}

export async function adminUpdateUser(
  env: Env,
  id: string,
  update: ProfileUpdate & { username: string; emailVerified: boolean },
): Promise<string | null> {
  try {
    await env.DB.prepare(
      `UPDATE users SET username = ?, name = ?, email = ?, email_verified = ?, picture = ?, updated_at = ?
       WHERE id = ?`,
    )
      .bind(
        update.username,
        update.name,
        update.email,
        update.email && update.emailVerified ? 1 : 0,
        update.picture,
        now(),
        id,
      )
      .run();
    return null;
  } catch (err) {
    if (String(err).includes("UNIQUE")) return "That username is already taken.";
    throw err;
  }
}

export async function setPasswordHash(env: Env, id: string, hash: string | null): Promise<void> {
  // Without a password there is nothing for TOTP to protect, so it goes too.
  const sql =
    hash === null
      ? "UPDATE users SET password_hash = NULL, totp_secret = NULL, totp_pending = NULL, updated_at = ? WHERE id = ?"
      : "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?";
  const stmt = env.DB.prepare(sql);
  await (hash === null ? stmt.bind(now(), id) : stmt.bind(hash, now(), id)).run();
}

export async function setTotpPending(env: Env, id: string, sealed: string | null): Promise<void> {
  await env.DB.prepare("UPDATE users SET totp_pending = ?, updated_at = ? WHERE id = ?")
    .bind(sealed, now(), id)
    .run();
}

export async function enableTotp(env: Env, id: string, sealed: string, step: number): Promise<void> {
  await env.DB.prepare(
    "UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_last_step = ?, updated_at = ? WHERE id = ?",
  )
    .bind(sealed, step, now(), id)
    .run();
}

export async function disableTotp(env: Env, id: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE users SET totp_secret = NULL, totp_pending = NULL, updated_at = ? WHERE id = ?",
  )
    .bind(now(), id)
    .run();
}

/**
 * Records `step` as used. Returns false if it (or a later step) was already
 * used, i.e. the code is a replay.
 */
export async function claimTotpStep(env: Env, id: string, step: number): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
  )
    .bind(step, id, step)
    .run();
  return result.meta.changes === 1;
}

export async function markLogin(env: Env, id: string): Promise<void> {
  await env.DB.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now(), id).run();
}

export async function setDisabled(env: Env, id: string, disabled: boolean): Promise<void> {
  const stmts = [
    env.DB.prepare("UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?").bind(
      disabled ? 1 : 0,
      now(),
      id,
    ),
  ];
  if (disabled) stmts.push(...revokeAllStatements(env, id));
  await env.DB.batch(stmts);
}

export function revokeAllStatements(env: Env, userId: string): D1PreparedStatement[] {
  return [
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId),
    env.DB.prepare("DELETE FROM pending_logins WHERE user_id = ?").bind(userId),
    env.DB.prepare(
      "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
    ).bind(now(), userId),
  ];
}

export async function deleteUser(env: Env, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
}

export async function setUserGroups(env: Env, userId: string, groups: string[]): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM user_groups WHERE user_id = ?").bind(userId),
    ...groups.map((g) =>
      env.DB.prepare(
        "INSERT OR IGNORE INTO user_groups (user_id, group_name) SELECT ?, name FROM groups WHERE name = ?",
      ).bind(userId, g),
    ),
  ]);
}
