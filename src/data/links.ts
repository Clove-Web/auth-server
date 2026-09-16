/* src/data/links.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { issuer, now, type Env } from "../env";
import { randomToken, sha256Hex } from "../lib/crypto";

/**
 * One-time sign-in links, issued by an admin to bootstrap a new account or
 * recover one that lost its passkeys. Returns the full URL, shown once.
 */
export async function createLoginLink(
  env: Env,
  userId: string,
  createdBy: string,
  ttlSeconds: number,
): Promise<{ url: string; expiresAt: number }> {
  const token = randomToken(32);
  const ts = now();
  const expiresAt = ts + ttlSeconds;
  await env.DB.batch([
    // Only the newest link for an account stays valid.
    env.DB.prepare("DELETE FROM login_links WHERE user_id = ?").bind(userId),
    env.DB.prepare(
      "INSERT INTO login_links (token_hash, user_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
    ).bind(await sha256Hex(token), userId, createdBy, ts, expiresAt),
  ]);
  return { url: `${issuer(env)}/login/link/${token}`, expiresAt };
}

export interface LinkTarget {
  user_id: string;
  username: string;
  name: string | null;
}

/** Looks a link up without using it (the confirmation page). */
export async function peekLoginLink(env: Env, token: string): Promise<LinkTarget | null> {
  return env.DB.prepare(
    `SELECT l.user_id, u.username, u.name FROM login_links l JOIN users u ON u.id = l.user_id
     WHERE l.token_hash = ? AND l.expires_at > ? AND u.disabled = 0`,
  )
    .bind(await sha256Hex(token), now())
    .first<LinkTarget>();
}

/** Uses a link up. Returns the account it signs in to, or null. */
export async function consumeLoginLink(env: Env, token: string): Promise<string | null> {
  const row = await env.DB.prepare(
    "DELETE FROM login_links WHERE token_hash = ? RETURNING user_id, expires_at",
  )
    .bind(await sha256Hex(token))
    .first<{ user_id: string; expires_at: number }>();
  if (!row || row.expires_at <= now()) return null;
  const user = await env.DB.prepare("SELECT disabled FROM users WHERE id = ?")
    .bind(row.user_id)
    .first<{ disabled: number }>();
  return user && !user.disabled ? row.user_id : null;
}

export async function hasOpenLoginLink(env: Env, userId: string): Promise<number | null> {
  const row = await env.DB.prepare("SELECT expires_at FROM login_links WHERE user_id = ? AND expires_at > ?")
    .bind(userId, now())
    .first<{ expires_at: number }>();
  return row?.expires_at ?? null;
}

export async function revokeLoginLinks(env: Env, userId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM login_links WHERE user_id = ?").bind(userId).run();
}
