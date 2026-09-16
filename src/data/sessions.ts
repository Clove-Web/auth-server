/* src/data/sessions.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { ADMIN_GROUP, TTL, isSecure, now, type AppContext, type CurrentUser, type Env, type SessionInfo } from "../env";
import { randomToken, sha256Hex } from "../lib/crypto";
import { clientIp, userAgent } from "../lib/http";
import { groupsFor, markLogin } from "./users";

function cookieName(env: Env, base: string): string {
  // __Host- pins the cookie to this exact origin: Secure, Path=/, no Domain.
  return isSecure(env) ? `__Host-${base}` : base;
}

export const sessionCookie = (env: Env) => cookieName(env, "sso_session");
export const pendingCookie = (env: Env) => cookieName(env, "sso_pending");

export function writeCookie(c: AppContext, name: string, value: string, maxAge: number): void {
  setCookie(c, name, value, {
    httpOnly: true,
    secure: isSecure(c.env),
    sameSite: "Lax",
    path: "/",
    maxAge,
  });
}

export function clearCookie(c: AppContext, name: string): void {
  deleteCookie(c, name, { path: "/", secure: isSecure(c.env) });
}

export async function startSession(c: AppContext, userId: string, amr: string[]): Promise<void> {
  // Drop whatever session this browser already had so ids never get reused
  // across a re-authentication.
  await endSession(c);

  const token = randomToken(32);
  const ts = now();
  await c.env.DB.prepare(
    `INSERT INTO sessions (id_hash, user_id, csrf, auth_time, amr, ip, user_agent, created_at, last_seen_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      await sha256Hex(token),
      userId,
      randomToken(24),
      ts,
      JSON.stringify(amr),
      clientIp(c),
      userAgent(c),
      ts,
      ts,
      ts + TTL.session,
    )
    .run();
  await markLogin(c.env, userId);
  writeCookie(c, sessionCookie(c.env), token, TTL.session);
}

export async function endSession(c: AppContext): Promise<void> {
  const token = getCookie(c, sessionCookie(c.env));
  if (token) {
    await c.env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(await sha256Hex(token)).run();
  }
  clearCookie(c, sessionCookie(c.env));
  c.set("session", null);
  c.set("user", null);
}

interface SessionJoin {
  id_hash: string;
  user_id: string;
  csrf: string;
  auth_time: number;
  amr: string;
  last_seen_at: number;
  expires_at: number;
  username: string;
  name: string | null;
  email: string | null;
  picture: string | null;
  disabled: number;
}

/** Resolves the session cookie into c.var.session / c.var.user. */
export async function loadSession(c: AppContext): Promise<void> {
  c.set("session", null);
  c.set("user", null);

  const token = getCookie(c, sessionCookie(c.env));
  if (!token) return;

  const idHash = await sha256Hex(token);
  const row = await c.env.DB.prepare(
    `SELECT s.*, u.username, u.name, u.email, u.picture, u.disabled
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.id_hash = ?`,
  )
    .bind(idHash)
    .first<SessionJoin>();

  const ts = now();
  if (!row || row.expires_at <= ts || row.disabled) {
    if (row) await c.env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(idHash).run();
    clearCookie(c, sessionCookie(c.env));
    return;
  }

  if (ts - row.last_seen_at > 300) {
    await c.env.DB.prepare("UPDATE sessions SET last_seen_at = ?, ip = ? WHERE id_hash = ?")
      .bind(ts, clientIp(c), idHash)
      .run();
  }

  const groups = await groupsFor(c.env, row.user_id);
  const session: SessionInfo = {
    idHash,
    userId: row.user_id,
    csrf: row.csrf,
    authTime: row.auth_time,
    amr: JSON.parse(row.amr) as string[],
  };
  const user: CurrentUser = {
    id: row.user_id,
    username: row.username,
    name: row.name,
    email: row.email,
    picture: row.picture,
    groups,
    isAdmin: groups.includes(ADMIN_GROUP),
  };
  c.set("session", session);
  c.set("user", user);
}

export interface SessionListing {
  id_hash: string;
  ip: string | null;
  user_agent: string | null;
  created_at: number;
  last_seen_at: number;
  amr: string;
}

export async function listSessions(env: Env, userId: string): Promise<SessionListing[]> {
  const { results } = await env.DB.prepare(
    `SELECT id_hash, ip, user_agent, created_at, last_seen_at, amr FROM sessions
     WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC`,
  )
    .bind(userId, now())
    .all<SessionListing>();
  return results;
}

export async function revokeSession(env: Env, userId: string, idHash: string): Promise<void> {
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND id_hash = ?").bind(userId, idHash).run();
}

export async function revokeOtherSessions(env: Env, userId: string, keepIdHash: string): Promise<void> {
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND id_hash != ?").bind(userId, keepIdHash).run();
}

// --- pending password logins (waiting on TOTP) --------------------------------

export async function startPendingLogin(c: AppContext, userId: string, returnTo: string): Promise<void> {
  const token = randomToken(32);
  await c.env.DB.prepare(
    "INSERT INTO pending_logins (id_hash, user_id, return_to, expires_at) VALUES (?, ?, ?, ?)",
  )
    .bind(await sha256Hex(token), userId, returnTo, now() + TTL.pendingLogin)
    .run();
  writeCookie(c, pendingCookie(c.env), token, TTL.pendingLogin);
}

export interface PendingLogin {
  id_hash: string;
  user_id: string;
  return_to: string;
  attempts: number;
}

export async function peekPendingLogin(c: AppContext): Promise<PendingLogin | null> {
  const token = getCookie(c, pendingCookie(c.env));
  if (!token) return null;
  return c.env.DB.prepare(
    "SELECT id_hash, user_id, return_to, attempts FROM pending_logins WHERE id_hash = ? AND expires_at > ?",
  )
    .bind(await sha256Hex(token), now())
    .first<PendingLogin>();
}

/** Counts a code attempt; returns the pending login only while attempts remain. */
export async function spendPendingAttempt(c: AppContext, maxAttempts: number): Promise<PendingLogin | null> {
  const token = getCookie(c, pendingCookie(c.env));
  if (!token) return null;
  const row = await c.env.DB.prepare(
    `UPDATE pending_logins SET attempts = attempts + 1
     WHERE id_hash = ? AND expires_at > ?
     RETURNING id_hash, user_id, return_to, attempts`,
  )
    .bind(await sha256Hex(token), now())
    .first<PendingLogin>();
  if (!row) return null;
  if (row.attempts > maxAttempts) {
    await finishPendingLogin(c, row.id_hash);
    return null;
  }
  return row;
}

export async function finishPendingLogin(c: AppContext, idHash: string): Promise<void> {
  await c.env.DB.prepare("DELETE FROM pending_logins WHERE id_hash = ?").bind(idHash).run();
  clearCookie(c, pendingCookie(c.env));
}
