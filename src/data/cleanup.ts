/* src/data/cleanup.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { TTL, now, type Env } from "../env";

const AUDIT_RETENTION = 60 * 60 * 24 * 180;
const RATE_LIMIT_RETENTION = 60 * 60 * 24;

/** Run from the cron trigger. Everything here is already unusable; this only reclaims space. */
export async function sweepExpired(env: Env): Promise<void> {
  const ts = now();
  const results = await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(ts),
    env.DB.prepare("DELETE FROM pending_logins WHERE expires_at <= ?").bind(ts),
    env.DB.prepare("DELETE FROM webauthn_challenges WHERE expires_at <= ?").bind(ts),
    env.DB.prepare("DELETE FROM login_links WHERE expires_at <= ?").bind(ts),
    env.DB.prepare("DELETE FROM auth_codes WHERE expires_at <= ?").bind(ts),
    // Revoked or used refresh tokens are kept until they expire anyway, so reuse
    // of an old token can still be recognised and its family shut down.
    env.DB.prepare("DELETE FROM refresh_tokens WHERE expires_at <= ?").bind(ts),
    env.DB.prepare("DELETE FROM signing_keys WHERE retired_at IS NOT NULL AND retired_at <= ?").bind(
      ts - TTL.retiredKey,
    ),
    env.DB.prepare("DELETE FROM rate_limits WHERE window_start <= ?").bind(ts - RATE_LIMIT_RETENTION),
    env.DB.prepare("DELETE FROM audit_log WHERE at <= ?").bind(ts - AUDIT_RETENTION),
  ]);
  const removed = results.reduce((sum, r) => sum + (r.meta.changes ?? 0), 0);
  console.log(`[cleanup] removed ${removed} expired rows`);
}
