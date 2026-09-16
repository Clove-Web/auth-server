/* src/lib/ratelimit.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { now, type Env } from "../env";

/**
 * Counts one attempt against `key` in a fixed window and reports whether it is
 * still within `limit`. The upsert is a single statement, so parallel requests
 * can't slip past the limit together.
 */
export async function attempt(
  env: Env,
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<boolean> {
  const ts = now();
  const stale = ts - windowSeconds;
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (key, count, window_start) VALUES (?1, 1, ?2)
     ON CONFLICT (key) DO UPDATE SET
       count        = CASE WHEN window_start <= ?3 THEN 1 ELSE count + 1 END,
       window_start = CASE WHEN window_start <= ?3 THEN ?2 ELSE window_start END
     RETURNING count`,
  )
    .bind(key, ts, stale)
    .first<{ count: number }>();
  return (row?.count ?? 1) <= limit;
}

export async function clearAttempts(env: Env, key: string): Promise<void> {
  await env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(key).run();
}
