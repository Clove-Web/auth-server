/* src/lib/audit.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { now, type AppContext } from "../env";
import { clientIp } from "./http";

export interface AuditEntry {
  id: number;
  at: number;
  actor_id: string | null;
  actor_username: string | null;
  action: string;
  target: string | null;
  ip: string | null;
  detail: string | null;
}

export async function audit(
  c: AppContext,
  action: string,
  opts: { actor?: string | null; target?: string | null; detail?: string | null } = {},
): Promise<void> {
  const actor = opts.actor === undefined ? (c.get("user")?.id ?? null) : opts.actor;
  try {
    await c.env.DB.prepare(
      "INSERT INTO audit_log (at, actor_id, action, target, ip, detail) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(now(), actor, action, opts.target ?? null, clientIp(c), opts.detail ?? null)
      .run();
  } catch (err) {
    // Never let a logging failure break a sign-in.
    console.error("[audit] write failed", action, err);
  }
}

export async function recentAudit(c: AppContext, limit = 200): Promise<AuditEntry[]> {
  const { results } = await c.env.DB.prepare(
    `SELECT a.*, u.username AS actor_username
     FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
     ORDER BY a.id DESC LIMIT ?`,
  )
    .bind(limit)
    .all<AuditEntry>();
  return results;
}
