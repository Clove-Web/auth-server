/* src/data/groups.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { now, type Env } from "../env";

export interface GroupRow {
  name: string;
  description: string;
  created_at: number;
  member_count: number;
}

export async function listGroups(env: Env): Promise<GroupRow[]> {
  const { results } = await env.DB.prepare(
    `SELECT g.*, (SELECT COUNT(*) FROM user_groups ug WHERE ug.group_name = g.name) AS member_count
     FROM groups g ORDER BY g.name`,
  ).all<GroupRow>();
  return results;
}

export async function createGroup(env: Env, name: string, description: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "INSERT OR IGNORE INTO groups (name, description, created_at) VALUES (?, ?, ?)",
  )
    .bind(name, description, now())
    .run();
  return result.meta.changes === 1;
}

export async function updateGroup(env: Env, name: string, description: string): Promise<void> {
  await env.DB.prepare("UPDATE groups SET description = ? WHERE name = ?").bind(description, name).run();
}

export async function deleteGroup(env: Env, name: string): Promise<void> {
  await env.DB.prepare("DELETE FROM groups WHERE name = ?").bind(name).run();
}
