/* src/data/clients.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { now, type Env } from "../env";
import { randomToken, sha256Hex, timingSafeEqualStr } from "../lib/crypto";

interface ClientRow {
  id: string;
  name: string;
  secret_hash: string | null;
  redirect_uris: string;
  post_logout_redirect_uris: string;
  allowed_groups: string;
  created_at: number;
  updated_at: number;
}

export interface Client {
  id: string;
  name: string;
  secretHash: string | null;
  isPublic: boolean;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedGroups: string[];
  createdAt: number;
  updatedAt: number;
}

function toClient(row: ClientRow): Client {
  return {
    id: row.id,
    name: row.name,
    secretHash: row.secret_hash,
    isPublic: row.secret_hash === null,
    redirectUris: JSON.parse(row.redirect_uris) as string[],
    postLogoutRedirectUris: JSON.parse(row.post_logout_redirect_uris) as string[],
    allowedGroups: JSON.parse(row.allowed_groups) as string[],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getClient(env: Env, id: string): Promise<Client | null> {
  const row = await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(id).first<ClientRow>();
  return row ? toClient(row) : null;
}

export async function listClients(env: Env): Promise<Client[]> {
  const { results } = await env.DB.prepare("SELECT * FROM clients ORDER BY name").all<ClientRow>();
  return results.map(toClient);
}

export interface ClientInput {
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedGroups: string[];
}

function newSecret(): string {
  return `dsso_${randomToken(32)}`;
}

/** Returns the plaintext secret for confidential clients — shown exactly once. */
export async function createClient(
  env: Env,
  id: string,
  confidential: boolean,
  input: ClientInput,
): Promise<{ ok: true; secret: string | null } | { ok: false; error: string }> {
  const secret = confidential ? newSecret() : null;
  const ts = now();
  try {
    await env.DB.prepare(
      `INSERT INTO clients (id, name, secret_hash, redirect_uris, post_logout_redirect_uris, allowed_groups, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        id,
        input.name,
        secret ? await sha256Hex(secret) : null,
        JSON.stringify(input.redirectUris),
        JSON.stringify(input.postLogoutRedirectUris),
        JSON.stringify(input.allowedGroups),
        ts,
        ts,
      )
      .run();
    return { ok: true, secret };
  } catch (err) {
    if (String(err).includes("UNIQUE")) return { ok: false, error: "That client id is already in use." };
    throw err;
  }
}

export async function updateClient(env: Env, id: string, input: ClientInput): Promise<void> {
  await env.DB.prepare(
    `UPDATE clients SET name = ?, redirect_uris = ?, post_logout_redirect_uris = ?, allowed_groups = ?, updated_at = ?
     WHERE id = ?`,
  )
    .bind(
      input.name,
      JSON.stringify(input.redirectUris),
      JSON.stringify(input.postLogoutRedirectUris),
      JSON.stringify(input.allowedGroups),
      now(),
      id,
    )
    .run();
}

/** Issues a new secret (making a public client confidential if need be). */
export async function rotateClientSecret(env: Env, id: string): Promise<string> {
  const secret = newSecret();
  await env.DB.prepare("UPDATE clients SET secret_hash = ?, updated_at = ? WHERE id = ?")
    .bind(await sha256Hex(secret), now(), id)
    .run();
  return secret;
}

export async function makeClientPublic(env: Env, id: string): Promise<void> {
  await env.DB.prepare("UPDATE clients SET secret_hash = NULL, updated_at = ? WHERE id = ?")
    .bind(now(), id)
    .run();
}

export async function deleteClient(env: Env, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM clients WHERE id = ?").bind(id).run();
}

export async function verifyClientSecret(client: Client, secret: string): Promise<boolean> {
  if (!client.secretHash) return false;
  return timingSafeEqualStr(await sha256Hex(secret), client.secretHash);
}

/** Empty allow-list = every account may use the client. */
export function clientAllows(client: Client, groups: string[]): boolean {
  return client.allowedGroups.length === 0 || client.allowedGroups.some((g) => groups.includes(g));
}
