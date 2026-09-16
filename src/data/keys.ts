/* src/data/keys.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JSONWebKeySet,
  type JWK,
} from "jose";
import { TTL, now, type Env } from "../env";
import { decrypt, encrypt } from "../lib/crypto";

export const ALG = "RS256";

interface KeyRow {
  kid: string;
  alg: string;
  private_jwk: string;
  public_jwk: string;
  created_at: number;
  retired_at: number | null;
}

export interface SigningKey {
  kid: string;
  key: CryptoKey;
}

// Per-isolate caches. The active-key lookup is re-checked every minute so a
// rotation made through another isolate is picked up quickly.
const privateKeys = new Map<string, Promise<CryptoKey>>();
let active: { kid: string; checkedAt: number } | null = null;
let jwks: { set: JSONWebKeySet; checkedAt: number } | null = null;

async function createKey(env: Env): Promise<KeyRow> {
  const { privateKey, publicKey } = await generateKeyPair(ALG, { modulusLength: 2048, extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  const row: KeyRow = {
    kid,
    alg: ALG,
    private_jwk: await encrypt(env.KEY_ENCRYPTION_KEY, JSON.stringify(await exportJWK(privateKey))),
    public_jwk: JSON.stringify({ ...publicJwk, kid, alg: ALG, use: "sig" }),
    created_at: now(),
    retired_at: null,
  };
  await env.DB.prepare(
    "INSERT INTO signing_keys (kid, alg, private_jwk, public_jwk, created_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(row.kid, row.alg, row.private_jwk, row.public_jwk, row.created_at)
    .run();
  return row;
}

function loadPrivate(env: Env, row: Pick<KeyRow, "kid" | "private_jwk">): Promise<CryptoKey> {
  let key = privateKeys.get(row.kid);
  if (!key) {
    key = decrypt(env.KEY_ENCRYPTION_KEY, row.private_jwk).then(
      async (json) => (await importJWK(JSON.parse(json) as JWK, ALG)) as CryptoKey,
    );
    key.catch(() => privateKeys.delete(row.kid));
    privateKeys.set(row.kid, key);
  }
  return key;
}

export async function signingKey(env: Env): Promise<SigningKey> {
  const ts = Date.now();
  if (active && ts - active.checkedAt < 60_000) {
    const cached = privateKeys.get(active.kid);
    if (cached) return { kid: active.kid, key: await cached };
  }

  let row = await env.DB.prepare(
    "SELECT kid, private_jwk FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1",
  ).first<Pick<KeyRow, "kid" | "private_jwk">>();
  // First run: nothing to sign with yet, so make a key.
  if (!row) row = await createKey(env);

  active = { kid: row.kid, checkedAt: ts };
  return { kid: row.kid, key: await loadPrivate(env, row) };
}

export async function publicJwks(env: Env): Promise<JSONWebKeySet> {
  const ts = Date.now();
  if (jwks && ts - jwks.checkedAt < 60_000) return jwks.set;

  const { results } = await env.DB.prepare(
    "SELECT public_jwk FROM signing_keys WHERE retired_at IS NULL OR retired_at > ? ORDER BY created_at DESC",
  )
    .bind(now() - TTL.retiredKey)
    .all<{ public_jwk: string }>();
  const set = { keys: results.map((r) => JSON.parse(r.public_jwk) as JWK) };
  // Don't cache an empty set: the first token signed would otherwise fail to
  // verify in this isolate for a minute.
  if (set.keys.length) jwks = { set, checkedAt: ts };
  return set;
}

export function resetJwksCache(): void {
  jwks = null;
}

export async function verificationKeys(env: Env) {
  return createLocalJWKSet(await publicJwks(env));
}

export interface KeyListing {
  kid: string;
  alg: string;
  created_at: number;
  retired_at: number | null;
}

export async function listKeys(env: Env): Promise<KeyListing[]> {
  const { results } = await env.DB.prepare(
    "SELECT kid, alg, created_at, retired_at FROM signing_keys ORDER BY created_at DESC",
  ).all<KeyListing>();
  return results;
}

/** Retires every current key and starts signing with a fresh one. */
export async function rotateKeys(env: Env): Promise<string> {
  await env.DB.prepare("UPDATE signing_keys SET retired_at = ? WHERE retired_at IS NULL").bind(now()).run();
  const row = await createKey(env);
  active = null;
  jwks = null;
  return row.kid;
}
