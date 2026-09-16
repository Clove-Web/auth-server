/* src/oidc/tokens.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { SignJWT, compactVerify, errors, jwtVerify, type JWTPayload } from "jose";
import { TTL, issuer, now, type Env } from "../env";
import { b64url, randomToken, sha256, sha256Hex } from "../lib/crypto";
import { ALG, resetJwksCache, signingKey, verificationKeys } from "../data/keys";
import { groupsFor, type UserRow } from "../data/users";

export const SUPPORTED_SCOPES = ["openid", "profile", "email", "groups", "offline_access"] as const;

export const SUPPORTED_CLAIMS = [
  "sub",
  "iss",
  "aud",
  "exp",
  "iat",
  "auth_time",
  "nonce",
  "amr",
  "at_hash",
  "name",
  "preferred_username",
  "picture",
  "updated_at",
  "email",
  "email_verified",
  "groups",
];

/** Keeps the scopes we know, in a stable order, without duplicates. */
export function parseScope(raw: string | undefined): string[] {
  const asked = new Set((raw ?? "").split(" ").filter(Boolean));
  return SUPPORTED_SCOPES.filter((s) => asked.has(s));
}

export async function userClaims(env: Env, user: UserRow, scopes: string[]): Promise<Record<string, unknown>> {
  const claims: Record<string, unknown> = { sub: user.id };
  if (scopes.includes("profile")) {
    claims.name = user.name ?? user.username;
    claims.preferred_username = user.username;
    if (user.picture) claims.picture = user.picture;
    claims.updated_at = user.updated_at;
  }
  if (scopes.includes("email") && user.email) {
    claims.email = user.email;
    claims.email_verified = user.email_verified === 1;
  }
  if (scopes.includes("groups")) {
    claims.groups = await groupsFor(env, user.id);
  }
  return claims;
}

export interface Grant {
  clientId: string;
  user: UserRow;
  scopes: string[];
  authTime: number;
  amr: string[];
  nonce?: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  id_token: string;
  scope: string;
  refresh_token?: string;
}

async function atHash(accessToken: string): Promise<string> {
  const digest = await sha256(accessToken);
  return b64url(digest.slice(0, digest.length / 2));
}

export async function issueTokens(
  env: Env,
  grant: Grant,
  refresh: { familyId: string } | null,
): Promise<TokenResponse> {
  const { kid, key } = await signingKey(env);
  const iss = issuer(env);
  const iat = now();

  const accessToken = await new SignJWT({
    client_id: grant.clientId,
    scope: grant.scopes.join(" "),
  })
    .setProtectedHeader({ alg: ALG, kid, typ: "at+jwt" })
    .setIssuer(iss)
    .setSubject(grant.user.id)
    .setAudience(grant.clientId)
    .setJti(randomToken(16))
    .setIssuedAt(iat)
    .setExpirationTime(iat + TTL.accessToken)
    .sign(key);

  const idClaims: JWTPayload = {
    ...(await userClaims(env, grant.user, grant.scopes)),
    auth_time: grant.authTime,
    amr: grant.amr,
    at_hash: await atHash(accessToken),
  };
  if (grant.nonce) idClaims.nonce = grant.nonce;

  const idToken = await new SignJWT(idClaims)
    .setProtectedHeader({ alg: ALG, kid, typ: "JWT" })
    .setIssuer(iss)
    .setSubject(grant.user.id)
    .setAudience(grant.clientId)
    .setIssuedAt(iat)
    .setExpirationTime(iat + TTL.idToken)
    .sign(key);

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: TTL.accessToken,
    id_token: idToken,
    scope: grant.scopes.join(" "),
  };

  if (refresh && grant.scopes.includes("offline_access")) {
    const token = `dssr_${randomToken(32)}`;
    await env.DB.prepare(
      `INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id, scope, auth_time, amr, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        await sha256Hex(token),
        refresh.familyId,
        grant.clientId,
        grant.user.id,
        grant.scopes.join(" "),
        grant.authTime,
        JSON.stringify(grant.amr),
        iat,
        iat + TTL.refreshToken,
      )
      .run();
    response.refresh_token = token;
  }

  return response;
}

/**
 * Verifies a token we signed. A key rotated in another isolate may not be in
 * this isolate's cached JWKS yet, so a missing key triggers one refetch.
 */
async function withKeys<T>(env: Env, fn: (keys: Awaited<ReturnType<typeof verificationKeys>>) => Promise<T>): Promise<T> {
  try {
    return await fn(await verificationKeys(env));
  } catch (err) {
    if (!(err instanceof errors.JWKSNoMatchingKey)) throw err;
    resetJwksCache();
    return fn(await verificationKeys(env));
  }
}

export interface AccessTokenClaims {
  sub: string;
  clientId: string;
  scopes: string[];
}

export async function verifyAccessToken(env: Env, token: string): Promise<AccessTokenClaims | null> {
  try {
    const { payload } = await withKeys(env, (keys) =>
      jwtVerify(token, keys, { issuer: issuer(env), typ: "at+jwt", algorithms: [ALG] }),
    );
    if (typeof payload.sub !== "string" || typeof payload.client_id !== "string") return null;
    return {
      sub: payload.sub,
      clientId: payload.client_id,
      scopes: typeof payload.scope === "string" ? payload.scope.split(" ") : [],
    };
  } catch {
    return null;
  }
}

/**
 * id_token_hint for logout: the signature and issuer must check out, but an
 * expired token is still a perfectly good hint.
 */
export async function verifyIdTokenHint(env: Env, token: string): Promise<{ sub: string; aud: string[] } | null> {
  try {
    const { payload } = await withKeys(env, (keys) => compactVerify(token, keys, { algorithms: [ALG] }));
    const claims = JSON.parse(new TextDecoder().decode(payload)) as JWTPayload;
    if (claims.iss !== issuer(env) || typeof claims.sub !== "string") return null;
    const aud = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
    return { sub: claims.sub, aud };
  } catch {
    return null;
  }
}
