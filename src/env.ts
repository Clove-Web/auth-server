/* src/env.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import type { Context } from "hono";

export interface Env {
  DB: D1Database;
  ISSUER: string;
  SITE_NAME: string;
  KEY_ENCRYPTION_KEY: string;
  SETUP_TOKEN?: string;
}

export interface SessionInfo {
  idHash: string;
  userId: string;
  csrf: string;
  authTime: number;
  amr: string[];
}

export interface CurrentUser {
  id: string;
  username: string;
  name: string | null;
  email: string | null;
  picture: string | null;
  groups: string[];
  isAdmin: boolean;
}

export type AppEnv = {
  Bindings: Env;
  Variables: {
    session: SessionInfo | null;
    user: CurrentUser | null;
  };
};

export type AppContext = Context<AppEnv>;

/** Members of this group can use /admin. */
export const ADMIN_GROUP = "auth-admin";

export const TTL = {
  session: 60 * 60 * 24 * 14,
  pendingLogin: 60 * 10,
  challenge: 60 * 5,
  authCode: 60,
  accessToken: 60 * 60,
  idToken: 60 * 60,
  refreshToken: 60 * 60 * 24 * 30,
  /** Changing sign-in methods or using /admin needs a sign-in this recent. */
  recentAuth: 60 * 30,
  /** Retired signing keys stay in the JWKS this long so issued tokens verify. */
  retiredKey: 60 * 60 * 24 * 2,
} as const;

export function issuer(env: Env): string {
  return env.ISSUER.replace(/\/+$/, "");
}

export function issuerOrigin(env: Env): string {
  return new URL(issuer(env)).origin;
}

/** WebAuthn relying party id: the issuer's hostname. */
export function rpId(env: Env): string {
  return new URL(issuer(env)).hostname;
}

export function isSecure(env: Env): boolean {
  return new URL(issuer(env)).protocol === "https:";
}

export function siteName(env: Env): string {
  return env.SITE_NAME || "Sign in";
}

export function now(): number {
  return Math.floor(Date.now() / 1000);
}
