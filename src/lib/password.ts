/* src/lib/password.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { b64url, fromB64url, randomBytes, timingSafeEqual, utf8 } from "./crypto";

// Sized for the Workers free plan's 10ms CPU budget per request (100k, the
// Workers maximum, costs ~10ms on its own). The count is stored with each hash
// and older hashes are upgraded on sign-in, so this can be raised to 100_000
// after moving to a paid plan.
const ITERATIONS = 40_000;
const SCHEME = "pbkdf2-sha256";

export const PASSWORD_MIN = 10;
export const PASSWORD_MAX = 512;

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number) {
  const key = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await derive(password, salt, ITERATIONS);
  return `${SCHEME}$${ITERATIONS}$${b64url(salt)}$${b64url(hash)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, iter, salt, hash] = stored.split("$");
  const iterations = Number(iter);
  if (scheme !== SCHEME || !salt || !hash || !Number.isInteger(iterations) || iterations < 1) {
    return false;
  }
  const actual = await derive(password, fromB64url(salt), iterations);
  return timingSafeEqual(actual, fromB64url(hash));
}

/** True when a hash was made with fewer iterations than we use now. */
export function needsRehash(stored: string): boolean {
  return Number(stored.split("$")[1]) < ITERATIONS;
}

// Burned on unknown usernames so response timing doesn't reveal which exist.
const DUMMY = `${SCHEME}$${ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;

export async function burnPasswordCheck(password: string): Promise<void> {
  await verifyPassword(password, DUMMY);
}

export function passwordProblem(password: string, username: string): string | null {
  if (password.length < PASSWORD_MIN) return `Passwords need at least ${PASSWORD_MIN} characters.`;
  if (password.length > PASSWORD_MAX) return `Passwords can be at most ${PASSWORD_MAX} characters.`;
  if (password.toLowerCase().includes(username.toLowerCase())) {
    return "Passwords can't contain your username.";
  }
  return null;
}
