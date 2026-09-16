/* src/data/passkeys.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { TTL, issuerOrigin, now, rpId, siteName, type Env } from "../env";
import { b64url, fromB64url, fromUtf8, randomToken, utf8 } from "../lib/crypto";
import type { UserRow } from "./users";

export interface PasskeyRow {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  transports: string;
  device_type: string;
  backed_up: number;
  name: string;
  created_at: number;
  last_used_at: number | null;
}

export async function listPasskeys(env: Env, userId: string): Promise<PasskeyRow[]> {
  const { results } = await env.DB.prepare(
    "SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at",
  )
    .bind(userId)
    .all<PasskeyRow>();
  return results;
}

export async function countPasskeys(env: Env, userId: string): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?")
    .bind(userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

export async function renamePasskey(env: Env, userId: string, id: string, name: string): Promise<void> {
  await env.DB.prepare("UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?").bind(name, id, userId).run();
}

export async function deletePasskey(env: Env, userId: string, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM passkeys WHERE id = ? AND user_id = ?").bind(id, userId).run();
}

async function saveChallenge(
  env: Env,
  challenge: string,
  purpose: "login" | "register",
  userId: string | null,
): Promise<string> {
  const id = randomToken(18);
  await env.DB.prepare(
    "INSERT INTO webauthn_challenges (id, challenge, purpose, user_id, expires_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(id, challenge, purpose, userId, now() + TTL.challenge)
    .run();
  return id;
}

/** Single use: the row is deleted as it is read. */
async function takeChallenge(
  env: Env,
  id: string,
  purpose: "login" | "register",
  userId: string | null,
): Promise<string | null> {
  const row = await env.DB.prepare(
    "DELETE FROM webauthn_challenges WHERE id = ? RETURNING challenge, purpose, user_id, expires_at",
  )
    .bind(id)
    .first<{ challenge: string; purpose: string; user_id: string | null; expires_at: number }>();
  if (!row || row.purpose !== purpose || row.user_id !== userId || row.expires_at <= now()) return null;
  return row.challenge;
}

// --- registration --------------------------------------------------------------

export async function registrationOptions(
  env: Env,
  user: UserRow,
): Promise<{ id: string; options: PublicKeyCredentialCreationOptionsJSON }> {
  const existing = await listPasskeys(env, user.id);
  const options = await generateRegistrationOptions({
    rpName: siteName(env),
    rpID: rpId(env),
    userName: user.username,
    userDisplayName: user.name ?? user.username,
    userID: utf8(user.id),
    attestationType: "none",
    excludeCredentials: existing.map((p) => ({
      id: p.id,
      transports: JSON.parse(p.transports) as string[],
    })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  const id = await saveChallenge(env, options.challenge, "register", user.id);
  return { id, options };
}

export type RegisterResult = { ok: true; passkey: PasskeyRow } | { ok: false; error: string };

export async function finishRegistration(
  env: Env,
  user: UserRow,
  challengeId: string,
  response: RegistrationResponseJSON,
  name: string,
): Promise<RegisterResult> {
  const challenge = await takeChallenge(env, challengeId, "register", user.id);
  if (!challenge) return { ok: false, error: "That request expired. Please try again." };

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: issuerOrigin(env),
      expectedRPID: rpId(env),
      requireUserVerification: true,
    });
  } catch (err) {
    console.warn("[passkeys] registration rejected", err);
    return { ok: false, error: "Your device's response couldn't be verified." };
  }
  if (!verification.verified) return { ok: false, error: "Your device's response couldn't be verified." };

  const info = verification.registrationInfo;
  const row: PasskeyRow = {
    id: info.credential.id,
    user_id: user.id,
    public_key: b64url(info.credential.publicKey),
    counter: info.credential.counter,
    transports: JSON.stringify(info.credential.transports ?? []),
    device_type: info.credentialDeviceType,
    backed_up: info.credentialBackedUp ? 1 : 0,
    name,
    created_at: now(),
    last_used_at: null,
  };
  try {
    await env.DB.prepare(
      `INSERT INTO passkeys (id, user_id, public_key, counter, transports, device_type, backed_up, name, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(row.id, row.user_id, row.public_key, row.counter, row.transports, row.device_type, row.backed_up, row.name, row.created_at)
      .run();
  } catch (err) {
    if (String(err).includes("UNIQUE")) return { ok: false, error: "That passkey is already registered." };
    throw err;
  }
  return { ok: true, passkey: row };
}

// --- authentication ------------------------------------------------------------

export async function authenticationOptions(
  env: Env,
): Promise<{ id: string; options: PublicKeyCredentialRequestOptionsJSON }> {
  // No allowCredentials: passkeys are discoverable, so the browser offers
  // whichever ones it holds for this site and the username never has to be typed.
  const options = await generateAuthenticationOptions({
    rpID: rpId(env),
    userVerification: "required",
  });
  const id = await saveChallenge(env, options.challenge, "login", null);
  return { id, options };
}

export type AuthResult = { ok: true; userId: string; amr: string[] } | { ok: false; error: string };

export async function finishAuthentication(
  env: Env,
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<AuthResult> {
  const failure = { ok: false, error: "That passkey couldn't be used to sign in." } as const;

  const challenge = await takeChallenge(env, challengeId, "login", null);
  if (!challenge) return { ok: false, error: "That sign-in attempt expired. Please try again." };

  const passkey = await env.DB.prepare("SELECT * FROM passkeys WHERE id = ?")
    .bind(String(response?.id ?? ""))
    .first<PasskeyRow>();
  if (!passkey) return { ok: false, error: "This passkey isn't registered here. It may have been removed." };

  const handle = response.response?.userHandle;
  if (handle) {
    try {
      if (fromUtf8(fromB64url(handle)) !== passkey.user_id) return failure;
    } catch {
      return failure;
    }
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: issuerOrigin(env),
      expectedRPID: rpId(env),
      credential: {
        id: passkey.id,
        publicKey: fromB64url(passkey.public_key),
        counter: passkey.counter,
        transports: JSON.parse(passkey.transports) as string[],
      },
      requireUserVerification: true,
    });
  } catch (err) {
    console.warn("[passkeys] authentication rejected", err);
    return failure;
  }
  if (!verification.verified) return failure;

  const info = verification.authenticationInfo;
  await env.DB.prepare(
    "UPDATE passkeys SET counter = ?, backed_up = ?, last_used_at = ? WHERE id = ?",
  )
    .bind(info.newCounter, info.credentialBackedUp ? 1 : 0, now(), passkey.id)
    .run();

  // RFC 8176: synced passkeys are software keys, device-bound ones hardware.
  // User verification was required, so either way it was multi-factor.
  const kind = info.credentialDeviceType === "multiDevice" ? "swk" : "hwk";
  return { ok: true, userId: passkey.user_id, amr: [kind, "user", "mfa"] };
}
