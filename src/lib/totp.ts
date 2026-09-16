/* src/lib/totp.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import { randomBytes } from "./crypto";

// RFC 6238: SHA-1, 6 digits, 30 second steps — what every authenticator app
// supports without asking.
const STEP = 30;
const DIGITS = 6;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
  const clean = input.toUpperCase().replace(/[\s=]/g, "");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const idx = ALPHABET.indexOf(char);
    if (idx === -1) throw new Error("invalid base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

async function codeAt(key: CryptoKey, step: number): Promise<string> {
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    (mac[offset + 1]! << 16) |
    (mac[offset + 2]! << 8) |
    mac[offset + 3]!;
  return String(binary % 10 ** DIGITS).padStart(DIGITS, "0");
}

/**
 * Checks `code` against the current step and one either side for clock drift.
 * Returns the matching step, which callers must persist and refuse to accept
 * again (or anything before it) so a code can't be replayed.
 */
export async function verifyTotp(
  secret: string,
  code: string,
  lastStep: number,
): Promise<number | null> {
  const digits = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(digits)) return null;

  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const current = Math.floor(Date.now() / 1000 / STEP);
  for (const step of [current - 1, current, current + 1]) {
    if (step <= lastStep) continue;
    if ((await codeAt(key, step)) === digits) return step;
  }
  return null;
}

export function otpauthUri(secret: string, issuerName: string, account: string): string {
  const label = encodeURIComponent(`${issuerName}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer: issuerName,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP),
  });
  return `otpauth://totp/${label}?${params}`;
}
