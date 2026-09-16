/* src/lib/crypto.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const b of view) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(input: string): Uint8Array<ArrayBuffer> {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function utf8(input: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(encoder.encode(input));
}

export function fromUtf8(input: Uint8Array): string {
  return decoder.decode(input);
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** A URL-safe random secret. 32 bytes = 256 bits. */
export function randomToken(bytes = 32): string {
  return b64url(randomBytes(bytes));
}

export async function sha256(input: string | Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const data = typeof input === "string" ? utf8(input) : input;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function sha256Hex(input: string): Promise<string> {
  return [...(await sha256(input))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqual(a: Uint8Array<ArrayBuffer>, b: Uint8Array<ArrayBuffer>): boolean {
  if (a.byteLength !== b.byteLength) return false;
  return crypto.subtle.timingSafeEqual(a, b);
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  return timingSafeEqual(utf8(a), utf8(b));
}

// --- encryption at rest ------------------------------------------------------
// AES-256-GCM, keyed off KEY_ENCRYPTION_KEY. Stored as `v1.<iv>.<ciphertext>`.

const aesKeys = new Map<string, Promise<CryptoKey>>();

function aesKey(secret: string): Promise<CryptoKey> {
  if (!secret || secret.length < 32) {
    throw new Error("KEY_ENCRYPTION_KEY is missing or shorter than 32 characters");
  }
  let key = aesKeys.get(secret);
  if (!key) {
    key = sha256(secret).then((raw) =>
      crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]),
    );
    aesKeys.set(secret, key);
  }
  return key;
}

export async function encrypt(secret: string, plaintext: string): Promise<string> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(secret), utf8(plaintext));
  return `v1.${b64url(iv)}.${b64url(ct)}`;
}

export async function decrypt(secret: string, sealed: string): Promise<string> {
  const [version, iv, ct] = sealed.split(".");
  if (version !== "v1" || !iv || !ct) throw new Error("unrecognised ciphertext");
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64url(iv) },
    await aesKey(secret),
    fromB64url(ct),
  );
  return fromUtf8(new Uint8Array(pt));
}
