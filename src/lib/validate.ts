/* src/lib/validate.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

// Lowercase, 1–32 chars, no leading/trailing punctuation. Apps use usernames
// as mailbox names and URL slugs, so they stay boring on purpose.
const USERNAME = /^[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$/;

// Must fit a 64 byte WebAuthn user handle.
const SUBJECT = /^[A-Za-z0-9._:@-]{1,64}$/;

const GROUP = /^[a-z0-9][a-z0-9_-]{0,63}$/;

const CLIENT_ID = /^[A-Za-z0-9._-]{3,128}$/;

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normaliseUsername(input: string | undefined): string {
  return (input ?? "").trim().toLowerCase();
}

export function usernameProblem(username: string): string | null {
  return USERNAME.test(username)
    ? null
    : "Usernames are 1–32 lowercase letters, digits, dots, dashes or underscores, starting and ending with a letter or digit.";
}

export function subjectProblem(subject: string): string | null {
  return SUBJECT.test(subject)
    ? null
    : "Subject ids are 1–64 letters, digits or . _ : @ - characters.";
}

export function groupProblem(name: string): string | null {
  return GROUP.test(name)
    ? null
    : "Group names are 1–64 lowercase letters, digits, dashes or underscores.";
}

export function clientIdProblem(id: string): string | null {
  return CLIENT_ID.test(id)
    ? null
    : "Client ids are 3–128 letters, digits, dots, dashes or underscores.";
}

export function cleanText(input: string | undefined, max: number): string | null {
  const value = (input ?? "").trim();
  if (!value) return null;
  return value.slice(0, max);
}

export function emailProblem(email: string | null): string | null {
  if (email === null) return null;
  return email.length <= 254 && EMAIL.test(email) ? null : "That email address doesn't look right.";
}

export function pictureProblem(url: string | null): string | null {
  if (url === null) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return "Picture URLs must use https.";
    return url.length <= 2048 ? null : "That picture URL is too long.";
  } catch {
    return "That picture URL isn't a valid URL.";
  }
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

/**
 * Redirect URIs are matched exactly, so validation only has to make sure they
 * are absolute, have no fragment, and use https (plain http only for loopback).
 */
export function redirectUriProblem(uri: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return `"${uri}" isn't an absolute URL.`;
  }
  if (parsed.hash || uri.includes("#")) return `"${uri}" can't contain a fragment.`;
  if (parsed.protocol === "https:") return null;
  if (parsed.protocol === "http:" && isLoopback(parsed.hostname)) return null;
  return `"${uri}" must use https (http is only allowed for localhost).`;
}
