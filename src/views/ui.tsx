/* src/views/ui.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import type { Child } from "hono/jsx";

// Flash messages travel as a fixed code in `?m=`, never as free text, so a
// crafted link can't put words in this site's mouth.
const MESSAGES: Record<string, string> = {
  "signed-out": "You're signed out.",
  "setup-done": "Your admin account is ready. Add a passkey or password below so you can sign in again.",
  "link-welcome": "You're signed in. Add a passkey (or a password) now so you can sign in next time.",
  "profile-saved": "Profile saved.",
  "passkey-added": "Passkey added.",
  "passkey-renamed": "Passkey renamed.",
  "passkey-removed": "Passkey removed.",
  "password-set": "Password saved. Your other sessions were signed out.",
  "password-removed": "Password removed. Sign in with a passkey from now on.",
  "totp-enabled": "Two-factor codes are on for password sign-ins.",
  "totp-disabled": "Two-factor codes are off.",
  "session-revoked": "Session signed out.",
  "sessions-revoked": "All other sessions are signed out.",
  "user-created": "User created.",
  "user-saved": "User saved.",
  "user-deleted": "User deleted.",
  "groups-saved": "Groups saved.",
  "group-created": "Group created.",
  "group-saved": "Group saved.",
  "group-deleted": "Group deleted.",
  "client-saved": "Application saved.",
  "client-deleted": "Application deleted.",
  "client-public": "Secret removed. The application is now a public (PKCE) client.",
  "keys-rotated": "Signing key rotated. The old key stays published for two days.",
  "credential-removed": "Sign-in method removed.",
  "user-disabled": "Account disabled and signed out everywhere.",
  "user-enabled": "Account enabled.",
  "user-signed-out": "Signed out of every session and application.",
  "link-revoked": "Sign-in link revoked.",
};

export function Flash(props: { code?: string | undefined }) {
  const text = props.code ? MESSAGES[props.code] : undefined;
  return text ? <p class="notice ok">{text}</p> : null;
}

export function ErrorNote(props: { error?: string | null | undefined }) {
  return props.error ? (
    <p class="notice error" role="alert">
      {props.error}
    </p>
  ) : null;
}

export function Csrf(props: { token: string }) {
  return <input type="hidden" name="_csrf" value={props.token} />;
}

export function Section(props: { title: string; children?: Child; id?: string; description?: string }) {
  return (
    <section class="panel" id={props.id}>
      <h2>{props.title}</h2>
      {props.description && <p class="muted">{props.description}</p>}
      {props.children}
    </section>
  );
}

export function Field(props: {
  label: string;
  name: string;
  type?: string;
  value?: string | null;
  required?: boolean;
  autocomplete?: string;
  hint?: string;
  placeholder?: string;
  maxlength?: number;
  inputmode?: string;
  pattern?: string;
  autofocus?: boolean;
}) {
  return (
    <label class="field">
      <span>{props.label}</span>
      <input
        type={props.type ?? "text"}
        name={props.name}
        value={props.value ?? ""}
        required={props.required}
        autocomplete={props.autocomplete}
        placeholder={props.placeholder}
        maxlength={props.maxlength}
        inputmode={props.inputmode as "numeric" | undefined}
        pattern={props.pattern}
        autofocus={props.autofocus}
      />
      {props.hint && <small class="muted">{props.hint}</small>}
    </label>
  );
}

export function date(ts: number | null | undefined): string {
  if (!ts) return "never";
  return new Date(ts * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

export function relative(ts: number | null | undefined): string {
  if (!ts) return "never";
  const diff = Math.floor(Date.now() / 1000) - ts;
  const future = diff < 0;
  const abs = Math.abs(diff);
  const unit =
    abs < 60 ? [abs, "second"] :
    abs < 3600 ? [Math.floor(abs / 60), "minute"] :
    abs < 86400 ? [Math.floor(abs / 3600), "hour"] :
    [Math.floor(abs / 86400), "day"];
  const [n, word] = unit as [number, string];
  const text = `${n} ${word}${n === 1 ? "" : "s"}`;
  return future ? `in ${text}` : `${text} ago`;
}

/** Short, friendly browser + OS guess for session lists. */
export function describeAgent(ua: string | null): string {
  if (!ua) return "Unknown device";
  const browser =
    /Edg\//.test(ua) ? "Edge" :
    /Firefox\//.test(ua) ? "Firefox" :
    /Chrome\//.test(ua) ? "Chrome" :
    /Safari\//.test(ua) ? "Safari" :
    "Browser";
  const os =
    /Windows/.test(ua) ? "Windows" :
    /iPhone|iPad/.test(ua) ? "iOS" :
    /Mac OS X/.test(ua) ? "macOS" :
    /Android/.test(ua) ? "Android" :
    /Linux/.test(ua) ? "Linux" :
    "unknown OS";
  return `${browser} on ${os}`;
}
