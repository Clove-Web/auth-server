/* public/static/app.js
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

"use strict";

// --- base64url <-> ArrayBuffer, for browsers without the WebAuthn JSON helpers --

function toBuffer(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function toB64url(buffer) {
  if (!buffer) return undefined;
  const bytes = new Uint8Array(buffer);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function creationOptions(json) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) {
    return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  }
  return {
    ...json,
    challenge: toBuffer(json.challenge),
    user: { ...json.user, id: toBuffer(json.user.id) },
    excludeCredentials: (json.excludeCredentials || []).map((c) => ({ ...c, id: toBuffer(c.id) })),
  };
}

function requestOptions(json) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) {
    return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  }
  return {
    ...json,
    challenge: toBuffer(json.challenge),
    allowCredentials: (json.allowCredentials || []).map((c) => ({ ...c, id: toBuffer(c.id) })),
  };
}

function credentialJSON(cred) {
  try {
    if (typeof cred.toJSON === "function") return cred.toJSON();
  } catch {
    // Some password managers return objects whose toJSON throws; build it by hand.
  }
  const r = cred.response;
  const response = { clientDataJSON: toB64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = toB64url(r.attestationObject);
    response.transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  } else {
    response.authenticatorData = toB64url(r.authenticatorData);
    response.signature = toB64url(r.signature);
    response.userHandle = toB64url(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response,
  };
}

async function postJSON(url, body) {
  const headers = { "Content-Type": "application/json" };
  const csrf = document.body.dataset.csrf;
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body || {}), credentials: "same-origin" });
  let data = {};
  try {
    data = await res.json();
  } catch {
    // non-JSON error page
  }
  if (res.status === 401 && data.reauth) {
    window.location.href = data.reauth;
    throw new Error("redirecting");
  }
  if (!res.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}

function showError(message) {
  const el = document.getElementById("passkey-error");
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("hidden", !message);
}

function webauthnMessage(err) {
  if (!err) return "Something went wrong. Please try again.";
  if (err.name === "NotAllowedError" || err.name === "AbortError") return "";
  if (err.name === "InvalidStateError") return "That passkey is already registered to your account.";
  if (err.name === "SecurityError") return "Passkeys can't be used on this address.";
  return err.message || "Something went wrong. Please try again.";
}

// --- sign in ---------------------------------------------------------------------

function initLogin() {
  const root = document.getElementById("login");
  const button = document.getElementById("passkey-signin");
  if (!root || !button) return;

  if (!window.PublicKeyCredential) {
    button.disabled = true;
    button.textContent = "Passkeys aren't supported in this browser";
    return;
  }

  const returnTo = root.dataset.return || "/account";
  let conditional = null;

  async function signIn(mediation) {
    const { id, options } = await postJSON("/login/passkey/options");
    const request = { publicKey: requestOptions(options) };
    if (mediation === "conditional") {
      conditional = new AbortController();
      request.mediation = "conditional";
      request.signal = conditional.signal;
    }
    const cred = await navigator.credentials.get(request);
    if (!cred) return;
    showError("");
    const result = await postJSON("/login/passkey/verify", { id, response: credentialJSON(cred), return: returnTo });
    window.location.href = result.redirect;
  }

  button.addEventListener("click", async () => {
    if (conditional) conditional.abort();
    button.disabled = true;
    try {
      await signIn("modal");
    } catch (err) {
      showError(webauthnMessage(err));
    } finally {
      button.disabled = false;
      startConditional();
    }
  });

  // Offer saved passkeys straight from the username field's autofill.
  async function startConditional() {
    if (!PublicKeyCredential.isConditionalMediationAvailable) return;
    if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
    try {
      await signIn("conditional");
    } catch (err) {
      if (err && err.name !== "AbortError") showError(webauthnMessage(err));
    }
  }
  startConditional();
}

// --- account -----------------------------------------------------------------------

function initAccount() {
  const formEl = document.getElementById("passkey-add");
  if (!formEl) return;
  const button = formEl.querySelector("button");

  if (!window.PublicKeyCredential) {
    button.disabled = true;
    button.textContent = "Passkeys aren't supported in this browser";
    return;
  }

  formEl.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("");
    button.disabled = true;
    try {
      const name = formEl.querySelector('input[name="name"]').value.trim();
      const { id, options } = await postJSON("/account/passkeys/options");
      const cred = await navigator.credentials.create({ publicKey: creationOptions(options) });
      if (!cred) return;
      const result = await postJSON("/account/passkeys/verify", { id, response: credentialJSON(cred), name });
      window.location.href = result.redirect;
    } catch (err) {
      showError(webauthnMessage(err));
    } finally {
      button.disabled = false;
    }
  });
}

// --- shared --------------------------------------------------------------------------

document.addEventListener("submit", (ev) => {
  const message = ev.target.dataset && ev.target.dataset.confirm;
  if (message && !window.confirm(message)) ev.preventDefault();
});

document.addEventListener("click", async (ev) => {
  const button = ev.target.closest && ev.target.closest("[data-copy]");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    const label = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = label), 1500);
  } catch {
    const input = button.parentElement.querySelector("input");
    if (input) input.select();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "login") initLogin();
  if (page === "account") initAccount();
});
