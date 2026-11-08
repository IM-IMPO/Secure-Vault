/**
 * SecureVault — cloud backup + sync (Firebase Auth for identity, Cloudflare R2 for storage)
 *
 * Zero-knowledge: the thing uploaded is the SAME encrypted envelope that is
 * stored on disk (AES-256-GCM, key wrapped by Argon2id(master password)).
 * Cloudflare only ever sees ciphertext. The PIN and biometric wraps are
 * stripped before upload — they're weaker, device-specific unlock paths and
 * must never leave the device.
 *
 * Access control: every request carries the user's Firebase ID token. The
 * Cloudflare Worker (cloudflare-worker/) verifies it and only ever touches the
 * single R2 object belonging to that Google account (vaults/<uid>/vault.json).
 *
 * Platforms:
 *   - Desktop / browser: Firebase popup sign-in.
 *   - Android APK: native Google sign-in through @capacitor-firebase/authentication
 *     (a WebView can't run Google's popup flow), then handed to the JS SDK.
 */
import { initializeApp } from "firebase/app";
import {
  getAuth, GoogleAuthProvider, signInWithPopup, signInWithCredential,
  signOut as fbSignOut, onAuthStateChanged,
} from "firebase/auth";
import { registerPlugin, Capacitor } from "@capacitor/core";

const firebaseConfig = {
  apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw",
  authDomain: "vault-b3bfb.firebaseapp.com",
  projectId: "vault-b3bfb",
  storageBucket: "vault-b3bfb.firebasestorage.app",
  messagingSenderId: "704056195218",
  appId: "1:704056195218:web:260d3454618d6e7fc8ce4b",
  measurementId: "G-11QJ0N17ZX",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: "select_account" });

// Where your deployed Cloudflare Worker lives. Set VITE_SV_CLOUD_API in a .env file (see .env.example).
const CLOUD_API = ((import.meta.env && import.meta.env.VITE_SV_CLOUD_API) || "").replace(/\/+$/, "");
const MAX_VAULT_BYTES = 25 * 1000 * 1000; // matches the Worker's limit
const OP_TIMEOUT_MS = 60000;

/* ---- helpers -------------------------------------------------------------- */

const isNative = () => {
  try { return Capacitor.isNativePlatform(); } catch { return false; }
};
const nativeAuthPlugin = () => registerPlugin("FirebaseAuthentication");

const toUser = (u) => (u ? { uid: u.uid, email: u.email || "", name: u.displayName || "", photo: u.photoURL || "" } : null);

const coded = (message, code) => Object.assign(new Error(message), { code });

/** Authenticated call to the Worker. Resolves with the Response (callers handle 404); throws on network/auth/server errors. */
async function api(path, { method = "GET", body, headers = {} } = {}) {
  const u = auth.currentUser;
  if (!u) throw new Error("Not signed in to Google.");
  if (!CLOUD_API) throw coded("Cloud storage isn't configured: set VITE_SV_CLOUD_API to your Worker URL and rebuild.", "sv/not-configured");
  const token = await u.getIdToken();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), OP_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(CLOUD_API + path, { method, body, headers: { Authorization: `Bearer ${token}`, ...headers }, signal: ctrl.signal });
  } catch (e) {
    throw coded(e && e.name === "AbortError" ? "The cloud didn't respond in time." : "Couldn't reach the cloud server.", e && e.name === "AbortError" ? "sv/timeout" : "sv/network");
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 401) throw coded("The cloud rejected your sign-in. Sign out of Google and sign in again.", "sv/unauthorized");
  if (res.status === 413) throw coded("Your vault is too large for cloud sync (over ~25 MB). Remove some large attachments.", "sv/too-large");
  if (res.status !== 404 && !res.ok) throw coded(`The cloud server returned an error (${res.status}).`, "sv/server");
  return res;
}

/* ---- auth ----------------------------------------------------------------- */

/** Calls cb(user|null) once the saved session has been restored, then on every change. */
export function watchCloudUser(cb) {
  return onAuthStateChanged(auth, (u) => cb(toUser(u)));
}

export async function cloudSignIn() {
  if (isNative()) {
    const result = await nativeAuthPlugin().signInWithGoogle();
    const idToken = result && result.credential && result.credential.idToken;
    if (!idToken) throw new Error("Google sign-in didn't return a token.");
    const cred = GoogleAuthProvider.credential(idToken);
    const res = await signInWithCredential(auth, cred);
    return toUser(res.user);
  }
  const res = await signInWithPopup(auth, googleProvider);
  return toUser(res.user);
}

export async function cloudSignOut() {
  try { if (isNative()) await nativeAuthPlugin().signOut(); } catch { /* ignore */ }
  await fbSignOut(auth);
}

export const friendlyAuthError = (err) => {
  const code = (err && err.code) || "";
  const msg = (err && err.message) || "";
  if (code === "auth/popup-closed-by-user" || code === "auth/cancelled-popup-request" || /canceled|cancelled/i.test(msg)) return "Sign-in was cancelled.";
  if (code === "auth/popup-blocked") return "The sign-in window was blocked. Allow pop-ups and try again.";
  if (code === "auth/network-request-failed") return "No internet connection. Connect and try again.";
  if (code === "auth/unauthorized-domain") return "This app's domain isn't authorized in Firebase (Authentication → Settings → Authorized domains).";
  if (code === "auth/operation-not-allowed") return "Google sign-in isn't enabled in the Firebase console (Authentication → Sign-in method).";
  if (code === "sv/network" || code === "sv/timeout") return "Couldn't reach the cloud server. Check your internet connection and the Worker URL (VITE_SV_CLOUD_API).";
  if (code === "sv/not-configured" || code === "sv/unauthorized" || code === "sv/too-large" || code === "sv/server") return msg;
  return msg || "Something went wrong talking to the cloud.";
};

/* ---- vault object ----------------------------------------------------------- */

/** The cloud copy never contains the PIN / biometric wraps. */
const forCloud = (envelope) => {
  const { pin, biometric, ...rest } = envelope; // eslint-disable-line no-unused-vars
  return { ...rest, pin: null, biometric: null };
};

/** { updatedAt, vaultId, ownerEmail } for the signed-in account's cloud vault, or null if none yet. */
export async function getCloudMeta() {
  const res = await api("/vault/meta");
  if (res.status === 404) return null;
  const m = await res.json();
  return { updatedAt: m.updatedAt || "", vaultId: m.vaultId || "", ownerEmail: m.ownerEmail || "" };
}

/** The encrypted envelope stored in the cloud, or null if this account has none. */
export async function downloadCloudVault() {
  const res = await api("/vault");
  if (res.status === 404) return null;
  const env = JSON.parse(await res.text());
  if (!env || !env.password || !env.data) throw new Error("The cloud vault is corrupted or in an unknown format.");
  return env;
}

export async function uploadCloudVault(envelope) {
  const json = JSON.stringify(forCloud(envelope));
  if (json.length > MAX_VAULT_BYTES) throw coded("Your vault is too large for cloud sync (over ~25 MB). Remove some large attachments.", "sv/too-large");
  await api("/vault", {
    method: "PUT",
    body: json,
    headers: { "Content-Type": "application/json", "X-Updated-At": envelope.updatedAt || "", "X-Vault-Id": envelope.vaultId || "" },
  });
}

export async function deleteCloudVault() {
  await api("/vault", { method: "DELETE" });
}

/* ---- tiny persisted flags ----------------------------------------------------- */

const LS_LAST_SYNC = "sv_cloud_last_sync";
const LS_LOCAL_ONLY = "sv_cloud_local_only";

const lsGet = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const lsSet = (k, v) => { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch { /* ignore */ } };

export const getLastCloudSync = () => lsGet(LS_LAST_SYNC);
export const setLastCloudSync = (iso) => lsSet(LS_LAST_SYNC, iso);
/** The cloud version (its updatedAt) this device last synced with, per Google account. Lets sync tell
 *  "only the cloud changed" / "only this device changed" / "both changed" apart. */
export const getCloudBase = (uid) => lsGet(`sv_cloud_base_${uid}`) || "";
export const setCloudBase = (uid, updatedAt) => lsSet(`sv_cloud_base_${uid}`, updatedAt || null);
export const getLocalOnlyChoice = () => lsGet(LS_LOCAL_ONLY) === "1";
export const setLocalOnlyChoice = (on) => lsSet(LS_LOCAL_ONLY, on ? "1" : null);

export const newVaultId = () => {
  const a = new Uint8Array(12);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
};
