/**
 * SecureVault — Firebase Cloud Sync
 *
 * Firebase config — fill in your Firebase project credentials:
 *   1. Go to https://console.firebase.google.com/
 *   2. Create a project (or use existing)
 *   3. Enable Authentication → Google provider
 *   4. Create Web App (📱 icon) → copy the config object
 *   5. Paste here (replace the placeholder values)
 *
 * NOTE: This is a zero-knowledge sync — the vault is encrypted client-side
 * before upload. Firebase only stores the encrypted blob. The server never
 * sees plaintext.
 */

import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut as firebaseSignOut, onAuthStateChanged } from "firebase/auth";
import { getStorage, ref, getDownloadURL, uploadBytes, listAll } from "firebase/storage";

const firebaseConfig = {
  apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw",
  authDomain: "vault-b3bfb.firebaseapp.com",
  projectId: "vault-b3bfb",
  storageBucket: "vault-b3bfb.firebasestorage.app",
  messagingSenderId: "704056195218",
  appId: "1:704056195218:web:260d3454618d6e7fc8ce4b",
  measurementId: "G-11QJ0N17ZX",
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const storage = getStorage(app);

export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: "select_account" });

// ─── AUTH HELPERS ───────────────────────────────────────────────────────
export const signInWithGoogle = async () => {
  return signInWithPopup(auth, googleProvider);
};

export const signOut = async () => {
  return firebaseSignOut(auth);
};

export const getAuthState = (callback) => {
  return onAuthStateChanged(auth, callback);
};

export const getCurrentUser = () => {
  return auth.currentUser;
};

export const getUserEmail = () => {
  const user = auth.currentUser;
  return user?.email ?? null;
};

export const isLoggedIn = () => {
  return !!auth.currentUser;
};

// ─── CLOUD STORAGE HELPERS ─────────────────────────────────────────────
// Vault blob is stored as a single file "<userId>.vault" in the "vaults" bucket
export const VAULT_CLOUD_PATH = "vaults/";

export const getUserVaultRef = (userId) => {
  return ref(storage, `${VAULT_CLOUD_PATH}${userId}.vault`);
};

export const uploadVaultToCloud = async (userId, encryptedBlob) => {
  const vaultRef = getUserVaultRef(userId);
  await uploadBytes(vaultRef, encryptedBlob, "application/json");
  return vaultRef.fullPath;
};

export const downloadVaultFromCloud = async (userId) => {
  const vaultRef = getUserVaultRef(userId);
  try {
    const url = await getDownloadURL(vaultRef);
    const response = await fetch(url);
    if (!response.ok) return null;
    return response.blob();
  } catch (err) {
    // No vault found on cloud (first install) — return null
    if (err.code === "storage/object-not-found") return null;
    throw err;
  }
};

export const listUserVaultVersions = async (userId) => {
  const vaultRef = getUserVaultRef(userId);
  try {
    const result = await listAll(vaultRef);
    return result.items.map((item) => ({
      name: item.name,
      fullPath: item.fullPath,
      time: item.metadata?.timeCreated?.toISOString() ?? null,
    }));
  } catch {
    return [];
  }
};

// ─── ONLINE/OFFLINE DETECTION ──────────────────────────────────────────
export const isOnline = (callback) => {
  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("online", () => callback(true));
    window.addEventListener("offline", () => callback(false));
    return () => {
      window.removeEventListener("online", () => {});
      window.removeEventListener("offline", () => {});
    };
  }
  return () => {};
};

export const isBrowserOnline = () => typeof navigator !== "undefined" ? navigator.onLine : true;

// ─── ONLINE/OFFLINE CHECK ──────────────────────────────────────────────
export const checkOnline = () => {
  return typeof navigator !== "undefined" ? navigator.onLine : true;
};
