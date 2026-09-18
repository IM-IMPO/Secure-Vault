import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { createPortal } from "react-dom";
import { argon2id } from "hash-wasm";
import {
  Lock, Unlock, Eye, EyeOff, Copy, Search, Plus, Settings as SettingsIcon,
  Shield, CreditCard, FileText, LayoutDashboard, TrendingUp, TrendingDown,
  Wallet, AlertTriangle, CheckCircle2, X, Trash2, Pencil, Pin, Archive,
  Moon, Sun, ChevronRight, ChevronLeft, RefreshCw, Fingerprint, KeyRound, Clock,
  ExternalLink, PiggyBank, ShieldCheck, ShieldAlert, Smartphone, Globe,
  ArrowUpRight, ArrowDownRight, Tag, Filter, ArrowUpDown, Sparkles,
  LogOut, Bell, ListChecks, Zap, Target, Calendar, MapPin, PartyPopper, CalendarDays,
  RotateCcw, Paperclip, Download, File as FileIcon, Upload,
  Users, Phone, Mail, Building2, Star, Image as ImageIcon2, Camera,
  Calculator as CalculatorIcon, Delete as BackspaceIcon, Repeat
} from "lucide-react";
import {
  ResponsiveContainer, LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, AreaChart, Area
} from "recharts";

/* ---------------------------------------------------------------------- */
/* Fonts + theme                                                          */
/* ---------------------------------------------------------------------- */

const FontStyles = () => (
  <style>{`
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, #root {
      margin: 0;
      padding: 0;
      height: 100%;
      background: #0B0F14;
      overflow: hidden;
    }

    .sv-root {
      --bg: #0B0F14;
      --surface: #121922;
      --surface-2: #1B2430;
      --surface-3: #232F3C;
      --border: #26313D;
      --text: #E7EDF3;
      --text-muted: #8A97A6;
      --text-faint: #57646F;
      --primary: #4C7CF3;
      --primary-soft: rgba(76,124,243,0.14);
      --mint: #34D399;
      --mint-soft: rgba(52,211,153,0.14);
      --amber: #F5A623;
      --amber-soft: rgba(245,166,35,0.14);
      --coral: #F0596B;
      --coral-soft: rgba(240,89,107,0.14);
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    .sv-root.light {
      --bg: #F3F5F8;
      --surface: #FFFFFF;
      --surface-2: #F7F9FB;
      --surface-3: #EEF1F5;
      --border: #E1E6EC;
      --text: #16202B;
      --text-muted: #5B6774;
      --text-faint: #93A0AC;
      --primary: #3B66D6;
      --primary-soft: rgba(59,102,214,0.10);
      --mint: #0F9D6A;
      --mint-soft: rgba(15,157,106,0.10);
      --amber: #B4720A;
      --amber-soft: rgba(180,114,10,0.10);
      --coral: #D93C51;
      --coral-soft: rgba(217,60,81,0.10);
    }
    .sv-display { font-family: 'Space Grotesk', sans-serif; }
    .sv-mono { font-family: 'JetBrains Mono', monospace; }

    .sv-scroll::-webkit-scrollbar { width: 8px; height: 8px; }
    .sv-scroll::-webkit-scrollbar-thumb { background: var(--surface-3); border-radius: 8px; }
    .sv-scroll::-webkit-scrollbar-track { background: transparent; }

    @keyframes sv-scan {
      0% { transform: translateY(-100%); opacity: 0; }
      10% { opacity: 1; }
      90% { opacity: 1; }
      100% { transform: translateY(420%); opacity: 0; }
    }
    .sv-scanline { animation: sv-scan 2.6s ease-in-out infinite; }

    @keyframes sv-decrypt {
      0% { filter: blur(2px); opacity: 0.4; letter-spacing: 2px; }
      100% { filter: blur(0); opacity: 1; letter-spacing: normal; }
    }
    .sv-decrypt { animation: sv-decrypt 0.22s ease-out; }

    @keyframes sv-fade-in {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .sv-fade-in { animation: sv-fade-in 0.18s ease-out; }

    @keyframes sv-toast-in {
      from { opacity: 0; transform: translateY(8px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    .sv-toast { animation: sv-toast-in 0.2s ease-out; }

    @media (prefers-reduced-motion: reduce) {
      .sv-scanline, .sv-decrypt, .sv-fade-in, .sv-toast { animation: none !important; }
    }

    .sv-focus:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: 2px;
    }
  `}</style>
);

/* ---------------------------------------------------------------------- */
/* Mock data                                                               */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* Crypto engine — Argon2id key derivation + AES-256-GCM encryption.      */
/*                                                                        */
/* Design (the same pattern real password managers use):                  */
/*   - A random 256-bit "vault key" K encrypts your actual data.          */
/*   - Your master password is run through Argon2id to derive a          */
/*     "wrapping key" that encrypts (wraps) K — the password itself      */
/*     never touches your data directly.                                 */
/*   - Your PIN, if enabled, wraps its own copy of K the same way, so     */
/*     quick PIN unlock doesn't require weakening the master password.   */
/*   - Only ciphertext, salts, and Argon2id parameters are ever written   */
/*     to disk. Nothing there is reversible without doing the (slow,     */
/*     memory-hard) Argon2id derivation first.                            */
/* ---------------------------------------------------------------------- */

// OWASP-recommended-range Argon2id parameters for the master password.
const PASSWORD_ARGON2_PARAMS = { iterations: 3, memorySize: 65536, parallelism: 1, hashLength: 32 };
// Lighter parameters for PIN unlock — PINs have far less entropy than a
// password to begin with, so this trades a little KDF cost for snappier
// day-to-day unlocking. It's a convenience path, not the strong one.
const PIN_ARGON2_PARAMS = { iterations: 2, memorySize: 19456, parallelism: 1, hashLength: 32 };

function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}
function bytesToB64(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Argon2id-derive raw key bytes from a password/PIN + salt. */
async function deriveKeyBytes(secret, saltBytes, params) {
  const out = await argon2id({
    password: secret,
    salt: saltBytes,
    iterations: params.iterations,
    memorySize: params.memorySize,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
    outputType: "binary",
  });
  return out; // Uint8Array(32)
}

async function importAesKey(rawBytes) {
  return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function aesEncryptBytes(cryptoKey, plainBytes) {
  const iv = randomBytes(12);
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, plainBytes);
  return { iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ctBuf)) };
}
/** Throws if the key/IV is wrong — the GCM auth tag won't verify. */
async function aesDecryptBytes(cryptoKey, ivB64, ctB64) {
  const iv = b64ToBytes(ivB64);
  const ct = b64ToBytes(ctB64);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct);
  return new Uint8Array(ptBuf);
}
async function aesEncryptJSON(cryptoKey, obj) {
  return aesEncryptBytes(cryptoKey, new TextEncoder().encode(JSON.stringify(obj)));
}
async function aesDecryptJSON(cryptoKey, ivB64, ctB64) {
  const bytes = await aesDecryptBytes(cryptoKey, ivB64, ctB64);
  return JSON.parse(new TextDecoder().decode(bytes));
}

/** Wrap the 32-byte vault key K using a password/PIN-derived key. */
async function wrapVaultKey(vaultKeyBytes, secret, saltBytes, params) {
  const wrappingKeyBytes = await deriveKeyBytes(secret, saltBytes, params);
  const wrappingKey = await importAesKey(wrappingKeyBytes);
  return aesEncryptBytes(wrappingKey, vaultKeyBytes);
}
/** Unwrap K. Throws (auth tag mismatch) if the password/PIN is wrong. */
async function unwrapVaultKey(secret, saltBytes, params, iv, ciphertext) {
  const wrappingKeyBytes = await deriveKeyBytes(secret, saltBytes, params);
  const wrappingKey = await importAesKey(wrappingKeyBytes);
  return aesDecryptBytes(wrappingKey, iv, ciphertext); // Uint8Array(32) = K
}

/** Create a brand-new vault: fresh K, wrapped by the chosen master password. */
async function createVaultEnvelope(masterPassword, initialData) {
  const vaultKeyBytes = randomBytes(32);
  const salt = randomBytes(16);
  const wrapped = await wrapVaultKey(vaultKeyBytes, masterPassword, salt, PASSWORD_ARGON2_PARAMS);
  const K = await importAesKey(vaultKeyBytes);
  const dataEnc = await aesEncryptJSON(K, initialData);
  const envelope = {
    version: 2,
    kdf: "argon2id",
    cipher: "AES-256-GCM",
    password: { salt: bytesToB64(salt), iv: wrapped.iv, wrappedKey: wrapped.ciphertext, params: PASSWORD_ARGON2_PARAMS },
    pin: null,
    biometric: null,
    data: dataEnc,
    updatedAt: new Date().toISOString(),
  };
  return { envelope, vaultKeyBytes };
}

async function unlockWithPasswordEnvelope(envelope, password) {
  const meta = envelope.password;
  const vaultKeyBytes = await unwrapVaultKey(password, b64ToBytes(meta.salt), meta.params, meta.iv, meta.wrappedKey);
  const K = await importAesKey(vaultKeyBytes);
  const data = await aesDecryptJSON(K, envelope.data.iv, envelope.data.ciphertext);
  return { vaultKeyBytes, data };
}

async function unlockWithPinEnvelope(envelope, pin) {
  if (!envelope.pin) throw new Error("PIN not set up");
  const meta = envelope.pin;
  const vaultKeyBytes = await unwrapVaultKey(pin, b64ToBytes(meta.salt), meta.params, meta.iv, meta.wrappedKey);
  const K = await importAesKey(vaultKeyBytes);
  const data = await aesDecryptJSON(K, envelope.data.iv, envelope.data.ciphertext);
  return { vaultKeyBytes, data };
}

async function rewrapPassword(vaultKeyBytes, newPassword) {
  const salt = randomBytes(16);
  const wrapped = await wrapVaultKey(vaultKeyBytes, newPassword, salt, PASSWORD_ARGON2_PARAMS);
  return { salt: bytesToB64(salt), iv: wrapped.iv, wrappedKey: wrapped.ciphertext, params: PASSWORD_ARGON2_PARAMS };
}
async function rewrapPin(vaultKeyBytes, newPin) {
  const salt = randomBytes(16);
  const wrapped = await wrapVaultKey(vaultKeyBytes, newPin, salt, PIN_ARGON2_PARAMS);
  return { salt: bytesToB64(salt), iv: wrapped.iv, wrappedKey: wrapped.ciphertext, params: PIN_ARGON2_PARAMS };
}

async function encryptVaultData(vaultKeyBytes, dataObj) {
  const K = await importAesKey(vaultKeyBytes);
  return aesEncryptJSON(K, dataObj);
}

/* ---------------------------------------------------------------------- */
/* Local-only persistence — the encrypted envelope is saved as a real     */
/* file in D:\Local Data via the small local server (server.js). The      */
/* server only ever sees ciphertext, salts, and KDF parameters.           */
/* ---------------------------------------------------------------------- */

const SV_API = `http://localhost:${(typeof window !== "undefined" && window.SV_PORT) || 4787}`;

async function pingLocalServer() {
  try {
    const res = await fetch(`${SV_API}/api/ping`, { signal: AbortSignal.timeout(1500) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function loadEnvelope() {
  try {
    const res = await fetch(`${SV_API}/api/data`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { envelope: null, integrity: null, ok: false };
    const body = await res.json();
    return { envelope: body.data, integrity: body.integrity || null, ok: true };
  } catch {
    return { envelope: null, integrity: null, ok: false };
  }
}

async function saveEnvelope(envelope) {
  try {
    const res = await fetch(`${SV_API}/api/data`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function deleteEnvelope() {
  try {
    const res = await fetch(`${SV_API}/api/data`, { method: "DELETE", signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}

async function backupNow() {
  try {
    const res = await fetch(`${SV_API}/api/backup`, { method: "POST", signal: AbortSignal.timeout(5000) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: body.error || "Backup failed." };
    return { ok: true, backupFile: body.backupFile };
  } catch (e) {
    return { ok: false, error: e.message || "Couldn't reach the local server." };
  }
}

/** Checks the vault file's integrity against what the server last legitimately wrote. */
async function checkIntegrity() {
  try {
    const res = await fetch(`${SV_API}/api/integrity`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/** Lists available version snapshots, newest first. */
async function listVersions() {
  try {
    const res = await fetch(`${SV_API}/api/versions`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return [];
    const body = await res.json();
    return body.versions || [];
  } catch {
    return [];
  }
}

/** Fetches the raw (still-encrypted) content of a specific version snapshot. */
async function fetchVersionContent(file) {
  try {
    const res = await fetch(`${SV_API}/api/version-content?file=${encodeURIComponent(file)}`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { ok: false };
    const body = await res.json();
    return { ok: true, data: body.data };
  } catch {
    return { ok: false };
  }
}

/** Restores a specific version snapshot as the current vault file. */
async function restoreVersion(file) {
  try {
    const res = await fetch(`${SV_API}/api/restore-version`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file }),
      signal: AbortSignal.timeout(5000),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: body.error || "Restore failed." };
    return { ok: true, data: body.data, undoFile: body.undoFile || null };
  } catch (e) {
    return { ok: false, error: e.message || "Couldn't reach the local server." };
  }
}

/** Accepts whatever is currently on disk as the new trusted baseline. */
async function trustCurrentFile() {
  try {
    const res = await fetch(`${SV_API}/api/trust-changes`, { method: "POST", signal: AbortSignal.timeout(5000) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: body.error || "Couldn't trust the current file." };
    return { ok: true, data: body.data };
  } catch (e) {
    return { ok: false, error: e.message || "Couldn't reach the local server." };
  }
}

/** Triggers a browser/Electron "Save As" download of a JSON object. */
function downloadJSON(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/** Triggers a download of a data URL (used for note attachments). */
function downloadDataUrl(filename, dataUrl) {
  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

const MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024; // 5MB — attachments live inline in the encrypted vault file.

function fmtFileSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.readAsDataURL(file);
  });
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.readAsText(file);
  });
}

const MAX_IMPORT_TEXT_SIZE = 2 * 1024 * 1024; // 2MB per note file — this is plain text, not attachments.

/** Strips the extension and cleans up a filename for use as a note title. */
function filenameToTitle(name) {
  const withoutExt = name.replace(/\.[^./\\]+$/, "");
  return withoutExt.replace(/[_-]+/g, " ").trim() || name;
}

const TRASH_RETENTION_DAYS = 30;
/** Days since a trash item was deleted (positive = that many days ago). */
function trashAgeDays(deletedAt) {
  const then = new Date(deletedAt + "T00:00:00");
  const now = new Date(); now.setHours(0, 0, 0, 0);
  return Math.round((now - then) / 86400000);
}

const uid = () => Math.random().toString(36).slice(2, 10);
const today = new Date();
const daysAgo = (n) => { const d = new Date(today); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); };
const daysFromNow = (n) => daysAgo(-n);
const fmtDate = (iso) => new Date(iso + "T00:00:00").toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
const fmtMoney = (n) => (n < 0 ? "-₱" + Math.abs(n).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : "₱" + n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }));
const fmtCompactMoney = (n) => {
  const abs = Math.abs(n);
  const sign = n < 0 ? "-" : "";
  if (abs >= 1000000) return sign + "₱" + (abs / 1000000).toFixed(1).replace(/\.0$/, "") + "M";
  if (abs >= 1000) return sign + "₱" + (abs / 1000).toFixed(abs % 1000 === 0 ? 0 : 1).replace(/\.0$/, "") + "k";
  return sign + "₱" + abs;
};

const PASSWORD_CATEGORIES = ["Social Media", "Banking", "Email", "Work", "Shopping", "Gaming", "Development", "Other"];
const NOTE_CATEGORIES = ["Recovery Codes", "Wi-Fi", "Personal", "Documents", "Licenses", "Reminders", "Other"];
const INCOME_CATEGORIES = ["Salary", "Freelance", "Business", "Allowance", "Investment", "Savings", "Other"];
const EXPENSE_CATEGORIES = ["Food", "Transportation", "Bills", "Shopping", "Entertainment", "Rent", "Education", "Health", "Savings", "Other"];
const GOAL_CATEGORIES = ["Gadget", "Travel", "Emergency Fund", "Vehicle", "Home", "Education", "Gift", "Other"];
const EVENT_CATEGORIES = ["Personal", "Work", "Bill", "Birthday", "Appointment", "Reminder", "Other"];
const EVENT_CATEGORY_COLORS = {
  Personal: "#4C7CF3", Work: "#F5A623", Bill: "#F0596B", Birthday: "#F472B6",
  Appointment: "#A78BFA", Reminder: "#34D399", Other: "#94A3B8",
};
const CONTACT_CATEGORIES = ["Family", "Friend", "Work", "Business", "Other"];
const CONTACT_CATEGORY_COLORS = {
  Family: "#F472B6", Friend: "#34D399", Work: "#F5A623", Business: "#4C7CF3", Other: "#94A3B8",
};

const initialPasswords = [
  { id: uid(), title: "Google", url: "https://google.com", username: "j.reyes@gmail.com", password: "Sunrise!482x", category: "Email", tags: ["primary"], notes: "", createdAt: daysAgo(340), updatedAt: daysAgo(340) },
  { id: uid(), title: "BPI Online", url: "https://bpi.com.ph", username: "jreyes_bpi", password: "MangoTree!91", category: "Banking", tags: ["finance"], notes: "", createdAt: daysAgo(210), updatedAt: daysAgo(12) },
  { id: uid(), title: "GitHub", url: "https://github.com", username: "jreyes-dev", password: "correcthorsebattery9", category: "Development", tags: ["work"], notes: "SSH key stored separately", createdAt: daysAgo(500), updatedAt: daysAgo(500) },
  { id: uid(), title: "Instagram", url: "https://instagram.com", username: "@j.reyes", password: "correcthorsebattery9", category: "Social Media", tags: [], notes: "", createdAt: daysAgo(600), updatedAt: daysAgo(600) },
  { id: uid(), title: "Shopee", url: "https://shopee.ph", username: "jreyes09", password: "shopee123", category: "Shopping", tags: [], notes: "", createdAt: daysAgo(120), updatedAt: daysAgo(120) },
  { id: uid(), title: "Steam", url: "https://store.steampowered.com", username: "jreyes_gg", password: "Falcon#Nebula77Q", category: "Gaming", tags: [], notes: "", createdAt: daysAgo(90), updatedAt: daysAgo(3) },
  { id: uid(), title: "Notion (Work)", url: "https://notion.so", username: "j.reyes@work.com", password: "shopee123", category: "Work", tags: ["team"], notes: "", createdAt: daysAgo(60), updatedAt: daysAgo(60) },
];

const initialNotes = [
  { id: uid(), title: "2FA Recovery Codes — Google", content: "Backup codes for account recovery. Store printed copy in safe at home.\n\n1. 48213-99021\n2. 77102-33847\n3. 55901-12456", category: "Recovery Codes", tags: ["google", "2fa"], pinned: true, archived: false, createdAt: daysAgo(300), updatedAt: daysAgo(300) },
  { id: uid(), title: "Home Wi-Fi", content: "Network: Reyes_5G\nPassword: not stored in plaintext here — see password manager entry.", category: "Wi-Fi", tags: ["home"], pinned: true, archived: false, createdAt: daysAgo(150), updatedAt: daysAgo(20) },
  { id: uid(), title: "Passport Number", content: "Passport no. and expiry — keep offline copy too. Renewal reminder set for next year.", category: "Documents", tags: ["travel"], pinned: false, archived: false, createdAt: daysAgo(400), updatedAt: daysAgo(400) },
  { id: uid(), title: "Adobe CC License", content: "License key for Creative Cloud, tied to work email. Renews annually in March.", category: "Licenses", tags: ["work"], pinned: false, archived: false, createdAt: daysAgo(80), updatedAt: daysAgo(80) },
  { id: uid(), title: "Old bank PINs (archived)", content: "Retired account, kept for records only.", category: "Other", tags: [], pinned: false, archived: true, createdAt: daysAgo(700), updatedAt: daysAgo(700) },
];

const initialTransactions = [
  { id: uid(), type: "income", amount: 65000, party: "Acme Corp Payroll", category: "Salary", date: daysAgo(2), description: "Monthly salary", recurring: true, method: "" },
  { id: uid(), type: "income", amount: 8500, party: "Freelance client — Studio K", category: "Freelance", date: daysAgo(9), description: "Landing page project", recurring: false, method: "" },
  { id: uid(), type: "expense", amount: 12000, party: "Landlord", category: "Rent", date: daysAgo(3), description: "Monthly rent", recurring: true, method: "Bank Transfer" },
  { id: uid(), type: "expense", amount: 2450, party: "SM Supermarket", category: "Food", date: daysAgo(4), description: "Groceries", recurring: false, method: "Card" },
  { id: uid(), type: "expense", amount: 1200, party: "Grab", category: "Transportation", date: daysAgo(5), description: "Rides this week", recurring: false, method: "E-wallet" },
  { id: uid(), type: "expense", amount: 1800, party: "Meralco", category: "Bills", date: daysAgo(6), description: "Electricity", recurring: true, method: "Bank Transfer" },
  { id: uid(), type: "expense", amount: 950, party: "Netflix + Spotify", category: "Entertainment", date: daysAgo(7), description: "Subscriptions", recurring: true, method: "Card" },
  { id: uid(), type: "expense", amount: 3200, party: "Uniqlo", category: "Shopping", date: daysAgo(11), description: "New jacket", recurring: false, method: "Card" },
  { id: uid(), type: "expense", amount: 1500, party: "Clinic visit", category: "Health", date: daysAgo(14), description: "Checkup", recurring: false, method: "Cash" },
  { id: uid(), type: "income", amount: 3000, party: "Dividend — index fund", category: "Investment", date: daysAgo(18), description: "Quarterly payout", recurring: false, method: "" },
  { id: uid(), type: "expense", amount: 2200, party: "Food delivery", category: "Food", date: daysAgo(20), description: "Various", recurring: false, method: "E-wallet" },
  { id: uid(), type: "expense", amount: 4500, party: "Course platform", category: "Education", date: daysAgo(35), description: "UX course", recurring: false, method: "Card" },
  { id: uid(), type: "income", amount: 65000, party: "Acme Corp Payroll", category: "Salary", date: daysAgo(33), description: "Monthly salary", recurring: true, method: "" },
  { id: uid(), type: "expense", amount: 12000, party: "Landlord", category: "Rent", date: daysAgo(34), description: "Monthly rent", recurring: true, method: "Bank Transfer" },
  { id: uid(), type: "expense", amount: 2100, party: "Gas station", category: "Transportation", date: daysAgo(40), description: "Fuel", recurring: false, method: "Card" },
];

const initialBudgets = [
  { id: uid(), category: "Food", amount: 5000, period: "monthly" },
  { id: uid(), category: "Transportation", amount: 3000, period: "monthly" },
  { id: uid(), category: "Entertainment", amount: 1500, period: "monthly" },
  { id: uid(), category: "Shopping", amount: 4000, period: "monthly" },
];

const initialGoals = [
  {
    id: uid(), title: "New Laptop", category: "Gadget", targetAmount: 65000, currentAmount: 24000,
    targetDate: daysFromNow(90), notes: "16GB RAM, for work and editing.", createdAt: daysAgo(60),
    contributions: [
      { id: uid(), amount: 15000, date: daysAgo(55), note: "Initial deposit" },
      { id: uid(), amount: 9000, date: daysAgo(20), note: "From freelance payout" },
    ],
  },
  {
    id: uid(), title: "Emergency Fund", category: "Emergency Fund", targetAmount: 100000, currentAmount: 42000,
    targetDate: daysFromNow(240), notes: "Aiming for ~2 months of expenses.", createdAt: daysAgo(150),
    contributions: [
      { id: uid(), amount: 30000, date: daysAgo(140), note: "" },
      { id: uid(), amount: 12000, date: daysAgo(45), note: "" },
    ],
  },
  {
    id: uid(), title: "Boracay Trip", category: "Travel", targetAmount: 20000, currentAmount: 20000,
    targetDate: daysFromNow(-10), notes: "Flights + 3 nights.", createdAt: daysAgo(120),
    contributions: [
      { id: uid(), amount: 20000, date: daysAgo(15), note: "Fully funded!" },
    ],
  },
];

const initialEvents = [
  { id: uid(), title: "Rent due", date: daysFromNow(2), time: "", endTime: "", category: "Bill", location: "", notes: "Monthly rent — bank transfer", allDay: true, recurrence: "monthly", completedDates: [], createdAt: daysAgo(30) },
  { id: uid(), title: "Team standup", date: daysFromNow(1), time: "09:00", endTime: "09:30", category: "Work", location: "Google Meet", notes: "", allDay: false, recurrence: "none", completedDates: [], createdAt: daysAgo(10) },
  { id: uid(), title: "Dentist appointment", date: daysFromNow(5), time: "14:00", endTime: "15:00", category: "Appointment", location: "Makati Dental Clinic", notes: "Bring previous x-ray", allDay: false, recurrence: "none", completedDates: [], createdAt: daysAgo(7) },
  { id: uid(), title: "Mom's birthday", date: "2026-09-11", time: "", endTime: "", category: "Birthday", location: "", notes: "Get a cake", allDay: true, recurrence: "yearly", completedDates: [], createdAt: daysAgo(90) },
  { id: uid(), title: "Netflix payment", date: "2026-08-05", time: "", endTime: "", category: "Bill", location: "", notes: "", allDay: true, recurrence: "monthly", completedDates: ["2026-08-05"], createdAt: daysAgo(200) },
  { id: uid(), title: "Project deadline — Studio K", date: daysFromNow(4), time: "18:00", endTime: "", category: "Work", location: "", notes: "Final delivery", allDay: false, recurrence: "none", completedDates: [], createdAt: daysAgo(20) },
  { id: uid(), title: "Grocery run", date: daysFromNow(0), time: "17:30", endTime: "", category: "Personal", location: "SM Supermarket", notes: "", allDay: false, recurrence: "none", completedDates: [daysFromNow(0)], createdAt: daysAgo(2) },
];

const initialContacts = [
  {
    id: uid(), name: "Maria Reyes", category: "Family", phone: "+63 917 555 0132", email: "maria.reyes@gmail.com",
    company: "", jobTitle: "", tags: ["mom"], notes: "Birthday is in August.", favorite: true,
    avatar: null, banner: null, createdAt: daysAgo(300), updatedAt: daysAgo(300),
  },
  {
    id: uid(), name: "Studio K — Anna", category: "Work", phone: "+63 918 222 4471", email: "anna@studiok.ph",
    company: "Studio K", jobTitle: "Creative Director", tags: ["client"], notes: "Main contact for the landing page project.", favorite: true,
    avatar: null, banner: null, createdAt: daysAgo(60), updatedAt: daysAgo(9),
  },
  {
    id: uid(), name: "Jom Dela Cruz", category: "Friend", phone: "+63 919 887 6655", email: "jom.delacruz@yahoo.com",
    company: "", jobTitle: "", tags: [], notes: "", favorite: false,
    avatar: null, banner: null, createdAt: daysAgo(500), updatedAt: daysAgo(500),
  },
  {
    id: uid(), name: "Makati Dental Clinic", category: "Business", phone: "+63 2 8888 1234", email: "appointments@makatidental.ph",
    company: "Makati Dental Clinic", jobTitle: "", tags: ["health"], notes: "Ask for Dra. Santos.", favorite: false,
    avatar: null, banner: null, createdAt: daysAgo(200), updatedAt: daysAgo(200),
  },
];

const initialActivity = [
  { id: uid(), type: "vault_unlocked", detail: "Vault unlocked", ts: daysAgo(0) },
  { id: uid(), type: "login", detail: "Login from Chrome on Windows", ts: daysAgo(0) },
  { id: uid(), type: "password_copied", detail: "Copied password for Steam", ts: daysAgo(3) },
  { id: uid(), type: "password_updated", detail: "Updated password for BPI Online", ts: daysAgo(12) },
  { id: uid(), type: "expense_recorded", detail: "Recorded expense — SM Supermarket", ts: daysAgo(4) },
  { id: uid(), type: "income_recorded", detail: "Recorded income — Freelance client", ts: daysAgo(9) },
  { id: uid(), type: "note_created", detail: "Created note — Adobe CC License", ts: daysAgo(80) },
  { id: uid(), type: "login", detail: "Login from Safari on iPhone", ts: daysAgo(6) },
];

const SESSIONS = [
  { id: uid(), device: "Chrome on Windows", location: "Manila, PH", current: true, lastActive: "Active now" },
  { id: uid(), device: "Safari on iPhone 15", location: "Manila, PH", current: false, lastActive: "6 days ago" },
  { id: uid(), device: "Firefox on macOS", location: "Cebu, PH", current: false, lastActive: "21 days ago" },
];

/* ---------------------------------------------------------------------- */
/* Password strength                                                      */
/* ---------------------------------------------------------------------- */

function scorePassword(pw) {
  if (!pw) return 0;
  let score = 0;
  const len = pw.length;
  if (len >= 8) score++;
  if (len >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (len < 6) score = Math.min(score, 1);
  return Math.min(score, 5);
}
const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"];
const STRENGTH_COLORS = ["var(--coral)", "var(--coral)", "var(--amber)", "var(--amber)", "var(--mint)", "var(--mint)"];

function StrengthMeter({ password }) {
  const score = scorePassword(password);
  return (
    <div>
      <div style={{ display: "flex", gap: 4 }}>
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} style={{
            height: 5, flex: 1, borderRadius: 3,
            background: i < score ? STRENGTH_COLORS[score] : "var(--surface-3)",
            transition: "background 0.2s"
          }} />
        ))}
      </div>
      <div className="sv-mono" style={{ fontSize: 11, marginTop: 6, color: STRENGTH_COLORS[score] }}>
        {password ? STRENGTH_LABELS[score] : "No password"}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Small reusable UI                                                      */
/* ---------------------------------------------------------------------- */

function IconBtn({ icon: Icon, onClick, title, size = 16, danger, active }) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="sv-focus"
      style={{
        display: "inline-flex", alignItems: "center", justifyContent: "center",
        width: 30, height: 30, borderRadius: 8, border: "1px solid var(--border)",
        background: active ? "var(--primary-soft)" : "var(--surface-2)",
        color: danger ? "var(--coral)" : active ? "var(--primary)" : "var(--text-muted)",
        cursor: "pointer", transition: "all 0.15s"
      }}
      onMouseEnter={(e) => { if (!active) e.currentTarget.style.color = "var(--text)"; }}
      onMouseLeave={(e) => { if (!active) e.currentTarget.style.color = danger ? "var(--coral)" : "var(--text-muted)"; }}
    >
      <Icon size={size} />
    </button>
  );
}

function Button({ children, onClick, variant = "primary", icon: Icon, size = "md", type = "button", disabled }) {
  const styles = {
    primary: { background: "var(--primary)", color: "#fff", border: "1px solid var(--primary)" },
    ghost: { background: "transparent", color: "var(--text)", border: "1px solid var(--border)" },
    danger: { background: "var(--coral)", color: "#fff", border: "1px solid var(--coral)" },
    subtle: { background: "var(--surface-2)", color: "var(--text)", border: "1px solid var(--border)" },
  };
  const pad = size === "sm" ? "6px 10px" : "9px 16px";
  const fontSize = size === "sm" ? 12.5 : 13.5;
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className="sv-focus"
      style={{
        ...styles[variant], padding: pad, borderRadius: 9, fontWeight: 600, fontSize,
        display: "inline-flex", alignItems: "center", gap: 7, cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1, transition: "opacity 0.15s, transform 0.1s", whiteSpace: "nowrap"
      }}
      onMouseDown={(e) => { if (!disabled) e.currentTarget.style.transform = "scale(0.98)"; }}
      onMouseUp={(e) => { e.currentTarget.style.transform = "scale(1)"; }}
    >
      {Icon && <Icon size={14} />}
      {children}
    </button>
  );
}

function Badge({ children, tone = "default" }) {
  const tones = {
    default: { bg: "var(--surface-3)", fg: "var(--text-muted)" },
    primary: { bg: "var(--primary-soft)", fg: "var(--primary)" },
    mint: { bg: "var(--mint-soft)", fg: "var(--mint)" },
    amber: { bg: "var(--amber-soft)", fg: "var(--amber)" },
    coral: { bg: "var(--coral-soft)", fg: "var(--coral)" },
  };
  const t = tones[tone];
  return (
    <span style={{
      background: t.bg, color: t.fg, fontSize: 11, fontWeight: 600, padding: "3px 8px",
      borderRadius: 6, display: "inline-flex", alignItems: "center", gap: 4, whiteSpace: "nowrap"
    }}>
      {children}
    </span>
  );
}

function Card({ children, style, className = "" }) {
  return (
    <div className={"sv-fade-in " + className} style={{
      background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 14,
      padding: 18, ...style
    }}>
      {children}
    </div>
  );
}

function ProgressBar({ pct, tone = "primary" }) {
  const colorMap = { primary: "var(--primary)", mint: "var(--mint)", amber: "var(--amber)", coral: "var(--coral)" };
  return (
    <div style={{ height: 7, borderRadius: 4, background: "var(--surface-3)", overflow: "hidden" }}>
      <div style={{
        width: `${Math.min(pct, 100)}%`, height: "100%", background: colorMap[tone],
        borderRadius: 4, transition: "width 0.3s ease"
      }} />
    </div>
  );
}

function Modal({ title, onClose, children, width = 480 }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0, background: "rgba(4,7,10,0.6)", backdropFilter: "blur(2px)",
        display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, padding: 20
      }}
    >
      <div className="sv-fade-in sv-scroll" style={{
        width, maxWidth: "100%", maxHeight: "88vh", overflowY: "auto",
        background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 16,
        boxShadow: "0 24px 60px rgba(0,0,0,0.4)"
      }}>
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "16px 20px", borderBottom: "1px solid var(--border)", position: "sticky", top: 0,
          background: "var(--surface)", zIndex: 1
        }}>
          <h3 className="sv-display" style={{ fontSize: 16, fontWeight: 600, margin: 0 }}>{title}</h3>
          <IconBtn icon={X} onClick={onClose} title="Close (Esc)" />
        </div>
        <div style={{ padding: 20 }}>{children}</div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ display: "block", fontSize: 12.5, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6 }}>{label}</label>
      {children}
    </div>
  );
}

const inputStyle = {
  width: "100%", background: "var(--surface-2)", border: "1px solid var(--border)",
  borderRadius: 9, padding: "9px 11px", color: "var(--text)", fontSize: 13.5,
  fontFamily: "Inter, sans-serif", outline: "none", boxSizing: "border-box"
};

function Input(props) {
  return <input {...props} className="sv-focus" style={{ ...inputStyle, ...(props.style || {}) }} />;
}
function TextArea(props) {
  return <textarea {...props} className="sv-focus" style={{ ...inputStyle, resize: "vertical", minHeight: 90, fontFamily: "'JetBrains Mono', monospace", fontSize: 12.5, ...(props.style || {}) }} />;
}
function Select({ children, ...props }) {
  return <select {...props} className="sv-focus" style={{ ...inputStyle, cursor: "pointer" }}>{children}</select>;
}

function ConfirmDialog({ title, message, confirmLabel = "Confirm", danger, onConfirm, onCancel }) {
  return (
    <Modal title={title} onClose={onCancel} width={400}>
      <p style={{ color: "var(--text-muted)", fontSize: 13.5, lineHeight: 1.6, margin: "0 0 18px" }}>{message}</p>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>{confirmLabel}</Button>
      </div>
    </Modal>
  );
}

function EmptyState({ icon: Icon, title, subtitle, action }) {
  return (
    <div style={{ textAlign: "center", padding: "48px 20px", color: "var(--text-muted)" }}>
      <div style={{
        width: 48, height: 48, borderRadius: 12, background: "var(--surface-2)", border: "1px solid var(--border)",
        display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 14px"
      }}>
        <Icon size={22} color="var(--text-faint)" />
      </div>
      <div className="sv-display" style={{ fontWeight: 600, color: "var(--text)", marginBottom: 4 }}>{title}</div>
      <div style={{ fontSize: 13, marginBottom: action ? 16 : 0 }}>{subtitle}</div>
      {action}
    </div>
  );
}

/* Masked value that "decrypts" on reveal */
function MaskedValue({ value, revealed, mono = true }) {
  const [justRevealed, setJustRevealed] = useState(false);
  const prevRevealed = useRef(revealed);
  useEffect(() => {
    if (revealed && !prevRevealed.current) {
      setJustRevealed(true);
      const t = setTimeout(() => setJustRevealed(false), 250);
      return () => clearTimeout(t);
    }
    prevRevealed.current = revealed;
  }, [revealed]);
  return (
    <span className={mono ? "sv-mono" : ""} style={{ fontSize: 13.5, letterSpacing: revealed ? "normal" : 1 }}>
      <span className={justRevealed ? "sv-decrypt" : ""} style={{ display: "inline-block" }}>
        {revealed ? value : "•".repeat(Math.min(value.length, 14))}
      </span>
    </span>
  );
}

/* ---------------------------------------------------------------------- */
/* Password generator                                                     */
/* ---------------------------------------------------------------------- */

const CHARSETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{}<>?",
};
const AMBIGUOUS = "il1Lo0O";

function generatePassword({ length, upper, lower, numbers, symbols, excludeAmbiguous }) {
  let pool = "";
  if (lower) pool += CHARSETS.lower;
  if (upper) pool += CHARSETS.upper;
  if (numbers) pool += CHARSETS.numbers;
  if (symbols) pool += CHARSETS.symbols;
  if (!pool) pool = CHARSETS.lower;
  if (excludeAmbiguous) pool = [...pool].filter((c) => !AMBIGUOUS.includes(c)).join("");
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < length; i++) out += pool[arr[i] % pool.length];
  return out;
}

function PasswordGenerator({ onUse, embedded }) {
  const [opts, setOpts] = useState({ length: 16, upper: true, lower: true, numbers: true, symbols: true, excludeAmbiguous: true });
  const [pw, setPw] = useState(() => generatePassword({ length: 16, upper: true, lower: true, numbers: true, symbols: true, excludeAmbiguous: true }));

  const regen = useCallback((next) => {
    const o = { ...opts, ...next };
    setOpts(o);
    setPw(generatePassword(o));
  }, [opts]);

  return (
    <div>
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10,
        background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 10,
        padding: "12px 14px", marginBottom: 14
      }}>
        <span className="sv-mono" style={{ fontSize: 15, wordBreak: "break-all" }}>{pw}</span>
        <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
          <IconBtn icon={RefreshCw} onClick={() => regen({})} title="Regenerate" />
          <IconBtn icon={Copy} onClick={() => navigator.clipboard.writeText(pw)} title="Copy" />
        </div>
      </div>
      <StrengthMeter password={pw} />

      <div style={{ marginTop: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12.5, color: "var(--text-muted)", marginBottom: 6 }}>
          <span>Length</span><span className="sv-mono">{opts.length}</span>
        </div>
        <input type="range" min={8} max={32} value={opts.length}
          onChange={(e) => regen({ length: Number(e.target.value) })}
          style={{ width: "100%", accentColor: "var(--primary)" }} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 14 }}>
        {[
          ["upper", "Uppercase letters"],
          ["lower", "Lowercase letters"],
          ["numbers", "Numbers"],
          ["symbols", "Symbols"],
        ].map(([key, label]) => (
          <label key={key} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" }}>
            <input type="checkbox" checked={opts[key]} onChange={(e) => regen({ [key]: e.target.checked })} style={{ accentColor: "var(--primary)" }} />
            {label}
          </label>
        ))}
      </div>
      <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer", marginTop: 10 }}>
        <input type="checkbox" checked={opts.excludeAmbiguous} onChange={(e) => regen({ excludeAmbiguous: e.target.checked })} style={{ accentColor: "var(--primary)" }} />
        Exclude ambiguous characters (i, l, 1, O, 0)
      </label>

      {onUse && (
        <div style={{ marginTop: 18, display: "flex", justifyContent: "flex-end" }}>
          <Button icon={CheckCircle2} onClick={() => onUse(pw)}>Use this password</Button>
        </div>
      )}
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Toasts                                                                  */
/* ---------------------------------------------------------------------- */

function ToastStack({ toasts, dismiss }) {
  return (
    <div style={{ position: "fixed", bottom: 20, right: 20, display: "flex", flexDirection: "column", gap: 8, zIndex: 200, width: 320, maxWidth: "90vw" }}>
      {toasts.map((t) => (
        <div key={t.id} className="sv-toast" style={{
          background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 12,
          padding: "12px 14px", display: "flex", gap: 10, alignItems: "flex-start",
          boxShadow: "0 10px 30px rgba(0,0,0,0.35)"
        }}>
          {t.tone === "danger" ? <ShieldAlert size={17} color="var(--coral)" style={{ marginTop: 1, flexShrink: 0 }} /> :
            t.tone === "success" ? <CheckCircle2 size={17} color="var(--mint)" style={{ marginTop: 1, flexShrink: 0 }} /> :
            <Shield size={17} color="var(--primary)" style={{ marginTop: 1, flexShrink: 0 }} />}
          <div style={{ fontSize: 12.5, lineHeight: 1.5, color: "var(--text)" }}>{t.message}</div>
          <button onClick={() => dismiss(t.id)} style={{ marginLeft: "auto", background: "none", border: "none", color: "var(--text-faint)", cursor: "pointer", flexShrink: 0 }}>
            <X size={13} />
          </button>
        </div>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Lock Screen                                                             */
/* ---------------------------------------------------------------------- */

function LockScreen({ onUnlockWithPassword, onUnlockWithPin, onUnlockWithBiometric, biometricAvailable, appName = "SecureVault", envelope, serverStatus, dataFilePath }) {
  const [pin, setPin] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [biometricBusy, setBiometricBusy] = useState(false);
  const pinAvailable = !!envelope.pin;
  const biometricSetUp = !!envelope.biometric && biometricAvailable;
  const [step, setStep] = useState(pinAvailable ? "pin" : "password");

  const submitPin = async (e) => {
    e.preventDefault();
    if (pin.length < 4) { setError("Enter at least 4 digits."); return; }
    setError(""); setBusy(true);
    // brief yield so "Verifying…" paints before the KDF work runs
    await new Promise((r) => setTimeout(r, 30));
    const result = await onUnlockWithPin(pin);
    setBusy(false);
    if (!result.ok) { setError(result.error || "Incorrect PIN."); setPin(""); }
  };

  const submitPassword = async (e) => {
    e.preventDefault();
    if (!password) return;
    setError(""); setBusy(true);
    await new Promise((r) => setTimeout(r, 30));
    const result = await onUnlockWithPassword(password);
    setBusy(false);
    if (!result.ok) { setError(result.error || "Incorrect master password."); }
  };

  const tryBiometric = async () => {
    setError(""); setBiometricBusy(true);
    const result = await onUnlockWithBiometric();
    setBiometricBusy(false);
    if (!result.ok) setError(result.error || "Windows Hello unlock failed.");
  };

  return (
    <div className="sv-root dark" style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", position: "relative", overflow: "hidden" }}>
      <FontStyles />
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(circle at 50% 20%, rgba(76,124,243,0.10), transparent 60%)"
      }} />
      <div className="sv-fade-in" style={{ width: 380, maxWidth: "90vw", position: "relative", zIndex: 1 }}>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{
            width: 64, height: 64, borderRadius: 18, margin: "0 auto 16px", position: "relative", overflow: "hidden",
            background: "linear-gradient(160deg, var(--surface-2), var(--surface-3))",
            border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            <Lock size={26} color="var(--primary)" />
            <div className="sv-scanline" style={{
              position: "absolute", left: 0, right: 0, height: 14,
              background: "linear-gradient(180deg, transparent, rgba(76,124,243,0.35), transparent)"
            }} />
          </div>
          <div className="sv-display" style={{ fontSize: 22, fontWeight: 700 }}>{appName}</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 4 }}>
            {busy ? "Deriving encryption key…" : biometricBusy ? "Follow the Windows Hello prompt…" : step === "password" ? "Sign in to your vault" : "Vault locked — enter your PIN to continue"}
          </div>
        </div>

        {serverStatus === "offline" && (
          <div style={{
            display: "flex", gap: 8, alignItems: "flex-start", fontSize: 12, color: "var(--amber)",
            background: "var(--amber-soft)", border: "1px solid var(--border)", borderRadius: 10, padding: 12, marginBottom: 14
          }}>
            <ShieldAlert size={15} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>Local server isn't running, so nothing you do will be saved to D:\Local Data. Start it with <code className="sv-mono">node server.js</code> and reload.</span>
          </div>
        )}

        {biometricSetUp && (
          <div style={{ textAlign: "center" }}>
            <Button
              size="md"
              variant="subtle"
              onClick={tryBiometric}
              disabled={busy || biometricBusy}
            >
              <Fingerprint size={16} /> {biometricBusy ? "Waiting for Windows Hello…" : "Unlock with Windows Hello"}
            </Button>
          </div>
        )}
        {biometricSetUp && (
          <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "14px 0" }}>
            <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
            <span style={{ fontSize: 11, color: "var(--text-faint)" }}>or</span>
            <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
          </div>
        )}

        <Card>
          {step === "password" ? (
            <form onSubmit={submitPassword}>
              <Field label="Master password">
                <Input type="password" value={password} onChange={(e) => { setPassword(e.target.value); setError(""); }} placeholder="Master password" required autoFocus disabled={busy} />
              </Field>
              {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 10 }}>{error}</div>}
              <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginBottom: 14, display: "flex", alignItems: "center", gap: 6 }}>
                <KeyRound size={12} /> Verified with Argon2id — never stored or sent as plaintext.
              </div>
              <Button type="submit" size="md" disabled={busy}>
                <span style={{ display: "flex", alignItems: "center", gap: 7 }}>{busy ? <RefreshCw size={14} className="" /> : <Unlock size={14} />} {busy ? "Verifying…" : "Unlock vault"}</span>
              </Button>
              {pinAvailable && (
                <button type="button" onClick={() => { setStep("pin"); setError(""); }} className="sv-focus" style={{ display: "block", margin: "12px auto 0", background: "none", border: "none", color: "var(--text-faint)", fontSize: 12, cursor: "pointer" }}>
                  Use PIN instead
                </button>
              )}
            </form>
          ) : (
            <form onSubmit={submitPin}>
              <Field label="4–6 digit PIN">
                <Input
                  type="password" inputMode="numeric" autoFocus maxLength={6} disabled={busy}
                  value={pin} onChange={(e) => { setPin(e.target.value.replace(/\D/g, "")); setError(""); }}
                  placeholder="••••" style={{ textAlign: "center", fontSize: 22, letterSpacing: 8 }}
                />
              </Field>
              {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 10 }}>{error}</div>}
              <Button type="submit" size="md" disabled={busy}>
                <span style={{ display: "flex", alignItems: "center", gap: 7 }}><Unlock size={14} /> {busy ? "Verifying…" : "Unlock"}</span>
              </Button>
              <button type="button" onClick={() => { setStep("password"); setError(""); }} className="sv-focus" style={{ display: "block", margin: "12px auto 0", background: "none", border: "none", color: "var(--text-faint)", fontSize: 12, cursor: "pointer" }}>
                Use master password instead
              </button>
            </form>
          )}
        </Card>
        <div style={{ textAlign: "center", fontSize: 11.5, color: "var(--text-faint)", marginTop: 16 }}>
          {serverStatus === "connected"
            ? <>Encrypted (AES-256-GCM) and saved to <span className="sv-mono">{dataFilePath || "D:\\Local Data"}</span></>
            : "Zero-knowledge design — even SecureVault can't read your stored data without your password."}
        </div>
      </div>
    </div>
  );
}

/* First-run screen: create the master password that will protect the vault. */
function VaultSetupScreen({ onCreate, serverStatus, dataFilePath }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (password.length < 8) { setError("Master password must be at least 8 characters."); return; }
    if (password !== confirm) { setError("Passwords don't match."); return; }
    setError(""); setBusy(true);
    await new Promise((r) => setTimeout(r, 30));
    await onCreate(password);
    // component unmounts on success; no need to reset busy
  };

  return (
    <div className="sv-root dark" style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", position: "relative", overflow: "hidden" }}>
      <FontStyles />
      <div style={{ position: "absolute", inset: 0, background: "radial-gradient(circle at 50% 20%, rgba(76,124,243,0.10), transparent 60%)" }} />
      <div className="sv-fade-in" style={{ width: 400, maxWidth: "90vw", position: "relative", zIndex: 1 }}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{
            width: 64, height: 64, borderRadius: 18, margin: "0 auto 16px",
            background: "linear-gradient(160deg, var(--surface-2), var(--surface-3))",
            border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            <ShieldCheck size={26} color="var(--primary)" />
          </div>
          <div className="sv-display" style={{ fontSize: 22, fontWeight: 700 }}>Create your vault</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 4 }}>
            No vault found yet{serverStatus === "connected" ? <> at <span className="sv-mono">{dataFilePath}</span></> : ""}. Set a master password to encrypt it.
          </div>
        </div>
        <Card>
          <form onSubmit={submit}>
            <Field label="Master password">
              <Input type="password" value={password} onChange={(e) => { setPassword(e.target.value); setError(""); }} autoFocus disabled={busy} placeholder="At least 8 characters" />
            </Field>
            {password && <div style={{ marginTop: -8, marginBottom: 14 }}><StrengthMeter password={password} /></div>}
            <Field label="Confirm master password">
              <Input type="password" value={confirm} onChange={(e) => { setConfirm(e.target.value); setError(""); }} disabled={busy} />
            </Field>
            {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 10 }}>{error}</div>}
            <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginBottom: 14, lineHeight: 1.6 }}>
              This password derives (via Argon2id) the key that encrypts everything you store — write it down somewhere safe. There's no recovery if you forget it; that's what makes it zero-knowledge.
            </div>
            <Button type="submit" size="md" disabled={busy || !password || !confirm}>
              <span style={{ display: "flex", alignItems: "center", gap: 7 }}>{busy ? "Encrypting vault…" : <>Create vault <ChevronRight size={14} /></>}</span>
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Sidebar                                                                 */
/* ---------------------------------------------------------------------- */

const NAV = [
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { key: "passwords", label: "Passwords", icon: KeyRound },
  { key: "notes", label: "Secure Notes", icon: FileText },
  { key: "finance", label: "Finance", icon: Wallet },
  { key: "budgets", label: "Budgets", icon: PiggyBank },
  { key: "goals", label: "Savings Goals", icon: Target },
  { key: "planner", label: "Planner", icon: CalendarDays },
  { key: "contacts", label: "Contacts", icon: Users },
  { key: "trash", label: "Trash", icon: Trash2 },
  { key: "security", label: "Security Center", icon: Shield },
  { key: "settings", label: "Settings", icon: SettingsIcon },
];

function Avatar({ src, name, size = 30, fontSize = 12 }) {
  const initials = (name || "?").slice(0, 2).toUpperCase();
  return (
    <div style={{
      width: size, height: size, borderRadius: "50%", background: "var(--surface-3)", flexShrink: 0,
      display: "flex", alignItems: "center", justifyContent: "center", fontSize, fontWeight: 700,
      overflow: "hidden"
    }}>
      {src ? <img src={src} alt={name} style={{ width: "100%", height: "100%", objectFit: "cover" }} /> : initials}
    </div>
  );
}

/* Resize an uploaded image down to a small square before storing it, so the
   encrypted vault file doesn't balloon with a full-resolution photo. */
function resizeImageFile(file, maxSize = 200, quality = 0.85) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("Could not load image"));
      img.onload = () => {
        const side = Math.min(img.width, img.height);
        const sx = (img.width - side) / 2;
        const sy = (img.height - side) / 2;
        const canvas = document.createElement("canvas");
        canvas.width = maxSize;
        canvas.height = maxSize;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, sx, sy, side, side, 0, 0, maxSize, maxSize);
        resolve(canvas.toDataURL("image/jpeg", quality));
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

/** Like resizeImageFile, but crops to an arbitrary aspect ratio (e.g. a wide
    banner) instead of a square — used for contact cover photos. */
function resizeImageFileToAspect(file, targetWidth, targetHeight, quality = 0.85) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("Could not load image"));
      img.onload = () => {
        const targetRatio = targetWidth / targetHeight;
        const srcRatio = img.width / img.height;
        let sx, sy, sw, sh;
        if (srcRatio > targetRatio) {
          sh = img.height;
          sw = sh * targetRatio;
          sy = 0;
          sx = (img.width - sw) / 2;
        } else {
          sw = img.width;
          sh = sw / targetRatio;
          sx = 0;
          sy = (img.height - sh) / 2;
        }
        const canvas = document.createElement("canvas");
        canvas.width = targetWidth;
        canvas.height = targetHeight;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, sx, sy, sw, sh, 0, 0, targetWidth, targetHeight);
        resolve(canvas.toDataURL("image/jpeg", quality));
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

function Sidebar({ view, setView, onLock, theme, toggleTheme, counts, serverStatus, auth }) {
  return (
    <div style={{
      width: 236, flexShrink: 0, borderRight: "1px solid var(--border)", background: "var(--surface)",
      display: "flex", flexDirection: "column", height: "100vh", position: "sticky", top: 0
    }}>
      <div style={{ padding: "20px 18px 16px", display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 9, background: "var(--primary-soft)",
          display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
        }}>
          <ShieldCheck size={17} color="var(--primary)" />
        </div>
        <span className="sv-display" style={{ fontWeight: 700, fontSize: 15.5 }}>SecureVault</span>
      </div>

      <div style={{ padding: "0 18px 12px" }}>
        <div title={serverStatus === "connected" ? "Saving to D:\\Local Data" : "Local server not running — changes won't be saved"} style={{
          display: "flex", alignItems: "center", gap: 6, fontSize: 10.5, color: serverStatus === "connected" ? "var(--mint)" : "var(--coral)"
        }}>
          <span style={{
            width: 6, height: 6, borderRadius: "50%",
            background: serverStatus === "connected" ? "var(--mint)" : "var(--coral)"
          }} />
          {serverStatus === "connected" ? "Local save: D:\\Local Data" : "Local server offline"}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "6px 12px" }} className="sv-scroll">
        {NAV.map((item) => {
          const active = view === item.key;
          const count = counts?.[item.key];
          return (
            <button
              key={item.key}
              onClick={() => setView(item.key)}
              className="sv-focus"
              style={{
                width: "100%", display: "flex", alignItems: "center", gap: 10, textAlign: "left",
                padding: "9px 11px", borderRadius: 9, marginBottom: 2, border: "none", cursor: "pointer",
                background: active ? "var(--primary-soft)" : "transparent",
                color: active ? "var(--primary)" : "var(--text-muted)",
                fontSize: 13.5, fontWeight: active ? 600 : 500, transition: "all 0.15s"
              }}
            >
              <item.icon size={16} />
              <span style={{ flex: 1 }}>{item.label}</span>
              {count != null && <span className="sv-mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>{count}</span>}
            </button>
          );
        })}
      </div>

      <div style={{ padding: 12, borderTop: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: 9, marginBottom: 8 }}>
          <Avatar src={auth?.avatar} name={auth?.username} />
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12.5, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{auth?.username || "User"}</div>
            <div style={{ fontSize: 11, color: "var(--text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{auth?.email || ""}</div>
          </div>
          <button onClick={toggleTheme} title="Toggle theme" style={{
            marginLeft: "auto", background: "var(--surface-2)", border: "1px solid var(--border)",
            borderRadius: 8, width: 28, height: 28, display: "flex", alignItems: "center", justifyContent: "center",
            color: "var(--text-muted)", cursor: "pointer", flexShrink: 0
          }}>
            {theme === "dark" ? <Sun size={14} /> : <Moon size={14} />}
          </button>
        </div>
        <Button variant="subtle" size="sm" icon={Lock} onClick={onLock}>
          Lock Vault <span style={{ marginLeft: "auto", color: "var(--text-faint)", fontWeight: 500 }}>Ctrl L</span>
        </Button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* TopBar with global search                                              */
/* ---------------------------------------------------------------------- */

function TopBar({ title, subtitle, onOpenSearch, right }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16,
      padding: "22px 28px 18px", flexWrap: "wrap"
    }}>
      <div>
        <h1 className="sv-display" style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>{title}</h1>
        {subtitle && <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 3 }}>{subtitle}</div>}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button onClick={onOpenSearch} className="sv-focus" style={{
          display: "flex", alignItems: "center", gap: 8, background: "var(--surface-2)",
          border: "1px solid var(--border)", borderRadius: 9, padding: "8px 12px", color: "var(--text-faint)",
          cursor: "pointer", fontSize: 12.5
        }}>
          <Search size={14} /> Search everything
          <span className="sv-mono" style={{ background: "var(--surface-3)", padding: "1px 6px", borderRadius: 5, fontSize: 10.5, marginLeft: 4 }}>Ctrl K</span>
        </button>
        {right}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Global search                                                          */
/* ---------------------------------------------------------------------- */

function GlobalSearch({ onClose, passwords, notes, transactions, locked, goTo }) {
  const [q, setQ] = useState("");
  const ql = q.toLowerCase();

  const pwResults = locked ? [] : passwords.filter((p) => p.title.toLowerCase().includes(ql) || p.username.toLowerCase().includes(ql)).slice(0, 5);
  const noteResults = locked ? [] : notes.filter((n) => n.title.toLowerCase().includes(ql)).slice(0, 5);
  const txResults = transactions.filter((t) => t.party.toLowerCase().includes(ql) || t.category.toLowerCase().includes(ql)).slice(0, 5);

  const hasQuery = q.trim().length > 0;
  const noResults = hasQuery && !pwResults.length && !noteResults.length && !txResults.length;

  return (
    <Modal title="Global search" onClose={onClose} width={560}>
      <Input autoFocus placeholder="Search passwords, notes, transactions…" value={q} onChange={(e) => setQ(e.target.value)} style={{ marginBottom: 14 }} />
      {locked && <div style={{ fontSize: 12, color: "var(--amber)", marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}><Lock size={12} /> Vault is locked — passwords and notes are hidden from search results.</div>}

      {!hasQuery && <div style={{ fontSize: 12.5, color: "var(--text-faint)" }}>Start typing to search across your vault.</div>}
      {noResults && <div style={{ fontSize: 12.5, color: "var(--text-faint)" }}>No matches found.</div>}

      {pwResults.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", marginBottom: 6 }}>Passwords</div>
          {pwResults.map((p) => (
            <button key={p.id} onClick={() => { goTo("passwords"); onClose(); }} className="sv-focus" style={resultRowStyle}>
              <KeyRound size={14} color="var(--primary)" /> <span>{p.title}</span> <span style={{ color: "var(--text-faint)", marginLeft: "auto", fontSize: 12 }}>{p.username}</span>
            </button>
          ))}
        </div>
      )}
      {noteResults.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", marginBottom: 6 }}>Secure Notes</div>
          {noteResults.map((n) => (
            <button key={n.id} onClick={() => { goTo("notes"); onClose(); }} className="sv-focus" style={resultRowStyle}>
              <FileText size={14} color="var(--mint)" /> <span>{n.title}</span>
            </button>
          ))}
        </div>
      )}
      {txResults.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", marginBottom: 6 }}>Transactions</div>
          {txResults.map((t) => (
            <button key={t.id} onClick={() => { goTo("finance"); onClose(); }} className="sv-focus" style={resultRowStyle}>
              {t.type === "income" ? <ArrowUpRight size={14} color="var(--mint)" /> : <ArrowDownRight size={14} color="var(--coral)" />}
              <span>{t.party}</span>
              <span className="sv-mono" style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-faint)" }}>{fmtMoney(t.amount)}</span>
            </button>
          ))}
        </div>
      )}
    </Modal>
  );
}
const resultRowStyle = {
  width: "100%", display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", borderRadius: 8,
  background: "transparent", border: "none", cursor: "pointer", color: "var(--text)", fontSize: 13, textAlign: "left"
};

/* ---------------------------------------------------------------------- */
/* Dashboard                                                              */
/* ---------------------------------------------------------------------- */

function StatCard({ icon: Icon, label, value, tone = "primary", sub, onEdit }) {
  const toneColor = { primary: "var(--primary)", mint: "var(--mint)", amber: "var(--amber)", coral: "var(--coral)" }[tone];
  const toneBg = { primary: "var(--primary-soft)", mint: "var(--mint-soft)", amber: "var(--amber-soft)", coral: "var(--coral-soft)" }[tone];
  return (
    <Card style={{ padding: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
        <span style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>{label}</span>
        <div style={{ width: 30, height: 30, borderRadius: 8, background: toneBg, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon size={15} color={toneColor} />
        </div>
      </div>
      <div className="sv-display sv-mono" style={{ fontSize: 21, fontWeight: 700 }}>{value}</div>
      {sub && (
        <div style={{ display: "flex", alignItems: "center", gap: 5, marginTop: 4 }}>
          <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{sub}</div>
          {onEdit && (
            <button onClick={onEdit} title="Modify" className="sv-focus" style={{
              background: "none", border: "none", padding: 2, cursor: "pointer", color: "var(--text-faint)",
              display: "flex", alignItems: "center", flexShrink: 0
            }}>
              <Pencil size={11} />
            </button>
          )}
        </div>
      )}
    </Card>
  );
}

function ActivityIcon({ type }) {
  const map = {
    vault_unlocked: [Unlock, "primary"], vault_locked: [Lock, "amber"], login: [Smartphone, "primary"],
    password_copied: [Copy, "primary"], password_updated: [Pencil, "mint"], password_added: [Plus, "mint"],
    note_created: [FileText, "mint"], note_accessed: [FileText, "primary"], income_recorded: [ArrowUpRight, "mint"],
    expense_recorded: [ArrowDownRight, "coral"], security_change: [Shield, "amber"], logout: [LogOut, "default"],
    goal_created: [Target, "primary"], goal_contribution: [Target, "mint"], event_created: [CalendarDays, "primary"],
    contact_created: [Users, "primary"],
  };
  const [Icon, tone] = map[type] || [Bell, "default"];
  const color = { primary: "var(--primary)", mint: "var(--mint)", amber: "var(--amber)", coral: "var(--coral)", default: "var(--text-faint)" }[tone];
  const bg = { primary: "var(--primary-soft)", mint: "var(--mint-soft)", amber: "var(--amber-soft)", coral: "var(--coral-soft)", default: "var(--surface-3)" }[tone];
  return (
    <div style={{ width: 28, height: 28, borderRadius: 8, background: bg, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
      <Icon size={13} color={color} />
    </div>
  );
}

function Dashboard({ data, setView, openModal, onLock }) {
  const { passwords, notes, transactions, goals, generalSavings, activity } = data;
  const thisMonth = new Date().getMonth();
  const monthTx = transactions.filter((t) => new Date(t.date + "T00:00:00").getMonth() === thisMonth);
  const monthIncome = monthTx.filter((t) => t.type === "income").reduce((s, t) => s + t.amount, 0);
  const monthExpense = monthTx.filter((t) => t.type === "expense").reduce((s, t) => s + t.amount, 0);
  const totalIncome = transactions.filter((t) => t.type === "income").reduce((s, t) => s + t.amount, 0);
  const totalExpense = transactions.filter((t) => t.type === "expense").reduce((s, t) => s + t.amount, 0);
  const totalSaved = (goals || []).reduce((s, g) => s + g.currentAmount, 0) + (generalSavings?.balance || 0);
  // Savings goal money is entirely separate — funding a goal never reduces
  // this directly. (If a deposit came from your available balance, that's
  // already reflected here as a real expense transaction, not a special case.)
  const availableBalance = totalIncome - totalExpense;

  return (
    <div>
      <TopBar title="Dashboard" subtitle="Your private overview — nothing here is stored in plaintext." onOpenSearch={() => openModal("search")}
        right={<Button icon={Lock} variant="subtle" onClick={onLock}>Lock</Button>} />
      <div style={{ padding: "0 28px 28px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px,1fr))", gap: 14, marginBottom: 20 }}>
          <StatCard icon={KeyRound} label="Saved passwords" value={passwords.length} tone="primary" sub={`${new Set(passwords.map(p=>p.category)).size} categories`} />
          <StatCard icon={FileText} label="Secure notes" value={notes.filter(n=>!n.archived).length} tone="mint" sub={`${notes.filter(n=>n.pinned).length} pinned`} />
          <StatCard icon={ArrowUpRight} label="Monthly income" value={fmtMoney(monthIncome)} tone="mint" />
          <StatCard icon={ArrowDownRight} label="Monthly expenses" value={fmtMoney(monthExpense)} tone="coral" />
          <StatCard icon={Wallet} label="Available balance" value={fmtMoney(availableBalance)} tone="primary" sub="Reflects any transfers into savings" />
          <StatCard icon={Target} label="Total savings" value={fmtMoney(totalSaved)} tone="mint" sub="Goals + General Savings" />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 16 }}>
          <Card>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14.5, marginBottom: 14 }}>Quick actions</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
              <QuickAction icon={KeyRound} label="Add password" onClick={() => openModal("password-add")} />
              <QuickAction icon={FileText} label="Add note" onClick={() => openModal("note-add")} />
              <QuickAction icon={ArrowUpRight} label="Add income" onClick={() => openModal("transaction-add", { type: "income" })} />
              <QuickAction icon={ArrowDownRight} label="Add expense" onClick={() => openModal("transaction-add", { type: "expense" })} />
              <QuickAction icon={Target} label="Add savings goal" onClick={() => openModal("goal-add")} />
              <QuickAction icon={CalendarDays} label="Add event" onClick={() => openModal("event-add", { date: todayStr() })} />
              <QuickAction icon={Sparkles} label="Generate password" onClick={() => openModal("generator")} />
              <QuickAction icon={Lock} label="Lock vault" onClick={onLock} />
            </div>
          </Card>

          <Card>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14.5, marginBottom: 14 }}>Recent activity</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 240, overflowY: "auto" }} className="sv-scroll">
              {activity.slice(0, 8).map((a) => (
                <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <ActivityIcon type={a.type} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.detail}</div>
                    <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{fmtDate(a.ts)}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function QuickAction({ icon: Icon, label, onClick }) {
  return (
    <button onClick={onClick} className="sv-focus" style={{
      display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 8, padding: "12px 12px",
      borderRadius: 11, background: "var(--surface-2)", border: "1px solid var(--border)", cursor: "pointer",
      color: "var(--text)", transition: "border-color 0.15s"
    }}
      onMouseEnter={(e) => e.currentTarget.style.borderColor = "var(--primary)"}
      onMouseLeave={(e) => e.currentTarget.style.borderColor = "var(--border)"}
    >
      <Icon size={16} color="var(--primary)" />
      <span style={{ fontSize: 12, fontWeight: 600, lineHeight: 1.3 }}>{label}</span>
    </button>
  );
}

/* ---------------------------------------------------------------------- */
/* Passwords view                                                        */
/* ---------------------------------------------------------------------- */

function PasswordsView({ passwords, openModal, deletePassword, logActivity, toast }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const [sortBy, setSortBy] = useState("updated");
  const [revealed, setRevealed] = useState({});
  const [confirmDelete, setConfirmDelete] = useState(null);

  const filtered = useMemo(() => {
    let list = passwords.filter((p) =>
      (category === "All" || p.category === category) &&
      (p.title.toLowerCase().includes(query.toLowerCase()) || p.username.toLowerCase().includes(query.toLowerCase()))
    );
    if (sortBy === "updated") list = [...list].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    if (sortBy === "name") list = [...list].sort((a, b) => a.title.localeCompare(b.title));
    if (sortBy === "strength") list = [...list].sort((a, b) => scorePassword(b.password) - scorePassword(a.password));
    return list;
  }, [passwords, query, category, sortBy]);

  const copy = (text, label) => {
    navigator.clipboard.writeText(text);
    toast(`${label} copied. Clipboard will clear in 30 seconds.`, "success");
    logActivity(label.includes("Password") ? "password_copied" : "login", `Copied ${label.toLowerCase()}`);
    setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30000);
  };

  return (
    <div>
      <TopBar title="Passwords" subtitle={`${passwords.length} saved credentials`}
        right={<Button icon={Plus} onClick={() => openModal("password-add")}>Add password</Button>} />
      <div style={{ padding: "0 28px 28px" }}>
        <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: "1 1 220px" }}>
            <Search size={14} style={{ position: "absolute", left: 11, top: 11, color: "var(--text-faint)" }} />
            <Input placeholder="Search passwords…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ paddingLeft: 32 }} />
          </div>
          <Select value={category} onChange={(e) => setCategory(e.target.value)} style={{ width: 170 }}>
            <option>All</option>
            {PASSWORD_CATEGORIES.map((c) => <option key={c}>{c}</option>)}
          </Select>
          <Select value={sortBy} onChange={(e) => setSortBy(e.target.value)} style={{ width: 170 }}>
            <option value="updated">Sort: Last updated</option>
            <option value="name">Sort: Name</option>
            <option value="strength">Sort: Strength</option>
          </Select>
        </div>

        {filtered.length === 0 ? (
          <Card><EmptyState icon={KeyRound} title="No passwords found" subtitle="Try a different search or add a new credential."
            action={<Button icon={Plus} onClick={() => openModal("password-add")}>Add password</Button>} /></Card>
        ) : (
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div className="sv-scroll" style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 760 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    {["Website", "Username", "Password", "Category", "Strength", "Updated", ""].map((h) => (
                      <th key={h} style={{ textAlign: "left", padding: "12px 16px", fontSize: 11, color: "var(--text-faint)", fontWeight: 700, textTransform: "uppercase" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((p) => {
                    const isRevealed = !!revealed[p.id];
                    const strength = scorePassword(p.password);
                    return (
                      <tr key={p.id} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={{ padding: "12px 16px" }}>
                          <div style={{ fontWeight: 600, fontSize: 13 }}>{p.title}</div>
                          {p.url && <div style={{ fontSize: 11, color: "var(--text-faint)", display: "flex", alignItems: "center", gap: 4 }}><Globe size={10} /> {p.url.replace(/^https?:\/\//, "")}</div>}
                        </td>
                        <td style={{ padding: "12px 16px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5 }}>
                            {p.username}
                            <IconBtn icon={Copy} size={12} onClick={() => copy(p.username, "Username")} title="Copy username" />
                          </div>
                        </td>
                        <td style={{ padding: "12px 16px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <MaskedValue value={p.password} revealed={isRevealed} />
                            <IconBtn icon={isRevealed ? EyeOff : Eye} size={12} onClick={() => setRevealed((r) => ({ ...r, [p.id]: !r[p.id] }))} title={isRevealed ? "Hide" : "Show"} />
                            <IconBtn icon={Copy} size={12} onClick={() => copy(p.password, "Password")} title="Copy password" />
                          </div>
                        </td>
                        <td style={{ padding: "12px 16px" }}><Badge>{p.category}</Badge></td>
                        <td style={{ padding: "12px 16px", width: 90 }}>
                          <div style={{ height: 5, borderRadius: 3, background: "var(--surface-3)", overflow: "hidden" }}>
                            <div style={{ width: `${(strength / 5) * 100}%`, height: "100%", background: STRENGTH_COLORS[strength] }} />
                          </div>
                        </td>
                        <td style={{ padding: "12px 16px", fontSize: 12, color: "var(--text-faint)" }} className="sv-mono">{fmtDate(p.updatedAt)}</td>
                        <td style={{ padding: "12px 16px" }}>
                          <div style={{ display: "flex", gap: 5 }}>
                            {p.url && <IconBtn icon={ExternalLink} size={12} onClick={() => window.open(p.url, "_blank")} title="Open website" />}
                            <IconBtn icon={Pencil} size={12} onClick={() => openModal("password-edit", p)} title="Edit" />
                            <IconBtn icon={Trash2} size={12} danger onClick={() => setConfirmDelete(p)} title="Delete" />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>

      {confirmDelete && (
        <ConfirmDialog
          title="Delete password"
          message={`Move the password for "${confirmDelete.title}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger
          onCancel={() => setConfirmDelete(null)}
          onConfirm={() => { deletePassword(confirmDelete.id); setConfirmDelete(null); }}
        />
      )}
    </div>
  );
}

function PasswordForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || {
    title: "", url: "", username: "", password: "", category: "Other", notes: "", tags: "",
  });
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const [showGen, setShowGen] = useState(false);
  const [visible, setVisible] = useState(false);

  return (
    <div>
      <Field label="Title"><Input value={form.title} onChange={set("title")} placeholder="e.g. Google" /></Field>
      <Field label="Website URL"><Input value={form.url} onChange={set("url")} placeholder="https://example.com" /></Field>
      <Field label="Username / Email"><Input value={form.username} onChange={set("username")} placeholder="you@example.com" /></Field>
      <Field label="Password">
        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ position: "relative", flex: 1 }}>
            <Input type={visible ? "text" : "password"} value={form.password} onChange={set("password")} placeholder="Enter or generate a password" style={{ paddingRight: 34 }} />
            <button onClick={() => setVisible((v) => !v)} type="button" style={{ position: "absolute", right: 8, top: 8, background: "none", border: "none", color: "var(--text-faint)", cursor: "pointer" }}>
              {visible ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
          <Button variant="subtle" icon={Sparkles} onClick={() => setShowGen((s) => !s)}>Generate</Button>
        </div>
        {form.password && <div style={{ marginTop: 8 }}><StrengthMeter password={form.password} /></div>}
      </Field>

      {showGen && (
        <Card style={{ marginBottom: 14, background: "var(--surface-2)" }}>
          <PasswordGenerator onUse={(pw) => { setForm((f) => ({ ...f, password: pw })); setShowGen(false); setVisible(true); }} />
        </Card>
      )}

      <Field label="Category">
        <Select value={form.category} onChange={set("category")}>
          {PASSWORD_CATEGORIES.map((c) => <option key={c}>{c}</option>)}
        </Select>
      </Field>
      <Field label="Tags (comma separated)"><Input value={form.tags} onChange={set("tags")} placeholder="work, primary" /></Field>
      <Field label="Notes"><TextArea value={form.notes} onChange={set("notes")} placeholder="Optional notes…" style={{ fontFamily: "Inter, sans-serif" }} /></Field>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave(form)} disabled={!form.title || !form.password}>Save password</Button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Secure Notes view                                                     */
/* ---------------------------------------------------------------------- */

function NotesView({ notes, openModal, deleteNote, togglePin, toggleArchive, locked, onImportNotes }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const [showArchived, setShowArchived] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const importInputRef = useRef(null);
  const [importing, setImporting] = useState(false);

  const filtered = useMemo(() => {
    let list = notes.filter((n) =>
      n.archived === showArchived &&
      (category === "All" || n.category === category) &&
      n.title.toLowerCase().includes(query.toLowerCase())
    );
    return [...list].sort((a, b) => (b.pinned - a.pinned) || b.updatedAt.localeCompare(a.updatedAt));
  }, [notes, query, category, showArchived]);

  const handleImportFiles = async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = ""; // allow re-selecting the same file(s) later
    if (!files.length) return;
    setImporting(true);
    // One note per file — never merged — even when multiple files are selected.
    const results = await Promise.all(files.map(async (file) => {
      if (file.size > MAX_IMPORT_TEXT_SIZE) {
        return { ok: false, name: file.name, error: "too large" };
      }
      try {
        const text = await readFileAsText(file);
        return {
          ok: true,
          note: {
            title: filenameToTitle(file.name),
            content: text,
            category: "Other",
            tags: [],
            attachments: [],
          },
        };
      } catch {
        return { ok: false, name: file.name, error: "couldn't be read as text" };
      }
    }));
    setImporting(false);
    const succeeded = results.filter((r) => r.ok).map((r) => r.note);
    const failed = results.filter((r) => !r.ok);
    onImportNotes(succeeded, failed);
  };

  return (
    <div>
      <TopBar title="Secure Notes" subtitle={`${notes.filter(n=>!n.archived).length} active notes`}
        right={<>
          <input ref={importInputRef} type="file" multiple accept=".txt,.md,.markdown,.text,text/plain,text/markdown" onChange={handleImportFiles} style={{ display: "none" }} />
          <Button variant="subtle" icon={Upload} onClick={() => importInputRef.current?.click()} disabled={importing}>
            {importing ? "Importing…" : "Import"}
          </Button>
          <Button icon={Plus} onClick={() => openModal("note-add")}>Add note</Button>
        </>} />
      <div style={{ padding: "0 28px 28px" }}>
        <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: "1 1 220px" }}>
            <Search size={14} style={{ position: "absolute", left: 11, top: 11, color: "var(--text-faint)" }} />
            <Input placeholder="Search notes…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ paddingLeft: 32 }} />
          </div>
          <Select value={category} onChange={(e) => setCategory(e.target.value)} style={{ width: 170 }}>
            <option>All</option>
            {NOTE_CATEGORIES.map((c) => <option key={c}>{c}</option>)}
          </Select>
          <Button variant={showArchived ? "primary" : "subtle"} icon={Archive} onClick={() => setShowArchived((s) => !s)}>
            {showArchived ? "Showing archived" : "Show archived"}
          </Button>
        </div>

        {locked ? (
          <Card><EmptyState icon={Lock} title="Vault locked" subtitle="Unlock your vault to view secure notes." /></Card>
        ) : filtered.length === 0 ? (
          <Card><EmptyState icon={FileText} title={showArchived ? "No archived notes" : "No notes found"} subtitle="Create a note to store sensitive information privately."
            action={!showArchived && <Button icon={Plus} onClick={() => openModal("note-add")}>Add note</Button>} /></Card>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px,1fr))", gap: 14 }}>
            {filtered.map((n) => (
              <Card key={n.id} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <button
                  onClick={() => openModal("note-view", n)}
                  className="sv-focus"
                  style={{ display: "flex", flexDirection: "column", gap: 10, textAlign: "left", background: "none", border: "none", padding: 0, cursor: "pointer", color: "inherit" }}
                  title="Click to view full note"
                >
                  <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
                    <div style={{ fontWeight: 600, fontSize: 13.5, lineHeight: 1.3 }}>{n.title}</div>
                    {n.pinned && <Pin size={13} color="var(--amber)" style={{ flexShrink: 0, marginTop: 2 }} />}
                  </div>
                  <div style={{ position: "relative" }}>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5, whiteSpace: "pre-line", maxHeight: 84, overflow: "hidden", fontFamily: "'JetBrains Mono', monospace" }}>
                      {n.content}
                    </div>
                    {n.content.length > 160 && (
                      <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 28, background: "linear-gradient(180deg, transparent, var(--surface))" }} />
                    )}
                  </div>
                  {n.content.length > 160 && (
                    <div style={{ fontSize: 11, color: "var(--primary)", fontWeight: 600, marginTop: -6 }}>Click to read full note →</div>
                  )}
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <Badge tone="mint">{n.category}</Badge>
                    {n.tags.map((t) => <Badge key={t}>#{t}</Badge>)}
                    {(n.attachments || []).length > 0 && (
                      <Badge><Paperclip size={10} /> {n.attachments.length}</Badge>
                    )}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-faint)" }} className="sv-mono">Updated {fmtDate(n.updatedAt)}</div>
                </button>
                <div style={{ display: "flex", gap: 6, marginTop: 2 }}>
                  <IconBtn icon={Pin} active={n.pinned} onClick={() => togglePin(n.id)} title={n.pinned ? "Unpin" : "Pin"} />
                  <IconBtn icon={Archive} onClick={() => toggleArchive(n.id)} title={n.archived ? "Unarchive" : "Archive"} />
                  <IconBtn icon={Pencil} onClick={() => openModal("note-edit", n)} title="Edit" />
                  <IconBtn icon={Trash2} danger onClick={() => setConfirmDelete(n)} title="Delete" />
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      {confirmDelete && (
        <ConfirmDialog
          title="Delete note" message={`Move "${confirmDelete.title}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger
          onCancel={() => setConfirmDelete(null)}
          onConfirm={() => { deleteNote(confirmDelete.id); setConfirmDelete(null); }}
        />
      )}
    </div>
  );
}

function NoteForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || { title: "", content: "", category: "Other", tags: "", attachments: [] });
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const fileInputRef = useRef(null);
  const [attachError, setAttachError] = useState("");
  const [attaching, setAttaching] = useState(false);

  const handleFiles = async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = "";
    if (!files.length) return;
    setAttachError("");
    setAttaching(true);
    const added = [];
    for (const file of files) {
      if (file.size > MAX_ATTACHMENT_SIZE) {
        setAttachError(`"${file.name}" is too large (max ${fmtFileSize(MAX_ATTACHMENT_SIZE)} per file).`);
        continue;
      }
      try {
        const dataUrl = await readFileAsDataURL(file);
        added.push({ id: uid(), name: file.name, type: file.type || "application/octet-stream", size: file.size, dataUrl, addedAt: new Date().toISOString() });
      } catch {
        setAttachError(`Couldn't read "${file.name}".`);
      }
    }
    if (added.length) setForm((f) => ({ ...f, attachments: [...(f.attachments || []), ...added] }));
    setAttaching(false);
  };

  const removeAttachment = (id) => setForm((f) => ({ ...f, attachments: (f.attachments || []).filter((a) => a.id !== id) }));

  return (
    <div>
      <Field label="Title"><Input value={form.title} onChange={set("title")} placeholder="Note title" /></Field>
      <Field label="Content"><TextArea value={form.content} onChange={set("content")} placeholder="Write your private note… (markdown-style supported)" style={{ minHeight: 140 }} /></Field>
      <Field label="Category">
        <Select value={form.category} onChange={set("category")}>{NOTE_CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select>
      </Field>
      <Field label="Tags (comma separated)"><Input value={form.tags} onChange={set("tags")} placeholder="home, 2fa" /></Field>

      <Field label="Attachments">
        <input ref={fileInputRef} type="file" multiple onChange={handleFiles} style={{ display: "none" }} />
        <Button variant="subtle" size="sm" icon={Paperclip} onClick={() => fileInputRef.current?.click()} disabled={attaching}>
          {attaching ? "Adding…" : "Attach files"}
        </Button>
        <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 6 }}>
          Stored encrypted inside your vault — keep files under {fmtFileSize(MAX_ATTACHMENT_SIZE)} each.
        </div>
        {attachError && <div style={{ color: "var(--coral)", fontSize: 12, marginTop: 6 }}>{attachError}</div>}
        {(form.attachments || []).length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 10 }}>
            {form.attachments.map((a) => (
              <div key={a.id} style={{
                display: "flex", alignItems: "center", gap: 8, background: "var(--surface-2)",
                border: "1px solid var(--border)", borderRadius: 8, padding: "7px 10px"
              }}>
                {a.type.startsWith("image/")
                  ? <img src={a.dataUrl} alt={a.name} style={{ width: 26, height: 26, borderRadius: 5, objectFit: "cover", flexShrink: 0 }} />
                  : <div style={{ width: 26, height: 26, borderRadius: 5, background: "var(--surface-3)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><FileIcon size={13} color="var(--text-faint)" /></div>}
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</div>
                  <div style={{ fontSize: 10.5, color: "var(--text-faint)" }}>{fmtFileSize(a.size)}</div>
                </div>
                <IconBtn icon={X} size={12} onClick={() => removeAttachment(a.id)} title="Remove" />
              </div>
            ))}
          </div>
        )}
      </Field>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave(form)} disabled={!form.title}>Save note</Button>
      </div>
    </div>
  );
}

/** Read-only full view of a note — for content too long to show on the card. */
function NoteViewModal({ note, onClose, onEdit, togglePin, toggleArchive, onDeleteRequest }) {
  const attachments = note.attachments || [];
  return (
    <Modal title={note.title} onClose={onClose} width={660}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
        <Badge tone="mint">{note.category}</Badge>
        {note.pinned && <Badge tone="amber">Pinned</Badge>}
        {note.archived && <Badge>Archived</Badge>}
        {note.tags.map((t) => <Badge key={t}>#{t}</Badge>)}
      </div>

      <div
        className="sv-scroll sv-mono"
        style={{
          fontSize: 13, lineHeight: 1.7, whiteSpace: "pre-wrap", wordBreak: "break-word",
          background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 10,
          padding: 16, maxHeight: "50vh", overflowY: "auto", marginBottom: 14
        }}
      >
        {note.content || <span style={{ color: "var(--text-faint)" }}>(This note has no content.)</span>}
      </div>

      {attachments.length > 0 && (
        <div style={{ marginBottom: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
            <Paperclip size={12} /> {attachments.length} attachment{attachments.length === 1 ? "" : "s"}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {attachments.map((a) => {
              const isImage = a.type.startsWith("image/");
              const isVideo = a.type.startsWith("video/");
              if (isImage || isVideo) {
                return (
                  <div key={a.id} style={{
                    background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden"
                  }}>
                    {isImage ? (
                      <img src={a.dataUrl} alt={a.name} style={{ width: "100%", maxHeight: 380, objectFit: "contain", display: "block", background: "#000" }} />
                    ) : (
                      <video src={a.dataUrl} controls style={{ width: "100%", maxHeight: 380, display: "block", background: "#000" }} />
                    )}
                    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px" }}>
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</div>
                        <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{fmtFileSize(a.size)}</div>
                      </div>
                      <IconBtn icon={Download} onClick={() => downloadDataUrl(a.name, a.dataUrl)} title="Download" />
                    </div>
                  </div>
                );
              }
              return (
                <div key={a.id} style={{
                  display: "flex", alignItems: "center", gap: 10, background: "var(--surface-2)",
                  border: "1px solid var(--border)", borderRadius: 9, padding: "8px 10px"
                }}>
                  <div style={{ width: 34, height: 34, borderRadius: 6, background: "var(--surface-3)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><FileIcon size={16} color="var(--text-faint)" /></div>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</div>
                    <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{fmtFileSize(a.size)}</div>
                  </div>
                  <IconBtn icon={Download} onClick={() => downloadDataUrl(a.name, a.dataUrl)} title="Download" />
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-faint)", marginBottom: 18 }} className="sv-mono">
        <span>Created {fmtDate(note.createdAt)}</span>
        <span>Updated {fmtDate(note.updatedAt)}</span>
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <div style={{ display: "flex", gap: 6 }}>
          <Button size="sm" variant="subtle" icon={Pin} onClick={() => togglePin(note.id)}>{note.pinned ? "Unpin" : "Pin"}</Button>
          <Button size="sm" variant="subtle" icon={Archive} onClick={() => toggleArchive(note.id)}>{note.archived ? "Unarchive" : "Archive"}</Button>
          <Button size="sm" variant="danger" icon={Trash2} onClick={() => onDeleteRequest(note)}>Delete</Button>
        </div>
        <Button size="sm" icon={Pencil} onClick={() => onEdit(note)}>Edit note</Button>
      </div>
    </Modal>
  );
}

/* ---------------------------------------------------------------------- */
/* Finance view                                                          */
/* ---------------------------------------------------------------------- */

const CATEGORY_COLORS = ["#4C7CF3", "#34D399", "#F5A623", "#F0596B", "#A78BFA", "#38BDF8", "#FB923C", "#F472B6", "#94A3B8"];

function FinanceView({ transactions, goals, generalSavings, savingsAdjustment, onAdjustSavings, openModal, deleteTransaction, hideValues }) {
  const [range, setRange] = useState("monthly");
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("All");
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [showAdjust, setShowAdjust] = useState(false);

  const totalIncome = transactions.filter((t) => t.type === "income").reduce((s, t) => s + t.amount, 0);
  const totalExpense = transactions.filter((t) => t.type === "expense").reduce((s, t) => s + t.amount, 0);
  const totalSaved = (goals || []).reduce((s, g) => s + g.currentAmount, 0) + (generalSavings?.balance || 0);
  // Raw total pulled from actual contribution records, before any manual
  // correction. The correction exists because this figure is an aggregate
  // across many individual deposits, not something you can just retype.
  const rawExternalSavings = sumExternalSavingsDeposits(goals, generalSavings);
  const externalSavings = rawExternalSavings + (savingsAdjustment || 0);
  // Available balance is purely transaction-based. If a savings deposit came
  // from your available balance, it's already reflected here as a real
  // "Savings" expense transaction — no separate adjustment needed.
  const availableBalance = totalIncome - totalExpense;
  // Total income includes only *new* money that went straight to savings —
  // balance-sourced transfers are excluded since they're just a transaction
  // already counted, not fresh income.
  const combinedIncome = totalIncome + externalSavings;
  const savingsRate = combinedIncome > 0 ? Math.round((totalSaved / combinedIncome) * 100) : 0;

  const trendData = useMemo(() => {
    const buckets = {};
    transactions.forEach((t) => {
      const d = new Date(t.date + "T00:00:00");
      const key = range === "yearly" ? String(d.getFullYear()) : range === "weekly" ? `Wk of ${fmtDate(t.date)}` : d.toLocaleDateString(undefined, { month: "short" });
      buckets[key] = buckets[key] || { name: key, income: 0, expense: 0 };
      buckets[key][t.type] += t.amount;
    });
    return Object.values(buckets).slice(-8);
  }, [transactions, range]);

  const byCategory = useMemo(() => {
    const map = {};
    transactions.filter((t) => t.type === "expense").forEach((t) => { map[t.category] = (map[t.category] || 0) + t.amount; });
    return Object.entries(map).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  }, [transactions]);

  const filteredTx = useMemo(() => {
    return [...transactions]
      .filter((t) => (typeFilter === "All" || t.type === typeFilter) && (t.party.toLowerCase().includes(query.toLowerCase()) || t.category.toLowerCase().includes(query.toLowerCase())))
      .sort((a, b) => b.date.localeCompare(a.date));
  }, [transactions, query, typeFilter]);

  const mask = (s) => hideValues ? "••••" : s;

  return (
    <div>
      <TopBar title="Finance" subtitle="Income, expenses, and balance at a glance"
        right={<>
          <Button variant="subtle" icon={ArrowUpRight} onClick={() => openModal("transaction-add", { type: "income" })}>Add income</Button>
          <Button icon={ArrowDownRight} onClick={() => openModal("transaction-add", { type: "expense" })}>Add expense</Button>
        </>} />
      <div style={{ padding: "0 28px 28px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))", gap: 14, marginBottom: 18 }}>
          <StatCard icon={ArrowUpRight} label="Total income" value={mask(fmtMoney(combinedIncome))} tone="mint"
            sub={externalSavings > 0 ? `Includes ${fmtMoney(externalSavings)} in new savings` : undefined}
            onEdit={externalSavings > 0 ? () => setShowAdjust(true) : undefined} />
          <StatCard icon={ArrowDownRight} label="Total expenses" value={mask(fmtMoney(totalExpense))} tone="coral" />
          <StatCard icon={Wallet} label="Available balance" value={mask(fmtMoney(availableBalance))} tone="primary" sub="Reflects any transfers into savings" />
          <StatCard icon={Target} label="Total savings" value={mask(fmtMoney(totalSaved))} tone="mint" sub={`Goals + General · ${savingsRate}% of income`} />
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginBottom: 12 }}>
          {["weekly", "monthly", "yearly"].map((r) => (
            <Button key={r} size="sm" variant={range === r ? "primary" : "subtle"} onClick={() => setRange(r)}>{r[0].toUpperCase() + r.slice(1)}</Button>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 16, marginBottom: 18 }}>
          <Card>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14, marginBottom: 14 }}>Income vs expenses</div>
            {trendData.length < 2 ? (
              <div style={{ height: 220, display: "flex", flexDirection: "column", justifyContent: "center", gap: 16 }}>
                <div style={{ fontSize: 12, color: "var(--text-faint)" }}>
                  Not enough history yet to draw a trend line — here's the {range === "yearly" ? "year's" : range === "weekly" ? "week's" : "month's"} totals so far:
                </div>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 7 }}>
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}><ArrowUpRight size={14} color="var(--mint)" /> Income</span>
                    <span className="sv-mono" style={{ fontWeight: 700, color: "var(--mint)" }}>{fmtMoney(trendData[0]?.income || 0)}</span>
                  </div>
                  <ProgressBar pct={100} tone="mint" />
                </div>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 7 }}>
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}><ArrowDownRight size={14} color="var(--coral)" /> Expenses</span>
                    <span className="sv-mono" style={{ fontWeight: 700, color: "var(--coral)" }}>{fmtMoney(trendData[0]?.expense || 0)}</span>
                  </div>
                  <ProgressBar pct={trendData[0]?.income ? (trendData[0].expense / trendData[0].income) * 100 : trendData[0]?.expense ? 100 : 0} tone="coral" />
                </div>
                <div style={{ fontSize: 11, color: "var(--text-faint)" }}>
                  Keep adding transactions over time and this becomes a line chart automatically.
                </div>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={trendData} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="inc" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#34D399" stopOpacity={0.35} /><stop offset="100%" stopColor="#34D399" stopOpacity={0} /></linearGradient>
                    <linearGradient id="exp" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#F0596B" stopOpacity={0.35} /><stop offset="100%" stopColor="#F0596B" stopOpacity={0} /></linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: "var(--text-faint)" }} axisLine={{ stroke: "var(--border)" }} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--text-faint)" }} axisLine={false} tickLine={false} width={46} tickFormatter={fmtCompactMoney} />
                  <Tooltip
                    contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: "var(--text)", fontWeight: 600, marginBottom: 4 }}
                    formatter={(value, name) => [fmtMoney(value), name]}
                  />
                  <Area type="monotone" dataKey="income" stroke="#34D399" fill="url(#inc)" strokeWidth={2.5} name="Income" dot={{ r: 3.5, strokeWidth: 0, fill: "#34D399" }} activeDot={{ r: 6 }} />
                  <Area type="monotone" dataKey="expense" stroke="#F0596B" fill="url(#exp)" strokeWidth={2.5} name="Expense" dot={{ r: 3.5, strokeWidth: 0, fill: "#F0596B" }} activeDot={{ r: 6 }} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </Card>
          <Card>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14, marginBottom: 14 }}>Expenses by category</div>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={byCategory} dataKey="value" nameKey="name" innerRadius={48} outerRadius={78} paddingAngle={2}>
                  {byCategory.map((_, i) => <Cell key={i} fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }} formatter={(v) => fmtMoney(v)} />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </div>

        <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: "1 1 220px" }}>
            <Search size={14} style={{ position: "absolute", left: 11, top: 11, color: "var(--text-faint)" }} />
            <Input placeholder="Search transactions…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ paddingLeft: 32 }} />
          </div>
          <Select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} style={{ width: 150 }}>
            <option>All</option><option value="income">Income</option><option value="expense">Expense</option>
          </Select>
        </div>

        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div className="sv-scroll" style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 680 }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  {["Party", "Category", "Date", "Method", "Amount", ""].map((h) => (
                    <th key={h} style={{ textAlign: "left", padding: "12px 16px", fontSize: 11, color: "var(--text-faint)", fontWeight: 700, textTransform: "uppercase" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredTx.map((t) => (
                  <tr key={t.id} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 600 }}>
                      <button onClick={() => openModal("transaction-view", t)} className="sv-focus" style={{
                        display: "flex", alignItems: "center", gap: 8, background: "none", border: "none",
                        padding: 0, cursor: "pointer", color: "inherit", textAlign: "left"
                      }}>
                        {t.type === "income" ? <ArrowUpRight size={13} color="var(--mint)" /> : <ArrowDownRight size={13} color="var(--coral)" />}
                        <span style={{ color: "var(--text)" }}>{t.party}</span>{t.recurring && <Badge>recurring</Badge>}
                      </button>
                    </td>
                    <td style={{ padding: "12px 16px" }}><Badge>{t.category}</Badge></td>
                    <td style={{ padding: "12px 16px", fontSize: 12 }} className="sv-mono">{fmtDate(t.date)}</td>
                    <td style={{ padding: "12px 16px", fontSize: 12, color: "var(--text-muted)" }}>{t.method || "—"}</td>
                    <td style={{ padding: "12px 16px", fontSize: 13 }} className="sv-mono">
                      <span style={{ color: t.type === "income" ? "var(--mint)" : "var(--coral)", fontWeight: 700 }}>
                        {mask((t.type === "income" ? "+" : "-") + fmtMoney(t.amount).replace("-", ""))}
                      </span>
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <div style={{ display: "flex", gap: 5 }}>
                        <IconBtn icon={Pencil} size={12} onClick={() => openModal("transaction-edit", t)} title="Edit" />
                        <IconBtn icon={Trash2} size={12} danger onClick={() => setConfirmDelete(t)} title="Delete" />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {confirmDelete && (
        <ConfirmDialog title="Delete transaction" message={`Move the transaction "${confirmDelete.party}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger onCancel={() => setConfirmDelete(null)}
          onConfirm={() => { deleteTransaction(confirmDelete.id); setConfirmDelete(null); }} />
      )}
      {showAdjust && (
        <AdjustSavingsModal
          currentTotal={externalSavings}
          onCancel={() => setShowAdjust(false)}
          onSave={(newTotal) => { onAdjustSavings(newTotal - rawExternalSavings); setShowAdjust(false); }}
        />
      )}
    </div>
  );
}

function AdjustSavingsModal({ currentTotal, onCancel, onSave }) {
  const [value, setValue] = useState(String(currentTotal.toFixed(2)));
  const num = Number(value);
  const valid = value !== "" && !isNaN(num) && num >= 0;

  return (
    <Modal title="Modify new-money savings total" onClose={onCancel} width={420}>
      <div style={{ fontSize: 12.5, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 16 }}>
        This figure is normally totaled up automatically from every "new money" deposit across your goals and
        General Savings. If it's grown inaccurate — from testing, or a deposit that shouldn't have counted — set the
        correct total here. This only changes how it's displayed; your individual goal and savings balances aren't touched.
      </div>
      <Field label="Correct total">
        <Input type="number" value={value} onChange={(e) => setValue(e.target.value)} placeholder="0.00" autoFocus />
      </Field>
      {!valid && value !== "" && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 10 }}>Enter a valid amount, 0 or more.</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave(num)} disabled={!valid}>Save</Button>
      </div>
    </Modal>
  );
}

function TransactionForm({ initial, defaultType = "expense", onSave, onCancel }) {
  const [form, setForm] = useState(initial || {
    type: defaultType, amount: "", party: "", category: defaultType === "income" ? "Salary" : "Food",
    date: new Date().toISOString().slice(0, 10), description: "", recurring: false, method: "Card",
  });
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const cats = form.type === "income" ? INCOME_CATEGORIES : EXPENSE_CATEGORIES;

  return (
    <div>
      <Field label="Type">
        <div style={{ display: "flex", gap: 8 }}>
          {["income", "expense"].map((t) => (
            <button key={t} type="button" onClick={() => setForm((f) => ({ ...f, type: t, category: t === "income" ? INCOME_CATEGORIES[0] : EXPENSE_CATEGORIES[0] }))}
              style={{
                flex: 1, padding: "9px", borderRadius: 9, cursor: "pointer", fontWeight: 600, fontSize: 13,
                border: `1px solid ${form.type === t ? "var(--primary)" : "var(--border)"}`,
                background: form.type === t ? "var(--primary-soft)" : "var(--surface-2)",
                color: form.type === t ? "var(--primary)" : "var(--text-muted)"
              }}>
              {t === "income" ? "Income" : "Expense"}
            </button>
          ))}
        </div>
      </Field>
      <Field label="Amount"><Input type="number" value={form.amount} onChange={set("amount")} placeholder="0.00" /></Field>
      <Field label={form.type === "income" ? "Source" : "Merchant"}><Input value={form.party} onChange={set("party")} placeholder={form.type === "income" ? "e.g. Employer" : "e.g. Store name"} /></Field>
      <Field label="Category"><Select value={form.category} onChange={set("category")}>{cats.map((c) => <option key={c}>{c}</option>)}</Select></Field>
      <Field label="Date"><Input type="date" value={form.date} onChange={set("date")} /></Field>
      <Field label={form.type === "income" ? "Deposit method" : "Payment method"}>
        <Select value={form.method} onChange={set("method")}>
          {["Card", "Cash", "Bank Transfer", "E-wallet"].map((m) => <option key={m}>{m}</option>)}
        </Select>
      </Field>
      <Field label="Description"><Input value={form.description} onChange={set("description")} placeholder="Optional" /></Field>
      <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, marginBottom: 16, cursor: "pointer" }}>
        <input type="checkbox" checked={form.recurring} onChange={(e) => setForm((f) => ({ ...f, recurring: e.target.checked }))} style={{ accentColor: "var(--primary)" }} />
        This is a recurring {form.type}
      </label>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave({ ...form, amount: Number(form.amount) || 0 })} disabled={!form.party || !form.amount}>Save transaction</Button>
      </div>
    </div>
  );
}

/** Read-only full view of a transaction — surfaces the description, which
    the table row never had room to show. */
function TransactionViewModal({ transaction, onClose, onEdit, onDeleteRequest }) {
  const t = transaction;
  const isIncome = t.type === "income";
  return (
    <Modal title="" onClose={onClose} width={440}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, marginBottom: 18 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 34, height: 34, borderRadius: 9, flexShrink: 0,
              background: isIncome ? "var(--mint-soft)" : "var(--coral-soft)",
              display: "flex", alignItems: "center", justifyContent: "center"
            }}>
              {isIncome ? <ArrowUpRight size={16} color="var(--mint)" /> : <ArrowDownRight size={16} color="var(--coral)" />}
            </div>
            <div>
              <div className="sv-display" style={{ fontWeight: 700, fontSize: 16 }}>{t.party}</div>
              <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{isIncome ? "Income" : "Expense"} · {fmtDate(t.date)}</div>
            </div>
          </div>
        </div>
        <div className="sv-mono" style={{ fontSize: 22, fontWeight: 700, color: isIncome ? "var(--mint)" : "var(--coral)", whiteSpace: "nowrap" }}>
          {(isIncome ? "+" : "-") + fmtMoney(t.amount).replace("-", "")}
        </div>
      </div>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 16 }}>
        <Badge>{t.category}</Badge>
        {t.method && <Badge>{t.method}</Badge>}
        {t.recurring && <Badge tone="amber">Recurring</Badge>}
      </div>

      <div style={{ marginBottom: 6, fontSize: 11, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.4 }}>Description</div>
      <div
        className="sv-scroll"
        style={{
          fontSize: 13, lineHeight: 1.7, color: t.description ? "var(--text)" : "var(--text-faint)",
          whiteSpace: "pre-wrap", wordBreak: "break-word",
          background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 10,
          padding: 14, maxHeight: "40vh", overflowY: "auto", marginBottom: 20
        }}
      >
        {t.description || "No description added for this transaction."}
      </div>

      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <Button size="sm" variant="danger" icon={Trash2} onClick={() => onDeleteRequest(t)}>Delete</Button>
        <Button size="sm" icon={Pencil} onClick={() => onEdit(t)}>Edit transaction</Button>
      </div>
    </Modal>
  );
}

/* ---------------------------------------------------------------------- */
/* Budgets view                                                          */
/* ---------------------------------------------------------------------- */

function BudgetsView({ budgets, transactions, openModal, deleteBudget }) {
  const [confirmDelete, setConfirmDelete] = useState(null);
  const spentByCategory = useMemo(() => {
    const map = {};
    const thisMonth = new Date().getMonth();
    transactions.filter((t) => t.type === "expense" && new Date(t.date + "T00:00:00").getMonth() === thisMonth)
      .forEach((t) => { map[t.category] = (map[t.category] || 0) + t.amount; });
    return map;
  }, [transactions]);

  return (
    <div>
      <TopBar title="Budgets" subtitle="Monthly spending limits by category"
        right={<Button icon={Plus} onClick={() => openModal("budget-add")}>Add budget</Button>} />
      <div style={{ padding: "0 28px 28px" }}>
        {budgets.length === 0 ? (
          <Card><EmptyState icon={PiggyBank} title="No budgets yet" subtitle="Set spending limits to keep your categories in check."
            action={<Button icon={Plus} onClick={() => openModal("budget-add")}>Add budget</Button>} /></Card>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 14 }}>
            {budgets.map((b) => {
              const spent = spentByCategory[b.category] || 0;
              const pct = Math.round((spent / b.amount) * 100);
              const tone = pct >= 100 ? "coral" : pct >= 80 ? "amber" : "mint";
              return (
                <Card key={b.id}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 14 }}>{b.category}</div>
                      <div style={{ fontSize: 11, color: "var(--text-faint)", textTransform: "capitalize" }}>{b.period}</div>
                    </div>
                    <div style={{ display: "flex", gap: 5 }}>
                      <IconBtn icon={Pencil} size={12} onClick={() => openModal("budget-edit", b)} title="Edit" />
                      <IconBtn icon={Trash2} size={12} danger onClick={() => setConfirmDelete(b)} title="Delete" />
                    </div>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12.5, marginBottom: 6 }} className="sv-mono">
                    <span style={{ color: "var(--text)" }}>{fmtMoney(spent)} spent</span>
                    <span style={{ color: "var(--text-faint)" }}>of {fmtMoney(b.amount)}</span>
                  </div>
                  <ProgressBar pct={pct} tone={tone} />
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8 }}>
                    <span className="sv-mono" style={{ fontSize: 11.5, color: `var(--${tone === "coral" ? "coral" : tone === "amber" ? "amber" : "mint"})` }}>{pct}% used</span>
                    {pct >= 100 ? (
                      <span style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--coral)" }}><AlertTriangle size={11} /> Over budget</span>
                    ) : pct >= 80 ? (
                      <span style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--amber)" }}><AlertTriangle size={11} /> Approaching limit</span>
                    ) : (
                      <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{fmtMoney(b.amount - spent)} remaining</span>
                    )}
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </div>
      {confirmDelete && (
        <ConfirmDialog title="Delete budget" message={`Move the budget for "${confirmDelete.category}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`} confirmLabel="Move to Trash" danger
          onCancel={() => setConfirmDelete(null)} onConfirm={() => { deleteBudget(confirmDelete.id); setConfirmDelete(null); }} />
      )}
    </div>
  );
}

function BudgetForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || { category: "Food", amount: "", period: "monthly" });
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <div>
      <Field label="Category"><Select value={form.category} onChange={set("category")}>{EXPENSE_CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select></Field>
      <Field label="Budget amount"><Input type="number" value={form.amount} onChange={set("amount")} placeholder="0.00" /></Field>
      <Field label="Period"><Select value={form.period} onChange={set("period")}><option value="weekly">Weekly</option><option value="monthly">Monthly</option><option value="yearly">Yearly</option></Select></Field>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave({ ...form, amount: Number(form.amount) || 0 })} disabled={!form.amount}>Save budget</Button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Savings Goals                                                          */
/* ---------------------------------------------------------------------- */

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const target = new Date(dateStr + "T00:00:00");
  const now = new Date(); now.setHours(0, 0, 0, 0);
  return Math.round((target - now) / 86400000);
}

function suggestedMonthlyContribution(goal) {
  const remaining = goal.targetAmount - goal.currentAmount;
  if (remaining <= 0 || !goal.targetDate) return null;
  const days = daysUntil(goal.targetDate);
  if (days == null || days <= 0) return null;
  const months = Math.max(1, days / 30.4);
  return remaining / months;
}

/**
 * Sums only the "external" (new money, not from Available Balance) savings
 * deposits across goals and General Savings — used for the Total Income
 * figure. Balance-sourced deposits are deliberately excluded here since
 * those already show up as real Expense transactions (category "Savings"),
 * so counting them again here would double them.
 */
function sumExternalSavingsDeposits(goals, generalSavings) {
  const fromGoals = (goals || []).reduce((sum, g) => {
    return sum + (g.contributions || []).reduce((s, c) => {
      if (c.source === "balance" || c.source === "withdraw" || c.source === "general") return s;
      return s + c.amount;
    }, 0);
  }, 0);
  const fromGeneral = (generalSavings?.history || []).reduce((s, h) => {
    if (h.type !== "deposit" || h.source === "balance") return s;
    return s + h.amount;
  }, 0);
  return fromGoals + fromGeneral;
}

/* ---------------------------------------------------------------------- */
/* Calculator                                                             */
/* ---------------------------------------------------------------------- */

/** Rounds away floating-point artifacts (0.1 + 0.2 = 0.30000000000000004). */
function roundClean(n) {
  if (!isFinite(n)) return n;
  return Math.round((n + Number.EPSILON) * 1e10) / 1e10;
}

function Calculator({ onUseValue }) {
  const [display, setDisplay] = useState("0");
  const [storedValue, setStoredValue] = useState(null);
  const [pendingOp, setPendingOp] = useState(null);
  const [waitingForOperand, setWaitingForOperand] = useState(false);
  const [expression, setExpression] = useState("");

  const compute = (a, b, op) => {
    switch (op) {
      case "+": return roundClean(a + b);
      case "−": return roundClean(a - b);
      case "×": return roundClean(a * b);
      case "÷": return b === 0 ? NaN : roundClean(a / b);
      default: return b;
    }
  };

  const inputDigit = (d) => {
    if (waitingForOperand) { setDisplay(d); setWaitingForOperand(false); }
    else setDisplay(display === "0" ? d : display.length < 15 ? display + d : display);
  };
  const inputDecimal = () => {
    if (waitingForOperand) { setDisplay("0."); setWaitingForOperand(false); return; }
    if (!display.includes(".")) setDisplay(display + ".");
  };
  const clearAll = () => { setDisplay("0"); setStoredValue(null); setPendingOp(null); setWaitingForOperand(false); setExpression(""); };
  const backspace = () => {
    if (waitingForOperand) return;
    setDisplay(display.length > 1 ? display.slice(0, -1) : "0");
  };
  const toggleSign = () => setDisplay(display === "0" ? display : display.startsWith("-") ? display.slice(1) : "-" + display);
  const inputPercent = () => setDisplay(String(roundClean(parseFloat(display) / 100)));

  const performOp = (nextOp) => {
    const inputValue = parseFloat(display);
    if (isNaN(inputValue)) return;
    if (storedValue == null) {
      setStoredValue(inputValue);
      setExpression(`${display} ${nextOp === "=" ? "" : nextOp}`.trim());
    } else if (pendingOp && !waitingForOperand) {
      const result = compute(storedValue, inputValue, pendingOp);
      setStoredValue(result);
      setDisplay(isNaN(result) ? "Error" : String(result));
      setExpression(nextOp === "=" ? "" : `${result} ${nextOp}`);
    } else if (pendingOp) {
      // Operator pressed again without a new operand — just switch the operator.
      setExpression(`${storedValue} ${nextOp === "=" ? "" : nextOp}`.trim());
    }
    setWaitingForOperand(true);
    setPendingOp(nextOp === "=" ? null : nextOp);
  };

  const handleKey = (key) => {
    if (/^[0-9]$/.test(key)) inputDigit(key);
    else if (key === ".") inputDecimal();
    else if (key === "C") clearAll();
    else if (key === "back") backspace();
    else if (key === "±") toggleSign();
    else if (key === "%") inputPercent();
    else performOp(key);
  };

  const numericValue = parseFloat(display);
  const canUse = onUseValue && !isNaN(numericValue) && display !== "Error";

  const BTN = [
    ["C", "back", "%", "÷"],
    ["7", "8", "9", "×"],
    ["4", "5", "6", "−"],
    ["1", "2", "3", "+"],
    ["±", "0", ".", "="],
  ];

  const btnStyle = (key) => {
    const isOp = ["÷", "×", "−", "+", "="].includes(key);
    const isFunc = ["C", "back", "%", "±"].includes(key);
    return {
      height: 46, borderRadius: 10, border: "1px solid var(--border)", cursor: "pointer",
      fontSize: key === "=" ? 16 : 15, fontWeight: 600,
      background: key === "=" ? "var(--primary)" : isOp ? "var(--primary-soft)" : isFunc ? "var(--surface-3)" : "var(--surface-2)",
      color: key === "=" ? "#fff" : isOp ? "var(--primary)" : "var(--text)",
      display: "flex", alignItems: "center", justifyContent: "center",
    };
  };

  return (
    <div style={{ width: 260 }}>
      <div style={{
        background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 12,
        padding: "14px 14px 10px", marginBottom: 12, textAlign: "right"
      }}>
        <div className="sv-mono" style={{ fontSize: 11, color: "var(--text-faint)", minHeight: 14, marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {expression || "\u00A0"}
        </div>
        <div className="sv-mono" style={{
          fontSize: display.length > 9 ? 22 : 30, fontWeight: 700, color: display === "Error" ? "var(--coral)" : "var(--text)",
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums"
        }}>
          {display}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
        {BTN.flat().map((key, i) => (
          <button key={i} onClick={() => handleKey(key)} className="sv-focus" style={btnStyle(key)}>
            {key === "back" ? <BackspaceIcon size={16} /> : key}
          </button>
        ))}
      </div>

      {onUseValue && (
        <div style={{ marginTop: 12, display: "flex", justifyContent: "center" }}>
          <Button onClick={() => onUseValue(numericValue)} disabled={!canUse} icon={CheckCircle2} size="sm">
            Use this value
          </Button>
        </div>
      )}
    </div>
  );
}

function CalculatorModal({ onClose, onUseValue }) {
  return createPortal(
    <Modal title="Calculator" onClose={onClose} width={300}>
      <Calculator onUseValue={onUseValue ? (v) => { onUseValue(v); onClose(); } : undefined} />
    </Modal>,
    document.querySelector(".sv-root") || document.body
  );
}

function GeneralSavingsCard({ generalSavings, openModal }) {
  const balance = generalSavings?.balance || 0;
  return (
    <Card style={{ marginBottom: 16, background: "linear-gradient(135deg, var(--primary-soft), var(--surface))" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 14 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: "var(--primary-soft)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <PiggyBank size={17} color="var(--primary)" />
            </div>
            <div>
              <div className="sv-display" style={{ fontWeight: 700, fontSize: 15 }}>General Savings</div>
              <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>For whenever you don't have a specific goal yet</div>
            </div>
          </div>
          <div className="sv-mono" style={{ fontSize: 28, fontWeight: 700, marginTop: 14 }}>{fmtMoney(balance)}</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignSelf: "center" }}>
          <Button size="sm" variant="subtle" icon={ArrowUpRight} onClick={() => openModal("savings-withdraw", { type: "general", balance })} disabled={balance <= 0}>Withdraw</Button>
          <Button size="sm" icon={Plus} onClick={() => openModal("savings-deposit", { type: "general", balance })}>Add funds</Button>
        </div>
      </div>
    </Card>
  );
}

function GoalsView({ goals, generalSavings, openModal, deleteGoal }) {
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [showCalc, setShowCalc] = useState(false);

  return (
    <div>
      <TopBar title="Savings Goals" subtitle={`${goals.length} goal${goals.length === 1 ? "" : "s"} — separate money that never reduces your available balance`}
        right={<>
          <Button variant="subtle" icon={CalculatorIcon} onClick={() => setShowCalc(true)}>Calculator</Button>
          <Button icon={Plus} onClick={() => openModal("goal-add")}>Add goal</Button>
        </>} />
      <div style={{ padding: "0 28px 28px" }}>
        <GeneralSavingsCard generalSavings={generalSavings} openModal={openModal} />

        {goals.length === 0 ? (
          <Card><EmptyState icon={Target} title="No savings goals yet" subtitle="Set a target — a new gadget, a trip, an emergency fund — and track your progress toward it. Or just use General Savings above if you don't have a specific goal in mind."
            action={<Button icon={Plus} onClick={() => openModal("goal-add")}>Add goal</Button>} /></Card>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px,1fr))", gap: 14 }}>
            {goals.map((g) => {
              const pct = g.targetAmount > 0 ? Math.round((g.currentAmount / g.targetAmount) * 100) : 0;
              const reached = g.currentAmount >= g.targetAmount;
              const days = daysUntil(g.targetDate);
              const suggested = suggestedMonthlyContribution(g);
              const tone = reached ? "mint" : pct >= 60 ? "primary" : "amber";
              return (
                <Card key={g.id}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 14.5, display: "flex", alignItems: "center", gap: 6 }}>
                        {g.title}
                        {reached && <PartyPopper size={14} color="var(--mint)" />}
                      </div>
                      <div style={{ marginTop: 4 }}><Badge>{g.category}</Badge></div>
                    </div>
                    <div style={{ display: "flex", gap: 5 }}>
                      <IconBtn icon={Pencil} size={12} onClick={() => openModal("goal-edit", g)} title="Edit" />
                      <IconBtn icon={Trash2} size={12} danger onClick={() => setConfirmDelete(g)} title="Delete" />
                    </div>
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12.5, marginBottom: 6 }} className="sv-mono">
                    <span style={{ color: "var(--text)" }}>{fmtMoney(g.currentAmount)} saved</span>
                    <span style={{ color: "var(--text-faint)" }}>of {fmtMoney(g.targetAmount)}</span>
                  </div>
                  <ProgressBar pct={pct} tone={tone} />
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8, marginBottom: 12 }}>
                    <span className="sv-mono" style={{ fontSize: 11.5, color: reached ? "var(--mint)" : "var(--text-faint)" }}>{pct}% funded</span>
                    {g.targetDate && (
                      <span style={{ fontSize: 11, color: "var(--text-faint)" }}>
                        {reached ? `Target: ${fmtDate(g.targetDate)}` : days < 0 ? `${Math.abs(days)}d past target` : `${days}d left`}
                      </span>
                    )}
                  </div>

                  {reached && <Badge tone="mint">Goal reached! 🎉</Badge>}
                  {!reached && suggested && (
                    <div style={{ fontSize: 11, color: "var(--text-faint)", marginBottom: 10 }}>
                      Save ~{fmtMoney(suggested)}/month to hit your target date.
                    </div>
                  )}
                  <div style={{ display: "flex", gap: 8, marginTop: reached ? 10 : 0 }}>
                    <Button size="sm" variant="subtle" icon={ArrowUpRight} onClick={() => openModal("savings-withdraw", { type: "goal", goal: g, balance: g.currentAmount })} disabled={g.currentAmount <= 0}>Withdraw</Button>
                    <Button size="sm" icon={Plus} onClick={() => openModal("savings-deposit", { type: "goal", goal: g })}>Add funds</Button>
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </div>
      {confirmDelete && (
        <ConfirmDialog title="Delete goal" message={`Move "${confirmDelete.title}" to Trash, including its contribution history? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger onCancel={() => setConfirmDelete(null)}
          onConfirm={() => { deleteGoal(confirmDelete.id); setConfirmDelete(null); }} />
      )}
      {showCalc && <CalculatorModal onClose={() => setShowCalc(false)} />}
    </div>
  );
}

function GoalForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || { title: "", category: "Gadget", targetAmount: "", currentAmount: "0", targetDate: "", notes: "" });
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <div>
      <Field label="What are you saving for?"><Input value={form.title} onChange={set("title")} placeholder="e.g. New Laptop" /></Field>
      <Field label="Category"><Select value={form.category} onChange={set("category")}>{GOAL_CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select></Field>
      <Field label="Target amount"><Input type="number" value={form.targetAmount} onChange={set("targetAmount")} placeholder="0.00" /></Field>
      <Field label="Already saved (optional)"><Input type="number" value={form.currentAmount} onChange={set("currentAmount")} placeholder="0.00" /></Field>
      <Field label="Target date (optional)"><Input type="date" value={form.targetDate} onChange={set("targetDate")} /></Field>
      <Field label="Notes"><TextArea value={form.notes} onChange={set("notes")} placeholder="Optional notes…" style={{ fontFamily: "Inter, sans-serif", minHeight: 70 }} /></Field>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave({ ...form, targetAmount: Number(form.targetAmount) || 0, currentAmount: Number(form.currentAmount) || 0 })} disabled={!form.title || !form.targetAmount}>Save goal</Button>
      </div>
    </div>
  );
}

/**
 * Deposit money into a goal or General Savings. The key choice is *source*:
 *   - "external": money from outside the tracked system (a gift, cash,
 *     untracked side income) — doesn't touch Available Balance, but does
 *     count toward Total Income since it genuinely arrived.
 *   - "balance": money you already have in Available Balance, being moved
 *     into savings — this creates a real linked Expense transaction
 *     (category "Savings") so Available Balance correctly goes down and
 *     Finance shows exactly where the money went. Never double-counted
 *     as extra income, since it was already counted when it was earned.
 */
function SavingsDepositForm({ target, generalSavings, onSave, onCancel }) {
  const [amount, setAmount] = useState("");
  const [date, setDate] = useState(new Date().toISOString().slice(0, 10));
  const [note, setNote] = useState("");
  const [source, setSource] = useState("external");
  const [showCalc, setShowCalc] = useState(false);
  const amountNum = Number(amount) || 0;

  const label = target.type === "goal" ? target.goal.title : "General Savings";
  const remaining = target.type === "goal" ? Math.max(0, target.goal.targetAmount - target.goal.currentAmount) : null;
  const generalBalance = generalSavings?.balance || 0;
  // Reallocating from General Savings only makes sense when funding a
  // specific goal — General Savings can't fund itself.
  const canUseGeneral = target.type === "goal" && generalBalance > 0;
  const exceedsGeneral = source === "general" && amountNum > generalBalance;

  const sourceOptions = [
    { key: "external", label: "New money" },
    { key: "balance", label: "My available balance" },
    ...(canUseGeneral ? [{ key: "general", label: "From General Savings" }] : []),
  ];

  return (
    <div>
      <div style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 14 }}>
        {target.type === "goal"
          ? <>{fmtMoney(target.goal.currentAmount)} saved of {fmtMoney(target.goal.targetAmount)} — {fmtMoney(remaining)} to go.</>
          : <>{fmtMoney(target.balance || 0)} currently in General Savings.</>}
      </div>
      <Field label="Amount to add">
        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ flex: 1 }}><Input type="number" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.00" autoFocus /></div>
          <IconBtn icon={CalculatorIcon} onClick={() => setShowCalc(true)} title="Open calculator" />
        </div>
      </Field>

      <Field label="Where's this money coming from?">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {sourceOptions.map((opt) => (
            <button key={opt.key} type="button" onClick={() => setSource(opt.key)}
              style={{
                flex: "1 1 auto", padding: "9px", borderRadius: 9, cursor: "pointer", fontWeight: 600, fontSize: 12.5,
                border: `1px solid ${source === opt.key ? "var(--primary)" : "var(--border)"}`,
                background: source === opt.key ? "var(--primary-soft)" : "var(--surface-2)",
                color: source === opt.key ? "var(--primary)" : "var(--text-muted)"
              }}>
              {opt.label}
            </button>
          ))}
        </div>
        {source === "general" && (
          <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 6 }}>{fmtMoney(generalBalance)} available in General Savings.</div>
        )}
      </Field>

      <Field label="Date"><Input type="date" value={date} onChange={(e) => setDate(e.target.value)} /></Field>
      <Field label="Note (optional)"><Input value={note} onChange={(e) => setNote(e.target.value)} placeholder={source === "external" ? "e.g. From bonus" : "e.g. Monthly transfer"} /></Field>

      {exceedsGeneral && (
        <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 10 }}>That's more than what's currently in General Savings.</div>
      )}

      {amountNum > 0 && !exceedsGeneral && (
        <div style={{
          fontSize: 12, color: "var(--text-faint)", lineHeight: 1.5,
          background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8, padding: "8px 10px", marginBottom: 6
        }}>
          {source === "balance" && <>This records a {fmtMoney(amountNum)} expense (category "Savings") and moves it into {label} — your available balance will go down by {fmtMoney(amountNum)}.</>}
          {source === "external" && <>This adds {fmtMoney(amountNum)} to {label} as new money — it counts toward your total income, but your available balance stays exactly as it is.</>}
          {source === "general" && <>This moves {fmtMoney(amountNum)} from General Savings into {label} — your total savings stay the same, nothing changes to your available balance.</>}
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave({ amount: amountNum, date, note, source })} disabled={!amount || amountNum <= 0 || exceedsGeneral}>Add funds</Button>
      </div>
      {showCalc && <CalculatorModal onClose={() => setShowCalc(false)} onUseValue={(v) => setAmount(String(v))} />}
    </div>
  );
}

/** Withdraw money out of a goal or General Savings. Asks where the money
    should go: back into Available Balance (recorded as real income), or
    out as physical cash (no transaction — it's just leaving the app). */
function SavingsWithdrawForm({ target, onSave, onCancel }) {
  const [amount, setAmount] = useState("");
  const [date, setDate] = useState(new Date().toISOString().slice(0, 10));
  const [note, setNote] = useState("");
  const [destination, setDestination] = useState("balance");
  const [showCalc, setShowCalc] = useState(false);
  const balance = target.balance || 0;
  const amountNum = Number(amount) || 0;
  const label = target.type === "goal" ? target.goal.title : "General Savings";

  return (
    <div>
      <div style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 14 }}>
        {fmtMoney(balance)} currently in {label}.
      </div>
      <Field label="Amount to withdraw">
        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ flex: 1 }}><Input type="number" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.00" autoFocus /></div>
          <IconBtn icon={CalculatorIcon} onClick={() => setShowCalc(true)} title="Open calculator" />
        </div>
      </Field>

      <Field label="Where's this money going?">
        <div style={{ display: "flex", gap: 8 }}>
          {[
            { key: "balance", label: "Back to available balance" },
            { key: "physical", label: "Physical cash" },
          ].map((opt) => (
            <button key={opt.key} type="button" onClick={() => setDestination(opt.key)}
              style={{
                flex: 1, padding: "9px", borderRadius: 9, cursor: "pointer", fontWeight: 600, fontSize: 12.5,
                border: `1px solid ${destination === opt.key ? "var(--primary)" : "var(--border)"}`,
                background: destination === opt.key ? "var(--primary-soft)" : "var(--surface-2)",
                color: destination === opt.key ? "var(--primary)" : "var(--text-muted)"
              }}>
              {opt.label}
            </button>
          ))}
        </div>
      </Field>

      <Field label="Date"><Input type="date" value={date} onChange={(e) => setDate(e.target.value)} /></Field>
      <Field label="What's it for? (optional)"><Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Buying the laptop" /></Field>
      {amountNum > balance && (
        <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 10 }}>That's more than what's currently saved here.</div>
      )}
      <div style={{
        fontSize: 12, color: "var(--text-faint)", lineHeight: 1.5,
        background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8, padding: "8px 10px", marginBottom: 6
      }}>
        {destination === "balance"
          ? <>This records a {fmtMoney(amountNum || 0)} income (category "Savings") — your available balance goes back up by that amount.</>
          : <>This just reduces {label} — nothing is added to Finance, since the cash is leaving the app entirely.</>}
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave({ amount: amountNum, date, note, destination })} disabled={!amount || amountNum <= 0 || amountNum > balance}>Withdraw</Button>
      </div>
      {showCalc && <CalculatorModal onClose={() => setShowCalc(false)} onUseValue={(v) => setAmount(String(v))} />}
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Event Planner + Calendar                                               */
/* ---------------------------------------------------------------------- */

const WEEKDAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTH_LABELS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

function ymd(year, month, day) {
  const mm = String(month + 1).padStart(2, "0");
  const dd = String(day).padStart(2, "0");
  return `${year}-${mm}-${dd}`;
}
function todayStr() {
  const d = new Date();
  return ymd(d.getFullYear(), d.getMonth(), d.getDate());
}
function buildMonthGrid(year, month) {
  const firstWeekday = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const totalCells = Math.ceil((firstWeekday + daysInMonth) / 7) * 7;
  const cells = [];
  for (let i = 0; i < totalCells; i++) {
    const dayNum = i - firstWeekday + 1;
    if (dayNum < 1 || dayNum > daysInMonth) cells.push(null);
    else cells.push(ymd(year, month, dayNum));
  }
  return cells;
}

/** Clamps a day-of-month to whatever actually exists in that month (e.g. a
    Jan 31 monthly repeat lands on Feb 28/29, not an invalid Feb 31). */
function clampDayOfMonth(year, month, day) {
  const lastDay = new Date(year, month + 1, 0).getDate();
  return Math.min(day, lastDay);
}

const RECURRENCE_LABELS = { weekly: "Weekly", monthly: "Monthly", yearly: "Yearly" };

/** "1" -> "st", "2" -> "nd", "3" -> "rd", "5" -> "th", "11"-"13" -> "th", etc. */
function ordinalSuffix(n) {
  const v = n % 100;
  if (v >= 11 && v <= 13) return "th";
  switch (n % 10) {
    case 1: return "st";
    case 2: return "nd";
    case 3: return "rd";
    default: return "th";
  }
}

/**
 * Expands a single event's recurrence rule into the actual date strings it
 * falls on within [rangeStart, rangeEnd] (inclusive, 'YYYY-MM-DD'). A
 * non-repeating event just returns its own date if it's in range. Nothing
 * is stored per-occurrence — this is computed fresh whenever the calendar
 * needs to know what's on screen.
 */
function getOccurrencesInRange(event, rangeStart, rangeEnd) {
  const anchor = event.date;
  if (!event.recurrence || event.recurrence === "none") {
    return (anchor >= rangeStart && anchor <= rangeEnd) ? [anchor] : [];
  }

  const occurrences = [];
  const anchorDate = new Date(anchor + "T00:00:00");
  const rangeEndDate = new Date(rangeEnd + "T00:00:00");
  const effectiveStart = anchor > rangeStart ? anchor : rangeStart;

  if (event.recurrence === "weekly") {
    let cur = new Date(anchorDate);
    // Fast-forward to the first occurrence on/after effectiveStart.
    while (ymd(cur.getFullYear(), cur.getMonth(), cur.getDate()) < effectiveStart) {
      cur.setDate(cur.getDate() + 7);
    }
    while (true) {
      const dateStr = ymd(cur.getFullYear(), cur.getMonth(), cur.getDate());
      if (dateStr > rangeEnd) break;
      occurrences.push(dateStr);
      cur.setDate(cur.getDate() + 7);
    }
  } else if (event.recurrence === "monthly") {
    const anchorDay = anchorDate.getDate();
    let y = anchorDate.getFullYear(), m = anchorDate.getMonth();
    const startY = Number(effectiveStart.slice(0, 4)), startM = Number(effectiveStart.slice(5, 7)) - 1;
    if (y < startY || (y === startY && m < startM)) { y = startY; m = startM; }
    let guard = 0;
    while (guard++ < 1200) {
      const d = clampDayOfMonth(y, m, anchorDay);
      const dateStr = ymd(y, m, d);
      if (dateStr > rangeEnd) break;
      if (dateStr >= anchor) occurrences.push(dateStr);
      m++; if (m > 11) { m = 0; y++; }
    }
  } else if (event.recurrence === "yearly") {
    const anchorMonth = anchorDate.getMonth(), anchorDay = anchorDate.getDate();
    let y = Math.max(anchorDate.getFullYear(), Number(effectiveStart.slice(0, 4)));
    let guard = 0;
    while (guard++ < 200) {
      const d = clampDayOfMonth(y, anchorMonth, anchorDay);
      const dateStr = ymd(y, anchorMonth, d);
      if (dateStr > rangeEnd) break;
      if (dateStr >= anchor) occurrences.push(dateStr);
      y++;
    }
  }
  return occurrences;
}

/** Expands every event in a list across a date range into individual
    calendar entries — one per occurrence, tagged with which date they
    landed on, but still pointing back at the same underlying event id. */
function expandEventsInRange(events, rangeStart, rangeEnd) {
  const out = [];
  for (const event of events) {
    for (const dateStr of getOccurrencesInRange(event, rangeStart, rangeEnd)) {
      out.push({ ...event, date: dateStr, baseDate: event.date, completed: isOccurrenceCompleted(event, dateStr) });
    }
  }
  return out;
}

/** Whether a specific occurrence (by date) of an event is marked done.
    Each recurrence of a weekly/monthly/yearly event tracks its own
    completion independently — marking this month's Netflix payment done
    doesn't touch any other month's. */
function isOccurrenceCompleted(event, dateStr) {
  return (event.completedDates || []).includes(dateStr);
}

function fmtEventTime(time) {
  if (!time) return "";
  const [h, m] = time.split(":").map(Number);
  const period = h >= 12 ? "PM" : "AM";
  const h12 = h % 12 === 0 ? 12 : h % 12;
  return `${h12}:${String(m).padStart(2, "0")} ${period}`;
}
function fmtEventDateLabel(dateStr) {
  const diff = daysUntil(dateStr);
  if (diff === 0) return "Today";
  if (diff === 1) return "Tomorrow";
  if (diff === -1) return "Yesterday";
  return fmtDate(dateStr);
}

function PlannerView({ events, openModal, deleteEvent, toggleEventComplete }) {
  const [cursor, setCursor] = useState(() => { const d = new Date(); return { year: d.getFullYear(), month: d.getMonth() }; });
  const [selectedDate, setSelectedDate] = useState(todayStr());
  const [confirmDelete, setConfirmDelete] = useState(null);

  const grid = useMemo(() => buildMonthGrid(cursor.year, cursor.month), [cursor]);
  const monthRange = useMemo(() => {
    const firstShown = grid.find((d) => d) || ymd(cursor.year, cursor.month, 1);
    const lastShown = [...grid].reverse().find((d) => d) || ymd(cursor.year, cursor.month, 28);
    return { start: firstShown, end: lastShown };
  }, [grid, cursor]);

  // Recurring events don't exist as separate stored records per occurrence —
  // they're expanded fresh here, for whatever range is actually on screen.
  const visibleOccurrences = useMemo(
    () => expandEventsInRange(events, monthRange.start, monthRange.end),
    [events, monthRange]
  );
  const eventsByDate = useMemo(() => {
    const map = {};
    visibleOccurrences.forEach((e) => { (map[e.date] = map[e.date] || []).push(e); });
    Object.values(map).forEach((list) => list.sort((a, b) => (a.time || "").localeCompare(b.time || "")));
    return map;
  }, [visibleOccurrences]);

  const upcoming = useMemo(() => {
    const t = todayStr();
    const farOut = ymd(new Date().getFullYear() + 1, new Date().getMonth(), new Date().getDate());
    return expandEventsInRange(events, t, farOut)
      .sort((a, b) => a.date.localeCompare(b.date) || (a.time || "").localeCompare(b.time || ""))
      .slice(0, 8);
  }, [events]);

  const selectedEvents = eventsByDate[selectedDate] || [];
  // All-day items first (no fixed time), then timed items in chronological order.
  const selectedEventsSorted = useMemo(() => {
    return [...selectedEvents].sort((a, b) => {
      if (a.allDay && !b.allDay) return -1;
      if (!a.allDay && b.allDay) return 1;
      return (a.time || "").localeCompare(b.time || "");
    });
  }, [selectedEvents]);

  const goMonth = (delta) => {
    setCursor((c) => {
      const d = new Date(c.year, c.month + delta, 1);
      return { year: d.getFullYear(), month: d.getMonth() };
    });
  };
  const goToday = () => {
    const d = new Date();
    setCursor({ year: d.getFullYear(), month: d.getMonth() });
    setSelectedDate(todayStr());
  };
  const jumpToDate = (dateStr) => {
    setCursor({ year: Number(dateStr.slice(0, 4)), month: Number(dateStr.slice(5, 7)) - 1 });
    setSelectedDate(dateStr);
  };
  // Editing must always operate on the true stored record (with its
  // original anchor date), never on a virtual occurrence's shifted date.
  const editBase = (occurrence) => openModal("event-edit", events.find((x) => x.id === occurrence.id) || occurrence);

  return (
    <div>
      <TopBar title="Planner" subtitle="Your schedule at a glance"
        right={<Button icon={Plus} onClick={() => openModal("event-add", { date: selectedDate })}>Add event</Button>} />
      <div style={{ padding: "0 28px 28px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: 16, marginBottom: 16 }}>
          {/* Calendar */}
          <Card style={{ padding: 18 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
              <div className="sv-display" style={{ fontWeight: 600, fontSize: 15 }}>{MONTH_LABELS[cursor.month]} {cursor.year}</div>
              <div style={{ display: "flex", gap: 6 }}>
                <Button size="sm" variant="subtle" onClick={goToday}>Today</Button>
                <IconBtn icon={ChevronLeft} onClick={() => goMonth(-1)} title="Previous month" />
                <IconBtn icon={ChevronRight} onClick={() => goMonth(1)} title="Next month" />
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 4, marginBottom: 6 }}>
              {WEEKDAY_LABELS.map((d) => (
                <div key={d} style={{ textAlign: "center", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", padding: "4px 0" }}>{d}</div>
              ))}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 4 }}>
              {grid.map((dateStr, i) => {
                if (!dateStr) return <div key={i} style={{ minHeight: 68 }} />;
                const dayNum = Number(dateStr.slice(-2));
                const dayEvents = eventsByDate[dateStr] || [];
                const isToday = dateStr === todayStr();
                const isSelected = dateStr === selectedDate;
                return (
                  <button
                    key={i}
                    onClick={() => setSelectedDate(dateStr)}
                    className="sv-focus"
                    style={{
                      minHeight: 68, borderRadius: 9, padding: "6px 6px", textAlign: "left", cursor: "pointer",
                      border: isSelected ? "1px solid var(--primary)" : "1px solid var(--border)",
                      background: isSelected ? "var(--primary-soft)" : "var(--surface-2)",
                      display: "flex", flexDirection: "column", gap: 3, overflow: "hidden"
                    }}
                  >
                    <span className="sv-mono" style={{
                      fontSize: 11.5, fontWeight: isToday ? 700 : 500,
                      color: isToday ? "var(--primary)" : "var(--text)",
                      display: "inline-flex", alignItems: "center", justifyContent: "center",
                      width: isToday ? 18 : "auto", height: isToday ? 18 : "auto",
                      borderRadius: "50%", background: isToday ? "var(--primary)" : "transparent",
                      ...(isToday ? { color: "#fff" } : {})
                    }}>{dayNum}</span>
                    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                      {dayEvents.slice(0, 2).map((e) => (
                        <div key={`${e.id}-${e.date}`} style={{
                          display: "flex", alignItems: "center", gap: 3,
                          fontSize: 9.5, padding: "1px 4px", borderRadius: 4, color: "#fff", fontWeight: 600,
                          background: EVENT_CATEGORY_COLORS[e.category] || "var(--primary)",
                          whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
                          opacity: e.completed ? 0.5 : 1
                        }}>
                          {e.recurrence && e.recurrence !== "none" && <Repeat size={8} style={{ flexShrink: 0 }} />}
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", textDecoration: e.completed ? "line-through" : "none" }}>{e.title}</span>
                        </div>
                      ))}
                      {dayEvents.length > 2 && <div style={{ fontSize: 9, color: "var(--text-faint)" }}>+{dayEvents.length - 2} more</div>}
                    </div>
                  </button>
                );
              })}
            </div>
          </Card>

          {/* Side panel: Today + Upcoming */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <Card>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                <div className="sv-display" style={{ fontWeight: 600, fontSize: 14 }}>{fmtEventDateLabel(selectedDate)}</div>
                <IconBtn icon={Plus} onClick={() => openModal("event-add", { date: selectedDate })} title="Add event on this day" />
              </div>
              {selectedEventsSorted.length === 0 ? (
                <div style={{ fontSize: 12.5, color: "var(--text-faint)" }}>No events on this day.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {selectedEventsSorted.map((e) => (
                    <EventRow key={`${e.id}-${e.date}`} event={e} onClick={() => editBase(e)} onDelete={() => setConfirmDelete(e)} onToggleComplete={() => toggleEventComplete(e.id, e.date)} />
                  ))}
                </div>
              )}
            </Card>

            <Card>
              <div className="sv-display" style={{ fontWeight: 600, fontSize: 14, marginBottom: 12 }}>Upcoming</div>
              {upcoming.length === 0 ? (
                <div style={{ fontSize: 12.5, color: "var(--text-faint)" }}>Nothing scheduled — enjoy the calm.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 260, overflowY: "auto" }} className="sv-scroll">
                  {upcoming.map((e) => (
                    <div key={`${e.id}-${e.date}`} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                      <button
                        onClick={() => toggleEventComplete(e.id, e.date)}
                        title={e.completed ? "Mark as not done" : "Mark as done"}
                        className="sv-focus"
                        style={{
                          width: 15, height: 15, borderRadius: 4, flexShrink: 0, marginTop: 2, cursor: "pointer",
                          border: `1.5px solid ${e.completed ? "var(--mint)" : "var(--text-faint)"}`,
                          background: e.completed ? "var(--mint)" : "transparent",
                          display: "flex", alignItems: "center", justifyContent: "center", padding: 0
                        }}
                      >
                        {e.completed && <CheckCircle2 size={10} color="#0B0F14" strokeWidth={3.5} />}
                      </button>
                      <button onClick={() => jumpToDate(e.date)}
                        className="sv-focus" style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0, background: "none", border: "none", padding: 0, cursor: "pointer", textAlign: "left" }}>
                        <div style={{ width: 6, height: 6, borderRadius: "50%", background: EVENT_CATEGORY_COLORS[e.category] || "var(--primary)", flexShrink: 0 }} />
                        <div style={{ minWidth: 0, flex: 1 }}>
                          <div style={{
                            display: "flex", alignItems: "center", gap: 5,
                            fontSize: 12.5, color: e.completed ? "var(--text-faint)" : "var(--text)",
                            textDecoration: e.completed ? "line-through" : "none",
                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                          }}>
                            {e.recurrence && e.recurrence !== "none" && <Repeat size={10} color="var(--text-faint)" style={{ flexShrink: 0 }} />}
                            <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{e.title}</span>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{fmtEventDateLabel(e.date)}{e.time ? ` · ${fmtEventTime(e.time)}` : ""}</div>
                        </div>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
        </div>

        {/* Live digital clock, replacing the old Selected Day detail panel */}
        <DigitalClockCard />
      </div>
      {confirmDelete && (
        <ConfirmDialog
          title="Delete event"
          message={
            confirmDelete.recurrence && confirmDelete.recurrence !== "none"
              ? `"${confirmDelete.title}" repeats ${RECURRENCE_LABELS[confirmDelete.recurrence].toLowerCase()}. Deleting it removes every past and future occurrence — you can restore it from Trash within ${TRASH_RETENTION_DAYS} days.`
              : `Move "${confirmDelete.title}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`
          }
          confirmLabel="Move to Trash" danger onCancel={() => setConfirmDelete(null)}
          onConfirm={() => { deleteEvent(confirmDelete.id); setConfirmDelete(null); }} />
      )}
    </div>
  );
}

/** A simple live-updating digital clock, styled like an LED/LCD display. */
function DigitalClockCard() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const interval = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  const hours24 = now.getHours();
  const hours12 = hours24 % 12 === 0 ? 12 : hours24 % 12;
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const seconds = String(now.getSeconds()).padStart(2, "0");
  const period = hours24 >= 12 ? "PM" : "AM";
  const blink = now.getSeconds() % 2 === 0;
  const dateLabel = now.toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" });

  return (
    <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "40px 20px" }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 14 }}>
        Current Time
      </div>
      <div
        className="sv-mono"
        style={{
          fontSize: 56, fontWeight: 700, lineHeight: 1, letterSpacing: 2,
          color: "var(--primary)", fontVariantNumeric: "tabular-nums",
          background: "var(--surface-2)", border: "1px solid var(--border)",
          borderRadius: 16, padding: "20px 36px", display: "flex", alignItems: "baseline", gap: 4
        }}
      >
        <span>{String(hours12).padStart(2, "0")}</span>
        <span style={{ opacity: blink ? 1 : 0.15, transition: "opacity 0.15s" }}>:</span>
        <span>{minutes}</span>
        <span style={{ opacity: blink ? 1 : 0.15, transition: "opacity 0.15s" }}>:</span>
        <span>{seconds}</span>
        <span style={{ fontSize: 20, fontWeight: 700, color: "var(--text-faint)", marginLeft: 8, alignSelf: "flex-start", marginTop: 6 }}>{period}</span>
      </div>
      <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 18 }}>{dateLabel}</div>
    </Card>
  );
}

function EventRow({ event, onClick, onDelete, onToggleComplete }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
      <div style={{ width: 4, alignSelf: "stretch", borderRadius: 3, background: EVENT_CATEGORY_COLORS[event.category] || "var(--primary)", flexShrink: 0, opacity: event.completed ? 0.4 : 1 }} />
      <button
        onClick={onToggleComplete}
        title={event.completed ? "Mark as not done" : "Mark as done"}
        className="sv-focus"
        style={{
          width: 18, height: 18, borderRadius: 5, flexShrink: 0, marginTop: 2, cursor: "pointer",
          border: `1.5px solid ${event.completed ? "var(--mint)" : "var(--text-faint)"}`,
          background: event.completed ? "var(--mint)" : "transparent",
          display: "flex", alignItems: "center", justifyContent: "center", padding: 0
        }}
      >
        {event.completed && <CheckCircle2 size={12} color="#0B0F14" strokeWidth={3} />}
      </button>
      <button onClick={onClick} className="sv-focus" style={{ flex: 1, minWidth: 0, textAlign: "left", background: "none", border: "none", padding: 0, cursor: "pointer" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: event.completed ? "var(--text-faint)" : "var(--text)", textDecoration: event.completed ? "line-through" : "none" }}>{event.title}</span>
          {event.recurrence && event.recurrence !== "none" && (
            <span title={`Repeats ${RECURRENCE_LABELS[event.recurrence].toLowerCase()}`} style={{ display: "inline-flex", alignItems: "center", color: "var(--text-faint)" }}>
              <Repeat size={11} />
            </span>
          )}
          {event.completed && <Badge tone="mint">Done</Badge>}
        </div>
        <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>
          {event.allDay ? "All day" : [fmtEventTime(event.time), event.endTime ? `– ${fmtEventTime(event.endTime)}` : ""].filter(Boolean).join(" ")}
          {event.location && <> · {event.location}</>}
        </div>
        {event.notes && <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>{event.notes}</div>}
      </button>
      <IconBtn icon={Trash2} size={12} danger onClick={onDelete} title="Delete" />
    </div>
  );
}

function EventForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || { title: "", date: todayStr(), time: "", endTime: "", category: "Personal", location: "", notes: "", allDay: false, recurrence: "none" });
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <div>
      <Field label="Title"><Input value={form.title} onChange={set("title")} placeholder="e.g. Dentist appointment" autoFocus /></Field>
      <Field label="Date"><Input type="date" value={form.date} onChange={set("date")} /></Field>
      <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, marginBottom: 14, cursor: "pointer" }}>
        <input type="checkbox" checked={form.allDay} onChange={(e) => setForm((f) => ({ ...f, allDay: e.target.checked }))} style={{ accentColor: "var(--primary)" }} />
        All-day event
      </label>
      {!form.allDay && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <Field label="Start time"><Input type="time" value={form.time} onChange={set("time")} /></Field>
          <Field label="End time (optional)"><Input type="time" value={form.endTime} onChange={set("endTime")} /></Field>
        </div>
      )}
      <Field label="Category"><Select value={form.category} onChange={set("category")}>{EVENT_CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select></Field>
      <Field label="Repeats">
        <Select value={form.recurrence || "none"} onChange={set("recurrence")}>
          <option value="none">Does not repeat</option>
          <option value="weekly">Weekly — every {WEEKDAY_LABELS[new Date(form.date + "T00:00:00").getDay()]}</option>
          <option value="monthly">Monthly — every {new Date(form.date + "T00:00:00").getDate()}{ordinalSuffix(new Date(form.date + "T00:00:00").getDate())} of the month</option>
          <option value="yearly">Yearly — every {MONTH_LABELS[new Date(form.date + "T00:00:00").getMonth()]} {new Date(form.date + "T00:00:00").getDate()}</option>
        </Select>
        {form.recurrence && form.recurrence !== "none" && (
          <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 6 }}>
            Repeats forever based on today's date field — there's no separate "original" date once this is saved as recurring.
          </div>
        )}
      </Field>
      <Field label="Location (optional)"><Input value={form.location} onChange={set("location")} placeholder="e.g. Makati Dental Clinic" /></Field>
      <Field label="Notes (optional)"><TextArea value={form.notes} onChange={set("notes")} placeholder="Any details…" style={{ fontFamily: "Inter, sans-serif", minHeight: 70 }} /></Field>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave(form)} disabled={!form.title || !form.date}>Save event</Button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Contacts                                                                */
/* ---------------------------------------------------------------------- */

function ContactBanner({ contact, height = 84 }) {
  const color = CONTACT_CATEGORY_COLORS[contact.category] || "var(--primary)";
  return (
    <div style={{
      height, width: "100%", position: "relative", overflow: "hidden",
      background: contact.banner ? `url(${contact.banner}) center/cover no-repeat` : `linear-gradient(135deg, ${color}55, ${color}15)`,
    }} />
  );
}

function ContactAvatar({ contact, size = 64, ring = 3 }) {
  return (
    <div style={{
      width: size, height: size, borderRadius: "50%", flexShrink: 0,
      border: `${ring}px solid var(--surface)`, boxSizing: "content-box", overflow: "hidden"
    }}>
      <Avatar src={contact.avatar} name={contact.name} size={size} fontSize={size * 0.36} />
    </div>
  );
}

function ContactsView({ contacts, openModal, deleteContact, toggleFavorite }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const [confirmDelete, setConfirmDelete] = useState(null);

  const filtered = useMemo(() => {
    const list = contacts.filter((c) =>
      (category === "All" || c.category === category) &&
      (c.name.toLowerCase().includes(query.toLowerCase()) ||
        c.company.toLowerCase().includes(query.toLowerCase()) ||
        c.email.toLowerCase().includes(query.toLowerCase()))
    );
    return [...list].sort((a, b) => (b.favorite - a.favorite) || a.name.localeCompare(b.name));
  }, [contacts, query, category]);

  return (
    <div>
      <TopBar title="Contacts" subtitle={`${contacts.length} contact${contacts.length === 1 ? "" : "s"}`}
        right={<Button icon={Plus} onClick={() => openModal("contact-add")}>Add contact</Button>} />
      <div style={{ padding: "0 28px 28px" }}>
        <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: "1 1 220px" }}>
            <Search size={14} style={{ position: "absolute", left: 11, top: 11, color: "var(--text-faint)" }} />
            <Input placeholder="Search contacts…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ paddingLeft: 32 }} />
          </div>
          <Select value={category} onChange={(e) => setCategory(e.target.value)} style={{ width: 170 }}>
            <option>All</option>
            {CONTACT_CATEGORIES.map((c) => <option key={c}>{c}</option>)}
          </Select>
        </div>

        {filtered.length === 0 ? (
          <Card><EmptyState icon={Users} title="No contacts found" subtitle="Add people you want to keep securely on hand — with a photo and cover if you like."
            action={<Button icon={Plus} onClick={() => openModal("contact-add")}>Add contact</Button>} /></Card>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px,1fr))", gap: 16 }}>
            {filtered.map((c) => (
              <Card key={c.id} style={{ padding: 0, overflow: "hidden" }}>
                <div style={{ position: "relative" }}>
                  <button onClick={() => openModal("contact-view", c)} className="sv-focus" style={{ display: "block", width: "100%", border: "none", padding: 0, cursor: "pointer", background: "none" }}>
                    <ContactBanner contact={c} />
                  </button>
                  <div style={{ position: "absolute", left: 16, bottom: -28 }}>
                    <button onClick={() => openModal("contact-view", c)} className="sv-focus" style={{ border: "none", padding: 0, cursor: "pointer", background: "none", borderRadius: "50%" }}>
                      <ContactAvatar contact={c} size={60} />
                    </button>
                  </div>
                  <button
                    onClick={() => toggleFavorite(c.id)}
                    title={c.favorite ? "Unfavorite" : "Favorite"}
                    className="sv-focus"
                    style={{
                      position: "absolute", top: 8, right: 8, width: 26, height: 26, borderRadius: 7,
                      background: "rgba(11,15,20,0.55)", border: "1px solid rgba(255,255,255,0.15)",
                      display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer"
                    }}
                  >
                    <Star size={13} color={c.favorite ? "var(--amber)" : "#fff"} fill={c.favorite ? "var(--amber)" : "none"} />
                  </button>
                </div>

                <div style={{ padding: "36px 16px 16px" }}>
                  <button onClick={() => openModal("contact-view", c)} className="sv-focus" style={{ display: "block", width: "100%", textAlign: "left", background: "none", border: "none", padding: 0, cursor: "pointer", color: "inherit" }}>
                    <div style={{ fontWeight: 600, fontSize: 14.5, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</div>
                    {(c.jobTitle || c.company) && (
                      <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {[c.jobTitle, c.company].filter(Boolean).join(" · ")}
                      </div>
                    )}
                  </button>
                  <div style={{ marginTop: 8 }}><Badge>{c.category}</Badge></div>

                  {(c.phone || c.email) && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 10 }}>
                      {c.phone && <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-muted)" }}><Phone size={12} color="var(--text-faint)" /> {c.phone}</div>}
                      {c.email && <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}><Mail size={12} color="var(--text-faint)" /> {c.email}</div>}
                    </div>
                  )}

                  <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
                    <IconBtn icon={Pencil} onClick={() => openModal("contact-edit", c)} title="Edit" />
                    <IconBtn icon={Trash2} danger onClick={() => setConfirmDelete(c)} title="Delete" />
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
      {confirmDelete && (
        <ConfirmDialog title="Delete contact" message={`Move "${confirmDelete.name}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger onCancel={() => setConfirmDelete(null)}
          onConfirm={() => { deleteContact(confirmDelete.id); setConfirmDelete(null); }} />
      )}
    </div>
  );
}

const MAX_BANNER_SIZE = 6 * 1024 * 1024; // 6MB source upload cap, resized down before storing either way.

/**
 * A small, self-contained image crop tool — drag to reposition, slider to
 * zoom, crop to an exact output size. No external cropper library; just
 * canvas math. `shape="circle"` overlays a circular guide (for avatars)
 * without changing the actual captured rectangle.
 */
function ImageCropModal({ imageSrc, aspect, outputWidth, outputHeight, shape = "rect", title, onCancel, onCropped }) {
  const [naturalSize, setNaturalSize] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const dragRef = useRef(null);
  const imgRef = useRef(null);

  const VW = 320;
  const VH = Math.round(VW / aspect);

  useEffect(() => {
    let cancelled = false;
    const img = new Image();
    img.onload = () => { if (!cancelled) setNaturalSize({ width: img.naturalWidth, height: img.naturalHeight }); };
    img.src = imageSrc;
    return () => { cancelled = true; };
  }, [imageSrc]);

  if (!naturalSize) {
    return createPortal(
      <Modal title={title} onClose={onCancel} width={VW + 40}>
        <div style={{ fontSize: 13, color: "var(--text-faint)", textAlign: "center", padding: "50px 0" }}>Loading image…</div>
      </Modal>,
      document.querySelector(".sv-root") || document.body
    );
  }

  const baseScale = Math.max(VW / naturalSize.width, VH / naturalSize.height);
  const totalScale = baseScale * zoom;
  const displayWidth = naturalSize.width * totalScale;
  const displayHeight = naturalSize.height * totalScale;

  const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
  const clampOffset = (off, dw, dh) => ({ x: clamp(off.x, VW - dw, 0), y: clamp(off.y, VH - dh, 0) });

  const handlePointerDown = (e) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    dragRef.current = { startX: e.clientX, startY: e.clientY, startOffset: offset };
  };
  const handlePointerMove = (e) => {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.startX;
    const dy = e.clientY - dragRef.current.startY;
    setOffset(clampOffset(
      { x: dragRef.current.startOffset.x + dx, y: dragRef.current.startOffset.y + dy },
      displayWidth, displayHeight
    ));
  };
  const handlePointerUp = () => { dragRef.current = null; };

  const handleZoom = (e) => {
    const z = Number(e.target.value);
    setZoom(z);
    const dw = naturalSize.width * baseScale * z;
    const dh = naturalSize.height * baseScale * z;
    setOffset((off) => clampOffset(off, dw, dh));
  };

  const applyCrop = () => {
    const sx = -offset.x / totalScale;
    const sy = -offset.y / totalScale;
    const sw = VW / totalScale;
    const sh = VH / totalScale;
    const canvas = document.createElement("canvas");
    canvas.width = outputWidth;
    canvas.height = outputHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(imgRef.current, sx, sy, sw, sh, 0, 0, outputWidth, outputHeight);
    onCropped(canvas.toDataURL("image/jpeg", 0.9));
  };

  const holeSize = Math.min(VW, VH);

  return createPortal(
    <Modal title={title} onClose={onCancel} width={VW + 40}>
      <div
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
        style={{
          width: VW, height: VH, margin: "0 auto", position: "relative", overflow: "hidden",
          borderRadius: 12, background: "var(--surface-3)", border: "1px solid var(--border)",
          cursor: "grab", touchAction: "none", userSelect: "none"
        }}
      >
        <img
          ref={imgRef}
          src={imageSrc}
          alt=""
          draggable={false}
          style={{
            position: "absolute", left: 0, top: 0, width: displayWidth, height: displayHeight,
            maxWidth: "none", transform: `translate(${offset.x}px, ${offset.y}px)`, pointerEvents: "none"
          }}
        />
        {shape === "circle" && (
          <div style={{
            position: "absolute", left: (VW - holeSize) / 2, top: (VH - holeSize) / 2,
            width: holeSize, height: holeSize, borderRadius: "50%",
            boxShadow: "0 0 0 9999px rgba(11,15,20,0.6)", pointerEvents: "none"
          }} />
        )}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 16 }}>
        <span style={{ fontSize: 11, color: "var(--text-faint)", flexShrink: 0 }}>Zoom</span>
        <input type="range" min={1} max={3} step={0.01} value={zoom} onChange={handleZoom} style={{ flex: 1, accentColor: "var(--primary)" }} />
      </div>
      <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 8, textAlign: "center" }}>Drag to reposition · use the slider to zoom</div>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 18 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={applyCrop}>Apply crop</Button>
      </div>
    </Modal>,
    document.querySelector(".sv-root") || document.body
  );
}

function ContactForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || {
    name: "", category: "Friend", phone: "", email: "", company: "", jobTitle: "",
    tags: "", notes: "", favorite: false, avatar: null, banner: null,
  });
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const avatarInputRef = useRef(null);
  const bannerInputRef = useRef(null);
  const [imgError, setImgError] = useState("");
  // { type: "avatar" | "banner", src: dataURL } while the crop modal is open
  const [pendingCrop, setPendingCrop] = useState(null);

  const handleAvatarSelect = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/")) { setImgError("Please choose an image file for the profile photo."); return; }
    setImgError("");
    try {
      const src = await readFileAsDataURL(file);
      setPendingCrop({ type: "avatar", src });
    } catch {
      setImgError("Couldn't read that image file.");
    }
  };

  const handleBannerSelect = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/")) { setImgError("Please choose an image file for the banner."); return; }
    if (file.size > MAX_BANNER_SIZE) { setImgError(`That banner image is a bit large — try one under ${fmtFileSize(MAX_BANNER_SIZE)}.`); return; }
    setImgError("");
    try {
      const src = await readFileAsDataURL(file);
      setPendingCrop({ type: "banner", src });
    } catch {
      setImgError("Couldn't read that image file.");
    }
  };

  const handleCropped = (dataUrl) => {
    setForm((f) => ({ ...f, [pendingCrop.type]: dataUrl }));
    setPendingCrop(null);
  };

  return (
    <div>
      {/* Banner + avatar preview/upload */}
      <div style={{ position: "relative", marginBottom: 44, borderRadius: 12, overflow: "hidden" }}>
        <input ref={bannerInputRef} type="file" accept="image/*" onChange={handleBannerSelect} style={{ display: "none" }} />
        <div
          onClick={() => bannerInputRef.current?.click()}
          style={{
            height: 110, cursor: "pointer", position: "relative",
            background: form.banner ? `url(${form.banner}) center/cover no-repeat` : "linear-gradient(135deg, var(--primary-soft), var(--surface-3))",
            display: "flex", alignItems: "center", justifyContent: "center"
          }}
        >
          <div style={{
            background: "rgba(11,15,20,0.55)", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 8,
            padding: "6px 12px", display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#fff", fontWeight: 600
          }}>
            <Camera size={13} /> {form.banner ? "Change banner" : "Add banner photo"}
          </div>
        </div>

        <input ref={avatarInputRef} type="file" accept="image/*" onChange={handleAvatarSelect} style={{ display: "none" }} />
        <div style={{ position: "absolute", left: 16, bottom: -30 }}>
          <button onClick={() => avatarInputRef.current?.click()} className="sv-focus" style={{ position: "relative", border: "none", padding: 0, cursor: "pointer", background: "none", borderRadius: "50%" }} title="Change profile photo">
            <div style={{ width: 66, height: 66, borderRadius: "50%", border: "3px solid var(--surface)", overflow: "hidden" }}>
              <Avatar src={form.avatar} name={form.name} size={66} fontSize={22} />
            </div>
            <div style={{
              position: "absolute", bottom: 0, right: 0, width: 22, height: 22, borderRadius: "50%",
              background: "var(--primary)", border: "2px solid var(--surface)", display: "flex", alignItems: "center", justifyContent: "center"
            }}>
              <Camera size={11} color="#fff" />
            </div>
          </button>
        </div>
      </div>
      {imgError && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 14 }}>{imgError}</div>}

      <Field label="Name"><Input value={form.name} onChange={set("name")} placeholder="Full name" autoFocus /></Field>
      <Field label="Category"><Select value={form.category} onChange={set("category")}>{CONTACT_CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select></Field>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Field label="Phone"><Input value={form.phone} onChange={set("phone")} placeholder="+63 917 000 0000" /></Field>
        <Field label="Email"><Input type="email" value={form.email} onChange={set("email")} placeholder="name@example.com" /></Field>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Field label="Company (optional)"><Input value={form.company} onChange={set("company")} placeholder="e.g. Studio K" /></Field>
        <Field label="Job title (optional)"><Input value={form.jobTitle} onChange={set("jobTitle")} placeholder="e.g. Creative Director" /></Field>
      </div>
      <Field label="Tags (comma separated)"><Input value={form.tags} onChange={set("tags")} placeholder="client, referral" /></Field>
      <Field label="Notes (optional)"><TextArea value={form.notes} onChange={set("notes")} placeholder="Anything worth remembering…" style={{ fontFamily: "Inter, sans-serif", minHeight: 70 }} /></Field>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 6 }}>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={() => onSave(form)} disabled={!form.name}>Save contact</Button>
      </div>

      {pendingCrop?.type === "avatar" && (
        <ImageCropModal
          imageSrc={pendingCrop.src}
          aspect={1}
          outputWidth={240}
          outputHeight={240}
          shape="circle"
          title="Crop profile photo"
          onCancel={() => setPendingCrop(null)}
          onCropped={handleCropped}
        />
      )}
      {pendingCrop?.type === "banner" && (
        <ImageCropModal
          imageSrc={pendingCrop.src}
          aspect={800 / 220}
          outputWidth={800}
          outputHeight={220}
          shape="rect"
          title="Crop banner photo"
          onCancel={() => setPendingCrop(null)}
          onCropped={handleCropped}
        />
      )}
    </div>
  );
}

function ContactViewModal({ contact, onClose, onEdit, onDeleteRequest, toggleFavorite }) {
  return (
    <Modal title="" onClose={onClose} width={480}>
      <div style={{ margin: "-20px -20px 0", position: "relative" }}>
        <ContactBanner contact={contact} height={140} />
        <button onClick={onClose} className="sv-focus" style={{
          position: "absolute", top: 12, right: 12, width: 30, height: 30, borderRadius: 8,
          background: "rgba(11,15,20,0.55)", border: "1px solid rgba(255,255,255,0.15)",
          display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer"
        }}>
          <X size={15} color="#fff" />
        </button>
        <button
          onClick={() => toggleFavorite(contact.id)}
          className="sv-focus"
          style={{
            position: "absolute", top: 12, left: 12, width: 30, height: 30, borderRadius: 8,
            background: "rgba(11,15,20,0.55)", border: "1px solid rgba(255,255,255,0.15)",
            display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer"
          }}
          title={contact.favorite ? "Unfavorite" : "Favorite"}
        >
          <Star size={14} color={contact.favorite ? "var(--amber)" : "#fff"} fill={contact.favorite ? "var(--amber)" : "none"} />
        </button>
        <div style={{ position: "absolute", left: 20, bottom: -32 }}>
          <ContactAvatar contact={contact} size={70} />
        </div>
      </div>

      <div style={{ paddingTop: 42 }}>
        <div className="sv-display" style={{ fontWeight: 700, fontSize: 19 }}>{contact.name}</div>
        {(contact.jobTitle || contact.company) && (
          <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 2 }}>{[contact.jobTitle, contact.company].filter(Boolean).join(" · ")}</div>
        )}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
          <Badge>{contact.category}</Badge>
          {contact.tags.map((t) => <Badge key={t}>#{t}</Badge>)}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 18 }}>
          {contact.phone && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
              <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--surface-2)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><Phone size={14} color="var(--text-faint)" /></div>
              <span className="sv-mono">{contact.phone}</span>
            </div>
          )}
          {contact.email && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
              <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--surface-2)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><Mail size={14} color="var(--text-faint)" /></div>
              <span>{contact.email}</span>
            </div>
          )}
          {contact.company && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
              <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--surface-2)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><Building2 size={14} color="var(--text-faint)" /></div>
              <span>{contact.company}</span>
            </div>
          )}
        </div>

        {contact.notes && (
          <div style={{
            marginTop: 16, fontSize: 12.5, color: "var(--text-muted)", lineHeight: 1.6,
            background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 10, padding: 12
          }}>
            {contact.notes}
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 20 }}>
          <Button size="sm" variant="danger" icon={Trash2} onClick={() => onDeleteRequest(contact)}>Delete</Button>
          <Button size="sm" icon={Pencil} onClick={() => onEdit(contact)}>Edit contact</Button>
        </div>
      </div>
    </Modal>
  );
}

/* ---------------------------------------------------------------------- */
/* Trash / Recently Deleted                                               */
/* ---------------------------------------------------------------------- */

const TRASH_TYPE_META = {
  password: { icon: KeyRound, label: "Password", tone: "primary" },
  note: { icon: FileText, label: "Note", tone: "mint" },
  transaction: { icon: Wallet, label: "Transaction", tone: "primary" },
  budget: { icon: PiggyBank, label: "Budget", tone: "amber" },
  goal: { icon: Target, label: "Goal", tone: "primary" },
  event: { icon: CalendarDays, label: "Event", tone: "primary" },
  contact: { icon: Users, label: "Contact", tone: "primary" },
};

function trashEntryTitle(entry) {
  const it = entry.item;
  switch (entry.type) {
    case "password": return it.title;
    case "note": return it.title;
    case "transaction": return it.party;
    case "budget": return `${it.category} budget`;
    case "goal": return it.title;
    case "event": return it.title;
    case "contact": return it.name;
    default: return "Item";
  }
}
function trashEntrySubtitle(entry) {
  const it = entry.item;
  switch (entry.type) {
    case "password": return it.username;
    case "note": return it.category;
    case "transaction": return `${it.type === "income" ? "+" : "-"}${fmtMoney(it.amount)} · ${it.category}`;
    case "budget": return `${fmtMoney(it.amount)} / ${it.period}`;
    case "goal": return `${fmtMoney(it.currentAmount)} of ${fmtMoney(it.targetAmount)}`;
    case "event": return fmtDate(it.date);
    case "contact": return it.category;
    default: return "";
  }
}

function TrashView({ trash, onRestore, onDeleteForever, onEmptyTrash }) {
  const [typeFilter, setTypeFilter] = useState("All");
  const [confirmDeleteForever, setConfirmDeleteForever] = useState(null);
  const [confirmEmpty, setConfirmEmpty] = useState(false);

  const filtered = useMemo(() => {
    return [...trash]
      .filter((e) => typeFilter === "All" || e.type === typeFilter)
      .sort((a, b) => b.deletedAt.localeCompare(a.deletedAt));
  }, [trash, typeFilter]);

  return (
    <div>
      <TopBar title="Trash" subtitle={`${trash.length} item${trash.length === 1 ? "" : "s"} — deleted items are kept for ${TRASH_RETENTION_DAYS} days before being permanently removed`}
        right={trash.length > 0 && <Button variant="danger" icon={Trash2} onClick={() => setConfirmEmpty(true)}>Empty trash</Button>} />
      <div style={{ padding: "0 28px 28px" }}>
        {trash.length > 0 && (
          <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
            <Select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} style={{ width: 190 }}>
              <option value="All">All types</option>
              {Object.entries(TRASH_TYPE_META).map(([key, meta]) => <option key={key} value={key}>{meta.label}s</option>)}
            </Select>
          </div>
        )}

        {filtered.length === 0 ? (
          <Card><EmptyState icon={Trash2} title={trash.length === 0 ? "Trash is empty" : "No items of this type"} subtitle="Deleted passwords, notes, transactions, budgets, goals, and events show up here before they're gone for good." /></Card>
        ) : (
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ display: "flex", flexDirection: "column" }}>
              {filtered.map((entry) => {
                const meta = TRASH_TYPE_META[entry.type] || {};
                const Icon = meta.icon || FileText;
                const age = trashAgeDays(entry.deletedAt);
                const daysLeft = Math.max(0, TRASH_RETENTION_DAYS - age);
                return (
                  <div key={entry.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
                    <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--surface-2)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <Icon size={14} color="var(--text-faint)" />
                    </div>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{trashEntryTitle(entry)}</div>
                      <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{meta.label} · {trashEntrySubtitle(entry)}</div>
                    </div>
                    <div style={{ textAlign: "right", flexShrink: 0 }}>
                      <div className="sv-mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>Deleted {fmtDate(entry.deletedAt)}</div>
                      <div style={{ fontSize: 10.5, color: daysLeft <= 5 ? "var(--coral)" : "var(--text-faint)" }}>{daysLeft}d left</div>
                    </div>
                    <div style={{ display: "flex", gap: 5, flexShrink: 0 }}>
                      <IconBtn icon={RotateCcw} onClick={() => onRestore(entry.id)} title="Restore" />
                      <IconBtn icon={Trash2} danger onClick={() => setConfirmDeleteForever(entry)} title="Delete forever" />
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        )}
      </div>
      {confirmDeleteForever && (
        <ConfirmDialog title="Delete forever" message={`Permanently delete "${trashEntryTitle(confirmDeleteForever)}"? This cannot be undone.`}
          confirmLabel="Delete forever" danger onCancel={() => setConfirmDeleteForever(null)}
          onConfirm={() => { onDeleteForever(confirmDeleteForever.id); setConfirmDeleteForever(null); }} />
      )}
      {confirmEmpty && (
        <ConfirmDialog title="Empty trash" message={`Permanently delete all ${trash.length} item${trash.length === 1 ? "" : "s"} in trash? This cannot be undone.`}
          confirmLabel="Empty trash" danger onCancel={() => setConfirmEmpty(false)}
          onConfirm={() => { onEmptyTrash(); setConfirmEmpty(false); }} />
      )}
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Security Center                                                       */
/* ---------------------------------------------------------------------- */

function SecurityCenter({ passwords, activity, sessions, onEndSession, onRestoreVersion, serverStatus, lastRestoreUndo, onUndoRestore }) {
  const [versions, setVersions] = useState([]);
  const [versionsLoading, setVersionsLoading] = useState(true);
  const [confirmRestore, setConfirmRestore] = useState(null);
  const [restoring, setRestoring] = useState(false);

  useEffect(() => {
    if (serverStatus !== "connected") { setVersionsLoading(false); return; }
    (async () => {
      const list = await listVersions();
      setVersions(list);
      setVersionsLoading(false);
    })();
  }, [serverStatus]);

  const doRestore = async () => {
    if (!confirmRestore) return;
    setRestoring(true);
    await onRestoreVersion(confirmRestore.file);
    setRestoring(false);
    setConfirmRestore(null);
    const list = await listVersions();
    setVersions(list);
  };

  const weak = passwords.filter((p) => scorePassword(p.password) <= 1);
  const pwCounts = {};
  passwords.forEach((p) => { pwCounts[p.password] = (pwCounts[p.password] || 0) + 1; });
  const reusedSet = new Set(Object.entries(pwCounts).filter(([, c]) => c > 1).map(([pw]) => pw));
  const reused = passwords.filter((p) => reusedSet.has(p.password));
  const old = passwords.filter((p) => {
    const days = (Date.now() - new Date(p.updatedAt).getTime()) / 86400000;
    return days > 180;
  });

  let score = 100;
  score -= weak.length * 6;
  score -= reused.length * 5;
  score -= old.length * 3;
  score = Math.max(0, Math.min(100, score));
  const scoreTone = score >= 80 ? "mint" : score >= 50 ? "amber" : "coral";

  const recs = [
    weak.length > 0 && { text: `${weak.length} password${weak.length > 1 ? "s are" : " is"} weak.`, tone: "coral" },
    reused.length > 0 && { text: `${reused.length} password${reused.length > 1 ? "s are" : " is"} reused across accounts.`, tone: "amber" },
    old.length > 0 && { text: `${old.length} password${old.length > 1 ? "s haven't" : " hasn't"} been updated in over 6 months.`, tone: "amber" },
    { text: "Enable two-factor authentication for your most sensitive accounts.", tone: "primary" },
  ].filter(Boolean);

  return (
    <div>
      <TopBar title="Security Center" subtitle="Your vault's health, at a glance" />
      <div style={{ padding: "0 28px 28px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 16, marginBottom: 18 }}>
          <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <div style={{ position: "relative", width: 130, height: 130 }}>
              <svg viewBox="0 0 120 120" width="130" height="130">
                <circle cx="60" cy="60" r="52" fill="none" stroke="var(--surface-3)" strokeWidth="10" />
                <circle cx="60" cy="60" r="52" fill="none" stroke={`var(--${scoreTone === "mint" ? "mint" : scoreTone === "amber" ? "amber" : "coral"})`}
                  strokeWidth="10" strokeDasharray={`${(score / 100) * 327} 327`} strokeLinecap="round"
                  transform="rotate(-90 60 60)" style={{ transition: "stroke-dasharray 0.5s ease" }} />
              </svg>
              <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <span className="sv-display sv-mono" style={{ fontSize: 26, fontWeight: 700 }}>{score}</span>
                <span style={{ fontSize: 10.5, color: "var(--text-faint)" }}>/ 100</span>
              </div>
            </div>
            <div className="sv-display" style={{ fontWeight: 600, marginTop: 10, fontSize: 13.5 }}>Security score</div>
          </Card>

          <Card>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14.5, marginBottom: 12 }}>Recommendations</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {recs.map((r, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
                  <AlertTriangle size={14} color={`var(--${r.tone === "coral" ? "coral" : r.tone === "amber" ? "amber" : "primary"})`} style={{ flexShrink: 0 }} />
                  {r.text}
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14, marginBottom: 18 }}>
          <StatCard icon={ShieldAlert} label="Weak passwords" value={weak.length} tone="coral" />
          <StatCard icon={RefreshCw} label="Reused passwords" value={reused.length} tone="amber" />
          <StatCard icon={Clock} label="Not updated in 6mo+" value={old.length} tone="amber" />
        </div>

        <Card style={{ marginBottom: 18 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14, flexWrap: "wrap", gap: 8 }}>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14 }}>Vault integrity</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {lastRestoreUndo && (
                <Button size="sm" variant="subtle" icon={RotateCcw} onClick={onUndoRestore}>Undo restore</Button>
              )}
              <Badge tone="mint"><ShieldCheck size={11} /> Verified</Badge>
            </div>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 16 }}>
            SecureVault checks that the file on disk matches what it last wrote, on every unlock and roughly once a
            minute while running. If it's ever edited, corrupted, replaced, or rolled back by anything else, you'll
            get a warning with the option to review what changed, restore an earlier version, or trust the new file.
          </div>
          <div className="sv-display" style={{ fontWeight: 600, fontSize: 13, marginBottom: 10 }}>Version history</div>
          {serverStatus !== "connected" ? (
            <div style={{ fontSize: 12, color: "var(--text-faint)" }}>Connect to the local server to see saved versions.</div>
          ) : versionsLoading ? (
            <div style={{ fontSize: 12, color: "var(--text-faint)" }}>Loading…</div>
          ) : versions.length === 0 ? (
            <div style={{ fontSize: 12, color: "var(--text-faint)" }}>No earlier versions yet — one is saved automatically every time you make a change.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 220, overflowY: "auto" }} className="sv-scroll">
              {versions.slice(0, 12).map((v) => (
                <div key={v.file} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 12.5 }}>
                  <Clock size={13} color="var(--text-faint)" style={{ flexShrink: 0 }} />
                  <span className="sv-mono" style={{ color: "var(--text-faint)", flexShrink: 0 }}>v{v.version}</span>
                  <span style={{ flex: 1, color: "var(--text-muted)" }}>
                    {new Date(v.savedAt).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}
                  </span>
                  <Button size="sm" variant="ghost" icon={RotateCcw} onClick={() => setConfirmRestore(v)}>Restore</Button>
                </div>
              ))}
            </div>
          )}
        </Card>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <Card>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14, marginBottom: 12 }}>Active sessions</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {sessions.map((s) => (
                <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Smartphone size={15} color="var(--text-faint)" />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12.5, fontWeight: 600 }}>{s.device} {s.current && <Badge tone="mint">this device</Badge>}</div>
                    <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{s.location} · {s.lastActive}</div>
                  </div>
                  {!s.current && <Button size="sm" variant="ghost" onClick={() => onEndSession(s.id)}>Log out</Button>}
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <div className="sv-display" style={{ fontWeight: 600, fontSize: 14, marginBottom: 12 }}>Security activity</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 220, overflowY: "auto" }} className="sv-scroll">
              {activity.slice(0, 10).map((a) => (
                <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <ActivityIcon type={a.type} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.detail}</div>
                    <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{fmtDate(a.ts)}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <Card style={{ marginTop: 16, background: "var(--surface-2)" }}>
          <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
            <ShieldCheck size={18} color="var(--primary)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div style={{ fontSize: 12.5, color: "var(--text-muted)", lineHeight: 1.7 }}>
              <strong style={{ color: "var(--text)" }}>How this vault is actually encrypted: </strong>
              a random 256-bit vault key encrypts everything (AES-256-GCM). That key is itself wrapped by a key
              derived from your master password via Argon2id — and, if enabled, by a second key derived from your PIN
              the same way, or by Windows DPAPI gated behind an actual Windows Hello prompt if biometric unlock is on.
              Only ciphertext, salts, and Argon2id parameters ever touch disk; the file at{" "}
              <span className="sv-mono">D:\Local Data\securevault-data.json</span> reveals nothing without your
              master password, PIN, or Windows Hello. This part is real, not simulated. What's still simplified for
              a local prototype: no TLS (traffic never leaves localhost), no server-side account system, 2FA is still
              a UI-only toggle, and biometric unlock currently only works on Windows.
            </div>
          </div>
        </Card>
      </div>

      {confirmRestore && (
        <ConfirmDialog
          title="Restore this version"
          message={`Restore vault version ${confirmRestore.version} from ${new Date(confirmRestore.savedAt).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}? Whatever's currently saved will itself be kept as a version, so this isn't a one-way trip.`}
          confirmLabel={restoring ? "Restoring…" : "Restore"} danger
          onCancel={() => setConfirmRestore(null)}
          onConfirm={doRestore}
        />
      )}
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Settings                                                               */
/* ---------------------------------------------------------------------- */

function SettingsSection({ title, children }) {
  return (
    <Card style={{ marginBottom: 16 }}>
      <div className="sv-display" style={{ fontWeight: 600, fontSize: 14.5, marginBottom: 14 }}>{title}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>{children}</div>
    </Card>
  );
}
function SettingRow({ label, sub, children }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
      <div>
        <div style={{ fontSize: 13, fontWeight: 600 }}>{label}</div>
        {sub && <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>{sub}</div>}
      </div>
      {children}
    </div>
  );
}
function Toggle({ checked, onChange, disabled }) {
  return (
    <button onClick={() => !disabled && onChange(!checked)} disabled={disabled} className="sv-focus" style={{
      width: 42, height: 24, borderRadius: 12, border: "none", cursor: disabled ? "not-allowed" : "pointer", flexShrink: 0,
      background: checked ? "var(--primary)" : "var(--surface-3)", position: "relative", transition: "background 0.2s",
      opacity: disabled ? 0.5 : 1
    }}>
      <div style={{
        width: 18, height: 18, borderRadius: "50%", background: "#fff", position: "absolute", top: 3,
        left: checked ? 21 : 3, transition: "left 0.2s"
      }} />
    </button>
  );
}

function ProfilePictureRow({ avatar, name, onUpdateAccount, toast }) {
  const fileInputRef = useRef(null);
  const [busy, setBusy] = useState(false);

  const handleFile = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = ""; // allow re-selecting the same file later
    if (!file) return;
    if (!file.type.startsWith("image/")) { toast("Please choose an image file.", "danger"); return; }
    if (file.size > 8 * 1024 * 1024) { toast("That image is a bit large — try one under 8MB.", "danger"); return; }
    setBusy(true);
    try {
      const dataUrl = await resizeImageFile(file, 200, 0.85);
      onUpdateAccount({ avatar: dataUrl });
      toast("Profile picture updated.", "success");
    } catch {
      toast("Couldn't process that image — try a different file.", "danger");
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingRow label="Profile picture" sub="Stored encrypted with the rest of your vault — not uploaded anywhere">
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <Avatar src={avatar} name={name} size={40} fontSize={14} />
        <input ref={fileInputRef} type="file" accept="image/*" onChange={handleFile} style={{ display: "none" }} />
        <Button size="sm" variant="subtle" onClick={() => fileInputRef.current?.click()} disabled={busy}>{busy ? "Processing…" : "Upload"}</Button>
        {avatar && (
          <Button size="sm" variant="ghost" onClick={() => { onUpdateAccount({ avatar: null }); toast("Profile picture removed.", "success"); }}>Remove</Button>
        )}
      </div>
    </SettingRow>
  );
}

/* ---------------------------------------------------------------------- */
/* Vault Integrity Protection                                             */
/* ---------------------------------------------------------------------- */

function diffArrays(oldArr, newArr) {
  const oldMap = new Map((oldArr || []).map((i) => [i.id, i]));
  const newMap = new Map((newArr || []).map((i) => [i.id, i]));
  const added = [], removed = [], changed = [];
  newMap.forEach((item, id) => { if (!oldMap.has(id)) added.push(item); });
  oldMap.forEach((item, id) => { if (!newMap.has(id)) removed.push(item); });
  newMap.forEach((item, id) => {
    if (oldMap.has(id)) {
      const before = oldMap.get(id);
      if (JSON.stringify(before) !== JSON.stringify(item)) changed.push({ before, after: item });
    }
  });
  return { added, removed, changed };
}

const DIFF_CATEGORIES = [
  { key: "passwords", label: "Passwords", labelFn: (i) => i.title },
  { key: "notes", label: "Secure Notes", labelFn: (i) => i.title },
  { key: "transactions", label: "Transactions", labelFn: (i) => i.party },
  { key: "budgets", label: "Budgets", labelFn: (i) => i.category },
  { key: "goals", label: "Savings Goals", labelFn: (i) => i.title },
  { key: "events", label: "Events", labelFn: (i) => i.title },
];

/** Structural diff between two decrypted vault snapshots, category by category. */
function diffVaultData(oldData, newData) {
  return DIFF_CATEGORIES
    .map((c) => ({ ...c, ...diffArrays(oldData?.[c.key], newData?.[c.key]) }))
    .filter((c) => c.added.length || c.removed.length || c.changed.length);
}

const INTEGRITY_STATUS_META = {
  modified: { title: "Vault integrity warning", desc: "SecureVault detected that the vault file changed outside of SecureVault." },
  rolled_back: { title: "Vault rollback detected", desc: "SecureVault detected that the vault file was replaced with an older version." },
  corrupted: { title: "Vault file corrupted", desc: "SecureVault couldn't read the vault file — it may be damaged or incomplete." },
  missing: { title: "Vault file missing", desc: "SecureVault couldn't find the vault file where it's expected to be." },
};

function IntegrityWarningModal({ issue, locked, onTrust, onRestore, onReview }) {
  const [step, setStep] = useState("choose"); // choose | diff
  const [password, setPassword] = useState("");
  const [diff, setDiff] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const meta = INTEGRITY_STATUS_META[issue.status] || INTEGRITY_STATUS_META.modified;
  const modifiedLabel = issue.modifiedAt
    ? new Date(issue.modifiedAt).toLocaleString(undefined, { hour: "numeric", minute: "2-digit", month: "short", day: "numeric" })
    : null;
  const rolledBackLabel = issue.rolledBackToDate ? fmtDate(issue.rolledBackToDate.slice(0, 10)) : null;

  const runReview = async () => {
    setError(""); setBusy(true);
    const result = await onReview(locked ? password : undefined);
    setBusy(false);
    if (!result.ok) { setError(result.error || "Couldn't review changes."); return; }
    setDiff(result.diff);
    setStep("diff");
  };
  const runRestore = async () => { setBusy(true); await onRestore(); setBusy(false); };
  const runTrust = async () => { setBusy(true); await onTrust(); setBusy(false); };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(4,7,10,0.75)", zIndex: 300,
      display: "flex", alignItems: "center", justifyContent: "center", padding: 20
    }}>
      <div className="sv-fade-in sv-scroll" style={{
        width: 480, maxWidth: "100%", background: "var(--surface)", border: "1px solid var(--coral)",
        borderRadius: 16, boxShadow: "0 24px 60px rgba(0,0,0,0.5)", maxHeight: "88vh", overflowY: "auto"
      }}>
        <div style={{ padding: "20px 22px", borderBottom: "1px solid var(--border)", display: "flex", gap: 12, alignItems: "flex-start" }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: "var(--coral-soft)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
            <ShieldAlert size={18} color="var(--coral)" />
          </div>
          <div>
            <div className="sv-display" style={{ fontWeight: 700, fontSize: 15 }}>{meta.title}</div>
            <div style={{ fontSize: 12.5, color: "var(--text-muted)", marginTop: 4, lineHeight: 1.5 }}>
              {meta.desc}{issue.status === "rolled_back" && rolledBackLabel && ` (from ${rolledBackLabel})`}
            </div>
          </div>
        </div>

        <div style={{ padding: 22 }}>
          {step === "choose" && (
            <>
              {modifiedLabel && (
                <div className="sv-mono" style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 16 }}>Modified: {modifiedLabel}</div>
              )}
              {locked && (
                <Field label="Master password (only needed to review changes)">
                  <Input type="password" value={password} onChange={(e) => { setPassword(e.target.value); setError(""); }} placeholder="Optional unless reviewing changes" />
                </Field>
              )}
              {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 12 }}>{error}</div>}
              <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 6 }}>
                <Button icon={Search} variant="subtle" onClick={runReview} disabled={busy || (locked && !password)}>
                  {busy ? "Checking…" : "Review Changes"}
                </Button>
                <Button icon={RotateCcw} onClick={runRestore} disabled={busy || !issue.previousVersion}>
                  {busy ? "Restoring…" : "Restore Previous Version"}
                </Button>
                <Button icon={CheckCircle2} variant="ghost" onClick={runTrust} disabled={busy}>
                  {busy ? "Trusting…" : "Trust Changes"}
                </Button>
              </div>
              {!issue.previousVersion && (
                <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 10 }}>No earlier saved version is available to restore to yet.</div>
              )}
            </>
          )}

          {step === "diff" && (
            <div>
              {(!diff || diff.length === 0) ? (
                <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16 }}>No structural differences found between the two versions.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 14, maxHeight: 320, overflowY: "auto", marginBottom: 16 }} className="sv-scroll">
                  {diff.map((c) => (
                    <div key={c.key}>
                      <div style={{ fontSize: 12.5, fontWeight: 700, marginBottom: 6 }}>{c.label}</div>
                      {c.added.length > 0 && (
                        <div style={{ fontSize: 12, color: "var(--mint)", marginBottom: 2 }}>
                          + {c.added.length} added: {c.added.slice(0, 4).map(c.labelFn).join(", ")}{c.added.length > 4 ? "…" : ""}
                        </div>
                      )}
                      {c.removed.length > 0 && (
                        <div style={{ fontSize: 12, color: "var(--coral)", marginBottom: 2 }}>
                          − {c.removed.length} removed: {c.removed.slice(0, 4).map(c.labelFn).join(", ")}{c.removed.length > 4 ? "…" : ""}
                        </div>
                      )}
                      {c.changed.length > 0 && (
                        <div style={{ fontSize: 12, color: "var(--amber)" }}>
                          ~ {c.changed.length} changed: {c.changed.slice(0, 4).map((x) => c.labelFn(x.after)).join(", ")}{c.changed.length > 4 ? "…" : ""}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <Button variant="ghost" onClick={() => setStep("choose")} disabled={busy}>Back</Button>
                <Button icon={RotateCcw} onClick={runRestore} disabled={busy || !issue.previousVersion}>Restore Previous</Button>
                <Button icon={CheckCircle2} onClick={runTrust} disabled={busy}>Trust Changes</Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ExportVaultModal({ onCancel, onExport, onDone }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(""); setBusy(true);
    const result = await onExport(password);
    setBusy(false);
    if (result.ok) onDone(result.filename);
    else setError(result.error || "Couldn't export the vault.");
  };

  return (
    <Modal title="Export vault" onClose={onCancel} width={420}>
      <div style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 14, lineHeight: 1.6 }}>
        This saves a copy of your vault exactly as encrypted on disk (AES-256-GCM ciphertext) — not a plaintext dump.
        Anyone who gets the file still needs your master password to read anything from it, but treat it like a
        second copy of your vault and store it somewhere safe.
      </div>
      <Field label="Confirm your master password">
        <Input type="password" value={password} onChange={(e) => { setPassword(e.target.value); setError(""); }} autoFocus disabled={busy} />
      </Field>
      {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 12 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={submit} disabled={busy || !password}>{busy ? "Verifying…" : "Export"}</Button>
      </div>
    </Modal>
  );
}

function ImportVaultModal({ onCancel, onImport }) {
  const fileInputRef = useRef(null);
  const [fileName, setFileName] = useState("");
  const [parsedEnvelope, setParsedEnvelope] = useState(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const handleFile = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setError(""); setParsedEnvelope(null); setFileName("");
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (!parsed?.password?.salt || !parsed?.data?.ciphertext) {
        setError("That doesn't look like a valid SecureVault backup file.");
        return;
      }
      setParsedEnvelope(parsed);
      setFileName(file.name);
    } catch {
      setError("Couldn't read that file — make sure it's a SecureVault backup .json file.");
    }
  };

  const submit = async () => {
    setError(""); setBusy(true);
    const result = await onImport(parsedEnvelope, password);
    setBusy(false);
    if (!result.ok) setError(result.error || "Import failed.");
  };

  return (
    <Modal title="Import vault" onClose={onCancel} width={460}>
      <div style={{ fontSize: 12.5, color: "var(--coral)", marginBottom: 14, lineHeight: 1.6, background: "var(--coral-soft)", padding: 12, borderRadius: 8 }}>
        Importing replaces everything currently in this vault — passwords, notes, finances, goals, and events —
        with the contents of the backup file. This can't be undone.
      </div>
      <input ref={fileInputRef} type="file" accept=".json,application/json" onChange={handleFile} style={{ display: "none" }} />
      <Button variant="subtle" onClick={() => fileInputRef.current?.click()} disabled={busy}>{fileName || "Choose backup file…"}</Button>
      {parsedEnvelope && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 8 }}>File loaded — enter the master password used to create this backup:</div>
          <Field label="Backup's master password">
            <Input type="password" value={password} onChange={(e) => { setPassword(e.target.value); setError(""); }} autoFocus disabled={busy} />
          </Field>
        </div>
      )}
      {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 12 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button variant="danger" icon={CheckCircle2} onClick={submit} disabled={busy || !parsedEnvelope || !password}>{busy ? "Verifying…" : "Replace vault"}</Button>
      </div>
    </Modal>
  );
}

function SettingsView({ settings, setSettings, theme, toggleTheme, onLock, sessions, onEndSession, toast, onEraseLocalData, auth, onUpdateAccount, serverStatus, dataFilePath, onChangeMasterPassword, onSetupPin, onChangePin, onDisablePin, pinEnabled, onSetupBiometric, onDisableBiometric, biometricEnabled, biometricAvailable, biometricReason, onExportVault, onImportVault, onBackupNow }) {
  const [confirmDeleteAcct, setConfirmDeleteAcct] = useState(false);
  const [confirmErase, setConfirmErase] = useState(false);
  const [confirmDisablePin, setConfirmDisablePin] = useState(false);
  const [showChangePw, setShowChangePw] = useState(false);
  const [showChangePin, setShowChangePin] = useState(false);
  const [showSetupPin, setShowSetupPin] = useState(false);
  const [confirmDisableBiometric, setConfirmDisableBiometric] = useState(false);
  const [biometricBusy, setBiometricBusy] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [backupBusy, setBackupBusy] = useState(false);

  const [usernameDraft, setUsernameDraft] = useState(auth.username);
  const [emailDraft, setEmailDraft] = useState(auth.email);
  const accountDirty = usernameDraft !== auth.username || emailDraft !== auth.email;

  return (
    <div>
      <TopBar title="Settings" subtitle="Manage your account, security, and preferences" />
      <div style={{ padding: "0 28px 28px", maxWidth: 720 }}>
        {serverStatus !== "connected" && (
          <Card style={{ marginBottom: 16, borderColor: "var(--coral)" }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-start", fontSize: 12.5, color: "var(--coral)" }}>
              <ShieldAlert size={16} style={{ flexShrink: 0, marginTop: 1 }} />
              <div>
                Local server isn't running — changes you make right now will only live in this tab and will be lost on refresh.
                Run <span className="sv-mono">node server.js</span> in the project folder, then reload the page.
              </div>
            </div>
          </Card>
        )}

        <SettingsSection title="Account">
          <ProfilePictureRow avatar={auth.avatar} name={auth.username} onUpdateAccount={onUpdateAccount} toast={toast} />
          <Field label="Username"><Input value={usernameDraft} onChange={(e) => setUsernameDraft(e.target.value)} /></Field>
          <Field label="Email"><Input value={emailDraft} onChange={(e) => setEmailDraft(e.target.value)} /></Field>
          {accountDirty && (
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: -6 }}>
              <Button size="sm" variant="ghost" onClick={() => { setUsernameDraft(auth.username); setEmailDraft(auth.email); }}>Discard</Button>
              <Button size="sm" icon={CheckCircle2} onClick={() => { onUpdateAccount({ username: usernameDraft, email: emailDraft }); toast("Account details updated.", "success"); }} disabled={!usernameDraft || !emailDraft}>Save changes</Button>
            </div>
          )}
          <SettingRow label="Change master password" sub="Re-encrypts your vault key with a new password — your data itself doesn't need to be re-encrypted">
            <Button variant="subtle" size="sm" onClick={() => setShowChangePw(true)}>Change</Button>
          </SettingRow>
          <SettingRow label="Delete account" sub="Permanently erase your vault and the encrypted file on this PC">
            <Button variant="danger" size="sm" onClick={() => setConfirmDeleteAcct(true)}>Delete account</Button>
          </SettingRow>
        </SettingsSection>

        <SettingsSection title="Security">
          <SettingRow label="Two-factor authentication" sub="Require a code from your authenticator app at login">
            <Toggle checked={settings.twoFA} onChange={(v) => setSettings((s) => ({ ...s, twoFA: v }))} />
          </SettingRow>
          <SettingRow label="PIN unlock" sub={pinEnabled ? "Quickly unlock the vault with a short PIN" : "Not set up — enable to unlock with a short PIN instead of your full password"}>
            <Toggle checked={pinEnabled} onChange={(v) => { if (v) setShowSetupPin(true); else setConfirmDisablePin(true); }} />
          </SettingRow>
          {pinEnabled && (
            <SettingRow label="Change PIN" sub="Update the PIN used for quick unlock">
              <Button variant="subtle" size="sm" onClick={() => setShowChangePin(true)}>Change</Button>
            </SettingRow>
          )}
          <SettingRow
            label="Biometric authentication (Windows Hello)"
            sub={
              biometricEnabled ? "Unlock with fingerprint, face, or Windows Hello PIN"
                : biometricAvailable ? "Not set up — enable to unlock with Windows Hello"
                : biometricReason || "Not available on this device"
            }
          >
            <Toggle
              checked={biometricEnabled}
              onChange={async (v) => {
                if (v) {
                  if (!biometricAvailable) { toast(biometricReason || "Windows Hello isn't available on this device.", "danger"); return; }
                  setBiometricBusy(true);
                  const result = await onSetupBiometric();
                  setBiometricBusy(false);
                  if (result.ok) toast("Windows Hello unlock enabled.", "success");
                  else toast(result.error || "Couldn't set up Windows Hello.", "danger");
                } else {
                  setConfirmDisableBiometric(true);
                }
              }}
              disabled={biometricBusy || (!biometricEnabled && !biometricAvailable)}
            />
          </SettingRow>
          {biometricBusy && (
            <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: -8 }}>Follow the Windows Hello prompt…</div>
          )}
          <SettingRow label="Auto-lock after inactivity" sub="Vault locks automatically when idle">
            <Select value={settings.autoLock} onChange={(e) => setSettings((s) => ({ ...s, autoLock: e.target.value }))} style={{ width: 150 }}>
              <option value="1">1 minute</option><option value="5">5 minutes</option><option value="15">15 minutes</option>
              <option value="30">30 minutes</option><option value="never">Never</option>
            </Select>
          </SettingRow>
          <SettingRow label="Security notifications" sub="Email me about new logins and sensitive actions">
            <Toggle checked={settings.securityNotifs} onChange={(v) => setSettings((s) => ({ ...s, securityNotifs: v }))} />
          </SettingRow>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Active sessions</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {sessions.map((s) => (
                <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 12.5 }}>
                  <Smartphone size={14} color="var(--text-faint)" />
                  <span>{s.device}</span>
                  <span style={{ color: "var(--text-faint)" }}>· {s.lastActive}</span>
                  {!s.current && <Button size="sm" variant="ghost" onClick={() => onEndSession(s.id)} >End</Button>}
                </div>
              ))}
            </div>
            <div style={{ marginTop: 10 }}>
              <Button size="sm" variant="danger" icon={LogOut} onClick={() => toast("All other devices have been logged out.", "success")}>Log out all other devices</Button>
            </div>
          </div>
        </SettingsSection>

        <SettingsSection title="Appearance">
          <SettingRow label="Theme" sub="Choose light, dark, or match your system">
            <div style={{ display: "flex", gap: 6 }}>
              <Button size="sm" variant={theme === "light" ? "primary" : "subtle"} onClick={() => theme !== "light" && toggleTheme()}>Light</Button>
              <Button size="sm" variant={theme === "dark" ? "primary" : "subtle"} onClick={() => theme !== "dark" && toggleTheme()}>Dark</Button>
            </div>
          </SettingRow>
        </SettingsSection>

        <SettingsSection title="Privacy">
          <SettingRow label="Clipboard clear timeout" sub="Automatically clear copied passwords">
            <Select value={settings.clipboardTimeout} onChange={(e) => setSettings((s) => ({ ...s, clipboardTimeout: e.target.value }))} style={{ width: 150 }}>
              <option value="10">10 seconds</option><option value="30">30 seconds</option><option value="60">1 minute</option>
            </Select>
          </SettingRow>
          <SettingRow label="Hide financial values by default" sub="Mask amounts on the Finance page until revealed">
            <Toggle checked={settings.hideFinance} onChange={(v) => setSettings((s) => ({ ...s, hideFinance: v }))} />
          </SettingRow>
          <SettingRow label="Hide sensitive info by default" sub="Passwords and notes stay masked until you choose to reveal them">
            <Toggle checked={settings.hideSensitive} onChange={(v) => setSettings((s) => ({ ...s, hideSensitive: v }))} />
          </SettingRow>
        </SettingsSection>

        <SettingsSection title="Data">
          <SettingRow label="Export vault" sub="Requires re-authentication — creates an encrypted file">
            <Button variant="subtle" size="sm" onClick={() => setShowExport(true)}>Export</Button>
          </SettingRow>
          <SettingRow label="Import data" sub="Restore from a SecureVault backup file">
            <Button variant="subtle" size="sm" onClick={() => setShowImport(true)}>Import</Button>
          </SettingRow>
          <SettingRow label="Backup vault" sub="Create a full encrypted backup, saved right next to your vault file">
            <Button variant="subtle" size="sm" onClick={async () => {
              setBackupBusy(true);
              const result = await onBackupNow();
              setBackupBusy(false);
              if (result.ok) toast(`Backup saved: ${result.backupFile}`, "success");
              else toast(result.error || "Backup failed.", "danger");
            }} disabled={backupBusy}>{backupBusy ? "Backing up…" : "Backup now"}</Button>
          </SettingRow>
          <SettingRow label="Where is my data stored?" sub="Encrypted (AES-256-GCM) and saved as a real file on this PC — nothing is sent to any server on the internet">
            <Badge tone="mint">Encrypted, local only</Badge>
          </SettingRow>
          {dataFilePath && (
            <div className="sv-mono" style={{ fontSize: 11, color: "var(--text-faint)", marginTop: -8 }}>{dataFilePath}</div>
          )}
          <SettingRow label="Erase all local data" sub="Permanently clears everything saved on this device and restarts from scratch">
            <Button variant="danger" size="sm" onClick={() => setConfirmErase(true)}>Erase local data</Button>
          </SettingRow>
        </SettingsSection>
      </div>

      {confirmDeleteAcct && (
        <ConfirmDialog title="Delete account" message="This will permanently delete your account and everything in your vault, including the encrypted file saved on this PC. This action cannot be undone."
          confirmLabel="Delete my account" danger onCancel={() => setConfirmDeleteAcct(false)}
          onConfirm={() => { setConfirmDeleteAcct(false); onEraseLocalData(); toast("Account deleted. All local data has been erased.", "success"); }} />
      )}
      {confirmErase && (
        <ConfirmDialog title="Erase local data" message="This permanently deletes the encrypted vault file saved on this device. This cannot be undone."
          confirmLabel="Erase everything" danger onCancel={() => setConfirmErase(false)}
          onConfirm={() => { setConfirmErase(false); onEraseLocalData(); }} />
      )}
      {confirmDisablePin && (
        <ConfirmDialog title="Disable PIN unlock" message="You'll only be able to unlock the vault with your full master password from now on."
          confirmLabel="Disable PIN" danger onCancel={() => setConfirmDisablePin(false)}
          onConfirm={() => { setConfirmDisablePin(false); onDisablePin(); toast("PIN unlock disabled.", "success"); }} />
      )}
      {confirmDisableBiometric && (
        <ConfirmDialog title="Disable Windows Hello unlock" message="You'll no longer be able to unlock the vault with your fingerprint, face, or Windows Hello PIN."
          confirmLabel="Disable" danger onCancel={() => setConfirmDisableBiometric(false)}
          onConfirm={async () => { setConfirmDisableBiometric(false); await onDisableBiometric(); toast("Windows Hello unlock disabled.", "success"); }} />
      )}
      {showChangePw && (
        <ChangePasswordModal
          onCancel={() => setShowChangePw(false)}
          onSubmit={onChangeMasterPassword}
          onSuccess={() => { setShowChangePw(false); toast("Master password updated — re-encrypted with Argon2id.", "success"); }}
        />
      )}
      {showSetupPin && (
        <SetupPinModal
          onCancel={() => setShowSetupPin(false)}
          onSubmit={onSetupPin}
          onSuccess={() => { setShowSetupPin(false); toast("PIN unlock enabled.", "success"); }}
        />
      )}
      {showChangePin && (
        <ChangePinModal
          onCancel={() => setShowChangePin(false)}
          onSubmit={onChangePin}
          onSuccess={() => { setShowChangePin(false); toast("PIN updated.", "success"); }}
        />
      )}
      {showExport && (
        <ExportVaultModal
          onCancel={() => setShowExport(false)}
          onExport={onExportVault}
          onDone={(filename) => { setShowExport(false); toast(`Vault exported${filename ? ` as ${filename}` : ""}.`, "success"); }}
        />
      )}
      {showImport && (
        <ImportVaultModal
          onCancel={() => setShowImport(false)}
          onImport={async (envelope, password) => {
            const result = await onImportVault(envelope, password);
            if (result.ok) { setShowImport(false); toast("Vault imported successfully.", "success"); }
            return result;
          }}
        />
      )}
    </div>
  );
}

function ChangePasswordModal({ onCancel, onSubmit, onSuccess }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (next.length < 8) { setError("New password must be at least 8 characters."); return; }
    if (next !== confirm) { setError("New passwords don't match."); return; }
    setError(""); setBusy(true);
    const result = await onSubmit(current, next);
    setBusy(false);
    if (result.ok) onSuccess();
    else setError(result.error || "Current master password is incorrect.");
  };

  return (
    <Modal title="Change master password" onClose={onCancel} width={420}>
      <Field label="Current master password"><Input type="password" value={current} onChange={(e) => { setCurrent(e.target.value); setError(""); }} autoFocus disabled={busy} /></Field>
      <Field label="New master password"><Input type="password" value={next} onChange={(e) => { setNext(e.target.value); setError(""); }} disabled={busy} /></Field>
      {next && <div style={{ marginTop: -8, marginBottom: 14 }}><StrengthMeter password={next} /></div>}
      <Field label="Confirm new password"><Input type="password" value={confirm} onChange={(e) => { setConfirm(e.target.value); setError(""); }} disabled={busy} /></Field>
      {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 12 }}>{error}</div>}
      <div style={{ fontSize: 11, color: "var(--text-faint)", marginBottom: 14 }}>Verifying your current password runs Argon2id, so this may take a moment.</div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={submit} disabled={busy || !current || !next || !confirm}>{busy ? "Verifying…" : "Update password"}</Button>
      </div>
    </Modal>
  );
}

function SetupPinModal({ onCancel, onSubmit, onSuccess }) {
  const [pin, setPin] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const numeric = (setter) => (e) => setter(e.target.value.replace(/\D/g, ""));

  const submit = async () => {
    if (pin.length < 4 || pin.length > 6) { setError("PIN must be 4–6 digits."); return; }
    if (pin !== confirm) { setError("PINs don't match."); return; }
    setError(""); setBusy(true);
    await onSubmit(pin);
    setBusy(false);
    onSuccess();
  };

  return (
    <Modal title="Set up PIN unlock" onClose={onCancel} width={380}>
      <Field label="New PIN"><Input type="password" inputMode="numeric" maxLength={6} value={pin} onChange={(e) => { numeric(setPin)(e); setError(""); }} autoFocus disabled={busy} style={{ textAlign: "center", letterSpacing: 6 }} /></Field>
      <Field label="Confirm PIN"><Input type="password" inputMode="numeric" maxLength={6} value={confirm} onChange={(e) => { numeric(setConfirm)(e); setError(""); }} disabled={busy} style={{ textAlign: "center", letterSpacing: 6 }} /></Field>
      {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 12 }}>{error}</div>}
      <div style={{ fontSize: 11, color: "var(--text-faint)", marginBottom: 14, lineHeight: 1.6 }}>Your PIN gets its own encrypted copy of the vault key, separate from your master password — it's a convenience path, so it's worth keeping your PIN non-obvious.</div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={submit} disabled={busy || !pin || !confirm}>{busy ? "Setting up…" : "Enable PIN"}</Button>
      </div>
    </Modal>
  );
}

function ChangePinModal({ onCancel, onSubmit, onSuccess }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const numeric = (setter) => (e) => setter(e.target.value.replace(/\D/g, ""));

  const submit = async () => {
    if (next.length < 4 || next.length > 6) { setError("PIN must be 4–6 digits."); return; }
    if (next !== confirm) { setError("New PINs don't match."); return; }
    setError(""); setBusy(true);
    const result = await onSubmit(current, next);
    setBusy(false);
    if (result.ok) onSuccess();
    else setError(result.error || "Current PIN is incorrect.");
  };

  return (
    <Modal title="Change PIN" onClose={onCancel} width={380}>
      <Field label="Current PIN"><Input type="password" inputMode="numeric" maxLength={6} value={current} onChange={(e) => { numeric(setCurrent)(e); setError(""); }} autoFocus disabled={busy} style={{ textAlign: "center", letterSpacing: 6 }} /></Field>
      <Field label="New PIN"><Input type="password" inputMode="numeric" maxLength={6} value={next} onChange={(e) => { numeric(setNext)(e); setError(""); }} disabled={busy} style={{ textAlign: "center", letterSpacing: 6 }} /></Field>
      <Field label="Confirm new PIN"><Input type="password" inputMode="numeric" maxLength={6} value={confirm} onChange={(e) => { numeric(setConfirm)(e); setError(""); }} disabled={busy} style={{ textAlign: "center", letterSpacing: 6 }} /></Field>
      {error && <div style={{ color: "var(--coral)", fontSize: 12, marginBottom: 12 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button icon={CheckCircle2} onClick={submit} disabled={busy || !current || !next || !confirm}>{busy ? "Verifying…" : "Update PIN"}</Button>
      </div>
    </Modal>
  );
}

/* ---------------------------------------------------------------------- */
/* Main App                                                               */
/* ---------------------------------------------------------------------- */

const DEFAULT_SETTINGS = {
  twoFA: true, biometric: false, autoLock: "5", securityNotifs: true,
  clipboardTimeout: "30", hideFinance: false, hideSensitive: true,
};
const DEFAULT_AUTH = { username: "jreyes", email: "j.reyes@gmail.com", avatar: null };

function BootScreen({ serverStatus }) {
  return (
    <div className="sv-root dark" style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 14 }}>
      <FontStyles />
      <ShieldCheck size={30} color="var(--primary)" style={{ opacity: 0.8 }} />
      <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
        {serverStatus === "checking" ? "Connecting to your local vault…" : "Loading…"}
      </div>
    </div>
  );
}

export default function App() {
  // "checking" -> "connected" (server + D:\Local Data reachable) -> "offline" (server not running)
  const [serverStatus, setServerStatus] = useState("checking");
  const [dataFilePath, setDataFilePath] = useState("");
  const [booted, setBooted] = useState(false);

  // The encrypted envelope as it exists on disk (salts, IVs, wrapped keys,
  // ciphertext). null = no vault created yet on this machine.
  const [envelope, setEnvelope] = useState(null);
  // The raw 32-byte vault key K, held only in memory, only while unlocked.
  // This is what actually decrypts/encrypts your data — it's never written
  // to disk on its own, only wrapped (encrypted) by your password/PIN.
  const vaultKeyRef = useRef(null);

  const [locked, setLocked] = useState(true);
  const [view, setView] = useState("dashboard");
  const [theme, setTheme] = useState("dark");
  const [modal, setModal] = useState(null); // { type, data }
  const [noteViewDeleteTarget, setNoteViewDeleteTarget] = useState(null);
  const [contactViewDeleteTarget, setContactViewDeleteTarget] = useState(null);
  const [transactionViewDeleteTarget, setTransactionViewDeleteTarget] = useState(null);
  const [toasts, setToasts] = useState([]);

  const [passwords, setPasswords] = useState([]);
  const [notes, setNotes] = useState([]);
  const [transactions, setTransactions] = useState([]);
  const [budgets, setBudgets] = useState([]);
  const [goals, setGoals] = useState([]);
  const [generalSavings, setGeneralSavings] = useState({ balance: 0, history: [] });
  // Manual correction applied on top of the computed "new money" savings
  // total shown in Finance — lets the figure be fixed directly when it's
  // drifted from testing or a miscategorized deposit, without touching
  // any individual goal or savings balance.
  const [savingsAdjustment, setSavingsAdjustment] = useState(0);
  const [events, setEvents] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [trash, setTrash] = useState([]);
  const [activity, setActivity] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [auth, setAuth] = useState(DEFAULT_AUTH);

  // Vault Integrity Protection — non-null when the file on disk doesn't
  // match what the server last legitimately wrote (edited, corrupted,
  // replaced, or rolled back outside the app).
  const [integrityIssue, setIntegrityIssue] = useState(null);
  // The snapshot file that represented the vault's state immediately
  // before the last restore — lets Security Center offer a one-click
  // "Undo restore" without hunting through the version list.
  const [lastRestoreUndo, setLastRestoreUndo] = useState(null);

  // Windows Hello availability — only meaningful inside the Electron app,
  // where preload.cjs exposes window.secureVaultNative.
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricReason, setBiometricReason] = useState("");
  useEffect(() => {
    (async () => {
      if (typeof window !== "undefined" && window.secureVaultNative) {
        const res = await window.secureVaultNative.biometricCheck();
        setBiometricAvailable(!!res.supported);
        setBiometricReason(res.reason || "");
      } else {
        setBiometricReason("Biometric unlock only works in the SecureVault desktop app.");
      }
    })();
  }, []);

  const toast = useCallback((message, tone = "info") => {
    const id = uid();
    setToasts((t) => [...t, { id, message, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);
  const dismissToast = (id) => setToasts((t) => t.filter((x) => x.id !== id));

  const logActivity = useCallback((type, detail) => {
    setActivity((a) => [{ id: uid(), type, detail, ts: new Date().toISOString().slice(0, 10) }, ...a]);
  }, []);

  // ---- Boot: ping the local server, then load the encrypted envelope -----
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ping = await pingLocalServer();
      if (cancelled) return;
      if (!ping) {
        setServerStatus("offline");
        setBooted(true);
        return;
      }
      setServerStatus("connected");
      setDataFilePath(ping.dataFile || "D:\\Local Data\\securevault-data.json");
      const { envelope: env, integrity } = await loadEnvelope();
      if (cancelled) return;
      setEnvelope(env); // null => VaultSetupScreen will be shown
      if (env && integrity && integrity.status !== "ok") setIntegrityIssue(integrity);
      setBooted(true);
    })();
    return () => { cancelled = true; };
  }, []);

  // ---- Ongoing watch: re-check integrity periodically while unlocked so a
  // file changed by something else *while the app is running* still gets
  // caught, not just at startup.
  useEffect(() => {
    if (locked || serverStatus !== "connected") return;
    const interval = setInterval(async () => {
      const result = await checkIntegrity();
      if (result && result.status !== "ok") setIntegrityIssue((prev) => prev || result);
    }, 60000);
    return () => clearInterval(interval);
  }, [locked, serverStatus]);

  function loadDecryptedIntoState(data) {
    setPasswords(data.passwords || initialPasswords);
    setNotes(data.notes || initialNotes);
    setTransactions(data.transactions || initialTransactions);
    setBudgets(data.budgets || initialBudgets);
    setGoals(data.goals || initialGoals);
    setGeneralSavings(data.generalSavings || { balance: 0, history: [] });
    setSavingsAdjustment(data.savingsAdjustment || 0);
    setEvents(data.events || initialEvents);
    setContacts(data.contacts || initialContacts);
    setActivity(data.activity || initialActivity);
    setSessions(data.sessions || SESSIONS);
    setSettings(data.settings || DEFAULT_SETTINGS);
    setAuth(data.auth || DEFAULT_AUTH);
    setTheme(data.theme || "dark");
    // Auto-purge anything that's been in trash longer than the retention window.
    const loadedTrash = data.trash || [];
    setTrash(loadedTrash.filter((e) => trashAgeDays(e.deletedAt) <= TRASH_RETENTION_DAYS));
  }

  // ---- First run: create a brand-new encrypted vault ----------------------
  const handleCreateVault = async (masterPassword) => {
    const initialData = {
      passwords: initialPasswords, notes: initialNotes, transactions: initialTransactions,
      budgets: initialBudgets, goals: initialGoals, generalSavings: { balance: 0, history: [] }, savingsAdjustment: 0, events: initialEvents, contacts: initialContacts, trash: [], activity: initialActivity, sessions: SESSIONS,
      settings: DEFAULT_SETTINGS, auth: DEFAULT_AUTH, theme: "dark",
    };
    const { envelope: newEnvelope, vaultKeyBytes } = await createVaultEnvelope(masterPassword, initialData);
    vaultKeyRef.current = vaultKeyBytes;
    setEnvelope(newEnvelope);
    loadDecryptedIntoState(initialData);
    setLocked(false);
    if (serverStatus === "connected") await saveEnvelope(newEnvelope);
    toast("Vault created and encrypted with your master password.", "success");
  };

  // ---- Unlock -------------------------------------------------------------
  const handleUnlockWithPassword = async (password) => {
    try {
      const { vaultKeyBytes, data } = await unlockWithPasswordEnvelope(envelope, password);
      vaultKeyRef.current = vaultKeyBytes;
      loadDecryptedIntoState(data);
      setLocked(false);
      logActivity("vault_unlocked", "Vault unlocked with master password");
      toast("Vault unlocked.", "success");
      return { ok: true };
    } catch {
      return { ok: false, error: "Incorrect master password." };
    }
  };
  const handleUnlockWithPin = async (pin) => {
    try {
      const { vaultKeyBytes, data } = await unlockWithPinEnvelope(envelope, pin);
      vaultKeyRef.current = vaultKeyBytes;
      loadDecryptedIntoState(data);
      setLocked(false);
      logActivity("vault_unlocked", "Vault unlocked with PIN");
      toast("Vault unlocked.", "success");
      return { ok: true };
    } catch {
      return { ok: false, error: "Incorrect PIN." };
    }
  };

  // ---- Lock: clear the key and sensitive state from memory ---------------
  const handleLock = () => {
    logActivity("vault_locked", "Vault locked");
    vaultKeyRef.current = null;
    setPasswords([]);
    setNotes([]);
    setTransactions([]);
    setBudgets([]);
    setGoals([]);
    setGeneralSavings({ balance: 0, history: [] });
    setSavingsAdjustment(0);
    setEvents([]);
    setContacts([]);
    setTrash([]);
    setModal(null);
    setLastRestoreUndo(null);
    setLocked(true);
  };

  // ---- Save: debounced re-encryption + write of the data blob ------------
  const saveTimer = useRef(null);
  const warnedOffline = useRef(false);
  useEffect(() => {
    // Pause auto-save entirely while an integrity issue is unresolved — we
    // don't want to silently overwrite a tampered/rolled-back file with a
    // re-encryption of whatever's currently in memory before the user has
    // chosen how to handle it.
    if (!booted || locked || serverStatus !== "connected" || !vaultKeyRef.current || !envelope || integrityIssue) return;
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(async () => {
      const dataObj = { passwords, notes, transactions, budgets, goals, generalSavings, savingsAdjustment, events, contacts, trash, activity, sessions, settings, auth, theme };
      const dataEnc = await encryptVaultData(vaultKeyRef.current, dataObj);
      const newEnvelope = { ...envelope, data: dataEnc, updatedAt: new Date().toISOString() };
      setEnvelope(newEnvelope);
      const ok = await saveEnvelope(newEnvelope);
      if (!ok && !warnedOffline.current) {
        warnedOffline.current = true;
        toast("Couldn't reach the local server — changes aren't being saved to D:\\Local Data right now.", "danger");
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, 500);
    return () => clearTimeout(saveTimer.current);
    // envelope intentionally excluded — it's updated as a *result* of this
    // effect, not a trigger for it, to avoid a save loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [passwords, notes, transactions, budgets, goals, generalSavings, savingsAdjustment, events, contacts, trash, activity, sessions, settings, auth, theme, booted, locked, serverStatus, integrityIssue]);

  /* auto-lock on inactivity */
  const idleTimer = useRef(null);
  useEffect(() => {
    if (locked || settings.autoLock === "never") return;
    const ms = Number(settings.autoLock) * 60 * 1000;
    const reset = () => {
      clearTimeout(idleTimer.current);
      idleTimer.current = setTimeout(() => { handleLock(); }, ms);
    };
    reset();
    const events = ["mousemove", "keydown", "click"];
    events.forEach((e) => window.addEventListener(e, reset));
    return () => { clearTimeout(idleTimer.current); events.forEach((e) => window.removeEventListener(e, reset)); };
  }, [locked, settings.autoLock]);

  const openModal = (type, data) => setModal({ type, data });
  const closeModal = () => setModal(null);

  /* keyboard shortcuts */
  useEffect(() => {
    const onKey = (e) => {
      const ctrl = e.ctrlKey || e.metaKey;
      if (ctrl && e.key.toLowerCase() === "k") { e.preventDefault(); if (!locked) openModal("search"); }
      if (ctrl && e.key.toLowerCase() === "l") { e.preventDefault(); if (!locked) handleLock(); }
      if (ctrl && e.key.toLowerCase() === "n") {
        e.preventDefault();
        if (!locked) {
          if (view === "passwords") openModal("password-add");
          else if (view === "notes") openModal("note-add");
          else if (view === "finance") openModal("transaction-add", { type: "expense" });
          else if (view === "budgets") openModal("budget-add");
          else if (view === "goals") openModal("goal-add");
          else if (view === "planner") openModal("event-add", { date: todayStr() });
          else if (view === "contacts") openModal("contact-add");
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [locked, view]);

  /* CRUD helpers */
  const savePassword = (form) => {
    const tags = typeof form.tags === "string" ? form.tags.split(",").map((t) => t.trim()).filter(Boolean) : form.tags;
    if (form.id) {
      setPasswords((ps) => ps.map((p) => p.id === form.id ? { ...p, ...form, tags, updatedAt: daysAgo(0) } : p));
      logActivity("password_updated", `Updated password for ${form.title}`);
      toast("Password updated.", "success");
    } else {
      setPasswords((ps) => [{ ...form, id: uid(), tags, createdAt: daysAgo(0), updatedAt: daysAgo(0) }, ...ps]);
      logActivity("password_added", `Added password for ${form.title}`);
      toast("Password saved.", "success");
    }
    closeModal();
  };
  // ---- Shared soft-delete helper: move an item to Trash instead of -------
  // wiping it immediately. Items sit here for TRASH_RETENTION_DAYS before
  // being auto-purged.
  const moveToTrash = (type, item) => {
    setTrash((t) => [{ id: uid(), type, item, deletedAt: daysAgo(0) }, ...t]);
  };

  const deletePassword = (id) => {
    const p = passwords.find((x) => x.id === id);
    setPasswords((ps) => ps.filter((x) => x.id !== id));
    if (p) {
      moveToTrash("password", p);
      logActivity("password_updated", `Moved password for ${p.title} to Trash`);
      toast("Password moved to Trash.", "success");
    }
  };

  const saveNote = (form) => {
    const tags = typeof form.tags === "string" ? form.tags.split(",").map((t) => t.trim()).filter(Boolean) : form.tags;
    if (form.id) {
      setNotes((ns) => ns.map((n) => n.id === form.id ? { ...n, ...form, tags, updatedAt: daysAgo(0) } : n));
      toast("Note updated.", "success");
    } else {
      setNotes((ns) => [{ ...form, id: uid(), tags, pinned: false, archived: false, createdAt: daysAgo(0), updatedAt: daysAgo(0) }, ...ns]);
      logActivity("note_created", `Created note — ${form.title}`);
      toast("Note saved.", "success");
    }
    closeModal();
  };
  // Imports one full note per file — files are never merged into a single
  // note, even when several are selected at once.
  const importNotes = (newNotes, failed = []) => {
    if (newNotes.length) {
      const now = daysAgo(0);
      setNotes((ns) => [
        ...newNotes.map((n) => ({ ...n, id: uid(), pinned: false, archived: false, createdAt: now, updatedAt: now })),
        ...ns,
      ]);
      logActivity("note_created", `Imported ${newNotes.length} note${newNotes.length === 1 ? "" : "s"} from file${newNotes.length === 1 ? "" : "s"}`);
    }
    if (newNotes.length && !failed.length) {
      toast(`Imported ${newNotes.length} note${newNotes.length === 1 ? "" : "s"}.`, "success");
    } else if (newNotes.length && failed.length) {
      toast(`Imported ${newNotes.length} note${newNotes.length === 1 ? "" : "s"} — ${failed.length} file${failed.length === 1 ? "" : "s"} skipped (${failed.map((f) => f.name).join(", ")}).`, "info");
    } else if (failed.length) {
      toast(`Couldn't import ${failed.length} file${failed.length === 1 ? "" : "s"} — only plain text files (.txt, .md) under 2MB are supported.`, "danger");
    }
  };
  const deleteNote = (id) => {
    const n = notes.find((x) => x.id === id);
    setNotes((ns) => ns.filter((x) => x.id !== id));
    if (n) moveToTrash("note", n);
    toast("Note moved to Trash.", "success");
  };
  const togglePin = (id) => setNotes((ns) => ns.map((n) => n.id === id ? { ...n, pinned: !n.pinned } : n));
  const toggleArchive = (id) => setNotes((ns) => ns.map((n) => n.id === id ? { ...n, archived: !n.archived } : n));

  const saveTransaction = (form) => {
    if (form.id) {
      setTransactions((ts) => ts.map((t) => t.id === form.id ? { ...t, ...form } : t));
      toast("Transaction updated.", "success");
    } else {
      setTransactions((ts) => [{ ...form, id: uid() }, ...ts]);
      logActivity(form.type === "income" ? "income_recorded" : "expense_recorded", `Recorded ${form.type} — ${form.party}`);
      toast(`${form.type === "income" ? "Income" : "Expense"} recorded.`, "success");
    }
    closeModal();
  };
  const deleteTransaction = (id) => {
    const t = transactions.find((x) => x.id === id);
    setTransactions((ts) => ts.filter((x) => x.id !== id));
    if (t) moveToTrash("transaction", t);
    toast("Transaction moved to Trash.", "success");
  };

  const saveBudget = (form) => {
    if (form.id) { setBudgets((bs) => bs.map((b) => b.id === form.id ? { ...b, ...form } : b)); toast("Budget updated.", "success"); }
    else { setBudgets((bs) => [{ ...form, id: uid() }, ...bs]); toast("Budget created.", "success"); }
    closeModal();
  };
  const deleteBudget = (id) => {
    const b = budgets.find((x) => x.id === id);
    setBudgets((bs) => bs.filter((x) => x.id !== id));
    if (b) moveToTrash("budget", b);
    toast("Budget moved to Trash.", "success");
  };

  const saveGoal = (form) => {
    if (form.id) {
      setGoals((gs) => gs.map((g) => g.id === form.id ? { ...g, ...form } : g));
      toast("Goal updated.", "success");
    } else {
      setGoals((gs) => [{ ...form, id: uid(), createdAt: daysAgo(0), contributions: [] }, ...gs]);
      logActivity("goal_created", `Created savings goal — ${form.title}`);
      toast("Goal created.", "success");
    }
    closeModal();
  };
  const deleteGoal = (id) => {
    const g = goals.find((x) => x.id === id);
    setGoals((gs) => gs.filter((x) => x.id !== id));
    if (g) moveToTrash("goal", g);
    toast("Goal moved to Trash.", "success");
  };
  // ---- Unified savings deposit/withdraw, for both goals and General -----
  // Savings. A "balance" deposit creates a real linked Expense transaction
  // (category "Savings") so Available Balance actually goes down and it's
  // visible in Finance. An "external" deposit doesn't touch a transaction
  // at all — it's money that wasn't already counted as income.
  const depositToSavings = (target, entry) => {
    const { amount, date, note, source } = entry;
    const label = target.type === "goal" ? target.goal.title : "General Savings";

    if (source === "balance") {
      const txn = {
        id: uid(), type: "expense", amount, category: "Savings",
        party: `Transfer to ${label}`, date, description: note || `Moved to ${label}`,
        recurring: false, method: "",
      };
      setTransactions((ts) => [txn, ...ts]);
    }
    if (source === "general") {
      setGeneralSavings((gs) => ({ ...gs, balance: Math.max(0, gs.balance - amount) }));
    }

    if (target.type === "goal") {
      setGoals((gs) => gs.map((g) => {
        if (g.id !== target.goal.id) return g;
        const newAmount = g.currentAmount + amount;
        const reached = newAmount >= g.targetAmount && g.currentAmount < g.targetAmount;
        if (reached) toast(`🎉 "${g.title}" goal reached!`, "success");
        return { ...g, currentAmount: newAmount, contributions: [{ id: uid(), amount, date, note, source }, ...g.contributions] };
      }));
      const sourceNote = source === "balance" ? " from available balance" : source === "general" ? " from General Savings" : "";
      logActivity("goal_contribution", `Added ${fmtMoney(amount)} to "${label}"${sourceNote}`);
    } else {
      setGeneralSavings((gs) => ({
        balance: gs.balance + amount,
        history: [{ id: uid(), type: "deposit", amount, date, note, source }, ...gs.history],
      }));
      logActivity("goal_contribution", `Added ${fmtMoney(amount)} to General Savings${source === "balance" ? " from available balance" : ""}`);
    }

    const toastMsg = source === "balance" ? `${fmtMoney(amount)} moved to ${label} — recorded as an expense.`
      : source === "general" ? `${fmtMoney(amount)} moved from General Savings to ${label}.`
      : `${fmtMoney(amount)} added to ${label}.`;
    toast(toastMsg, "success");
    closeModal();
  };

  const withdrawFromSavings = (target, entry) => {
    const { amount, date, note, destination } = entry;
    const label = target.type === "goal" ? target.goal.title : "General Savings";

    if (destination === "balance") {
      const txn = {
        id: uid(), type: "income", amount, category: "Savings",
        party: `Withdrawal from ${label}`, date, description: note || `Withdrawn from ${label}`,
        recurring: false, method: "",
      };
      setTransactions((ts) => [txn, ...ts]);
    }

    if (target.type === "goal") {
      setGoals((gs) => gs.map((g) => g.id === target.goal.id
        ? { ...g, currentAmount: Math.max(0, g.currentAmount - amount), contributions: [{ id: uid(), amount: -amount, date, note, source: "withdraw" }, ...g.contributions] }
        : g));
    } else {
      setGeneralSavings((gs) => ({
        balance: Math.max(0, gs.balance - amount),
        history: [{ id: uid(), type: "withdraw", amount, date, note, destination }, ...gs.history],
      }));
    }
    logActivity("goal_contribution", `Withdrew ${fmtMoney(amount)} from ${label}${destination === "balance" ? " back to available balance" : " as physical cash"}`);
    toast(destination === "balance" ? `${fmtMoney(amount)} withdrawn — added back to your available balance.` : `${fmtMoney(amount)} withdrawn as cash from ${label}.`, "success");
    closeModal();
  };

  const saveEvent = (form) => {
    if (form.id) {
      setEvents((es) => es.map((e) => e.id === form.id ? { ...e, ...form } : e));
      toast("Event updated.", "success");
    } else {
      setEvents((es) => [{ ...form, id: uid(), completedDates: [], createdAt: daysAgo(0) }, ...es]);
      logActivity("event_created", `Added event — ${form.title} (${fmtDate(form.date)})`);
      toast("Event added.", "success");
    }
    closeModal();
  };
  const deleteEvent = (id) => {
    const e = events.find((x) => x.id === id);
    setEvents((es) => es.filter((x) => x.id !== id));
    if (e) moveToTrash("event", e);
    toast("Event moved to Trash.", "success");
  };
  const toggleEventComplete = (id, occurrenceDate) => {
    setEvents((es) => es.map((e) => {
      if (e.id !== id) return e;
      const dates = e.completedDates || [];
      const isDone = dates.includes(occurrenceDate);
      return { ...e, completedDates: isDone ? dates.filter((d) => d !== occurrenceDate) : [...dates, occurrenceDate] };
    }));
  };

  const saveContact = (form) => {
    const tags = typeof form.tags === "string" ? form.tags.split(",").map((t) => t.trim()).filter(Boolean) : form.tags;
    if (form.id) {
      setContacts((cs) => cs.map((c) => c.id === form.id ? { ...c, ...form, tags, updatedAt: daysAgo(0) } : c));
      toast("Contact updated.", "success");
    } else {
      setContacts((cs) => [{ ...form, id: uid(), tags, favorite: false, createdAt: daysAgo(0), updatedAt: daysAgo(0) }, ...cs]);
      logActivity("contact_created", `Added contact — ${form.name}`);
      toast("Contact saved.", "success");
    }
    closeModal();
  };
  const deleteContact = (id) => {
    const c = contacts.find((x) => x.id === id);
    setContacts((cs) => cs.filter((x) => x.id !== id));
    if (c) moveToTrash("contact", c);
    toast("Contact moved to Trash.", "success");
  };
  const toggleContactFavorite = (id) => {
    setContacts((cs) => cs.map((c) => c.id === id ? { ...c, favorite: !c.favorite } : c));
  };

  const endSession = (id) => { setSessions((s) => s.filter((x) => x.id !== id)); toast("Session ended.", "success"); };

  // ---- Trash: restore, permanently delete, or empty ----------------------
  const restoreFromTrash = (trashId) => {
    const entry = trash.find((t) => t.id === trashId);
    if (!entry) return;
    setTrash((t) => t.filter((x) => x.id !== trashId));
    switch (entry.type) {
      case "password": setPasswords((ps) => [entry.item, ...ps]); break;
      case "note": setNotes((ns) => [entry.item, ...ns]); break;
      case "transaction": setTransactions((ts) => [entry.item, ...ts]); break;
      case "budget": setBudgets((bs) => [entry.item, ...bs]); break;
      case "goal": setGoals((gs) => [entry.item, ...gs]); break;
      case "event": setEvents((es) => [entry.item, ...es]); break;
      case "contact": setContacts((cs) => [entry.item, ...cs]); break;
      default: break;
    }
    toast(`${TRASH_TYPE_META[entry.type]?.label || "Item"} restored.`, "success");
  };
  const deleteForever = (trashId) => {
    setTrash((t) => t.filter((x) => x.id !== trashId));
    toast("Permanently deleted.", "success");
  };
  const emptyTrash = () => {
    setTrash([]);
    toast("Trash emptied.", "success");
  };


  const eraseLocalData = async () => {
    if (serverStatus === "connected") await deleteEnvelope();
    vaultKeyRef.current = null;
    setEnvelope(null);
    setPasswords([]); setNotes([]); setTransactions([]); setBudgets([]); setGoals([]); setGeneralSavings({ balance: 0, history: [] }); setSavingsAdjustment(0); setEvents([]); setContacts([]); setTrash([]); setActivity([]); setSessions([]);
    setSettings(DEFAULT_SETTINGS); setAuth(DEFAULT_AUTH);
    setLocked(true);
    toast("All local data erased. Set a new master password to create a fresh vault.", "success");
  };

  const updateAccount = (fields) => {
    setAuth((a) => ({ ...a, ...fields }));
  };

  // ---- Change master password: verify current, then re-wrap K -----------
  const changeMasterPassword = async (currentPassword, newPassword) => {
    try {
      await unwrapVaultKey(currentPassword, b64ToBytes(envelope.password.salt), envelope.password.params, envelope.password.iv, envelope.password.wrappedKey);
    } catch {
      return { ok: false, error: "Current master password is incorrect." };
    }
    const newMeta = await rewrapPassword(vaultKeyRef.current, newPassword);
    const newEnvelope = { ...envelope, password: newMeta, updatedAt: new Date().toISOString() };
    setEnvelope(newEnvelope);
    if (serverStatus === "connected") await saveEnvelope(newEnvelope);
    logActivity("security_change", "Master password changed");
    return { ok: true };
  };

  // ---- Set up a PIN for the first time (no current PIN to verify) --------
  const setupPin = async (newPin) => {
    const newMeta = await rewrapPin(vaultKeyRef.current, newPin);
    const newEnvelope = { ...envelope, pin: newMeta, updatedAt: new Date().toISOString() };
    setEnvelope(newEnvelope);
    setSettings((s) => ({ ...s, pin: true }));
    if (serverStatus === "connected") await saveEnvelope(newEnvelope);
    logActivity("security_change", "PIN unlock enabled");
    return { ok: true };
  };

  // ---- Change an existing PIN: verify current, then re-wrap K -----------
  const changePin = async (currentPin, newPin) => {
    try {
      await unwrapVaultKey(currentPin, b64ToBytes(envelope.pin.salt), envelope.pin.params, envelope.pin.iv, envelope.pin.wrappedKey);
    } catch {
      return { ok: false, error: "Current PIN is incorrect." };
    }
    const newMeta = await rewrapPin(vaultKeyRef.current, newPin);
    const newEnvelope = { ...envelope, pin: newMeta, updatedAt: new Date().toISOString() };
    setEnvelope(newEnvelope);
    if (serverStatus === "connected") await saveEnvelope(newEnvelope);
    logActivity("security_change", "PIN changed");
    return { ok: true };
  };

  const disablePin = async () => {
    const newEnvelope = { ...envelope, pin: null, updatedAt: new Date().toISOString() };
    setEnvelope(newEnvelope);
    setSettings((s) => ({ ...s, pin: false }));
    if (serverStatus === "connected") await saveEnvelope(newEnvelope);
    logActivity("security_change", "PIN unlock disabled");
  };

  // ---- Biometric (Windows Hello) setup/disable/unlock --------------------
  const setupBiometric = async () => {
    if (!window.secureVaultNative) return { ok: false, error: "Biometric unlock only works in the SecureVault desktop app." };
    const res = await window.secureVaultNative.biometricProtect(bytesToB64(vaultKeyRef.current));
    if (!res.ok) return { ok: false, error: res.error };
    const newEnvelope = { ...envelope, biometric: { protectedKey: res.protected }, updatedAt: new Date().toISOString() };
    setEnvelope(newEnvelope);
    setSettings((s) => ({ ...s, biometric: true }));
    if (serverStatus === "connected") await saveEnvelope(newEnvelope);
    logActivity("security_change", "Windows Hello unlock enabled");
    return { ok: true };
  };

  const disableBiometric = async () => {
    const newEnvelope = { ...envelope, biometric: null, updatedAt: new Date().toISOString() };
    setEnvelope(newEnvelope);
    setSettings((s) => ({ ...s, biometric: false }));
    if (serverStatus === "connected") await saveEnvelope(newEnvelope);
    logActivity("security_change", "Windows Hello unlock disabled");
  };

  // ---- Export: re-verify master password, then download the on-disk ------
  // encrypted envelope as-is (ciphertext only, nothing decrypted).
  const exportVault = async (password) => {
    try {
      await unwrapVaultKey(password, b64ToBytes(envelope.password.salt), envelope.password.params, envelope.password.iv, envelope.password.wrappedKey);
    } catch {
      return { ok: false, error: "Incorrect master password." };
    }
    const filename = `securevault-backup-${new Date().toISOString().slice(0, 10)}.json`;
    downloadJSON(filename, envelope);
    logActivity("security_change", "Exported encrypted vault backup");
    return { ok: true, filename };
  };

  // ---- Import: unlock the chosen backup file with its own master ---------
  // password, then swap it in as the active vault (and save it locally).
  const importVault = async (importedEnvelope, password) => {
    try {
      const { vaultKeyBytes, data } = await unlockWithPasswordEnvelope(importedEnvelope, password);
      vaultKeyRef.current = vaultKeyBytes;
      setEnvelope(importedEnvelope);
      loadDecryptedIntoState(data);
      if (serverStatus === "connected") await saveEnvelope(importedEnvelope);
      logActivity("security_change", "Imported vault from backup file");
      return { ok: true };
    } catch {
      return { ok: false, error: "Incorrect master password for this backup file, or the file is invalid." };
    }
  };

  // ---- Vault Integrity Protection: resolve handlers -----------------------
  // After any of these, whatever's now on disk becomes the new baseline the
  // server checks future loads against.

  const resolveIntegrityTrust = async () => {
    const result = await trustCurrentFile();
    if (!result.ok) { toast(result.error || "Couldn't trust the current file.", "danger"); return; }
    setEnvelope(result.data);
    if (!locked && vaultKeyRef.current) {
      try {
        const K = await importAesKey(vaultKeyRef.current);
        const data = await aesDecryptJSON(K, result.data.data.iv, result.data.data.ciphertext);
        loadDecryptedIntoState(data);
        toast("Changes trusted and loaded.", "success");
      } catch {
        toast("Trusted the file, but it needs a different password now — please unlock again.", "info");
        handleLock();
      }
    } else {
      toast("Changes trusted as the new baseline.", "success");
    }
    logActivity("security_change", "Trusted externally-modified vault file");
    setIntegrityIssue(null);
  };

  const restoreVersionByFile = async (file) => {
    if (!file) { toast("No version file specified.", "danger"); return { ok: false }; }
    const result = await restoreVersion(file);
    if (!result.ok) { toast(result.error || "Restore failed.", "danger"); return { ok: false }; }
    setEnvelope(result.data);
    if (!locked && vaultKeyRef.current) {
      try {
        const K = await importAesKey(vaultKeyRef.current);
        const data = await aesDecryptJSON(K, result.data.data.iv, result.data.data.ciphertext);
        loadDecryptedIntoState(data);
      } catch {
        handleLock();
      }
    }
    toast("Version restored.", "success");
    logActivity("security_change", "Restored a previous vault version");
    setIntegrityIssue(null);
    // Every restore (including an undo) sets this to whatever came right
    // before it — so clicking Undo repeatedly just toggles back and forth
    // between the two states, rather than being a one-shot action.
    setLastRestoreUndo(result.undoFile || null);
    return { ok: true };
  };

  const undoLastRestore = async () => {
    if (!lastRestoreUndo) return;
    await restoreVersionByFile(lastRestoreUndo);
  };

  const resolveIntegrityRestore = async () => {
    const file = integrityIssue?.previousVersion?.file;
    if (!file) { toast("No previous version available to restore.", "danger"); return; }
    await restoreVersionByFile(file);
  };

  const resolveIntegrityReview = async (password) => {
    try {
      let newData, oldData;
      if (!locked && vaultKeyRef.current) {
        const K = await importAesKey(vaultKeyRef.current);
        newData = await aesDecryptJSON(K, envelope.data.iv, envelope.data.ciphertext);
        oldData = { passwords, notes, transactions, budgets, goals, events };
      } else {
        if (!password) return { ok: false, error: "Enter your master password." };
        const unlockedNew = await unlockWithPasswordEnvelope(envelope, password);
        newData = unlockedNew.data;
        const prevFile = integrityIssue?.previousVersion?.file;
        if (!prevFile) return { ok: false, error: "No previous version available to compare against." };
        const prevContent = await fetchVersionContent(prevFile);
        if (!prevContent.ok) return { ok: false, error: "Couldn't load the previous version." };
        const unlockedOld = await unlockWithPasswordEnvelope(prevContent.data, password);
        oldData = unlockedOld.data;
      }
      return { ok: true, diff: diffVaultData(oldData, newData) };
    } catch {
      return { ok: false, error: "Couldn't decrypt one of the versions — the password may be wrong, or this may be a completely different vault file." };
    }
  };

  const handleUnlockWithBiometric = async () => {
    if (!window.secureVaultNative || !envelope?.biometric) {
      return { ok: false, error: "Windows Hello unlock isn't set up." };
    }
    const res = await window.secureVaultNative.biometricUnlock(envelope.biometric.protectedKey);
    if (!res.ok) return { ok: false, error: res.error };
    try {
      const vaultKeyBytes = b64ToBytes(res.plain);
      const K = await importAesKey(vaultKeyBytes);
      const data = await aesDecryptJSON(K, envelope.data.iv, envelope.data.ciphertext);
      vaultKeyRef.current = vaultKeyBytes;
      loadDecryptedIntoState(data);
      setLocked(false);
      logActivity("vault_unlocked", "Vault unlocked with Windows Hello");
      toast("Vault unlocked with Windows Hello.", "success");
      return { ok: true };
    } catch {
      return { ok: false, error: "Couldn't unlock the vault with the recovered key." };
    }
  };

  const counts = { passwords: passwords.length, notes: notes.filter((n) => !n.archived).length, budgets: budgets.length, goals: goals.length, contacts: contacts.length, trash: trash.length };

  if (!booted) {
    return <BootScreen serverStatus={serverStatus} />;
  }

  if (!envelope) {
    return <VaultSetupScreen onCreate={handleCreateVault} serverStatus={serverStatus} dataFilePath={dataFilePath} />;
  }

  if (locked) {
    return (
      <>
        <LockScreen
          onUnlockWithPassword={handleUnlockWithPassword}
          onUnlockWithPin={handleUnlockWithPin}
          onUnlockWithBiometric={handleUnlockWithBiometric}
          biometricAvailable={biometricAvailable}
          envelope={envelope}
          serverStatus={serverStatus}
          dataFilePath={dataFilePath}
        />
        {integrityIssue && (
          <IntegrityWarningModal
            issue={integrityIssue}
            locked={true}
            onTrust={resolveIntegrityTrust}
            onRestore={resolveIntegrityRestore}
            onReview={resolveIntegrityReview}
          />
        )}
      </>
    );
  }

  return (
    <div className={`sv-root ${theme}`} style={{ minHeight: "100vh", display: "flex" }}>
      <FontStyles />
      <Sidebar view={view} setView={setView} onLock={handleLock} theme={theme} toggleTheme={() => setTheme((t) => t === "dark" ? "light" : "dark")} counts={counts} serverStatus={serverStatus} auth={auth} />

      <div className="sv-scroll" style={{ flex: 1, minWidth: 0, overflowY: "auto", maxHeight: "100vh" }}>
        {view === "dashboard" && (
          <Dashboard data={{ passwords, notes, transactions, goals, generalSavings, activity }} setView={setView} openModal={openModal} onLock={handleLock} />
        )}
        {view === "passwords" && (
          <PasswordsView passwords={passwords} openModal={openModal} deletePassword={deletePassword} logActivity={logActivity} toast={toast} />
        )}
        {view === "notes" && (
          <NotesView notes={notes} openModal={openModal} deleteNote={deleteNote} togglePin={togglePin} toggleArchive={toggleArchive} locked={locked} onImportNotes={importNotes} />
        )}
        {view === "finance" && (
          <FinanceView transactions={transactions} goals={goals} generalSavings={generalSavings} savingsAdjustment={savingsAdjustment} onAdjustSavings={setSavingsAdjustment} openModal={openModal} deleteTransaction={deleteTransaction} hideValues={settings.hideFinance} />
        )}
        {view === "budgets" && (
          <BudgetsView budgets={budgets} transactions={transactions} openModal={openModal} deleteBudget={deleteBudget} />
        )}
        {view === "goals" && (
          <GoalsView goals={goals} generalSavings={generalSavings} openModal={openModal} deleteGoal={deleteGoal} />
        )}
        {view === "planner" && (
          <PlannerView events={events} openModal={openModal} deleteEvent={deleteEvent} toggleEventComplete={toggleEventComplete} />
        )}
        {view === "contacts" && (
          <ContactsView contacts={contacts} openModal={openModal} deleteContact={deleteContact} toggleFavorite={toggleContactFavorite} />
        )}
        {view === "trash" && (
          <TrashView trash={trash} onRestore={restoreFromTrash} onDeleteForever={deleteForever} onEmptyTrash={emptyTrash} />
        )}
        {view === "security" && (
          <SecurityCenter passwords={passwords} activity={activity} sessions={sessions} onEndSession={endSession} onRestoreVersion={restoreVersionByFile} serverStatus={serverStatus} lastRestoreUndo={lastRestoreUndo} onUndoRestore={undoLastRestore} />
        )}
        {view === "settings" && (
          <SettingsView settings={settings} setSettings={setSettings} theme={theme} toggleTheme={() => setTheme((t) => t === "dark" ? "light" : "dark")} onLock={handleLock} sessions={sessions} onEndSession={endSession} toast={toast} onEraseLocalData={eraseLocalData} auth={auth} onUpdateAccount={updateAccount} serverStatus={serverStatus} dataFilePath={dataFilePath} onChangeMasterPassword={changeMasterPassword} onSetupPin={setupPin} onChangePin={changePin} onDisablePin={disablePin} pinEnabled={!!envelope?.pin} onSetupBiometric={setupBiometric} onDisableBiometric={disableBiometric} biometricEnabled={!!envelope?.biometric} biometricAvailable={biometricAvailable} biometricReason={biometricReason} onExportVault={exportVault} onImportVault={importVault} onBackupNow={backupNow} />
        )}
      </div>

      {/* Modals */}
      {modal?.type === "search" && (
        <GlobalSearch onClose={closeModal} passwords={passwords} notes={notes} transactions={transactions} locked={locked} goTo={setView} />
      )}
      {modal?.type === "generator" && (
        <Modal title="Password generator" onClose={closeModal}><PasswordGenerator /></Modal>
      )}
      {(modal?.type === "password-add" || modal?.type === "password-edit") && (
        <Modal title={modal.type === "password-add" ? "Add password" : "Edit password"} onClose={closeModal}>
          <PasswordForm
            initial={modal.type === "password-edit" ? { ...modal.data, tags: (modal.data.tags || []).join(", ") } : undefined}
            onSave={savePassword} onCancel={closeModal}
          />
        </Modal>
      )}
      {modal?.type === "note-view" && (
        <NoteViewModal
          note={notes.find((n) => n.id === modal.data.id) || modal.data}
          onClose={closeModal}
          onEdit={(n) => openModal("note-edit", n)}
          togglePin={togglePin}
          toggleArchive={toggleArchive}
          onDeleteRequest={(n) => setNoteViewDeleteTarget(n)}
        />
      )}
      {(modal?.type === "note-add" || modal?.type === "note-edit") && (
        <Modal title={modal.type === "note-add" ? "Add secure note" : "Edit note"} onClose={closeModal} width={520}>
          <NoteForm
            initial={modal.type === "note-edit" ? { ...modal.data, tags: (modal.data.tags || []).join(", ") } : undefined}
            onSave={saveNote} onCancel={closeModal}
          />
        </Modal>
      )}
      {(modal?.type === "transaction-add" || modal?.type === "transaction-edit") && (
        <Modal title={modal.type === "transaction-add" ? "Add transaction" : "Edit transaction"} onClose={closeModal}>
          <TransactionForm
            initial={modal.type === "transaction-edit" ? modal.data : undefined}
            defaultType={modal.data?.type || "expense"}
            onSave={saveTransaction} onCancel={closeModal}
          />
        </Modal>
      )}
      {(modal?.type === "budget-add" || modal?.type === "budget-edit") && (
        <Modal title={modal.type === "budget-add" ? "Add budget" : "Edit budget"} onClose={closeModal} width={420}>
          <BudgetForm initial={modal.type === "budget-edit" ? modal.data : undefined} onSave={saveBudget} onCancel={closeModal} />
        </Modal>
      )}
      {(modal?.type === "goal-add" || modal?.type === "goal-edit") && (
        <Modal title={modal.type === "goal-add" ? "Add savings goal" : "Edit goal"} onClose={closeModal} width={460}>
          <GoalForm
            initial={modal.type === "goal-edit" ? { ...modal.data, targetAmount: String(modal.data.targetAmount), currentAmount: String(modal.data.currentAmount) } : undefined}
            onSave={saveGoal} onCancel={closeModal}
          />
        </Modal>
      )}
      {modal?.type === "savings-deposit" && (
        <Modal title={`Add funds — ${modal.data.type === "goal" ? modal.data.goal.title : "General Savings"}`} onClose={closeModal} width={440}>
          <SavingsDepositForm target={modal.data} generalSavings={generalSavings} onSave={(entry) => depositToSavings(modal.data, entry)} onCancel={closeModal} />
        </Modal>
      )}
      {modal?.type === "savings-withdraw" && (
        <Modal title={`Withdraw — ${modal.data.type === "goal" ? modal.data.goal.title : "General Savings"}`} onClose={closeModal} width={420}>
          <SavingsWithdrawForm target={modal.data} onSave={(entry) => withdrawFromSavings(modal.data, entry)} onCancel={closeModal} />
        </Modal>
      )}
      {(modal?.type === "event-add" || modal?.type === "event-edit") && (
        <Modal title={modal.type === "event-add" ? "Add event" : "Edit event"} onClose={closeModal} width={460}>
          <EventForm
            initial={modal.type === "event-edit" ? modal.data : (modal.data?.date ? { title: "", date: modal.data.date, time: "", endTime: "", category: "Personal", location: "", notes: "", allDay: false } : undefined)}
            onSave={saveEvent} onCancel={closeModal}
          />
        </Modal>
      )}
      {(modal?.type === "contact-add" || modal?.type === "contact-edit") && (
        <Modal title={modal.type === "contact-add" ? "Add contact" : "Edit contact"} onClose={closeModal} width={480}>
          <ContactForm
            initial={modal.type === "contact-edit" ? { ...modal.data, tags: (modal.data.tags || []).join(", ") } : undefined}
            onSave={saveContact} onCancel={closeModal}
          />
        </Modal>
      )}
      {modal?.type === "contact-view" && (
        <ContactViewModal
          contact={contacts.find((c) => c.id === modal.data.id) || modal.data}
          onClose={closeModal}
          onEdit={(c) => openModal("contact-edit", c)}
          onDeleteRequest={(c) => setContactViewDeleteTarget(c)}
          toggleFavorite={toggleContactFavorite}
        />
      )}
      {modal?.type === "transaction-view" && (
        <TransactionViewModal
          transaction={transactions.find((t) => t.id === modal.data.id) || modal.data}
          onClose={closeModal}
          onEdit={(t) => openModal("transaction-edit", t)}
          onDeleteRequest={(t) => setTransactionViewDeleteTarget(t)}
        />
      )}

      {noteViewDeleteTarget && (
        <ConfirmDialog
          title="Delete note"
          message={`Move "${noteViewDeleteTarget.title}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger
          onCancel={() => setNoteViewDeleteTarget(null)}
          onConfirm={() => { deleteNote(noteViewDeleteTarget.id); setNoteViewDeleteTarget(null); closeModal(); }}
        />
      )}
      {contactViewDeleteTarget && (
        <ConfirmDialog
          title="Delete contact"
          message={`Move "${contactViewDeleteTarget.name}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger
          onCancel={() => setContactViewDeleteTarget(null)}
          onConfirm={() => { deleteContact(contactViewDeleteTarget.id); setContactViewDeleteTarget(null); closeModal(); }}
        />
      )}
      {transactionViewDeleteTarget && (
        <ConfirmDialog
          title="Delete transaction"
          message={`Move the transaction "${transactionViewDeleteTarget.party}" to Trash? You can restore it within ${TRASH_RETENTION_DAYS} days.`}
          confirmLabel="Move to Trash" danger
          onCancel={() => setTransactionViewDeleteTarget(null)}
          onConfirm={() => { deleteTransaction(transactionViewDeleteTarget.id); setTransactionViewDeleteTarget(null); closeModal(); }}
        />
      )}

      {integrityIssue && (
        <IntegrityWarningModal
          issue={integrityIssue}
          locked={false}
          onTrust={resolveIntegrityTrust}
          onRestore={resolveIntegrityRestore}
          onReview={resolveIntegrityReview}
        />
      )}

      <ToastStack toasts={toasts} dismiss={dismissToast} />
    </div>
  );
}
