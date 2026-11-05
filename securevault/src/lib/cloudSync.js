/**
 * SecureVault — Cloud Sync Logic
 * Zero-knowledge sync: client-side only. Firebase never sees plaintext.
 */
import { getUserEmail, checkOnline as checkBrowserOnline } from "./firebase.js";

const SYNC_STATE = {
  status: "idle",
  queue: [],
  lastSyncTime: null,
  lastError: null,
};

export const getSyncState = () => ({ ...SYNC_STATE });

export const setSyncStatus = (status, error = null) => {
  SYNC_STATE.status = status;
  SYNC_STATE.lastError = error;
};

export const watchNetwork = (callback) => {
  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("online", () => callback(true));
    window.addEventListener("offline", () => callback(false));
    return () => {};
  }
  return () => {};
};

export const checkOnline = () => typeof navigator !== "undefined" ? navigator.onLine : true;

export const pushToQueue = (operation) => {
  SYNC_STATE.queue.push(operation);
  return SYNC_STATE.queue.length;
};

export const clearQueue = () => { SYNC_STATE.queue = []; };

export const hasPendingSync = () => SYNC_STATE.queue.length > 0;

export const getLastSyncTime = () => SYNC_STATE.lastSyncTime;

export const getDataDir = () => {
  if (typeof process !== "undefined" && process.env && process.env.SV_DATA_DIR) {
    return process.env.SV_DATA_DIR;
  }
  return "D:\\Local Data";
};

export const getDataFile = () => {
  return getStoragePath("securevault-data.json");
};

export { getUserVaultRef, uploadVaultToCloud, downloadVaultFromCloud, listUserVaultVersions } from "./firebase.js";

// —— Crypto helpers ——————————————————————————————————————————————————————————
const importAesKey = (rawBytes) => {
  return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
};

const deriveKeyBytes = async (secret, saltBytes, params) => {
  const secretKey = await crypto.subtle.importKey(
    "raw", secret, { name: "PBKDF2", hash: "SHA-256" }, false, ["deriveKey"]
  );
  const salt = new Uint8Array(saltBytes);
  const derivedKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: params.iterations, hash: "SHA-256" },
    secretKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const keyBytes = new Uint8Array(32);
  await crypto.subtle.exportKey("raw", derivedKey, keyBytes);
  return keyBytes;
};

const aesEncryptJSON = async (cryptoKey, obj) => {
  return aesEncryptBytes(cryptoKey, new TextEncoder().encode(JSON.stringify(obj)));
};

const aesEncryptBytes = async (cryptoKey, plainBytes) => {
  const iv = randomBytes(12);
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, plainBytes);
  return { iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ctBuf)) };
};

const aesDecryptBytes = async (cryptoKey, ivB64, ctB64) => {
  const iv = b64ToBytes(ivB64);
  const ct = b64ToBytes(ctB64);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct);
  return new Uint8Array(ptBuf);
};

const aesDecryptJSON = async (cryptoKey, ivB64, ctB64) => {
  const bytes = await aesDecryptBytes(cryptoKey, ivB64, ctB64);
  return JSON.parse(new TextDecoder().decode(bytes));
};

const wrapVaultKey = async (vaultKeyBytes, secret, saltBytes, params) => {
  const wrappingKeyBytes = await deriveKeyBytes(secret, saltBytes, params);
  const wrappingKey = await importAesKey(wrappingKeyBytes);
  return aesEncryptBytes(wrappingKey, vaultKeyBytes);
};

const unwrapVaultKey = async (secret, saltBytes, params, iv, ciphertext) => {
  const wrappingKeyBytes = await deriveKeyBytes(secret, saltBytes, params);
  const wrappingKey = await importAesKey(wrappingKeyBytes);
  return aesDecryptBytes(wrappingKey, iv, ciphertext);
};

const unlockWithPasswordEnvelope = async (envelope, password) => {
  const vaultKeyBytes = await unwrapVaultKey(
    password,
    b64ToBytes(envelope.password.salt),
    envelope.password.params,
    b64ToBytes(envelope.password.iv),
    b64ToBytes(envelope.password.wrappedKey)
  );
  const data = aesDecryptJSON(vaultKeyBytes, envelope.data.iv, envelope.data.ciphertext);
  return { vaultKeyBytes, data };
};

const randomBytes = (len) => {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
};

const bytesToB64 = (bytes) => {
  let binary = "";
  const bytesView = new Uint8Array(bytes);
  for (let i = 0; i < bytesView.byteLength; i++) binary += String.fromCharCode(bytesView[i]);
  return btoa(binary);
};

const b64ToBytes = (b64) => {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
};

const PASSWORD_ARGON2_PARAMS = { iterations: 3, memorySize: 65536, parallelism: 1, hashLength: 32 };

// —— Sync operations —————————————————————————————————————————————————————————
export const fullSync = async (localEnvelope, userId, localSyncToken = null, masterPassword = null) => {
  setSyncStatus("syncing");

  let cloudData = null;
  const online = checkBrowserOnline();
  if (online) {
    try {
      const blob = await downloadVaultFromCloud(userId);
      if (blob) {
        const cloudData = JSON.parse(await blob.text());
        if (!cloudData.password || !cloudData.data || !cloudData.updatedAt) {
          throw new Error("Corrupt vault on cloud");
        }
      }
    } catch (err) {
      if (err.message !== "storage/object-not-found") {
        setSyncStatus("error", err.message);
        return localEnvelope;
      }
    }
  }

  const merged = mergeVaults(localEnvelope, cloudData, localSyncToken);
  const encryptedBlob = await encryptForCloud(merged, masterPassword);
  await uploadVaultToCloud(userId, encryptedBlob);

  SYNC_STATE.lastSyncTime = new Date().toISOString();
  setSyncStatus("idle");
  clearQueue();

  return merged;
};

export const mergeVaults = (local, cloud, localSyncToken = null) => {
  if (!cloud) return { ...local, updatedAt: new Date().toISOString() };
  if (!cloud.password || !cloud.data) return { ...local, updatedAt: new Date().toISOString() };

  const merged = {
    ...local,
    version: cloud.version || local.version || 2,
    kdf: cloud.kdf || local.kdf || "argon2id",
    cipher: cloud.cipher || local.cipher || "AES-256-GCM",
    password: cloud.password && cloud.password.salt ? cloud.password : local.password,
    data: cloud.data && cloud.data.iv ? cloud.data : local.data,
    pin: cloud.pin || local.pin || null,
    biometric: cloud.biometric || local.biometric || null,
    userEmail: cloud.userEmail || local.userEmail || (getUserEmail() ?? "unknown"),
    updatedAt: local.updatedAt > cloud.updatedAt ? local.updatedAt : cloud.updatedAt,
  };

  if (local.files && cloud.files) merged.files = { ...cloud.files, ...local.files };
  return merged;
};

export const encryptForCloud = async (vaultData, masterPassword, passwordSalt) => {
  const salt = randomBytes(16);
  const wrapped = await wrapVaultKey(vaultData.vaultKeyBytes, masterPassword, salt, PASSWORD_ARGON2_PARAMS);
  const K = await importAesKey(vaultData.vaultKeyBytes);
  const dataEnc = await aesEncryptJSON(K, vaultData);

  return {
    version: 2,
    kdf: "argon2id",
    cipher: "AES-256-GCM",
    password: {
      salt: bytesToB64(salt),
      iv: wrapped.iv,
      wrappedKey: wrapped.ciphertext,
      params: PASSWORD_ARGON2_PARAMS,
    },
    data: dataEnc,
    userEmail: vaultData.userEmail || (getUserEmail() ?? "unknown"),
    updatedAt: new Date().toISOString(),
  };
};

export const decryptFromCloud = async (cloudData, masterPassword) => {
  if (!cloudData.password || !cloudData.data) throw new Error("Invalid cloud vault format");

  const envelope = {
    version: cloudData.version || 2,
    kdf: cloudData.kdf || "argon2id",
    cipher: cloudData.cipher || "AES-256-GCM",
    password: cloudData.password,
    pin: cloudData.pin || null,
    biometric: cloudData.biometric || null,
    data: cloudData.data,
  };

  const result = await unlockWithPasswordEnvelope(envelope, masterPassword);
  return result.data;
};
