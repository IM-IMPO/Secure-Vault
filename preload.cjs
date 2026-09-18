/**
 * Preload script — runs in an isolated context with access to Node/Electron
 * APIs, and selectively exposes a small, safe surface to the renderer
 * (your React app) via contextBridge. The renderer can never reach
 * ipcRenderer, Node, or the filesystem directly — only these specific
 * functions, which just forward to the main process.
 */
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("secureVaultNative", {
  /** Checks whether Windows Hello is set up and available on this PC. */
  biometricCheck: () => ipcRenderer.invoke("biometric:check"),

  /**
   * Prompts Windows Hello, and if verified, encrypts (DPAPI-protects) the
   * given base64-encoded bytes so only this Windows user account can
   * decrypt them again. Returns { ok, protected } or { ok: false, error }.
   */
  biometricProtect: (base64Bytes) => ipcRenderer.invoke("biometric:protect", base64Bytes),

  /**
   * Prompts Windows Hello, and if verified, decrypts (DPAPI-unprotects) a
   * previously protected base64 blob. Returns { ok, plain } or
   * { ok: false, error }.
   */
  biometricUnlock: (protectedBase64) => ipcRenderer.invoke("biometric:unlock", protectedBase64),
});
