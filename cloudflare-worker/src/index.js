/**
 * SecureVault sync Worker.
 *
 * Firebase Auth proves WHO is calling (a Google-signed ID token); R2 stores the
 * encrypted vault. The Worker is the only gatekeeper: it verifies the Firebase
 * ID token, then reads/writes exactly one object per account:
 *     vaults/<firebase uid>/vault.json
 * so one account can never touch another's file. The object is already
 * end-to-end encrypted by the app — the Worker and R2 only ever see ciphertext.
 *
 *   GET    /vault/meta  -> { updatedAt, vaultId, ownerEmail, size }   (404 if none)
 *   GET    /vault       -> the encrypted envelope JSON                (404 if none)
 *   PUT    /vault       -> store it (headers X-Updated-At, X-Vault-Id)
 *   DELETE /vault       -> remove it
 */

const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const MAX_VAULT_BYTES = 25 * 1024 * 1024;
const CLOCK_SKEW_SECONDS = 300;

const CORS = {
  "Access-Control-Allow-Origin": "*", // auth is a bearer token (no cookies), so a wildcard origin is safe
  "Access-Control-Allow-Methods": "GET, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Updated-At, X-Vault-Id",
  "Access-Control-Max-Age": "86400",
};

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...CORS } });

/* ---- Firebase ID token verification (RS256, Google's public keys) ---- */

const b64urlToBytes = (s) => {
  let b = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b.length % 4) b += "=";
  const bin = atob(b);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const decodeJson = (s) => JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));

let jwksCache = { keys: null, expires: 0 };
async function getJwks(force = false) {
  const now = Date.now();
  if (!force && jwksCache.keys && now < jwksCache.expires) return jwksCache.keys;
  const res = await fetch(JWKS_URL, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!res.ok) throw new Error("Couldn't fetch Google's signing keys");
  const { keys } = await res.json();
  jwksCache = { keys, expires: now + 60 * 60 * 1000 };
  return keys;
}

export async function verifyFirebaseToken(token, projectId) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);
  if (header.alg !== "RS256" || !header.kid) throw new Error("unexpected token header");

  let jwk = (await getJwks()).find((k) => k.kid === header.kid);
  if (!jwk) jwk = (await getJwks(true)).find((k) => k.kid === header.kid); // keys rotate
  if (!jwk) throw new Error("unknown signing key");

  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64urlToBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (!ok) throw new Error("bad signature");

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= now) throw new Error("token expired");
  if (typeof payload.iat !== "number" || payload.iat > now + CLOCK_SKEW_SECONDS) throw new Error("token issued in the future");
  if (payload.aud !== projectId) throw new Error("wrong audience");
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error("wrong issuer");
  if (typeof payload.sub !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(payload.sub)) throw new Error("bad subject");
  return payload;
}

/* ---- request handling ---- */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    const url = new URL(request.url);
    const route = url.pathname.replace(/\/+$/, "");
    if (route !== "/vault" && route !== "/vault/meta") return json(404, { error: "not found" });

    const bearer = (request.headers.get("Authorization") || "").match(/^Bearer\s+(.+)$/i);
    if (!bearer) return json(401, { error: "missing token" });
    let claims;
    try {
      claims = await verifyFirebaseToken(bearer[1], env.FIREBASE_PROJECT_ID);
    } catch (e) {
      return json(401, { error: "invalid token", detail: e.message });
    }
    const key = `vaults/${claims.sub}/vault.json`;

    if (route === "/vault/meta") {
      if (request.method !== "GET") return json(405, { error: "method not allowed" });
      const head = await env.VAULT.head(key);
      if (!head) return json(404, { error: "no vault" });
      const m = head.customMetadata || {};
      return json(200, { updatedAt: m.updatedAt || "", vaultId: m.vaultId || "", ownerEmail: m.ownerEmail || "", size: head.size });
    }

    switch (request.method) {
      case "GET": {
        const obj = await env.VAULT.get(key);
        if (!obj) return json(404, { error: "no vault" });
        return new Response(obj.body, { status: 200, headers: { "Content-Type": "application/json", ...CORS } });
      }
      case "PUT": {
        const declared = Number(request.headers.get("Content-Length") || 0);
        if (declared > MAX_VAULT_BYTES) return json(413, { error: "vault too large" });
        const body = await request.text();
        if (body.length > MAX_VAULT_BYTES) return json(413, { error: "vault too large" });
        let parsed;
        try { parsed = JSON.parse(body); } catch { return json(400, { error: "body is not JSON" }); }
        if (!parsed || !parsed.password || !parsed.data) return json(400, { error: "not a SecureVault envelope" });
        await env.VAULT.put(key, body, {
          httpMetadata: { contentType: "application/json" },
          customMetadata: {
            updatedAt: request.headers.get("X-Updated-At") || parsed.updatedAt || "",
            vaultId: request.headers.get("X-Vault-Id") || parsed.vaultId || "",
            ownerEmail: claims.email || "",
          },
        });
        return json(200, { ok: true });
      }
      case "DELETE":
        await env.VAULT.delete(key);
        return json(200, { ok: true });
      default:
        return json(405, { error: "method not allowed" });
    }
  },
};
