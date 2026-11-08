// Local test: fake Google keys + fake Firebase tokens + in-memory R2.
import worker from "../src/index.js";
import { webcrypto as crypto } from "node:crypto";
import assert from "node:assert/strict";

const PROJECT = "vault-b3bfb";
const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
const jwk = { ...(await crypto.subtle.exportKey("jwk", publicKey)), kid: "k1", alg: "RS256", use: "sig" };
const realFetch = globalThis.fetch;
globalThis.fetch = async (u, ...r) => String(u).includes("securetoken@system") ? new Response(JSON.stringify({ keys: [jwk] })) : realFetch(u, ...r);

const b64u = (b) => Buffer.from(b).toString("base64url");
async function token(over = {}, kid = "k1", key = privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud: PROJECT, iss: `https://securetoken.google.com/${PROJECT}`, sub: "uidA", email: "a@gmail.com", iat: now - 10, exp: now + 3000, ...over };
  const h = b64u(JSON.stringify({ alg: "RS256", kid, typ: "JWT" })), p = b64u(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(sig)}`;
}
const store = new Map();
const env = {
  FIREBASE_PROJECT_ID: PROJECT,
  VAULT: {
    async head(k) { const v = store.get(k); return v ? { size: v.body.length, customMetadata: v.meta } : null; },
    async get(k) { const v = store.get(k); return v ? { body: v.body } : null; },
    async put(k, body, o) { store.set(k, { body, meta: o.customMetadata }); },
    async delete(k) { store.delete(k); },
  },
};
const call = (path, method, tok, body, headers = {}) => worker.fetch(new Request("https://w.test" + path, {
  method, body, headers: { ...(tok ? { Authorization: `Bearer ${tok}` } : {}), ...headers } }), env);

const env1 = JSON.stringify({ password: { salt: "x" }, data: { iv: "y", ciphertext: "z" }, updatedAt: "2026-11-08T00:00:00.000Z", vaultId: "v1" });
const A = await token();

assert.equal((await call("/vault", "GET")).status, 401, "no token -> 401");
assert.equal((await call("/vault", "GET", "garbage")).status, 401, "garbage -> 401");
assert.equal((await call("/vault", "GET", await token({ aud: "other" }))).status, 401, "wrong project -> 401");
assert.equal((await call("/vault", "GET", await token({ exp: 1 }))).status, 401, "expired -> 401");
assert.equal((await call("/vault", "GET", await token({}, "k1", (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"])).privateKey))).status, 401, "forged signature -> 401");
const parts = A.split("."); const tampered = `${parts[0]}.${b64u(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1], "base64url")), sub: "uidB" }))}.${parts[2]}`;
assert.equal((await call("/vault", "GET", tampered)).status, 401, "tampered payload -> 401");

assert.equal((await call("/vault/meta", "GET", A)).status, 404, "meta before upload -> 404");
assert.equal((await call("/vault", "PUT", A, "not json")).status, 400);
assert.equal((await call("/vault", "PUT", A, "{}")).status, 400);
assert.equal((await call("/vault", "PUT", A, env1, { "X-Updated-At": "2026-11-08T00:00:00.000Z", "X-Vault-Id": "v1" })).status, 200, "upload");
const meta = await (await call("/vault/meta", "GET", A)).json();
assert.deepEqual([meta.updatedAt, meta.vaultId, meta.ownerEmail], ["2026-11-08T00:00:00.000Z", "v1", "a@gmail.com"]);
assert.equal(await (await call("/vault", "GET", A)).text(), env1, "download round-trips");

const B = await token({ sub: "uidB", email: "b@gmail.com" });
assert.equal((await call("/vault", "GET", B)).status, 404, "another account can't see A's vault");
assert.equal([...store.keys()].join(), "vaults/uidA/vault.json");
assert.equal((await call("/vault", "PUT", B, env1)).status, 200);
assert.equal(store.size, 2, "B writes to its own key only");
assert.equal((await call("/vault", "DELETE", A)).status, 200);
assert.equal((await call("/vault", "GET", A)).status, 404, "deleted");
assert.equal(store.has("vaults/uidB/vault.json"), true, "B untouched by A's delete");
const pre = await call("/vault", "OPTIONS");
assert.equal(pre.status, 204); assert.match(pre.headers.get("Access-Control-Allow-Headers"), /Authorization/);
assert.equal((await call("/other", "GET", A)).status, 404);
console.log("ALL WORKER TESTS PASSED");
