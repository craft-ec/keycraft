// The key store at rest: JSON of [{name, owner, store_key, signing_key}] under
// AES-GCM, the key from the passphrase by PBKDF2 (310k rounds, SHA-256).
// Stored as {v:1, salt, iv, data} base64 in chrome.storage.sync (≤ 8 KiB per
// item, so a store holds some dozens of identities).
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export async function deriveKey(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
export async function seal(key, salt, entries) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(entries)));
  return { v: 1, salt: b64(salt), iv: b64(iv), data: b64(data) };
}
export async function open(key, box) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.data));
  return JSON.parse(dec.decode(plain));
}
export const newSalt = () => crypto.getRandomValues(new Uint8Array(16));
export { b64, unb64 };
