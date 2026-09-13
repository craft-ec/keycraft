// The service worker: the key store and the signer. The sealed store sits in
// chrome.storage.sync (follows the Chrome profile); the unlocked key in
// chrome.storage.session (this browser session). Pages reach it through
// content.js, which asks the person before an app first uses an identity;
// the popup reaches it directly. A signing key never leaves this worker.
import { deriveKey, seal, open, newSalt, unb64 } from './crypto.js';

const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = s => { if (!/^[0-9a-fA-F]*$/.test(s) || s.length % 2) throw new Error('not hex'); return Uint8Array.from(s.match(/../g) || [], h => parseInt(h, 16)); };
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
// PKCS#8 wrapping of a raw 32-byte Ed25519 seed (RFC 8410), what WebCrypto imports
const PKCS8 = unhex('302e020100300506032b657004220420');
const seedToKey = async (seedHex, usages) => crypto.subtle.importKey('pkcs8', new Uint8Array([...PKCS8, ...unhex(seedHex)]), { name: 'Ed25519' }, true, usages);
const publicOf = async seedHex => { const jwk = await crypto.subtle.exportKey('jwk', await seedToKey(seedHex, ['sign'])); return hex(unb64u(jwk.x)); };

const getBox = async () => (await chrome.storage.sync.get('box')).box || null;
const getSession = async () => (await chrome.storage.session.get('jwk')).jwk || null;
const sessionKey = async () => { const jwk = await getSession(); return jwk ? crypto.subtle.importKey('jwk', jwk, 'AES-GCM', true, ['encrypt', 'decrypt']) : null; };
const entries = async () => { const box = await getBox(); if (!box) return []; const key = await sessionKey(); if (!key) throw new Error('locked'); return open(key, box); };
const save = async list => { const box = await getBox(); const key = await sessionKey(); if (!key || !box) throw new Error('locked'); await chrome.storage.sync.set({ box: await seal(key, unb64(box.salt), list) }); };
const find = async owner => { const e = (await entries()).find(e => e.owner === owner); if (!e) throw new Error('no such identity in the extension'); return e; };
const approvals = async () => (await chrome.storage.local.get('approvals')).approvals || {};

const ops = {
  async ping() { const box = await getBox(); return { extension: true, initialised: !!box, unlocked: !!(await getSession()) }; },
  async status() { return ops.ping(); },
  async unlock({ passphrase }) {
    let box = await getBox(); let key;
    if (!box) { const salt = newSalt(); key = await deriveKey(passphrase, salt); box = await seal(key, salt, []); await chrome.storage.sync.set({ box }); }
    else { key = await deriveKey(passphrase, unb64(box.salt)); await open(key, box); }
    await chrome.storage.session.set({ jwk: await crypto.subtle.exportKey('jwk', key) });
    return { ok: true };
  },
  async lock() { await chrome.storage.session.remove('jwk'); return { ok: true }; },
  // names and owners only
  async list() { return (await entries()).map(e => ({ name: e.name, owner: e.owner, can_sign: !!e.signing_key })); },
  // a new identity: an Ed25519 seed and a store key from the browser's randomness
  async create({ name }) {
    name = (name || '').trim(); if (!name || name.length > 64) throw new Error('a name is 1 to 64 characters');
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const seed = hex(pkcs8.slice(-32)), owner = hex(await crypto.subtle.exportKey('raw', kp.publicKey));
    const store_key = hex(crypto.getRandomValues(new Uint8Array(32)));
    const list = await entries(); if (list.some(e => e.name === name)) throw new Error('that name is taken');
    list.push({ name, owner, store_key, signing_key: seed, created_at: Math.floor(Date.now() / 1000) }); await save(list);
    return { owner };
  },
  // from a node's delegate, a keyfile, or another device; a store key alone is read-only
  async put({ entry }) {
    const name = (entry.name || '').trim(); if (!name) throw new Error('a name is needed');
    const store_key = entry.store_key.toLowerCase(); if (unhex(store_key).length !== 32) throw new Error('store key: 32 bytes');
    let signing_key = (entry.signing_key || '').toLowerCase(), owner = (entry.owner || '').toLowerCase();
    if (signing_key) { if (unhex(signing_key).length !== 32) throw new Error('signing key: 32 bytes'); owner = await publicOf(signing_key); }
    if (!owner) throw new Error('an owner key is needed for a read-only identity');
    const list = (await entries()).filter(e => e.owner !== owner); list.push({ name, owner, store_key, signing_key, created_at: Math.floor(Date.now() / 1000) }); await save(list);
    return { ok: true, owner, count: list.length };
  },
  async get({ owner }) { return find(owner); },
  async rename({ owner, name }) { name = (name || '').trim(); if (!name || name.length > 64) throw new Error('a name is 1 to 64 characters'); const list = await entries(); const e = list.find(e => e.owner === owner); if (!e) throw new Error('no such identity'); e.name = name; await save(list); return { ok: true }; },
  async remove({ owner }) { const list = (await entries()).filter(e => e.owner !== owner); await save(list); return { ok: true, count: list.length }; },
  // what an app needs: the store key to read, a signature to write
  async storeKey({ owner }) { return (await find(owner)).store_key; },
  async sign({ owner, message }) { const e = await find(owner); if (!e.signing_key) throw new Error('read-only identity'); const key = await seedToKey(e.signing_key, ['sign']); return hex(await crypto.subtle.sign('Ed25519', key, unhex(message))); },
  // per app, per identity: remembered once the person says yes in the page
  async approved({ app, owner }) { const a = await approvals(); return !!(a[app] && a[app][owner]); },
  async approve({ app, owner, name }) { const a = await approvals(); a[app] = a[app] || {}; a[app][owner] = { name, at: Date.now() }; await chrome.storage.local.set({ approvals: a }); return { ok: true }; },
  async listApprovals() { return approvals(); },
  async revoke({ app }) { const a = await approvals(); delete a[app]; await chrome.storage.local.set({ approvals: a }); return { ok: true }; },
  async exportFile() { const box = await getBox(); if (!box) throw new Error('no store'); return box; },
  async importFile({ box, passphrase }) { const key = await deriveKey(passphrase, unb64(box.salt)); const incoming = await open(key, box); let mine = []; try { mine = await entries(); } catch (e) {} const merged = [...mine.filter(m => !incoming.some(i => i.owner === m.owner)), ...incoming]; if (!(await getBox())) { const salt = newSalt(); const k2 = await deriveKey(passphrase, salt); await chrome.storage.sync.set({ box: await seal(k2, salt, merged) }); await chrome.storage.session.set({ jwk: await crypto.subtle.exportKey('jwk', k2) }); } else await save(merged); return { ok: true, count: merged.length }; },
};
// the native helper (keycraft-host) reads what a Freenet node on this machine holds
const HOST = 'com.craftworks.keycraft';
const native = msg => new Promise((res, rej) => { let port; try { port = chrome.runtime.connectNative(HOST); } catch (e) { return rej(e); } let done = false; port.onMessage.addListener(r => { done = true; port.disconnect(); r.error ? rej(new Error(r.error)) : res(r.ok); }); port.onDisconnect.addListener(() => { if (!done) rej(new Error(chrome.runtime.lastError ? chrome.runtime.lastError.message : 'helper closed')); }); port.postMessage(msg); });
ops.hostPing = async () => native({ op: 'ping' });
// every craftworks identity on this machine's node, and a count of what else is there
ops.scanNode = async ({ data_dir } = {}) => { const r = await native({ op: 'list', data_dir }); const mine = await entries(); const found = []; let others = 0; for (const d of r.delegates) { for (const i of d.identities) found.push({ ...i, delegate: d.address, here: mine.some(m => m.owner === i.owner) }); if (d.kind !== 'craftworks') others += Object.keys(d.secrets).length; } return { data_dir: r.data_dir, identities: found, other_secrets: others, delegates: r.delegates.length }; };
ops.importFromNode = async ({ data_dir } = {}) => { const r = await native({ op: 'list', data_dir }); let n = 0; for (const d of r.delegates) for (const i of d.identities) { if (!i.store_key) continue; try { await ops.put({ entry: { name: i.name, owner: i.owner, store_key: i.store_key, signing_key: i.signing_key } }); n++; } catch (e) {} } return { imported: n }; };

const FROM_PAGE = new Set(['ping', 'list', 'create', 'put', 'get', 'storeKey', 'sign', 'approved', 'approve']);

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const op = ops[msg && msg.op];
  if (!op) { reply({ error: 'unknown op' }); return; }
  // a page reaches here through content.js (its url is the page's); the popup's url is our own
  const fromPage = !(sender.url || '').startsWith(chrome.runtime.getURL(''));
  if (fromPage && !FROM_PAGE.has(msg.op)) { reply({ error: 'not from a page' }); return; }
  op(msg).then(v => reply({ ok: v }), e => reply({ error: String(e && e.message || e) }));
  return true;
});
