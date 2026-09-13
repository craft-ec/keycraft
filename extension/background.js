// The service worker: holds the unlocked key in chrome.storage.session (memory,
// per browser session), the sealed store in chrome.storage.sync (follows the
// profile). Pages reach it through content.js; the popup directly.
import { deriveKey, seal, open, newSalt, unb64 } from './crypto.js';

const getBox = async () => (await chrome.storage.sync.get('box')).box || null;
const getSession = async () => (await chrome.storage.session.get('jwk')).jwk || null;
const sessionKey = async () => { const jwk = await getSession(); return jwk ? crypto.subtle.importKey('jwk', jwk, 'AES-GCM', true, ['encrypt', 'decrypt']) : null; };

const entries = async () => { const box = await getBox(); if (!box) return []; const key = await sessionKey(); if (!key) throw new Error('locked'); return open(key, box); };
const save = async list => { const box = await getBox(); const key = await sessionKey(); if (!key || !box) throw new Error('locked'); await chrome.storage.sync.set({ box: await seal(key, unb64(box.salt), list) }); };

const ops = {
  async status() { const box = await getBox(); return { initialised: !!box, unlocked: !!(await getSession()), count: box && (await getSession()) ? (await entries()).length : null }; },
  // first use: a passphrase makes the store; later: the passphrase unlocks it
  async unlock({ passphrase }) {
    let box = await getBox(); let key;
    if (!box) { const salt = newSalt(); key = await deriveKey(passphrase, salt); box = await seal(key, salt, []); await chrome.storage.sync.set({ box }); }
    else { key = await deriveKey(passphrase, unb64(box.salt)); await open(key, box); /* throws on a wrong passphrase */ }
    await chrome.storage.session.set({ jwk: await crypto.subtle.exportKey('jwk', key) });
    return { ok: true };
  },
  async lock() { await chrome.storage.session.remove('jwk'); return { ok: true }; },
  // names and owners only: never a secret
  async list() { return (await entries()).map(e => ({ name: e.name, owner: e.owner, can_sign: !!e.signing_key })); },
  async put({ entry }) { const list = (await entries()).filter(e => e.owner !== entry.owner); list.push({ name: entry.name, owner: entry.owner, store_key: entry.store_key, signing_key: entry.signing_key || '' }); await save(list); return { ok: true, count: list.length }; },
  async get({ owner }) { const e = (await entries()).find(e => e.owner === owner); if (!e) throw new Error('not in the store'); return e; },
  async remove({ owner }) { const list = (await entries()).filter(e => e.owner !== owner); await save(list); return { ok: true, count: list.length }; },
  // a keyfile: the sealed box as-is, so the passphrase travels with the person, not the file
  async exportFile() { const box = await getBox(); if (!box) throw new Error('no store'); return box; },
  async importFile({ box, passphrase }) { const key = await deriveKey(passphrase, unb64(box.salt)); const incoming = await open(key, box); let mine = []; try { mine = await entries(); } catch (e) {} const merged = [...mine.filter(m => !incoming.some(i => i.owner === m.owner)), ...incoming]; if (!(await getBox())) { const salt = newSalt(); const k2 = await deriveKey(passphrase, salt); await chrome.storage.sync.set({ box: await seal(k2, salt, merged) }); await chrome.storage.session.set({ jwk: await crypto.subtle.exportKey('jwk', k2) }); } else await save(merged); return { ok: true, count: merged.length }; },
};

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const op = ops[msg && msg.op];
  if (!op) { reply({ error: 'unknown op' }); return; }
  // a page may only list, put and get; the popup does the rest
  if (sender.tab && !['status', 'list', 'put', 'get'].includes(msg.op)) { reply({ error: 'not from a page' }); return; }
  op(msg).then(v => reply({ ok: v }), e => reply({ error: String(e && e.message || e) }));
  return true;
});
