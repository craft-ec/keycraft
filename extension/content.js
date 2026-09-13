// The bridge a craftworks page sees. Page → { craftworksKeys: { id, op, ...args } };
// back → { craftworksKeysReply: { id, ok | error } }. The first time an app
// uses an identity (a store key to read, a signature to write) the person is
// asked here, once per app and identity; a secret leaves the extension only
// through get, and only after a question every time.
const app = (location.pathname.match(/\/v1\/contract\/web\/([^/]+)/) || [])[1] || location.host;
const send = m => chrome.runtime.sendMessage(m);
const names = new Map(); // owner -> name, for the questions
window.addEventListener('message', async e => {
  const m = e.data && e.data.craftworksKeys; if (!m || e.source !== window) return;
  const answer = r => window.postMessage({ craftworksKeysReply: { id: m.id, ...r } }, '*');
  // only these come from a page; approvals are written here, never on the page's say-so
  if (!['ping', 'list', 'create', 'put', 'get', 'storeKey', 'sign'].includes(m.op)) return answer({ error: 'not a page operation' });
  try {
    if (m.op === 'list') { const r = await send(m); if (r.ok) for (const x of r.ok) names.set(x.owner, x.name); return answer(r); }
    if (m.op === 'storeKey' || m.op === 'sign') {
      const ok = await send({ op: 'approved', owner: m.owner });
      if (!(ok && ok.ok)) {
        const name = names.get(m.owner) || m.owner.slice(0, 12) + '…';
        if (!window.confirm(`Let this app (${app}) use your identity "${name}" from the keycraft extension? It will read as ${name} and sign what you do here as ${name}. You are asked once per app.`)) return answer({ error: 'declined' });
        await send({ op: 'approve', owner: m.owner, name });
      }
      return answer(await send(m));
    }
    if (m.op === 'get' && !window.confirm(`Give this page (${app}) the secret keys of "${m.name || m.owner}" from the keycraft extension?`)) return answer({ error: 'declined' });
    if (m.op === 'put' && !window.confirm(`Save the keys of "${m.entry && m.entry.name}" into the keycraft extension? They sync with your Chrome profile, encrypted.`)) return answer({ error: 'declined' });
    if (m.op === 'create' && !window.confirm(`Create the identity "${m.name}" in the keycraft extension for this app (${app})?`)) return answer({ error: 'declined' });
    answer(await send(m));
  } catch (err) { answer({ error: String(err && err.message || err) }); }
});
window.postMessage({ craftworksKeysReady: true }, '*');
// the active identity changed in the popup: pages reload their account
chrome.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes.active) window.postMessage({ craftworksKeysChanged: true }, '*'); });
