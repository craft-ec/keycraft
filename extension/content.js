// The bridge a craftworks page sees: window.postMessage in, postMessage out.
// Page → { craftworksKeys: { id, op, ...args } }; back → { craftworksKeysReply: { id, ok | error } }.
// A page only ever gets a secret back after the person confirms in this frame.
window.addEventListener('message', async e => {
  const m = e.data && e.data.craftworksKeys; if (!m || e.source !== window) return;
  const answer = r => window.postMessage({ craftworksKeysReply: { id: m.id, ...r } }, '*');
  if (m.op === 'get' && !window.confirm(`Give this page the keys of "${m.name || m.owner}" from the keycraft extension? It will import them into the node it is connected to.`)) return answer({ error: 'declined' });
  if (m.op === 'put' && !window.confirm(`Save the keys of "${m.entry && m.entry.name}" into the keycraft extension? They will sync with your browser profile, encrypted.`)) return answer({ error: 'declined' });
  try { answer(await chrome.runtime.sendMessage(m)); } catch (err) { answer({ error: String(err) }); }
});
window.postMessage({ craftworksKeysReady: true }, '*');
