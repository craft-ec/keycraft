const $ = id => document.getElementById(id);
const send = m => chrome.runtime.sendMessage(m).then(r => { if (r.error) throw new Error(r.error); return r.ok; });
const render = async () => {
  const st = await send({ op: 'status' });
  $('locked').hidden = st.unlocked; $('open').hidden = !st.unlocked;
  $('lk-msg').textContent = st.initialised ? 'Unlock the key store.' : 'Pick a passphrase: it seals the store on this device and on every device your Chrome profile syncs to.';
  if (!st.unlocked) return;
  const list = await send({ op: 'list' }); const box = $('list'); box.replaceChildren();
  if (!list.length) box.append(Object.assign(document.createElement('p'), { className: 'muted', textContent: 'empty: save an identity from keycraft on a node' }));
  for (const e of list) { const d = document.createElement('div'); d.className = 'id'; d.innerHTML = `<span><b></b><br><code></code></span>`; d.querySelector('b').textContent = e.name + (e.can_sign ? '' : ' (read-only)'); d.querySelector('code').textContent = e.owner.slice(0, 20) + '…'; const rm = document.createElement('button'); rm.className = 'ghost'; rm.textContent = 'Remove'; rm.onclick = async () => { if (confirm(`Remove ${e.name} from the extension? Nodes that have it keep it.`)) { await send({ op: 'remove', owner: e.owner }); render(); } }; d.append(rm); box.append(d); }
};
$('unlock').onclick = async () => { $('lk-err').textContent = ''; try { await send({ op: 'unlock', passphrase: $('pw').value }); $('pw').value = ''; render(); } catch (e) { $('lk-err').textContent = 'wrong passphrase'; } };
$('pw').onkeydown = e => { if (e.key === 'Enter') $('unlock').click(); };
$('lock').onclick = async () => { await send({ op: 'lock' }); render(); };
$('export').onclick = async () => { const box = await send({ op: 'exportFile' }); const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(box)], { type: 'application/json' })); a.download = 'keycraft-keys.json'; a.click(); };
$('import').onclick = () => $('file').click();
$('file').onchange = async () => { const f = $('file').files[0]; if (!f) return; try { const box = JSON.parse(await f.text()); const pw = prompt('Passphrase of that keyfile'); if (pw == null) return; await send({ op: 'importFile', box, passphrase: pw }); render(); } catch (e) { $('err').textContent = String(e.message || e); } };
render();
