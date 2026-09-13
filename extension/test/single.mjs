// Single-active identity, against the local node (7510) with the two existing
// identities (their drives already exist, so no fresh-create). Seeds the store
// via the popup, sets one active, checks the page sees only that one, switches.
import { chromium } from 'playwright-core';
import path from 'node:path'; import fs from 'node:fs';
const port = process.argv[2] || '7510';
const ids = JSON.parse(fs.readFileSync('/Users/onlyabrak/.claude/jobs/2a0aa3ae/tmp/ids.json', 'utf8'));
const ext = path.resolve(new URL('..', import.meta.url).pathname);
const profile = path.join(process.env.HOME, '.claude/jobs/2a0aa3ae/tmp/kc-single'); fs.rmSync(profile, { recursive: true, force: true });
const t0 = Date.now(); const T = () => ((Date.now() - t0) / 1000).toFixed(1) + 's'; const say = (...a) => console.log(T(), ...a);
setTimeout(() => { say('TIMEOUT'); process.exit(3); }, 300000).unref();
const ctx = await chromium.launchPersistentContext(profile, { executablePath: process.env.PW_EXE, headless: true, args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`] });
const warm = await ctx.newPage(); await warm.goto(`http://localhost:8796/index.html?port=${port}`).catch(() => {});
let sw = ctx.serviceWorkers()[0]; if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 60000 });
const id = new URL(sw.url()).host; say('extension', id); await warm.close();
const popup = await ctx.newPage(); popup.on('dialog', d => d.accept());
await popup.goto(`chrome-extension://${id}/popup.html`);
await popup.fill('#pw', '246810'); await popup.click('#unlock'); await popup.waitForSelector('#open:not([hidden])', { timeout: 20000 }); say('unlocked');
// seed the two identities directly (popup context is trusted)
for (const i of ids) { const r = await popup.evaluate(e => chrome.runtime.sendMessage({ op: 'put', entry: e }), { name: i.name, owner: i.owner, store_key: i.store_key, signing_key: i.signing_key }); say('put', i.name, JSON.stringify(r)); }
const active = ids[0].owner;
say('setActive', ids[0].name, JSON.stringify(await popup.evaluate(o => chrome.runtime.sendMessage({ op: 'setActive', owner: o }), active)));
say('listAll', JSON.stringify(await popup.evaluate(() => chrome.runtime.sendMessage({ op: 'listAll' }))));
// what a PAGE sees: only the active identity
const fc = await ctx.newPage(); fc.on('dialog', d => d.accept());
await fc.goto(`http://localhost:8796/index.html?port=${port}`);
await fc.waitForFunction(() => typeof window.__app === 'function' && window.__app(), null, { timeout: 60000 });
say('page accounts:', await fc.evaluate(async () => JSON.parse(await window.__app().accounts()).people.map(p => p.name)));
await fc.waitForFunction(() => /list \/files: (ok|.*error)/.test(document.getElementById('log').textContent), null, { timeout: 120000 }).catch(() => {});
say('filecraft:', await fc.textContent('#acct-btn'), '|', await fc.textContent('#crumb'));
// a signed write on the existing drive (fast; proves the extension signs on the real path)
const n = 'sa-' + Date.now().toString(36);
await fc.evaluate(async name => { const st = window.__state(); await window.__app().mkdir(st.ks, st.dirId, name); }, n).then(() => say('mkdir signed by the extension: ok'), e => say('mkdir failed:', String(e).slice(0, 200)));
// switch active in the popup → the page reloads to the other identity
say('setActive', ids[1].name, JSON.stringify(await popup.evaluate(o => chrome.runtime.sendMessage({ op: 'setActive', owner: o }), ids[1].owner)));
await fc.waitForFunction(n => document.getElementById('acct-btn').textContent.includes(n), ids[1].name, { timeout: 60000 }).then(() => say('page switched to', ids[1].name), () => say('page did NOT switch; acct =', ''));
say('filecraft after switch:', await fc.textContent('#acct-btn'), '|', await fc.textContent('#crumb'));
await ctx.close(); process.exit(0);
