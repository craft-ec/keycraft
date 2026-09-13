// Smoke: with the extension holding two identities and one active, does a page
// show exactly one account in the top-right chip, with no switch menu?
import { chromium } from 'playwright-core';
import path from 'node:path'; import fs from 'node:fs';
const app = process.argv[2] || 'filecraft'; const portMap = { filecraft: 8796, papercraft: 8795, datacraft: 8797, dot: 8792, grid: 8793 };
const node = process.argv[3] || '7510';
const ids = JSON.parse(fs.readFileSync('/Users/onlyabrak/.claude/jobs/2a0aa3ae/tmp/ids.json', 'utf8'));
const ext = path.resolve(new URL('..', import.meta.url).pathname);
const profile = '/Users/onlyabrak/.claude/jobs/2a0aa3ae/tmp/kc-smoke-' + app; fs.rmSync(profile, { recursive: true, force: true });
const t0 = Date.now(); const T = () => ((Date.now() - t0) / 1000).toFixed(1) + 's'; const say = (...a) => console.log(T(), app, ...a);
setTimeout(() => { say('TIMEOUT'); process.exit(3); }, 120000).unref();
const ctx = await chromium.launchPersistentContext(profile, { executablePath: process.env.PW_EXE, headless: true, args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`] });
const warm = await ctx.newPage(); await warm.goto(`http://localhost:${portMap[app]}/index.html?port=${node}`).catch(() => {});
let sw = ctx.serviceWorkers()[0]; if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 60000 });
const id = new URL(sw.url()).host; await warm.close();
const popup = await ctx.newPage(); await popup.goto(`chrome-extension://${id}/popup.html`);
await popup.fill('#pw', '246810'); await popup.click('#unlock'); await popup.waitForSelector('#open:not([hidden])', { timeout: 20000 });
for (const i of ids) await popup.evaluate(e => chrome.runtime.sendMessage({ op: 'put', entry: e }), { name: i.name, owner: i.owner, store_key: i.store_key, signing_key: i.signing_key });
await popup.evaluate(o => chrome.runtime.sendMessage({ op: 'setActive', owner: o }), ids[0].owner);
say('active =', ids[0].name, '; extension holds', ids.length);
const pg = await ctx.newPage(); pg.on('dialog', d => d.accept());
await pg.goto(`http://localhost:${portMap[app]}/index.html?port=${node}`);
await pg.waitForFunction(() => typeof window.__app === 'function' && window.__app(), null, { timeout: 60000 }).catch(() => say('app global not ready'));
// let it settle, then read the account UI
await pg.waitForTimeout(4000);
const r = await pg.evaluate(async () => {
  const app = window.__app && window.__app(); let people = null;
  try { people = JSON.parse(await app.accounts()).people.map(p => p.name); } catch (e) { people = 'accounts err: ' + e; }
  const chip = document.getElementById('acct-btn');
  const chipRect = chip && !chip.hidden ? chip.getBoundingClientRect() : null;
  return { pageSeesPeople: people, chipText: chip ? chip.textContent : '(none)', chipHidden: chip ? chip.hidden : '(no chip)', chipRight: chipRect ? Math.round(window.innerWidth - chipRect.right) : null, chipTop: chipRect ? Math.round(chipRect.top) : null, hasMenu: !!document.getElementById('acct-menu') };
});
say('RESULT', JSON.stringify(r));
await ctx.close(); process.exit(0);
