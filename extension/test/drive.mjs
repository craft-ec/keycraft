// Drives Chromium with the extension loaded: unlock, import what this
// machine's node holds through the native helper, then use filecraft with
// the extension signing. Output streams; the whole run is capped.
//   PW_EXE=<chromium binary> node drive.mjs <node ws port> [profile dir]
import { chromium } from 'playwright-core';
import path from 'node:path';
import fs from 'node:fs';
const port = process.argv[2] || '7511';
const profile = process.argv[3] || path.join(process.env.HOME, '.claude/jobs/2a0aa3ae/tmp/kc-profile');
const ext = path.resolve(new URL('..', import.meta.url).pathname);
fs.rmSync(profile, { recursive: true, force: true }); fs.mkdirSync(profile, { recursive: true });
const t0 = Date.now(); const T = () => ((Date.now() - t0) / 1000).toFixed(1) + 's';
const say = (...a) => { console.log(T(), ...a); };
setTimeout(() => { say("HARNESS TIMEOUT"); process.exit(3); }, 360000).unref();
let ctx;
try {
  ctx = await chromium.launchPersistentContext(profile, { channel: process.env.PW_EXE ? undefined : 'chromium', executablePath: process.env.PW_EXE || undefined, headless: !process.env.HEADED, args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`], viewport: { width: 1100, height: 800 } });
  // the service worker starts with the first page that talks to it
  const warm = await ctx.newPage(); await warm.goto(`http://localhost:8796/index.html?port=${port}`).catch(() => {});
  let sw = ctx.serviceWorkers()[0]; if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 60000 });
  sw.on('console', m => say('worker:', m.type(), m.text().slice(0, 200)));
  const id = new URL(sw.url()).host; say('extension', id);

  say('opening the popup'); const popup = await ctx.newPage(); say('popup page created');
  popup.on('console', m => say('popup:', m.type(), m.text().slice(0, 200))); popup.on('pageerror', e => say('popup error:', String(e).slice(0, 200)));
  popup.on('dialog', d => { say('popup dialog:', d.message().slice(0, 100)); d.accept(); });
  await popup.goto(`chrome-extension://${id}/popup.html`, { timeout: 20000 }); say('popup loaded');
  await popup.fill('#pw', '246810', { timeout: 10000 }); say('PIN typed'); await popup.click('#unlock', { timeout: 10000 }); say('unlock clicked');
  try { await popup.waitForSelector('#open:not([hidden])', { timeout: 20000 }); say('unlocked'); }
  catch (e) { say('unlock did not complete; lk-err =', JSON.stringify(await popup.textContent('#lk-err')), 'status =', JSON.stringify(await popup.evaluate(() => chrome.runtime.sendMessage({ op: 'status' })))); throw e; }
  say('popup lists:', await popup.$$eval('#list .id b', n => n.map(x => x.textContent)));

  // the native helper: what this machine's node holds → into the extension
  await popup.click('#scan');
  await popup.waitForFunction(() => /imported|identit|helper|not installed|error/i.test(document.getElementById('scan-out').textContent) && !/asking/.test(document.getElementById('scan-out').textContent), null, { timeout: 30000 }).catch(() => {});
  say('scan:', await popup.textContent('#scan-out'));
  await popup.waitForFunction(() => document.querySelectorAll('#list .id').length > 0, null, { timeout: 15000 }).catch(() => {});
  say('popup lists:', await popup.$$eval('#list .id b', n => n.map(x => x.textContent)));

  // filecraft: read (store key), then write (a folder = one signed commit)
  const fc = await ctx.newPage(); fc.on('dialog', d => { say('page dialog:', d.message().slice(0, 100)); d.accept(); });
  fc.on('pageerror', e => say('page error:', String(e).slice(0, 200))); fc.on('console', m => say('fc console:', m.type(), m.text().slice(0, 200)));
  await fc.goto(`http://localhost:8796/index.html?port=${port}`);
  await fc.waitForFunction(() => /list \/files: ok/.test(document.getElementById('log').textContent) || /error/.test(document.getElementById('status').textContent) || document.getElementById('s-welcome').classList.contains('on'), null, { timeout: 120000 });
  if (await fc.evaluate(() => document.getElementById('s-welcome').classList.contains('on'))) {
    say('filecraft: no identity yet; creating one through the extension');
    await fc.fill('#w-name', 'harness-' + Date.now().toString(36)); await fc.click('#w-go');
    await fc.waitForFunction(() => /list \/files: ok/.test(document.getElementById('log').textContent) || document.getElementById('w-err').textContent.length > 0, null, { timeout: 260000 });
    say('welcome result:', JSON.stringify(await fc.textContent('#w-err')));
    say('FULL LOG:\n' + await fc.textContent('#log'));
  }
  say('filecraft:', await fc.textContent('#status'), '|', await fc.textContent('#acct-btn'), '|', await fc.textContent('#crumb'));
  fc.on('console', m => { if (m.type() === 'error') say('page console:', m.text().slice(0, 300)); });
  // one call at a time into the wasm: let the page's own use-stamp call finish first
  await fc.waitForFunction(() => /use stamp: (ok|.*error.*)/.test(document.getElementById('log').textContent) || !/use stamp: started/.test(document.getElementById('log').textContent), null, { timeout: 120000 }).catch(() => say('use stamp still running'));
  const name = 'ext-' + Date.now().toString(36);
  await fc.evaluate(async n => { const st = window.__state(); await window.__app().mkdir(st.ks, st.dirId, n); }, name).then(() => say('mkdir signed by the extension: ok'), e => say('mkdir failed:', String(e).slice(0, 300)));
  say('log tail:', (await fc.textContent('#log')).slice(-400));
} catch (e) { say('FAILED:', String(e).split('\n')[0]); process.exitCode = 1; }
finally { if (ctx) await ctx.close().catch(() => {}); }
