// Renders a session recorded by record.ts into assets/demo.gif (light terminal, 16px mono, no intro).
// Needs Playwright (PLAYWRIGHT_MODULE=<path to playwright package> if it is not installed here) and ffmpeg on PATH.
// Usage: node scripts/demo/render.mjs [session.json] [out.gif]
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const session = JSON.parse(fs.readFileSync(process.argv[2] ?? 'scripts/demo/session.json', 'utf8'));
const outGif = path.resolve(process.argv[3] ?? 'assets/demo.gif');
const mod = process.env.PLAYWRIGHT_MODULE;
const pw = await import(mod ? pathToFileURL(path.join(mod, 'index.js')).href : 'playwright');
const { chromium } = pw.chromium ? pw : pw.default;

const PROMPT = 'sandbox> ';
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
const paint = (s) => esc(s)
  .replace(/^(Found .*? reclaimable\.)/gm, '<b class="ok">$1</b>')
  .replace(/Nothing was changed\./g, '<span class="ok">Nothing was changed.</span>')
  .replace(/\[caution\]/g, '<span class="warn">[caution]</span>')
  .replace(/^(Receipt .*|Restored .*)$/gm, '<b class="ok">$1</b>')
  .replace(/(Apply this plan\? \[y\/N\]: )/g, '<b>$1</b>');

// Timeline: [html, ms]. The first frame already shows the finished scan (no intro).
const frames = [];
let screen = '';
const show = (ms) => frames.push([screen, ms]);
const prompt = () => `<span class="p">${esc(PROMPT)}</span>`;
const ev = session.events;
for (let i = 0; i < ev.length; i++) {
  const e = ev[i];
  if (e.kind === 'cmd') {
    if (i === 0) { screen += `${prompt()}<b>${esc(e.text)}</b>\n`; continue; }
    screen += prompt();
    for (let k = 0; k < e.text.length; k += 3) frames.push([`${screen}<b>${esc(e.text.slice(0, k))}</b><span class="cur"> </span>`, 45]);
    screen += `<b>${esc(e.text)}</b>\n`;
    show(350);
  } else if (e.kind === 'out') {
    screen += paint(e.text);
    const waiting = ev[i + 1]?.kind === 'input';
    if (!waiting) screen += '\n';
    const lines = e.text.split('\n').length;
    show(waiting ? 3200 : i === 1 ? 4200 : Math.min(3400, 1300 + lines * 260));
  } else {
    frames.push([`${screen}<span class="cur"> </span>`, 500]);
    screen += `<b>${esc(e.text)}</b>\n`;
    show(300);
  }
}
frames.push([`${screen}${prompt()}<span class="cur"> </span>`, 2600]);

const css = `
  body{margin:0;background:#f3f1ec;font-family:'Cascadia Mono',Consolas,monospace}
  .win{width:900px;box-sizing:border-box;background:#fffdf8;border:1px solid #d9d4c7}
  .bar{height:34px;display:flex;align-items:center;gap:8px;padding:0 14px;background:#ece8de;border-bottom:1px solid #d9d4c7;font:13px system-ui,sans-serif;color:#5b5648}
  .d{width:12px;height:12px;border-radius:50%;background:#d6d0c2}
  .t{margin-left:10px}
  pre{margin:0;height:520px;overflow:hidden;padding:14px 18px;font:16px/1.45 'Cascadia Mono',Consolas,monospace;color:#23211c;white-space:pre-wrap;overflow-wrap:anywhere}
  .p{color:#2f5fa7} .ok{color:#1d7a3e} .warn{color:#a15c00}
  .cur{background:#23211c}`;
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 900, height: 600 } });
await page.setContent(`<style>${css}</style><div class="win"><div class="bar"><i class="d"></i><i class="d"></i><i class="d"></i><span class="t">hydra-bane · real run against a throwaway sandbox profile</span></div><pre id="t"></pre></div>`);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-frames-'));
const win = page.locator('.win');
const list = [];
for (const [i, [html, ms]] of frames.entries()) {
  await page.evaluate((h) => { const t = document.getElementById('t'); t.innerHTML = h; t.scrollTop = t.scrollHeight; }, html);
  const f = path.join(dir, `f${String(i).padStart(4, '0')}.png`);
  await win.screenshot({ path: f });
  list.push(`file '${f.replace(/\\/g, '/')}'\nduration ${(ms / 1000).toFixed(3)}`);
}
await browser.close();
list.push(`file '${path.join(dir, `f${String(frames.length - 1).padStart(4, '0')}.png`).replace(/\\/g, '/')}'`);
fs.writeFileSync(path.join(dir, 'list.txt'), list.join('\n'));
fs.mkdirSync(path.dirname(outGif), { recursive: true });
const ff = (args) => { const r = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', ...args], { stdio: 'inherit' }); if (r.status !== 0) throw new Error('ffmpeg failed'); };
const pal = path.join(dir, 'pal.png');
ff(['-f', 'concat', '-safe', '0', '-i', path.join(dir, 'list.txt'), '-vf', 'palettegen=max_colors=48:stats_mode=full', pal]);
ff(['-f', 'concat', '-safe', '0', '-i', path.join(dir, 'list.txt'), '-i', pal, '-lavfi', 'paletteuse=dither=none:diff_mode=rectangle', '-loop', '0', outGif]);
fs.rmSync(dir, { recursive: true, force: true });
const total = frames.reduce((s, [, ms]) => s + ms, 0);
console.log(`${outGif}: ${frames.length} frames, ${(total / 1000).toFixed(1)} s, ${(fs.statSync(outGif).size / 2 ** 20).toFixed(2)} MB`);
