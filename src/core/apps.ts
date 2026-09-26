import fs from 'node:fs';
import path from 'node:path';
import type { Context } from './context.ts';
import { measureTree, type ScanItem } from './scan.ts';

// PLAN.md §3.1 user-level v0.1 targets: browser caches, GPU shader caches, crash dumps.
// Browser rule: only the cache folders below are ever targets. Cookies, Login Data, History, Local Storage,
// Service Worker storage and bookmarks live elsewhere in the profile and are never touched.

export const BROWSER_CACHE_DIRS = ['Cache', 'Code Cache', 'GPUCache', 'cache2'];

const BROWSERS: Array<{ id: string; name: string; dir: string[]; exe: string; firefox?: boolean }> = [
  { id: 'CHROME', name: 'Chrome', dir: ['Google', 'Chrome', 'User Data'], exe: 'chrome.exe' },
  { id: 'EDGE', name: 'Edge', dir: ['Microsoft', 'Edge', 'User Data'], exe: 'msedge.exe' },
  { id: 'BRAVE', name: 'Brave', dir: ['BraveSoftware', 'Brave-Browser', 'User Data'], exe: 'brave.exe' },
  { id: 'FIREFOX', name: 'Firefox', dir: ['Mozilla', 'Firefox', 'Profiles'], exe: 'firefox.exe', firefox: true },
];

const localAppData = (ctx: Context) => path.join(ctx.home, 'AppData', 'Local');
const dirs = (p: string) => { try { return fs.readdirSync(p, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.isSymbolicLink()).map((e) => e.name); } catch { return []; } };
const sum = (targets: string[]) => targets.map(measureTree).reduce((a, b) => ({ bytes: a.bytes + b.bytes, files: a.files + b.files }), { bytes: 0, files: 0 });

export function scanBrowsers(ctx: Context): ScanItem[] {
  const items: ScanItem[] = [];
  for (const b of BROWSERS) {
    const root = path.join(localAppData(ctx), ...b.dir);
    const profiles = b.firefox ? dirs(root) : dirs(root).filter((d) => d === 'Default' || /^Profile \d+$/.test(d));
    const targets = profiles.flatMap((p) => (b.firefox ? ['cache2'] : ['Cache', 'Code Cache', 'GPUCache']).map((c) => path.join(root, p, c))).filter((t) => fs.existsSync(t));
    const m = sum(targets);
    if (!targets.length || !m.bytes) continue;
    items.push({
      id: `BROWSER-${b.id}`, category: 'browser-cache', title: `${b.name} cache (${profiles.length} profile(s); cookies, logins and history are not touched)`,
      op: 'delete_cache', targets, allowRoot: root, targetNames: BROWSER_CACHE_DIRS, requiresClosed: [b.exe], ...m, risk: 'safe', reversible: 'redownload',
    });
  }
  return items;
}

const SHADERS: Array<[string, string[]]> = [
  ['SHADER-NVIDIA-DX', ['NVIDIA', 'DXCache']], ['SHADER-NVIDIA-GL', ['NVIDIA', 'GLCache']],
  ['SHADER-AMD-DX', ['AMD', 'DxCache']], ['SHADER-AMD-GL', ['AMD', 'GLCache']], ['SHADER-D3D', ['D3DSCache']],
];

export function scanShaders(ctx: Context): ScanItem[] {
  return SHADERS.flatMap(([id, rel]) => {
    const dir = path.join(localAppData(ctx), ...rel);
    const m = measureTree(dir);
    if (!m.bytes) return [];
    return [{ id, category: 'shader-cache', title: `GPU shader cache ${rel.join('\\')} (rebuilt by games; first launch may stutter)`, op: 'delete_cache', targets: [dir], allowRoot: dir, ...m, risk: 'safe', reversible: 'redownload' } satisfies ScanItem];
  });
}

export function scanCrashDumps(ctx: Context): ScanItem[] {
  const dir = path.join(localAppData(ctx), 'CrashDumps');
  let entries: string[] = [];
  try { entries = fs.readdirSync(dir).map((e) => path.join(dir, e)); } catch { return []; }
  const m = sum(entries);
  if (!entries.length || !m.bytes) return [];
  return [{ id: 'DUMPS', category: 'crash-dumps', title: `Application crash dumps (${entries.length} file(s); keep them if a developer asked for them)`, op: 'quarantine', targets: entries, allowRoot: dir, ...m, risk: 'safe', reversible: 'move-back' }];
}
