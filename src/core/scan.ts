import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { Context } from './context.ts';

// v0.1 Disk catalog subset (PLAN.md §3.1): user temp, npm cache, stale node_modules / Rust target.

export type Category = 'temp' | 'npm-cache' | 'node_modules' | 'target';

export interface ScanItem {
  id: string;
  category: Category;
  title: string;
  op: 'quarantine' | 'tool_cmd';
  targets: string[];
  allowRoot: string;
  command?: { file: string; args: string[] };
  bytes: number;
  files: number;
  risk: 'safe' | 'caution';
  reversible: 'move-back' | 'redownload';
}

const DAY = 86_400_000;
export const STALE_DAYS = 30;

export function measureTree(p: string): { bytes: number; files: number } {
  let bytes = 0, files = 0;
  let st: fs.Stats;
  try { st = fs.lstatSync(p); } catch { return { bytes, files }; }
  if (st.isSymbolicLink()) return { bytes, files };
  if (!st.isDirectory()) return { bytes: st.size, files: 1 };
  const stack = [p];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) stack.push(full);
      else { files++; try { bytes += fs.lstatSync(full).size; } catch { /* vanished */ } }
    }
  }
  return { bytes, files };
}

function scanTemp(ctx: Context): ScanItem[] {
  const cutoff = ctx.now().getTime() - DAY;
  let entries: string[] = [];
  try { entries = fs.readdirSync(ctx.tempDir); } catch { return []; }
  const old = entries.map((e) => path.join(ctx.tempDir, e)).filter((p) => {
    try { return fs.lstatSync(p).mtimeMs < cutoff; } catch { return false; }
  });
  if (!old.length) return [];
  const m = old.map(measureTree).reduce((a, b) => ({ bytes: a.bytes + b.bytes, files: a.files + b.files }), { bytes: 0, files: 0 });
  return [{ id: '', category: 'temp', title: `Temp files older than 24h (${old.length} entries)`, op: 'quarantine', targets: old, allowRoot: ctx.tempDir, ...m, risk: 'safe', reversible: 'move-back' }];
}

function scanNpmCache(ctx: Context): ScanItem[] {
  // npm is a .cmd shim: run through cmd.exe with constant arguments only (PLAN.md §5.4), never shell: true.
  const npm = spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', 'npm config get cache'], { encoding: 'utf8', windowsHide: true, timeout: 20_000 });
  const dir = npm.stdout?.trim();
  if (!dir || !fs.existsSync(dir)) return [];
  const m = measureTree(dir);
  if (!m.bytes) return [];
  return [{ id: '', category: 'npm-cache', title: 'npm cache', op: 'tool_cmd', targets: [dir], allowRoot: dir, command: { file: 'npm', args: ['cache', 'clean', '--force'] }, ...m, risk: 'safe', reversible: 'redownload' }];
}

function git(cwd: string, args: string[]): { status: number | null; out: string } {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', windowsHide: true, timeout: 20_000 });
  return { status: r.status, out: (r.stdout ?? '').trim() };
}

/** PLAN.md §3.2 eligibility: inside a git repo, git-ignored, nothing tracked, ecosystem marker present, stale. */
function eligibleArtifact(dir: string, markers: string[], cutoff: number): boolean {
  const parent = path.dirname(dir);
  if (!markers.every((m) => fs.existsSync(path.join(parent, m)))) return false;
  const mtimes = [dir, ...markers.map((m) => path.join(parent, m))].map((p) => fs.statSync(p).mtimeMs);
  if (Math.max(...mtimes) >= cutoff) return false;
  if (git(parent, ['rev-parse', '--is-inside-work-tree']).out !== 'true') return false;
  if (git(parent, ['check-ignore', '-q', dir]).status !== 0) return false;
  return git(parent, ['ls-files', '--', dir]).out === '';
}

const ARTIFACTS: Array<{ name: string; category: Category; markers: string[][] }> = [
  { name: 'node_modules', category: 'node_modules', markers: [['package.json', 'package-lock.json'], ['package.json', 'pnpm-lock.yaml'], ['package.json', 'yarn.lock'], ['package.json', 'bun.lock']] },
  { name: 'target', category: 'target', markers: [['Cargo.toml', 'Cargo.lock']] },
];

function scanProjects(ctx: Context): ScanItem[] {
  const cutoff = ctx.now().getTime() - STALE_DAYS * DAY;
  const items: ScanItem[] = [];
  for (const root of ctx.roots) {
    if (!fs.existsSync(root)) continue;
    const stack: Array<[string, number]> = [[root, 0]];
    while (stack.length) {
      const [dir, depth] = stack.pop()!;
      let entries: fs.Dirent[];
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
      for (const e of entries) {
        if (!e.isDirectory() || e.isSymbolicLink()) continue;
        const full = path.join(dir, e.name);
        const a = ARTIFACTS.find((x) => x.name === e.name);
        if (a) {
          if (a.markers.some((ms) => eligibleArtifact(full, ms, cutoff))) {
            const m = measureTree(full);
            items.push({ id: '', category: a.category, title: `${a.name} in ${path.basename(dir)} (untouched ${STALE_DAYS}+ days)`, op: 'quarantine', targets: [full], allowRoot: root, ...m, risk: 'caution', reversible: 'move-back' });
          }
          continue; // never descend into artifacts
        }
        if (e.name === '.git' || depth >= 6) continue;
        stack.push([full, depth + 1]);
      }
    }
  }
  return items;
}

const PREFIX: Record<Category, string> = { temp: 'T', 'npm-cache': 'N', node_modules: 'P', target: 'P' };

export function scan(ctx: Context, only?: Category[]): ScanItem[] {
  const want = (c: Category) => !only || only.includes(c);
  const items = [
    ...(want('temp') ? scanTemp(ctx) : []),
    ...(want('npm-cache') ? scanNpmCache(ctx) : []),
    ...(want('node_modules') || want('target') ? scanProjects(ctx).filter((i) => want(i.category)) : []),
  ];
  const counters: Record<string, number> = {};
  for (const i of items) {
    const p = PREFIX[i.category];
    counters[p] = (counters[p] ?? 0) + 1;
    i.id = `${p}${counters[p]}`;
  }
  return items;
}

