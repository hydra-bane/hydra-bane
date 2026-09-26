import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Context } from './context.ts';
import { Ledger } from '../ledger/ledger.ts';
import { scanBrowsers, scanCrashDumps, scanShaders } from './apps.ts';

// v0.1 Disk catalog subset (PLAN.md §3.1): user temp, package-manager caches, stale node_modules / Rust target.

export type Category = 'temp' | 'npm-cache' | 'pnpm-store' | 'pip-cache' | 'uv-cache' | 'cargo-registry' | 'browser-cache' | 'shader-cache' | 'crash-dumps' | 'node_modules' | 'target' | 'quarantine'
  // v0.2 user-level caches (PLAN.md §3.1)
  | 'yarn-cache' | 'bun-cache' | 'conda-pkgs' | 'poetry-cache' | 'go-cache' | 'nuget-cache' | 'gradle-cache' | 'maven-repo' | 'hf-models' | 'ollama-models'
  // v0.2 admin items (PLAN.md §3.1, §6.7)
  | 'system-temp' | 'windows-update' | 'delivery-optimization' | 'system-dumps' | 'wer-archive' | 'winsxs' | 'hibernation' | 'windows-old' | 'wsl-disk' | 'docker-disk'
  // v0.2 Atlas (PLAN.md §7)
  | 'atlas';

/** Vendor uninstaller that passed the PLAN.md §7.3 checks at scan time; apply re-checks everything. */
export interface UninstallSpec {
  entryId: string;
  kind: 'msi' | 'exe';
  /** Absolute path of the executable to run (msiexec.exe for MSI). */
  file: string;
  args: string[];
  /** Authenticode thumbprints the executable must be signed with (exe only). */
  signers: string[];
}

export interface ScanItem {
  id: string;
  category: Category;
  title: string;
  op: 'quarantine' | 'tool_cmd' | 'delete_cache' | 'purge_quarantine' | 'uninstall' | 'report_only';
  targets: string[];
  allowRoot: string;
  command?: { file: string; args: string[] };
  /** If set, apply only touches targets whose folder name is in this list (defense in depth). */
  targetNames?: string[];
  /** Executables that must not be running when this item is applied. */
  requiresClosed?: string[];
  bytes: number;
  files: number;
  risk: 'safe' | 'caution' | 'danger';
  reversible: 'move-back' | 'redownload' | 'reinstall-only' | 'none';
  /** Must run elevated (PLAN.md §6.7). apply refuses it in a non-elevated process. */
  needsAdmin?: boolean;
  uninstall?: UninstallSpec;
  /** Plain-language instructions for items Hydra-bane only reports (op 'report_only'). */
  instructions?: string;
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

export const RETENTION_DAYS = 7;

/** Quarantined transactions past the undo window (PLAN.md §6.6). Nothing is purged automatically. */
function scanQuarantine(ctx: Context): ScanItem[] {
  const cutoff = ctx.now().getTime() - RETENTION_DAYS * DAY;
  const bases = new Set<string>();
  for (const r of new Ledger(path.join(ctx.stateDir, 'ledger')).records()) {
    const base = (r.data as { quarantineBase?: string } | null)?.quarantineBase;
    if (r.type === 'done' && base) bases.add(base);
  }
  const items: ScanItem[] = [];
  for (const base of bases) {
    let txs: string[] = [];
    try { txs = fs.readdirSync(base).filter((t) => fs.existsSync(path.join(base, t, 'manifest.json'))); } catch { continue; }
    for (const tx of txs) {
      const dir = path.join(base, tx);
      let createdAt: string;
      try { createdAt = (JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')) as { createdAt: string }).createdAt; } catch { continue; }
      if (new Date(createdAt).getTime() >= cutoff) continue;
      const m = measureTree(dir);
      items.push({ id: '', category: 'quarantine', title: `Quarantine from ${createdAt.slice(0, 10)} (tx ${tx}), undo window over`, op: 'purge_quarantine', targets: [dir], allowRoot: base, ...m, risk: 'caution', reversible: 'none' });
    }
  }
  return items;
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

// Tool caches: locate with the tool itself, clean with its official command. cargo has none, so only its
// re-downloadable subfolders are deleted directly (~/.cargo/bin is never touched).
interface CacheSpec { category: Category; title: string; locate: (ctx: Context) => string[]; clean?: { file: string; args: string[] } }

const CACHES: CacheSpec[] = [
  { category: 'npm-cache', title: 'npm cache', locate: (ctx) => [ctx.locate('npm config get cache')].filter(isStr), clean: { file: 'npm', args: ['cache', 'clean', '--force'] } },
  { category: 'pnpm-store', title: 'pnpm store (prune removes unreferenced packages: up to this size)', locate: (ctx) => [ctx.locate('pnpm store path')].filter(isStr), clean: { file: 'pnpm', args: ['store', 'prune'] } },
  { category: 'pip-cache', title: 'pip cache', locate: (ctx) => [ctx.locate('pip cache dir')].filter(isStr), clean: { file: 'pip', args: ['cache', 'purge'] } },
  { category: 'uv-cache', title: 'uv cache (prune removes unused entries: up to this size)', locate: (ctx) => [ctx.locate('uv cache dir')].filter(isStr), clean: { file: 'uv', args: ['cache', 'prune'] } },
  {
    category: 'cargo-registry', title: 'cargo registry and git checkouts',
    locate: (ctx) => {
      const home = process.env.CARGO_HOME ?? path.join(ctx.home, '.cargo');
      return [['registry', 'cache'], ['registry', 'src'], ['git', 'checkouts']].map((p) => path.join(home, ...p));
    },
  },
];

const isStr = (x: string | undefined): x is string => !!x;

function scanCaches(ctx: Context, want: (c: Category) => boolean): ScanItem[] {
  const items: ScanItem[] = [];
  for (const c of CACHES) {
    if (!want(c.category)) continue;
    for (const dir of c.locate(ctx).filter((d) => path.isAbsolute(d) && fs.existsSync(d))) {
      const m = measureTree(dir);
      if (!m.bytes) continue;
      // Each item may only touch its own folder: allowRoot === target.
      items.push(c.clean
        ? { id: '', category: c.category, title: c.title, op: 'tool_cmd', targets: [dir], allowRoot: dir, command: c.clean, ...m, risk: 'safe', reversible: 'redownload' }
        : { id: '', category: c.category, title: `${c.title} (${path.basename(path.dirname(dir))}/${path.basename(dir)})`, op: 'delete_cache', targets: [dir], allowRoot: dir, ...m, risk: 'safe', reversible: 'redownload' });
      if (c.clean) break; // tool commands clean the whole cache once
    }
  }
  return items;
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

// IDs must not depend on --only or on what else was found, so an ID seen in one scan means the same
// item in the next: fixed names for singletons, a short path hash for per-folder items.
const FIXED_ID: Partial<Record<Category, string>> = { temp: 'TEMP', 'npm-cache': 'NPM', 'pnpm-store': 'PNPM', 'pip-cache': 'PIP', 'uv-cache': 'UV' };
const pathId = (prefix: string, p: string) => `${prefix}-${createHash('sha1').update(p.toLowerCase()).digest('hex').slice(0, 6)}`;

function stableId(i: ScanItem): string {
  const fixed = FIXED_ID[i.category];
  if (fixed) return fixed;
  if (i.category === 'cargo-registry') return `CARGO-${path.basename(path.dirname(i.targets[0]!)).toUpperCase()}-${path.basename(i.targets[0]!).toUpperCase()}`;
  if (i.category === 'quarantine') return `Q-${path.basename(i.targets[0]!).slice(0, 8)}`;
  return pathId(i.category === 'target' ? 'TGT' : 'NM', i.targets[0]!);
}

export function scan(ctx: Context, only?: Category[]): ScanItem[] {
  const want = (c: Category) => !only || only.includes(c);
  const items = [
    ...(want('temp') ? scanTemp(ctx) : []),
    ...scanCaches(ctx, want),
    ...(want('browser-cache') ? scanBrowsers(ctx) : []),
    ...(want('shader-cache') ? scanShaders(ctx) : []),
    ...(want('crash-dumps') ? scanCrashDumps(ctx) : []),
    ...(want('node_modules') || want('target') ? scanProjects(ctx).filter((i) => want(i.category)) : []),
    ...(want('quarantine') ? scanQuarantine(ctx) : []),
  ];
  for (const i of items) if (!i.id) i.id = stableId(i);
  return items;
}

