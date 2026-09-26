import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { decide } from '../guard/decide.ts';
import { isSameOrDescendant, normalizeWinPath } from '../guard/normalize.ts';
import { regQuery, type RegValue } from '../guard/protected.ts';
import type { ItemOutcome } from './apply.ts';
import { measureTree, type Category, type ScanItem } from './scan.ts';

// PLAN.md §3.1 administrator rows and §6.7. Every location comes from the environment block of this
// process (SystemRoot, SystemDrive, ProgramData, LOCALAPPDATA) or the registry, never from user input.
//
// Guard design: C:\Windows and C:\ProgramData are in the forbidden set P, but decide() only denies P
// itself and its ANCESTORS, so descendants such as C:\Windows\Temp pass the P check and are then refused
// only because no allow root covers them. The admin capability is therefore not a new decide() mode but
// a fixed allow-root table (adminAllowRoots) derived from the environment. The elevated process never
// takes allowRoot or command from the plan: it rebuilds both from its own environment and refuses any
// item whose values differ (verifyAdminItem).

const DAY = 86_400_000;
const gb = (b: number) => `${(b / 2 ** 30).toFixed(2)} GB`;

export type AdminCategory = Extract<Category, 'system-temp' | 'windows-update' | 'delivery-optimization' | 'system-dumps' | 'wer-archive' | 'winsxs' | 'hibernation' | 'windows-old' | 'wsl-disk' | 'docker-disk'>;
export const ADMIN_CATEGORIES: readonly AdminCategory[] = ['system-temp', 'windows-update', 'delivery-optimization', 'system-dumps', 'wer-archive', 'winsxs', 'hibernation', 'windows-old', 'wsl-disk', 'docker-disk'];

type Env = Record<string, string | undefined>;

/** Well-known locations, or undefined when the environment does not give a sane absolute path. */
export function adminLocations(env: Env = process.env) {
  const norm = (p: string | undefined) => { const n = p ? normalizeWinPath(p) : undefined; return n?.ok ? n.path : undefined; };
  const root = norm(env.SystemRoot);
  const drive = norm(env.SystemDrive ? `${env.SystemDrive}\\` : undefined);
  const pd = norm(env.ProgramData);
  if (!root || !drive || !pd) return undefined;
  const sys32 = path.win32.join(root, 'System32');
  return {
    root, drive, sys32,
    temp: path.win32.join(root, 'Temp'),
    wuParent: path.win32.join(root, 'SoftwareDistribution'),
    wuDownload: path.win32.join(root, 'SoftwareDistribution', 'Download'),
    doCache: path.win32.join(root, 'ServiceProfiles', 'NetworkService', 'AppData', 'Local', 'Microsoft', 'Windows', 'DeliveryOptimization', 'Cache'),
    memoryDmp: path.win32.join(root, 'MEMORY.DMP'),
    minidump: path.win32.join(root, 'Minidump'),
    wer: path.win32.join(pd, 'Microsoft', 'Windows', 'WER'),
    winsxs: path.win32.join(root, 'WinSxS'),
    hiberfil: path.win32.join(drive, 'hiberfil.sys'),
    windowsOld: path.win32.join(drive, 'Windows.old'),
    powershell: path.win32.join(sys32, 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
  };
}
type Loc = NonNullable<ReturnType<typeof adminLocations>>;

/**
 * Allow roots for the elevated capability, rebuilt from the environment in the elevated process. Items are
 * decided against these, never against the plan's allowRoot. Report-only and non-admin items have none.
 */
export function adminAllowRoots(env: Env = process.env): Partial<Record<AdminCategory, string[]>> {
  const l = adminLocations(env);
  if (!l) return {};
  return {
    'system-temp': [l.temp], 'windows-update': [l.wuDownload], 'delivery-optimization': [l.doCache],
    'system-dumps': [l.memoryDmp, l.minidump], winsxs: [l.winsxs], hibernation: [l.hiberfil],
  };
}

// Paths embedded in PowerShell single-quoted literals: allow only characters that cannot end the literal.
const SAFE_LITERAL = /^[A-Za-z]:\\[A-Za-z0-9 _.\\()-]*$/;
const PS = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command'];

/** The only commands admin items may run, rebuilt from the environment on both sides of elevation. */
export function adminCommand(category: AdminCategory, l: Loc): { file: string; args: string[] } | undefined {
  switch (category) {
    case 'windows-update': {
      if (!SAFE_LITERAL.test(l.wuDownload)) return undefined;
      // Services are restarted only if they were running; reparse points are removed as links, never followed.
      const script = `$ErrorActionPreference='Stop'; $d='${l.wuDownload}'; $s=@(Get-Service -Name wuauserv,bits | Where-Object Status -eq 'Running'); Stop-Service -Name wuauserv,bits -Force; try { Get-ChildItem -LiteralPath $d -Force | ForEach-Object { if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { $_.Delete() } else { Remove-Item -LiteralPath $_.FullName -Recurse -Force } } } finally { $s | Start-Service }`;
      return { file: l.powershell, args: [...PS, script] };
    }
    case 'delivery-optimization': return { file: l.powershell, args: [...PS, 'Delete-DeliveryOptimizationCache -Force'] };
    case 'winsxs': return { file: path.win32.join(l.sys32, 'Dism.exe'), args: ['/Online', '/Cleanup-Image', '/StartComponentCleanup'] };
    case 'hibernation': return { file: path.win32.join(l.sys32, 'powercfg.exe'), args: ['/hibernate', 'off'] };
    default: return undefined;
  }
}

/** WSL names are limited to these characters by wsl.exe; anything else is not ours to pass on. */
const DISTRO = /^[A-Za-z0-9._-]{1,64}$/;
export const wslCommand = (sys32: string, distro: string) => ({ file: path.win32.join(sys32, 'wsl.exe'), args: ['--manage', distro, '--set-sparse', 'true'] });

// --- Probes (all injectable; defaults are read-only) ---

export function isElevated(whoami: () => string = defaultWhoami): boolean {
  try { return /S-1-16-(12288|16384)\b/.test(whoami()); } catch { return false; }
}
function defaultWhoami(): string {
  return execFileSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe'), ['/groups', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true, timeout: 15_000 });
}

/** File size from the directory listing (works for hiberfil.sys, which cannot be opened or stat'ed). */
function defaultListedSize(file: string): number | undefined {
  const ps = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const r = spawnSync(ps, [...PS, 'Get-ChildItem -LiteralPath $env:HB_DIR -Force -Filter $env:HB_NAME | ForEach-Object Length'], {
    encoding: 'utf8', windowsHide: true, timeout: 20_000, env: { ...process.env, HB_DIR: path.win32.dirname(file), HB_NAME: path.win32.basename(file) },
  });
  const n = Number((r.stdout ?? '').trim());
  return r.status === 0 && Number.isFinite(n) && n > 0 ? n : undefined;
}

function defaultAnalyze(dism: string): string | undefined {
  const r = spawnSync(dism, ['/Online', '/Cleanup-Image', '/AnalyzeComponentStore'], { encoding: 'utf8', windowsHide: true, timeout: 900_000 });
  return r.status === 0 ? r.stdout : undefined;
}

export interface AdminScanDeps {
  env?: Env;
  elevated?: boolean;
  now?: () => Date;
  regQuery?: (key: string, recursive?: boolean) => RegValue[];
  /** Size of a file read from its directory listing. */
  listedSize?: (file: string) => number | undefined;
  /** `DISM /Online /Cleanup-Image /AnalyzeComponentStore` output. Only called when elevated (slow, admin-only). */
  analyzeComponentStore?: (dism: string) => string | undefined;
}

type Presence = 'missing' | 'readable' | 'unreadable';
function presence(p: string): Presence {
  try { fs.lstatSync(p); return 'readable'; } catch (e) { return (e as NodeJS.ErrnoException).code === 'ENOENT' ? 'missing' : 'unreadable'; }
}
const readable = (dir: string) => { try { fs.readdirSync(dir); return true; } catch { return false; } };

/** Regular top-level files older than `cutoff`. Never descends: see executeAdminItem('system-temp'). */
function oldTopFiles(dir: string, cutoff: number): { files: string[]; bytes: number } {
  const files: string[] = []; let bytes = 0;
  let names: string[] = [];
  try { names = fs.readdirSync(dir); } catch { return { files, bytes }; }
  for (const n of names) {
    const p = path.win32.join(dir, n);
    try { const st = fs.lstatSync(p); if (st.isFile() && st.mtimeMs < cutoff) { files.push(p); bytes += st.size; } } catch { /* vanished or locked */ }
  }
  return { files, bytes };
}

const dmpFiles = (dir: string) => { try { return fs.readdirSync(dir).filter((n) => /\.dmp$/i.test(n)).map((n) => path.win32.join(dir, n)).filter((p) => fs.lstatSync(p).isFile()); } catch { return []; } };

/** "Backups and Disabled Features" + "Cache and Temporary Data": the 3rd and 4th sizes in the report (labels are localized). */
export function parseComponentStore(out: string): number {
  const sizes = [...out.matchAll(/:\s*([\d.,]+)\s*(bytes|KB|MB|GB|TB)\b/gi)].map((m) => {
    const n = Number(m[1]!.replace(/,(?=\d{1,2}$)/, '.').replace(/,/g, ''));
    return n * 1024 ** ['bytes', 'kb', 'mb', 'gb', 'tb'].indexOf(m[2]!.toLowerCase());
  });
  return Math.round((sizes[2] ?? 0) + (sizes[3] ?? 0));
}

const LXSS = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss';
const POWER = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power';

export function scanAdmin(deps: AdminScanDeps = {}, only?: Category[]): ScanItem[] {
  const env = deps.env ?? process.env;
  const l = adminLocations(env);
  if (!l) return [];
  const want = (c: Category) => !only || only.includes(c);
  const elevated = deps.elevated ?? isElevated();
  const now = (deps.now ?? (() => new Date()))().getTime();
  const reg = deps.regQuery ?? regQuery;
  const items: ScanItem[] = [];
  const unknown = ' (size known after elevation)';
  const admin = { needsAdmin: true } as const;

  if (want('system-temp') && presence(l.temp) !== 'missing') {
    // Users may create files in C:\Windows\Temp, so only top-level regular files are ever unlinked (no recursion,
    // no link following). Directories there are left alone. Unreadable without elevation: size comes later.
    const m = readable(l.temp) ? oldTopFiles(l.temp, now - DAY) : undefined;
    if (!m || m.files.length) items.push({ id: 'SYS-TEMP', category: 'system-temp', title: m ? `Windows Temp files older than 24h (${m.files.length} files)` : `Windows Temp files older than 24h${unknown}`, op: 'delete_cache', targets: [l.temp], allowRoot: l.temp, bytes: m?.bytes ?? 0, files: m?.files.length ?? 0, risk: 'safe', reversible: 'none', ...admin });
  }

  const wuCmd = adminCommand('windows-update', l);
  if (want('windows-update') && wuCmd && presence(l.wuDownload) !== 'missing') {
    const m = readable(l.wuDownload) ? measureTree(l.wuDownload) : { bytes: 0, files: 0 };
    if (m.bytes || !readable(l.wuDownload)) items.push({ id: 'WU-DOWNLOAD', category: 'windows-update', title: `Downloaded Windows Update files${m.bytes ? '' : unknown}`, op: 'tool_cmd', targets: [l.wuDownload], allowRoot: l.wuDownload, command: wuCmd, bytes: m.bytes, files: m.files, risk: 'safe', reversible: 'redownload', ...admin });
  }

  if (want('delivery-optimization') && presence(l.doCache) !== 'missing') {
    const ok = readable(l.doCache);
    const m = ok ? measureTree(l.doCache) : { bytes: 0, files: 0 };
    if (m.bytes || !ok) items.push({ id: 'DO-CACHE', category: 'delivery-optimization', title: `Delivery Optimization cache${ok ? '' : unknown}`, op: 'tool_cmd', targets: [l.doCache], allowRoot: l.doCache, command: adminCommand('delivery-optimization', l)!, bytes: m.bytes, files: m.files, risk: 'safe', reversible: 'redownload', ...admin });
  }

  if (want('system-dumps')) {
    const targets: string[] = []; let bytes = 0, files = 0;
    try { const st = fs.lstatSync(l.memoryDmp); if (st.isFile()) { targets.push(l.memoryDmp); bytes += st.size; files++; } } catch { /* none */ }
    const minis = dmpFiles(l.minidump);
    if (minis.length) { targets.push(l.minidump); for (const f of minis) { bytes += fs.lstatSync(f).size; files++; } }
    if (targets.length) items.push({ id: 'SYS-DUMPS', category: 'system-dumps', title: `Windows crash dumps (${files} files)`, op: 'delete_cache', targets, allowRoot: l.root, bytes, files, risk: 'safe', reversible: 'none', ...admin });
  }

  if (want('wer-archive')) {
    // Authenticated Users have write+delete on these folders (checked on a real PC 2026-09-26), so PLAN §6.7
    // forbids touching them elevated. Their reports inherit that ACL, so the user can delete them unelevated.
    const reports = ['ReportArchive', 'ReportQueue'].flatMap((d) => {
      const dir = path.win32.join(l.wer, d);
      try { return fs.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.isSymbolicLink()).map((e) => path.win32.join(dir, e.name)); } catch { return []; }
    });
    const m = reports.map(measureTree).reduce((a, b) => ({ bytes: a.bytes + b.bytes, files: a.files + b.files }), { bytes: 0, files: 0 });
    if (reports.length && m.bytes) items.push({ id: 'WER', category: 'wer-archive', title: `Windows Error Reporting archive (${reports.length} reports)`, op: 'delete_cache', targets: reports, allowRoot: l.wer, ...m, risk: 'safe', reversible: 'none' });
  }

  if (want('winsxs') && presence(l.winsxs) !== 'missing') {
    const cmd = adminCommand('winsxs', l)!;
    const out = elevated ? (deps.analyzeComponentStore ?? defaultAnalyze)(cmd.file) : undefined;
    const bytes = out ? parseComponentStore(out) : 0;
    if (!elevated || bytes) items.push({ id: 'WINSXS', category: 'winsxs', title: out ? 'Superseded Windows components (WinSxS)' : 'Superseded Windows components (WinSxS) - size known after analysis', op: 'tool_cmd', targets: [l.winsxs], allowRoot: l.winsxs, command: cmd, bytes, files: 0, risk: 'caution', reversible: 'none', ...admin });
  }

  if (want('hibernation')) {
    const disabled = reg(POWER).some((v) => v.name === 'HibernateEnabled' && /^0x0$/i.test(v.data));
    if (!disabled && presence(l.hiberfil) !== 'missing') {
      let bytes: number | undefined;
      try { bytes = fs.statSync(l.hiberfil).size; } catch { bytes = (deps.listedSize ?? defaultListedSize)(l.hiberfil); }
      items.push({ id: 'HIBERNATE', category: 'hibernation', title: `Hibernation file (turns off hibernation and Fast Startup)${bytes ? '' : ' - size unknown'}`, op: 'tool_cmd', targets: [l.hiberfil], allowRoot: l.hiberfil, command: adminCommand('hibernation', l)!, bytes: bytes ?? 0, files: 1, risk: 'caution', reversible: 'none', ...admin });
    }
  }

  if (want('windows-old') && presence(l.windowsOld) !== 'missing') {
    const m = measureTree(l.windowsOld);
    items.push({ id: 'WINDOWS-OLD', category: 'windows-old', title: `Previous Windows installation (Windows.old)${m.bytes ? '' : ' - size unreadable'}`, op: 'report_only', targets: [l.windowsOld], allowRoot: l.windowsOld, bytes: m.bytes, files: m.files, risk: 'caution', reversible: 'none', ...admin,
      instructions: 'Open Settings > System > Storage > Temporary files, tick "Previous Windows installation(s)" and select Remove files. After that you can no longer roll back to the previous Windows version. Hydra-bane does not delete this folder itself.' });
  }

  if (want('wsl-disk')) {
    const byKey = new Map<string, Record<string, string>>();
    for (const v of reg(LXSS, true)) { const o = byKey.get(v.key) ?? {}; o[v.name] = v.data; byKey.set(v.key, o); }
    for (const o of byKey.values()) {
      const name = o.DistributionName, base = o.BasePath?.replace(/^\\\\\?\\/, '');
      if (!name || !base || !DISTRO.test(name)) continue;
      const n = normalizeWinPath(path.win32.join(base, 'ext4.vhdx'));
      if (!n.ok) continue;
      let size: number;
      try { size = fs.statSync(n.path).size; } catch { continue; }
      // Reclaimable space inside the disk is unknown until WSL trims it, so bytes stays 0. PLAN §3.1: never touch the file.
      items.push({ id: `WSL-${name}`, category: 'wsl-disk', title: `WSL disk of "${name}" (${gb(size)} file): let it shrink automatically (sparse mode)`, op: 'tool_cmd', targets: [n.path], allowRoot: n.path, command: wslCommand(l.sys32, name), bytes: 0, files: 1, risk: 'caution', reversible: 'none' });
    }
  }

  if (want('docker-disk') && env.LOCALAPPDATA) {
    for (const rel of [['disk', 'docker_data.vhdx'], ['data', 'ext4.vhdx']]) {
      const n = normalizeWinPath(path.win32.join(env.LOCALAPPDATA, 'Docker', 'wsl', ...rel));
      if (!n.ok) continue;
      let size: number;
      try { size = fs.statSync(n.path).size; } catch { continue; }
      items.push({ id: 'DOCKER-DISK', category: 'docker-disk', title: `Docker Desktop disk (${gb(size)} file)`, op: 'report_only', targets: [n.path], allowRoot: n.path, bytes: size, files: 1, risk: 'caution', reversible: 'none',
        instructions: 'Run `docker system prune` to remove stopped containers, unused networks, dangling images and build cache (it asks before deleting; do not add --volumes unless you know the volumes hold nothing you need, because volumes are your data). Then shrink the disk file from Docker Desktop: Troubleshoot > Clean / Purge data, or quit Docker Desktop, run `wsl --shutdown` and compact the .vhdx. Hydra-bane does not run these for you.' });
      break;
    }
  }
  return items;
}

// --- Elevated side ---

export interface AclDeps {
  /** Raw `icacls <path>` output. */
  icacls?: (target: string) => string;
}

function defaultIcacls(target: string): string {
  return execFileSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'icacls.exe'), [target], { encoding: 'utf8', windowsHide: true, timeout: 15_000 });
}

const ADMIN_TRUSTEES = new Set(['nt authority\\system', 'builtin\\administrators', 'nt service\\trustedinstaller', 's-1-5-18', 's-1-5-32-544', 's-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464']);
const WRITE_RIGHTS = new Set(['F', 'M', 'W', 'WD', 'AD', 'D', 'DC', 'WDAC', 'WO', 'GA', 'GW', 'MA']);

/**
 * Trustees other than SYSTEM / Administrators / TrustedInstaller whose allow ACE grants any write, delete or
 * ACL right (inherit-only ACEs included: they govern the children we would touch). CREATOR OWNER placeholders
 * and mandatory labels are ignored. Localized trustee names are unknown to us and count as non-admin (fail closed).
 */
export function nonAdminWriters(icaclsOut: string, target: string): string[] {
  const writers = new Set<string>();
  for (const [i, raw] of icaclsOut.split(/\r?\n/).entries()) {
    const line = (i === 0 && raw.toLowerCase().startsWith(target.toLowerCase()) ? raw.slice(target.length) : raw).trim();
    const m = /^(.+?):((?:\([^)]*\))+)$/.exec(line);
    if (!m) continue;
    const trustee = m[1]!.trim().replace(/^\*/, '');
    const groups = [...m[2]!.matchAll(/\(([^)]*)\)/g)].map((g) => g[1]!);
    if (groups.includes('DENY')) continue;
    const t = trustee.toLowerCase();
    if (ADMIN_TRUSTEES.has(t) || t === 'creator owner' || t.startsWith('mandatory label\\')) continue;
    if (groups.flatMap((g) => g.split(',')).some((r) => WRITE_RIGHTS.has(r))) writers.add(trustee);
  }
  return [...writers];
}

export function userWritable(dir: string, deps: AclDeps = {}): string[] | 'UNKNOWN' {
  try { return nonAdminWriters((deps.icacls ?? defaultIcacls)(dir), dir); } catch { return 'UNKNOWN'; }
}

/**
 * Folders whose DACL must not let non-admins write (PLAN §6.7). Only items whose elevated action resolves a
 * path through folders are listed. system-temp checks C:\Windows, not C:\Windows\Temp (which users can write):
 * its executor only unlinks top-level regular files and a swapped-in link is removed as a link, never followed.
 * powercfg / DISM / Delete-DeliveryOptimizationCache take no path from us.
 */
const ACL_CHECK: Partial<Record<AdminCategory, (l: Loc) => string[]>> = {
  'system-temp': (l) => [l.root],
  'windows-update': (l) => [l.wuParent, l.wuDownload],
  'system-dumps': (l) => [l.root, l.minidump],
};

export interface AdminApplyDeps extends AclDeps {
  env?: Env;
  /** Forbidden set P rebuilt in this process (buildProtectedPaths()). */
  protectedPaths: string[];
  now?: () => Date;
  /** Runs a program without a shell. */
  run?: (file: string, args: string[]) => { status: number | null; stderr: string };
}

const sameCmd = (a: ScanItem['command'], b: ScanItem['command']) => !!a && !!b && a.file === b.file && a.args.length === b.args.length && a.args.every((x, i) => x === b.args[i]);

/** Re-validates one plan item from scratch in the elevated process. Returns a refusal code, or undefined when OK. */
export function verifyAdminItem(item: ScanItem, deps: AdminApplyDeps): { code: string; detail: string } | undefined {
  const l = adminLocations(deps.env ?? process.env);
  if (!l) return { code: 'NO_ENV', detail: 'SystemRoot/SystemDrive/ProgramData missing' };
  const cat = item.category as AdminCategory;
  if (!item.needsAdmin || !ADMIN_CATEGORIES.includes(cat)) return { code: 'NOT_ADMIN_ITEM', detail: item.category };
  if (item.op === 'report_only') return { code: 'REPORT_ONLY', detail: 'follow the item instructions instead' };
  const roots = adminAllowRoots(deps.env ?? process.env)[cat];
  if (!roots) return { code: 'NOT_ADMIN_ITEM', detail: item.category };
  const expected = adminCommand(cat, l);
  if (item.op === 'tool_cmd' ? !sameCmd(item.command, expected) : !!item.command || item.op !== 'delete_cache') return { code: 'COMMAND_MISMATCH', detail: 'plan command differs from the one this version would run' };
  for (const t of item.targets) {
    const d = decide(t, 'disk', { protectedPaths: deps.protectedPaths, allowRoots: { disk: roots, atlas: [], purge: [] } });
    if (!d.allowed) return { code: `GUARD_${d.code}`, detail: t };
    if (d.path.toLowerCase() !== d.root.toLowerCase()) return { code: 'NOT_THE_ROOT', detail: `${t} must be exactly ${d.root}` };
  }
  for (const dir of ACL_CHECK[cat]?.(l) ?? []) {
    const w = userWritable(dir, deps);
    if (w === 'UNKNOWN') return { code: 'ACL_UNREADABLE', detail: dir };
    if (w.length) return { code: 'USER_WRITABLE_PARENT', detail: `${dir} is writable by ${w.join(', ')}` };
  }
  return undefined;
}

function unlinkFiles(files: string[], filter: (st: fs.Stats) => boolean): { bytes: number; failed: number } {
  let bytes = 0, failed = 0;
  for (const f of files) {
    try {
      const st = fs.lstatSync(f);
      if (!st.isFile() || !filter(st)) continue;
      fs.unlinkSync(f); // removes a link as a link if one was swapped in; never recurses
      bytes += st.size;
    } catch { failed++; }
  }
  return { bytes, failed };
}

const defaultRun = (file: string, args: string[]) => {
  const r = spawnSync(file, args, { encoding: 'utf8', windowsHide: true, timeout: 7_200_000 });
  return { status: r.status, stderr: (r.stderr || r.stdout || '').slice(-2000) };
};

/** Executes one admin item after verifyAdminItem. Callers must never send admin items through apply's generic path. */
export function executeAdminItem(item: ScanItem, deps: AdminApplyDeps): ItemOutcome[] {
  const bad = verifyAdminItem(item, deps);
  if (bad) return item.targets.map((target) => ({ id: item.id, target, ok: false, ...bad }));
  const l = adminLocations(deps.env ?? process.env)!;
  const now = (deps.now ?? (() => new Date()))().getTime();
  const target = item.targets[0]!;

  switch (item.category as AdminCategory) {
    case 'system-temp': {
      const names = (() => { try { return fs.readdirSync(l.temp); } catch { return []; } })();
      const r = unlinkFiles(names.map((n) => path.win32.join(l.temp, n)), (st) => st.mtimeMs < now - DAY);
      return [{ id: item.id, target, ok: true, bytes: r.bytes, ...(r.failed ? { detail: `${r.failed} files in use were skipped` } : {}) }];
    }
    case 'system-dumps':
      return item.targets.map((t) => {
        const files = t.toLowerCase() === l.minidump.toLowerCase() ? dmpFiles(l.minidump) : [l.memoryDmp];
        const r = unlinkFiles(files, () => true);
        return { id: item.id, target: t, ok: r.failed === 0, bytes: r.bytes, ...(r.failed ? { code: 'IO', detail: `${r.failed} files could not be removed` } : {}) };
      });
    default: {
      const measurable = item.category === 'windows-update' || item.category === 'delivery-optimization';
      const before = measurable ? measureTree(target).bytes : item.bytes;
      const r = (deps.run ?? defaultRun)(item.command!.file, item.command!.args);
      if (r.status !== 0) return [{ id: item.id, target, ok: false, code: 'TOOL_FAILED', detail: r.stderr.slice(0, 300) }];
      return [{ id: item.id, target, ok: true, bytes: measurable ? Math.max(0, before - measureTree(target).bytes) : before }];
    }
  }
}

/** True when `p` lies inside one of the admin allow roots; lets callers route items without trusting category alone. */
export const insideAdminRoots = (p: string, env: Env = process.env) => Object.values(adminAllowRoots(env)).flat().some((r) => !!r && isSameOrDescendant(p, r));
