import fs from 'node:fs';
import path from 'node:path';
import type { Context } from './context.ts';
import type { ExplainText } from './explain.ts';
import { regQuery as realRegQuery, type RegValue } from '../guard/protected.ts';
import type { Category, ScanItem } from './scan.ts';

// Windows counterpart of Mole's `mo optimize` (docs/research/mole-analysis.md §2): maintenance actions a standard user
// can run safely. Every command is a System32 executable with constant arguments (apply runs it through cmd.exe, so
// nothing read from this PC may reach argv). Anything needing admin, killing Explorer, opening a window or losing data
// is reported with steps instead. Detection only reads: it never runs a command.

type Env = Record<string, string | undefined>;

export interface OptimizeDeps {
  env: Env;
  regQuery: (key: string) => RegValue[];
  exists: (p: string) => boolean;
  readdir: (dir: string) => string[];
  readFile: (p: string) => Buffer;
}

const defaultDeps = (): OptimizeDeps => ({
  env: process.env,
  regQuery: (k) => realRegQuery(k),
  exists: (p) => fs.existsSync(p),
  readdir: (d) => { try { return fs.readdirSync(d); } catch { return []; } },
  readFile: (p) => fs.readFileSync(p),
});

export const RUN_KEYS = [
  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
] as const;

const sys32 = (env: Env) => path.win32.join(env.SystemRoot ?? 'C:\\Windows', 'System32');

const TOOLS = [
  {
    id: 'OPT-DNS', exe: 'ipconfig.exe', args: ['/flushdns'], title: 'Flush the DNS resolver cache',
    instructions: 'Runs "ipconfig /flushdns", which empties the list of website addresses Windows remembered. Harmless: the next visit to each site looks its address up again (a few milliseconds). Fixes sites that moved servers or stale entries after a VPN or hosts-file change. No files are deleted and no administrator rights are needed.',
  },
  {
    id: 'OPT-ICON-CACHE', exe: 'ie4uinit.exe', args: ['-show'], title: 'Refresh the icon cache',
    instructions: 'Runs "ie4uinit.exe -show", the Windows tool that tells Explorer to reload its icon cache. Harmless: fixes blank or outdated icons; the desktop may flicker once. No cache file is deleted and Explorer is not restarted.',
  },
] as const;

/** Reads the absolute target path stored in a .lnk shortcut (MS-SHLLINK LinkInfo), or undefined. */
export function lnkTarget(buf: Buffer): string | undefined {
  try {
    if (buf.length < 0x4c || buf.readUInt32LE(0) !== 0x4c) return undefined;
    const flags = buf.readUInt32LE(0x14);
    let off = 0x4c;
    if (flags & 1) off += 2 + buf.readUInt16LE(off); // LinkTargetIDList
    if (!(flags & 2)) return undefined; // no LinkInfo
    const headerSize = buf.readUInt32LE(off + 4);
    if (!(buf.readUInt32LE(off + 8) & 1)) return undefined; // VolumeIDAndLocalBasePath
    const cstr = (start: number, wide: boolean) => {
      if (wide) { let e = start; while (e + 1 < buf.length && buf.readUInt16LE(e)) e += 2; return buf.toString('utf16le', start, e); }
      const e = buf.indexOf(0, start); return buf.toString('latin1', start, e < 0 ? buf.length : e);
    };
    const s = headerSize >= 0x24 ? cstr(off + buf.readUInt32LE(off + 0x1c), true) : cstr(off + buf.readUInt32LE(off + 0x10), false);
    return s || undefined;
  } catch { return undefined; }
}

export function startupEntries(deps: OptimizeDeps): string[] {
  const lines: string[] = [];
  for (const key of RUN_KEYS) {
    for (const v of deps.regQuery(key)) if (v.name && v.name !== '(Default)' && v.data) lines.push(`${v.name} = ${v.data} (${key.split('\\')[0]} Run)`);
  }
  const folders = [
    deps.env.APPDATA && path.win32.join(deps.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    deps.env.ProgramData && path.win32.join(deps.env.ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp'),
  ].filter((f): f is string => !!f);
  for (const dir of folders) {
    for (const name of deps.readdir(dir)) {
      if (name.toLowerCase() === 'desktop.ini') continue;
      const full = path.win32.join(dir, name);
      let target: string | undefined;
      if (name.toLowerCase().endsWith('.lnk')) { try { target = lnkTarget(deps.readFile(full)); } catch { /* unreadable */ } }
      lines.push(`${name} = ${target ?? full} (Startup folder)`);
    }
  }
  return lines;
}

export function scanOptimize(ctx: Context, deps: Partial<OptimizeDeps> = {}): ScanItem[] {
  const d = { ...defaultDeps(), ...deps };
  const s32 = sys32(d.env);
  const items: ScanItem[] = [];

  for (const t of TOOLS) {
    const file = path.win32.join(s32, t.exe);
    if (!d.exists(file)) continue;
    // The executable is the target so apply has something tiny to measure; files: 0 turns off the drift check.
    items.push({ id: t.id, category: 'optimize', title: t.title, op: 'tool_cmd', targets: [file], allowRoot: s32, command: { file, args: [...t.args] }, bytes: 0, files: 0, risk: 'safe', reversible: 'none', instructions: t.instructions });
  }

  const report = (id: string, title: string, target: string, instructions: string, risk: ScanItem['risk'] = 'safe') =>
    items.push({ id, category: 'optimize', title, op: 'report_only', targets: [target], allowRoot: target, bytes: 0, files: 0, risk, reversible: 'none', instructions });

  report('OPT-STORE-CACHE', 'Microsoft Store cache reset (manual)', path.win32.join(s32, 'wsreset.exe'),
    'Not run automatically: the only reset tool, wsreset.exe, opens the Store window. To do it yourself press Win+R, type wsreset.exe and press Enter; a blank window appears and the Store opens when done. Apps and purchases are kept; it only fixes Store downloads that are stuck.');
  report('OPT-THUMB-CACHE', 'Explorer thumbnail and icon cache files (manual)', path.win32.join(d.env.LOCALAPPDATA ?? ctx.home, 'Microsoft', 'Windows', 'Explorer'),
    'Not run automatically: the thumbcache_*.db and iconcache_*.db files are locked while Explorer runs, and Hydra-bane does not stop Explorer. To clear them use Settings > System > Storage > Temporary files > Thumbnails, or Disk Cleanup (cleanmgr) > Thumbnails. Folders show thumbnails again as you browse (slower the first time).');
  report('OPT-SEARCH-INDEX', 'Windows Search index rebuild (manual, administrator)', path.win32.join(d.env.ProgramData ?? 'C:\\ProgramData', 'Microsoft', 'Search'),
    'Not run automatically: rebuilding needs administrator rights. Only do it if search misses files: Settings > Privacy & security > Searching Windows > Advanced indexing options > Advanced > Rebuild. Search results are incomplete for a few hours while it rebuilds.');
  report('OPT-RECYCLE-BIN', 'Empty the Recycle Bin (manual, permanent)', path.win32.join(d.env.SystemDrive ? `${d.env.SystemDrive}\\` : 'C:\\', '$Recycle.Bin'),
    'Not run automatically: emptying is permanent and cannot be undone. Look through it first (double-click Recycle Bin on the desktop), restore anything you want, then right-click it and choose Empty Recycle Bin.', 'danger');

  const startup = startupEntries(d);
  if (startup.length) {
    report('OPT-STARTUP', `Programs that start with Windows (${startup.length}, review only)`, path.win32.join(d.env.APPDATA ?? ctx.home, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
      `Hydra-bane changes nothing here. Each entry below runs at sign-in and slows startup: ${startup.join('; ')}. To turn one off, open Task Manager > Startup apps, right-click it and choose Disable (reversible: choose Enable).`);
  }
  return items;
}

export const OPTIMIZE_TEXT: Partial<Record<Category, ExplainText>> = {
  optimize: {
    what: 'A Windows maintenance action (the equivalent of Mole\'s optimize), not files taking up space.',
    why: 'Only actions a standard user can run without risk are executed: flushing the DNS cache and refreshing icons. Anything that needs administrator rights, restarts Explorer, opens a window or deletes data for good is only reported with steps.',
    after: 'Frees no disk space. The item instructions say exactly what happens.',
  },
};
