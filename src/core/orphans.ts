import fs from 'node:fs';
import path from 'node:path';
import { decide } from '../guard/decide.ts';
import { isDriveRoot, isSameOrDescendant, normalizeWinPath } from '../guard/normalize.ts';
import { regQuery } from '../guard/protected.ts';
import { listPrograms as defaultListPrograms, type Program } from '../atlas/programs.ts';
import { parentIsRedirected } from '../quarantine/quarantine.ts';
import { policyFor, type Context } from './context.ts';
import { defaultShortcutTargets, DOC_EXT, DOC_LIMIT, lnkFiles, nameVariants, publisherVariants, WALK_LIMIT } from './leftovers.ts';
import { measureTree, pathId, STALE_DAYS, type ScanItem } from './scan.ts';

// Remnants of programs removed outside Hydra-bane. Deliberately narrow, because there is no uninstall record to
// vouch for anything:
//  (a) folders under %LOCALAPPDATA%\Programs (the per-user install root) that hold an .exe, that no installed
//      program, shortcut (Start Menu, taskbar, desktop), Run entry, App Paths entry or PATH entry points into,
//      and where nothing changed for STALE_DAYS days;
//  (b) the user's Start Menu shortcuts whose target is gone (grouped into one item).
// Vendor folders in AppData without a program are never offered: a name alone cannot prove what owns them.

export interface OrphanDeps {
  listPrograms?: () => Program[];
  env?: Record<string, string | undefined>;
  shortcutTargets?: (files: string[]) => Map<string, string>;
  /** Other strings that may point into a program folder: Run / RunOnce commands, App Paths, PATH entries. */
  otherRefs?: () => string[];
}

const DAY = 86_400_000;
const REF_KEYS = ['HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths', 'HKCU\Environment', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'];
const SKIP_NAMES = new Set(['common']); // %LOCALAPPDATA%\Programs\Common is shared by several installers
const MAX_CLOSE = 50;
const lc = (s: string) => s.toLowerCase();

// Registry PATH as well as this process's: a portable app on PATH is in use even though nothing else names it.
const defaultOtherRefs = () => [...REF_KEYS.flatMap((k) => regQuery(k, k.endsWith('App Paths')).map((v) => v.data)), ...(process.env.PATH ?? '').split(';')];

/** git repos, documents, newest change time (files and folders), .exe names, and whether the walk stopped early. */
function walk(dir: string): { git: boolean; docs: number; newest: number; exes: string[]; truncated: boolean } {
  let docs = 0, seen = 0, newest = 0;
  const exes = new Set<string>();
  const stack = [dir];
  const result = (git: boolean, truncated: boolean) => ({ git, docs, newest, exes: [...exes], truncated });
  while (stack.length) {
    const d = stack.pop()!;
    try { newest = Math.max(newest, fs.lstatSync(d).mtimeMs); } catch { return result(false, true); }
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return result(false, true); }
    for (const e of entries) {
      if (++seen > WALK_LIMIT) return result(false, true);
      if (lc(e.name) === '.git') return result(true, false);
      const full = path.join(d, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { stack.push(full); continue; }
      try { newest = Math.max(newest, fs.lstatSync(full).mtimeMs); } catch { return result(false, true); }
      const ext = lc(path.extname(e.name));
      if (ext === '.exe') exes.add(e.name);
      else if (DOC_EXT.has(ext)) docs++;
    }
  }
  return result(false, false);
}

/** Missing for sure: the drive is there and Windows says the path is not. Access errors or unplugged drives are not "missing". */
function targetMissing(target: string): boolean {
  const n = normalizeWinPath(target);
  if (!n.ok || !/^[a-z]:\\/i.test(n.path) || isDriveRoot(n.path)) return false;
  if (!fs.existsSync(n.path.slice(0, 3))) return false;
  try { fs.lstatSync(n.path); return false; } catch (e) { const c = (e as NodeJS.ErrnoException).code; return c === 'ENOENT' || c === 'ENOTDIR'; }
}

export function scanOrphans(ctx: Context, deps: OrphanDeps = {}): ScanItem[] {
  const env = deps.env ?? process.env;
  const abs = (p: string | undefined) => { const n = p ? normalizeWinPath(p) : undefined; return n?.ok && !isDriveRoot(n.path) ? n.path : undefined; };
  const programsRoot = abs(env.LOCALAPPDATA && path.win32.join(env.LOCALAPPDATA, 'Programs'));
  const userStart = abs(env.APPDATA && path.win32.join(env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs'));
  const commonStart = abs(env.ProgramData && path.win32.join(env.ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs'));
  const state = abs(ctx.stateDir);
  const cutoff = ctx.now().getTime() - STALE_DAYS * DAY;

  // Candidate folders first: most PCs have few, and without any the program list and Run keys are never read.
  const candidates: string[] = [];
  if (programsRoot) {
    try {
      for (const e of fs.readdirSync(programsRoot, { withFileTypes: true })) {
        if (e.isDirectory() && !e.isSymbolicLink() && !SKIP_NAMES.has(lc(e.name))) candidates.push(path.win32.join(programsRoot, e.name));
      }
    } catch { /* no per-user programs */ }
  }

  const userLnks = userStart ? lnkFiles(userStart) : [];
  // Shortcuts that only count as references: all-users Start Menu, taskbar pins, desktops.
  const refDirs = [commonStart, abs(env.APPDATA && path.win32.join(env.APPDATA, 'Microsoft', 'Internet Explorer', 'Quick Launch')), abs(env.USERPROFILE && path.win32.join(env.USERPROFILE, 'Desktop')), abs(env.PUBLIC && path.win32.join(env.PUBLIC, 'Desktop'))];
  const commonLnks = candidates.length ? refDirs.flatMap((d) => (d ? lnkFiles(d) : [])) : [];
  const allLnks = [...userLnks, ...commonLnks];
  const targets = allLnks.length ? (deps.shortcutTargets ?? defaultShortcutTargets)(allLnks) : new Map<string, string>();

  const items: ScanItem[] = [];
  if (candidates.length && programsRoot) {
    const programs = (deps.listPrograms ?? (() => defaultListPrograms()))();
    const expand = (s: string) => lc(s.replace(/%([^%]+)%/g, (all, v: string) => env[v] ?? all).replace(/\//g, '\\'));
    const refs = [
      ...programs.flatMap((p) => [p.installLocation, p.displayIcon, p.uninstallString, p.quietUninstallString]),
      ...targets.values(),
      ...(deps.otherRefs ?? defaultOtherRefs)(),
    ].filter((s): s is string => !!s).map(expand);
    // 8.3 short names ("FOOBAR~1") hide the long folder name: resolve the leading path of such references.
    for (const r of refs.filter((x) => x.includes('~'))) {
      const m = /^"([^"]+)"|^(.+?\.exe)\b|^([^,]+)/i.exec(r);
      const p = m?.[1] ?? m?.[2] ?? m?.[3];
      for (const q of p ? [p, path.win32.dirname(p)] : []) {
        try { refs.push(lc(fs.realpathSync.native(q))); break; } catch { /* not there */ }
      }
    }
    const names = new Set(programs.flatMap((p) => [...nameVariants(p.name), ...(p.publisher ? publisherVariants(p.publisher) : [])]).map(lc));
    const referenced = (dir: string) => {
      const re = new RegExp(lc(dir).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![a-z0-9])');
      return refs.some((r) => re.test(r));
    };

    for (const t of candidates) {
      if (names.has(lc(path.win32.basename(t)))) continue; // an installed program or vendor of this name
      if (state && (isSameOrDescendant(state, t) || isSameOrDescendant(t, state))) continue;
      if (parentIsRedirected(t)) continue;
      if (!decide(t, 'disk', policyFor(ctx, [programsRoot])).allowed) continue;
      if (referenced(t)) continue;
      const look = walk(t);
      if (look.git || !look.exes.length || (!look.truncated && look.newest >= cutoff)) continue;
      const why: string[] = [];
      if (look.docs > DOC_LIMIT) why.push(`It contains ${look.docs} documents, pictures or media files; check it yourself.`);
      if (look.truncated) why.push('It is too large to check completely; check it yourself.');
      items.push({
        id: pathId('ORPHAN', t), category: 'orphans',
        title: `Program folder no installed program uses: ${t} (unchanged ${STALE_DAYS}+ days)`,
        op: why.length ? 'report_only' : 'quarantine', targets: [t], allowRoot: programsRoot, targetNames: [path.win32.basename(t)],
        requiresClosed: look.exes.slice(0, MAX_CLOSE), ...measureTree(t), risk: 'caution', reversible: why.length ? 'none' : 'move-back',
        ...(why.length ? { instructions: `${why.join(' ')} If the program is really gone, delete the folder yourself.` } : {}),
      });
    }
  }

  if (userStart) {
    const dead = userLnks.filter((l) => {
      const tgt = targets.get(l);
      return !!tgt && targetMissing(tgt) && decide(l, 'disk', policyFor(ctx, [userStart])).allowed && !parentIsRedirected(l);
    });
    if (dead.length) {
      const m = dead.map(measureTree).reduce((a, b) => ({ bytes: a.bytes + b.bytes, files: a.files + b.files }), { bytes: 0, files: 0 });
      items.push({
        id: 'DEAD-SHORTCUTS', category: 'orphans', title: `Start Menu shortcuts whose program is gone (${dead.length})`,
        op: 'quarantine', targets: dead, allowRoot: userStart, targetNames: [...new Set(dead.map((d) => path.win32.basename(d)))],
        ...m, risk: 'caution', reversible: 'move-back',
      });
    }
  }
  return items;
}
