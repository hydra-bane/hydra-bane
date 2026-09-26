import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { decide } from '../guard/decide.ts';
import { isDriveRoot, isSameOrDescendant, normalizeWinPath, pathKey } from '../guard/normalize.ts';
import { listPrograms as defaultListPrograms, type Program } from '../atlas/programs.ts';
import { Ledger } from '../ledger/ledger.ts';
import { parentIsRedirected } from '../quarantine/quarantine.ts';
import { policyFor, type Context } from './context.ts';
import { hkcuKeyProblem, keyExists as defaultKeyExists, RESERVED_KEY_SEGMENTS } from './registry.ts';
import { measureTree, pathId, type ScanItem } from './scan.ts';

// What removed programs leave behind. Conservative on purpose: a false positive quarantines someone's data.
// Only programs Hydra-bane itself uninstalled (ledger 'done' uninstall records) that are no longer installed are
// considered, and only folders/keys whose name is exactly the program's name are offered. Folders in the user
// profile are quarantined; machine-wide folders and HKLM keys are only reported.

type RemovedProgram = NonNullable<ScanItem['program']>;

export interface LeftoverDeps {
  listPrograms?: () => Program[];
  env?: Record<string, string | undefined>;
  keyExists?: (key: string) => boolean;
  /** .lnk file -> target path. Default reads each shortcut with WScript.Shell (read-only), in one PowerShell call. */
  shortcutTargets?: (files: string[]) => Map<string, string>;
}

/** More document-like files than this and the folder is only reported. */
export const DOC_LIMIT = 2;
const DOC_EXT = new Set(['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.hwp', '.hwpx', '.pdf', '.odt', '.ods', '.odp', '.rtf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.heic', '.webp', '.raw', '.cr2', '.nef', '.psd', '.ai', '.indd', '.dwg', '.mp3', '.wav', '.flac', '.mp4', '.mov', '.avi', '.mkv']);
const WALK_LIMIT = 50_000;

/** Folder/key names that are never one program's own. */
const GENERIC = new Set(['microsoft', 'windows', 'google', 'mozilla', 'apple', 'adobe', 'intel', 'nvidia', 'amd', 'common files', 'programs', 'packages', 'temp', 'tmp', 'cache', 'caches', 'data', 'config', 'logs', 'local', 'roaming', 'locallow', 'users', 'public', 'default', 'system', 'system32', 'app', 'apps', 'application', 'applications', 'program files', 'programdata', 'software', 'tools', 'bin', 'hydra-bane', 'package cache', 'installer', 'setup', 'update', 'updater', 'crashdumps', 'desktop', 'documents', 'downloads', 'onedrive', ...RESERVED_KEY_SEGMENTS]);

const usable = (n: string) => n.length >= 3 && !GENERIC.has(n.toLowerCase()) && !/[\\/:\0-\x1f"*?<>|]/.test(n) && !/[. ]$/.test(n);

/** The display name and the name without trailing version / architecture ("7-Zip 23.01 (x64)" -> "7-Zip"). */
export function nameVariants(name: string): string[] {
  const out = [name.trim()];
  let s = name.trim(), prev = '';
  while (s !== prev) {
    prev = s;
    s = s.replace(/\s*\((?:x64|x86|arm64|64-bit|32-bit|[^()]*\d[^()]*)\)$/i, '').replace(/\s+(?:v?\d+(?:[.\-_]\d+)*[a-z]?|x64|x86|arm64|64-bit|32-bit)$/i, '').replace(/[\s\-_,]+$/, '');
  }
  out.push(s);
  return [...new Set(out)].filter(usable);
}

/** The publisher and the publisher without a company suffix ("Foo Software, Inc." -> "Foo Software"). */
export function publisherVariants(publisher: string): string[] {
  const p = publisher.trim();
  const s = p.replace(/[,.\s]+(?:inc|llc|ltd|limited|corp|corporation|co|company|gmbh|ag|s\.?a|b\.?v|pty|plc|co\.,?\s*ltd)\.?$/i, '').trim();
  return [...new Set([p, s])].filter(usable);
}

const lc = (s: string) => s.toLowerCase();
const progKey = (p: { hive: string; view: string; keyName: string }) => lc(`${p.hive}|${p.view}|${p.keyName}`);

function removedPrograms(ctx: Context, listInstalled: () => Program[]): { removed: { program: RemovedProgram; removedAt: string }[]; installed: Program[] } {
  const latest = new Map<string, { program: RemovedProgram; removedAt: string }>();
  for (const r of new Ledger(path.join(ctx.stateDir, 'ledger')).records()) {
    const d = r.data as { op?: unknown; program?: Partial<RemovedProgram> } | null;
    const p = d?.program;
    if (r.type !== 'done' || d?.op !== 'uninstall' || !p || typeof p.name !== 'string' || typeof p.keyName !== 'string' || (p.hive !== 'HKLM' && p.hive !== 'HKCU') || (p.view !== '64' && p.view !== '32')) continue;
    latest.set(progKey(p as RemovedProgram), { program: p as RemovedProgram, removedAt: r.ts });
  }
  if (!latest.size) return { removed: [], installed: [] }; // the common case: no registry reads at all
  const installed = listInstalled();
  const installedKeys = new Set(installed.map(progKey));
  const installedNames = new Set(installed.flatMap((p) => nameVariants(p.name)).map(lc));
  // Reinstalled, or another version with the same name is installed: its folders are in use.
  return { removed: [...latest.values()].filter(({ program: p }) => !installedKeys.has(progKey(p)) && !nameVariants(p.name).some((n) => installedNames.has(lc(n)))), installed };
}

/** Real subfolders (no links or junctions) of dir, by lower-case name. */
function childDirs(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) if (e.isDirectory() && !e.isSymbolicLink()) out.set(lc(e.name), path.join(dir, e.name));
  } catch { /* missing */ }
  return out;
}

/** git repos anywhere inside, document-like files, and whether the walk had to stop early. */
function inspect(dir: string): { git: boolean; docs: number; truncated: boolean } {
  let docs = 0, seen = 0;
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return { git: false, docs, truncated: true }; }
    for (const e of entries) {
      if (++seen > WALK_LIMIT) return { git: false, docs, truncated: true };
      if (lc(e.name) === '.git') return { git: true, docs, truncated: false };
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) stack.push(path.join(d, e.name));
      else if (DOC_EXT.has(lc(path.extname(e.name)))) docs++;
    }
  }
  return { git: false, docs, truncated: false };
}

function defaultShortcutTargets(files: string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (!files.length) return out;
  const list = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-lnk-')), 'list.json');
  try {
    fs.writeFileSync(list, JSON.stringify(files), 'utf8');
    // CreateShortcut on an existing .lnk only loads it; nothing is saved without .Save().
    const ps = "$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;$s=New-Object -ComObject WScript.Shell;$o=[ordered]@{};foreach($p in (Get-Content -Raw -Encoding UTF8 -LiteralPath $env:HB_LNK_LIST | ConvertFrom-Json)){$o[$p]=$s.CreateShortcut($p).TargetPath};$o|ConvertTo-Json -Compress";
    const exe = path.win32.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const r = spawnSync(exe, ['-NoProfile', '-NonInteractive', '-Command', ps], { encoding: 'utf8', windowsHide: true, timeout: 60_000, env: { ...process.env, HB_LNK_LIST: list } });
    const parsed = JSON.parse((r.stdout ?? '').trim() || '{}') as Record<string, unknown>;
    for (const [k, v] of Object.entries(parsed)) if (typeof v === 'string' && v) out.set(k, v);
  } catch { /* unreadable shortcuts are simply not offered */ } finally {
    fs.rmSync(path.dirname(list), { recursive: true, force: true });
  }
  return out;
}

function lnkFiles(dir: string, depth = 0): string[] {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  return entries.flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) return [];
    if (e.isDirectory()) return depth < 3 ? lnkFiles(full, depth + 1) : [];
    return lc(path.extname(e.name)) === '.lnk' ? [full] : [];
  });
}

export function scanLeftovers(ctx: Context, deps: LeftoverDeps = {}): ScanItem[] {
  const { removed, installed } = removedPrograms(ctx, deps.listPrograms ?? (() => defaultListPrograms()));
  if (!removed.length) return [];

  const env = deps.env ?? process.env;
  const keyExists = deps.keyExists ?? defaultKeyExists;
  const abs = (p: string | undefined) => { const n = p ? normalizeWinPath(p) : undefined; return n?.ok && !isDriveRoot(n.path) ? n.path : undefined; };
  const userRoots = [abs(env.APPDATA), abs(env.LOCALAPPDATA), abs(env.LOCALAPPDATA && path.win32.join(env.LOCALAPPDATA, 'Programs'))].filter((r): r is string => !!r);
  const machineRoots = [abs(env.ProgramData), abs(env.ProgramFiles), abs(env['ProgramFiles(x86)']), abs(env.ProgramW6432)].filter((r): r is string => !!r);
  const allRoots = [...new Set([...userRoots, ...machineRoots])];
  const installedPubs = new Set(installed.flatMap((p) => (p.publisher ? publisherVariants(p.publisher) : [])).map(lc));
  const installedLocs = installed.map((p) => abs(p.installLocation)).filter((l): l is string => !!l);
  const state = abs(ctx.stateDir);

  const items: ScanItem[] = [];
  const taken: string[] = [];
  const title = (p: RemovedProgram, at: string, where: string) => `Leftover of ${p.name} (removed ${at.slice(0, 10)}): ${where}`;

  const offerFolder = (target: string, p: RemovedProgram, at: string, locations: string[]) => {
    const n = normalizeWinPath(target);
    if (!n.ok || isDriveRoot(n.path)) return;
    const t = n.path;
    if (allRoots.some((r) => pathKey(r) === pathKey(t))) return; // never a root folder itself
    if (taken.some((x) => isSameOrDescendant(t, x) || isSameOrDescendant(x, t))) return;
    if (state && isSameOrDescendant(state, t)) return;
    // A still-installed program lives here, or below it.
    if (installedLocs.some((l) => isSameOrDescendant(l, t) || isSameOrDescendant(t, l))) return;
    let st: fs.Stats;
    try { st = fs.lstatSync(t); } catch { return; }
    if (!st.isDirectory() || st.isSymbolicLink() || parentIsRedirected(t)) return;
    const userRoot = userRoots.filter((r) => isSameOrDescendant(t, r)).sort((a, b) => b.length - a.length)[0];
    const machineRoot = machineRoots.find((r) => isSameOrDescendant(t, r));
    // Guard first: never a protected path or an ancestor of one, never a drive root, never inside .git/.ssh.
    const guard = decide(t, 'disk', policyFor(ctx, [userRoot ?? t]));
    if (!guard.allowed) return;
    const look = inspect(t);
    if (look.git) return; // a repository is somebody's work, whatever its name
    const why: string[] = [];
    if (!userRoot) why.push(machineRoot ? `It is in ${machineRoot}, which needs administrator rights; Hydra-bane only reports it.` : 'It is outside the folders Hydra-bane cleans; Hydra-bane only reports it.');
    if (look.docs > DOC_LIMIT) why.push(`It contains ${look.docs} documents, pictures or media files; check it yourself.`);
    if (look.truncated) why.push('It is too large to check completely; check it yourself.');
    const m = measureTree(t);
    taken.push(t);
    locations.push(t);
    items.push({
      id: pathId('LEFT', t), category: 'leftovers', title: title(p, at, t),
      op: why.length ? 'report_only' : 'quarantine', targets: [t], allowRoot: userRoot ?? machineRoot ?? path.win32.dirname(t),
      ...m, risk: 'caution', reversible: why.length ? 'none' : 'move-back', program: p,
      ...(why.length ? { instructions: `${why.join(' ')} If it is really left over from ${p.name}, delete it yourself.` } : {}),
    });
  };

  const perProgram: { p: RemovedProgram; at: string; locations: string[] }[] = [];
  for (const { program: p, removedAt: at } of removed) {
    const names = nameVariants(p.name);
    if (!names.length) continue;
    const nameSet = new Set(names.map(lc));
    const pubs = p.publisher ? publisherVariants(p.publisher).filter((x) => !nameSet.has(lc(x))) : [];
    const locations: string[] = [];
    const recorded = abs(p.installLocation);
    if (recorded) locations.push(recorded); // for shortcuts, even when the folder is gone
    if (recorded && nameSet.has(lc(path.win32.basename(recorded)))) offerFolder(recorded, p, at, locations);
    for (const root of allRoots) {
      const kids = childDirs(root);
      for (const n of names) { const d = kids.get(lc(n)); if (d) offerFolder(d, p, at, locations); }
      for (const pub of pubs) {
        const pubDir = kids.get(lc(pub));
        if (!pubDir) continue;
        const inside = childDirs(pubDir);
        for (const n of names) {
          const prod = inside.get(lc(n));
          if (!prod) continue;
          let all: string[] = [];
          try { all = fs.readdirSync(pubDir); } catch { /* raced */ }
          // The vendor folder goes only when this product is all it holds and no installed program shares the vendor.
          offerFolder(all.length === 1 && !installedPubs.has(lc(pub)) ? pubDir : prod, p, at, locations);
        }
      }
    }
    for (const n of names) {
      for (const r of allRoots) locations.push(path.win32.join(r, n));
      for (const pub of pubs) for (const r of allRoots) locations.push(path.win32.join(r, pub, n));
    }
    perProgram.push({ p, at, locations });

    // Registry: exact names only. HKCU keys can be exported and deleted; HKLM keys are reported.
    const keyNames = [...names.map((n) => [n]), ...pubs.flatMap((pub) => names.map((n) => [pub, n]))];
    for (const segs of keyNames) {
      const hkcu = `HKCU\\Software\\${segs.join('\\')}`;
      if (!hkcuKeyProblem(hkcu) && keyExists(hkcu)) {
        items.push({ id: pathId('LEFT', hkcu), category: 'leftovers', title: title(p, at, hkcu), op: 'reg_delete', targets: [hkcu], regKeys: [hkcu], allowRoot: 'HKCU\\Software', bytes: 0, files: 0, risk: 'caution', reversible: 'move-back', program: p });
      }
      if (segs.some((s) => RESERVED_KEY_SEGMENTS.has(lc(s)))) continue;
      for (const base of ['HKLM\\SOFTWARE', 'HKLM\\SOFTWARE\\WOW6432Node']) {
        const k = `${base}\\${segs.join('\\')}`;
        if (!keyExists(k)) continue;
        items.push({ id: pathId('LEFT', k), category: 'leftovers', title: title(p, at, k), op: 'report_only', targets: [k], allowRoot: base, bytes: 0, files: 0, risk: 'caution', reversible: 'none', program: p, instructions: `This machine-wide registry key needs administrator rights; Hydra-bane only reports it. If it is really left over from ${p.name}, back it up (reg export "${k}" backup.reg) and delete it in regedit.` });
      }
    }
  }

  // Start Menu shortcuts that point into a removed program's folder and no longer resolve.
  const startMenu = env.APPDATA ? abs(path.win32.join(env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs')) : undefined;
  const lnks = startMenu ? lnkFiles(startMenu) : [];
  if (startMenu && lnks.length) {
    const targets = (deps.shortcutTargets ?? defaultShortcutTargets)(lnks);
    for (const lnk of lnks) {
      const tn = normalizeWinPath(targets.get(lnk) ?? '');
      if (!tn.ok || fs.existsSync(tn.path)) continue;
      const owner = perProgram.find(({ locations }) => locations.some((l) => isSameOrDescendant(tn.path, l)));
      if (!owner || !decide(lnk, 'disk', policyFor(ctx, [startMenu])).allowed || parentIsRedirected(lnk)) continue;
      items.push({ id: pathId('LEFT', lnk), category: 'leftovers', title: title(owner.p, owner.at, lnk), op: 'quarantine', targets: [lnk], allowRoot: startMenu, ...measureTree(lnk), risk: 'caution', reversible: 'move-back', program: owner.p });
    }
  }
  const ids = new Set<string>();
  return items.filter((i) => !ids.has(i.id) && !!ids.add(i.id)); // two removed programs can share a name
}
