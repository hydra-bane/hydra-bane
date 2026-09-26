import fs from 'node:fs';
import path from 'node:path';
import { decide } from '../guard/decide.ts';
import { isDriveRoot, normalizeWinPath } from '../guard/normalize.ts';
import { regQuery } from '../guard/protected.ts';
import { parentIsRedirected } from '../quarantine/quarantine.ts';
import { policyFor, type Context } from './context.ts';
import { pathId, STALE_DAYS, type ScanItem } from './scan.ts';

// Mole `mo installer` parity: old installer files at the top level of the user's Downloads folder.
// Downloads is in the protected set P, and the guard ignores an allow root that is in P, so each file is its own
// item with allowRoot = the file itself and targetNames = its name: apply can move exactly that file and nothing else.

export interface InstallerDeps {
  /** The Downloads folder. Default: HKCU User Shell Folders {374DE290-...} expanded, else <home>\Downloads. */
  downloadsDir?: string;
  /** Whether another process holds the file open without sharing write access (running installer, mounted ISO). */
  isLocked?: (file: string) => boolean;
}

const DOWNLOADS_VALUE = '{374DE290-123F-4565-9164-39C4925E467B}';
const INSTALLER_EXT = new Set(['.exe', '.msi', '.msix', '.msixbundle', '.appx', '.appxbundle', '.iso', '.img', '.dmg', '.pkg']);
/** Disk images are only reported: a .img in Downloads can be a card or disk backup the user made. */
const REPORT_EXT = new Set(['.img']);
const ZIP_KEYWORDS = new Set(['setup', 'install', 'installer', 'portable']);
const ZIP_ARCH = new Set(['x64', 'x86', 'win64', 'win32', 'amd64', 'arm64']);
const DAY = 86_400_000;

/**
 * A .zip counts as an installer only when its name says so: a word setup/install/installer/portable, or an
 * architecture word (x64, win64, amd64, ...) together with a version number. A version or date alone
 * ("photos 2024.05.zip") is not enough.
 */
export function zipLooksLikeInstaller(name: string): boolean {
  const stem = name.replace(/\.zip$/i, '');
  const words = stem.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/);
  if (words.some((w) => ZIP_KEYWORDS.has(w))) return true;
  return words.some((w) => ZIP_ARCH.has(w)) && /\d+\.\d+/.test(stem);
}

export function isInstallerName(name: string): boolean {
  const ext = path.extname(name).toLowerCase();
  return INSTALLER_EXT.has(ext) || (ext === '.zip' && zipLooksLikeInstaller(name));
}

function defaultDownloadsDir(ctx: Context): string {
  const v = regQuery('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders').find((x) => x.name === DOWNLOADS_VALUE)?.data;
  const expanded = v?.replace(/%([^%]+)%/g, (all, n: string) => process.env[n] ?? all);
  return expanded && !expanded.includes('%') ? expanded : path.join(ctx.home, 'Downloads');
}

/** Opening for read+write fails while a process holds the file without FILE_SHARE_WRITE. Nothing is written. */
function defaultIsLocked(file: string): boolean {
  try { fs.closeSync(fs.openSync(file, 'r+')); return false; } catch { return true; }
}

export function scanInstallers(ctx: Context, deps: InstallerDeps = {}): ScanItem[] {
  const n = normalizeWinPath(deps.downloadsDir ?? defaultDownloadsDir(ctx));
  if (!n.ok || isDriveRoot(n.path)) return [];
  const downloads = n.path;
  const isLocked = deps.isLocked ?? defaultIsLocked;
  const cutoff = ctx.now().getTime() - STALE_DAYS * DAY;
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(downloads, { withFileTypes: true }); } catch { return []; }

  const items: ScanItem[] = [];
  for (const e of entries) {
    if (!e.isFile() || e.isSymbolicLink() || !isInstallerName(e.name)) continue; // top level only, no links
    const file = path.win32.join(downloads, e.name);
    let st: fs.Stats;
    try { st = fs.lstatSync(file); } catch { continue; }
    if (!st.isFile() || st.mtimeMs >= cutoff) continue;
    if (!decide(file, 'disk', policyFor(ctx, [file])).allowed || parentIsRedirected(file)) continue;
    if (isLocked(file)) continue;
    const report = REPORT_EXT.has(path.extname(e.name).toLowerCase());
    const exe = path.extname(e.name).toLowerCase() === '.exe';
    items.push({
      id: pathId('INST', file), category: 'installers',
      title: `Old installer in Downloads: ${e.name} (unchanged since ${new Date(st.mtimeMs).toISOString().slice(0, 10)})`,
      op: report ? 'report_only' : 'quarantine', targets: [file], allowRoot: file, targetNames: [e.name],
      ...(exe ? { requiresClosed: [e.name] } : {}),
      bytes: st.size, files: 1, risk: 'caution', reversible: report ? 'none' : 'move-back',
      ...(report ? { instructions: 'A .img file can be a disk or memory-card backup you made. If it is an installer or OS image you no longer need, delete it yourself.' } : {}),
    });
  }
  return items;
}
