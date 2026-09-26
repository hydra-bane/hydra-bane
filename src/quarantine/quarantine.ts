import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { decide, type Capability, type GuardPolicy } from '../guard/decide.ts';
import { isSameOrDescendant, normalizeWinPath, pathKey } from '../guard/normalize.ts';
import { killPoint } from '../ledger/ledger.ts';

// PLAN.md §6.6 (v0.1 scope, §6.5 note): move whole items with fs.rename on the same volume, never recurse,
// never follow links, and re-check links right before moving. No automatic purge.

const SYS32 = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');
const SINGLE_FILE_HASH_LIMIT = 256 * 1024 * 1024;

export interface QuarantinedItem {
  id: string;
  source: string;
  stored: string;
  kind: 'file' | 'dir' | 'link';
  bytes: number;
  files: number;
  sha256?: string;
  /** Written before the rename (intent). Cleared once the rename is done. Crash recovery resolves leftovers. */
  pending?: true;
  /** Set by restore right after the item is moved back, so an interrupted undo can be re-run safely. */
  restoredTo?: string;
}

export interface Manifest { schemaVersion: 1; tx: string; createdAt: string; items: QuarantinedItem[] }

export type MoveError = 'GUARD' | 'MISSING' | 'PARENT_IS_LINK' | 'CROSS_VOLUME' | 'LOCKED' | 'IO';
export type MoveResult = { ok: true; item: QuarantinedItem } | { ok: false; code: MoveError; detail: string };

export type RestoreOutcome =
  | { id: string; ok: true; restoredTo: string }
  | { id: string; ok: false; code: 'STORED_MISSING' | 'HASH_MISMATCH' | 'PARENT_UNSAFE' | 'IO'; detail: string };

export function currentUserSid(): string {
  const out = execFileSync(path.join(SYS32, 'whoami.exe'), ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
  const sid = /"(S-1-[\d-]+)"/.exec(out)?.[1];
  if (!sid) throw new Error('could not resolve current user SID');
  return sid;
}

/** `<drive>:\.hydra-bane-quarantine\<SID>` for the volume that holds `target`. */
export const defaultQuarantineBase = (target: string, sid: string) => path.win32.join(target.slice(0, 3), '.hydra-bane-quarantine', sid);

function hardenBase(base: string) {
  if (fs.existsSync(path.join(base, 'README.txt'))) return;
  fs.mkdirSync(base, { recursive: true });
  const user = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
  // Protected DACL: no inheritance from the drive root; owner + SYSTEM only; files inside cannot be executed.
  execFileSync(path.join(SYS32, 'icacls.exe'), [base, '/inheritance:r', '/grant:r', `${user}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '/deny', `${user}:(OI)(IO)(X)`], { windowsHide: true, stdio: 'ignore' });
  execFileSync(path.join(SYS32, 'attrib.exe'), ['+I', base], { windowsHide: true, stdio: 'ignore' });
  fs.writeFileSync(path.join(base, 'README.txt'),
    'Hydra-bane quarantine. Deleting this folder removes your ability to undo.\r\nUse `hydra-bane undo <tx>` to restore or `hydra-bane purge` to reclaim space.\r\n');
}

/** Resolve links in the parent chain; if it differs from the literal path, something redirects it. */
export function parentIsRedirected(p: string): boolean {
  const parent = path.win32.dirname(p);
  try {
    return pathKey(fs.realpathSync.native(parent)) !== pathKey(parent);
  } catch {
    return true;
  }
}

function measure(p: string, kind: QuarantinedItem['kind']): Pick<QuarantinedItem, 'bytes' | 'files' | 'sha256'> {
  if (kind === 'link') return { bytes: 0, files: 0 };
  if (kind === 'file') {
    const { size } = fs.lstatSync(p);
    // ponytail: whole-file hash only for single files up to 256 MB; directories get size+count. Upgrade to per-file hashes if undo integrity needs it.
    return size <= SINGLE_FILE_HASH_LIMIT
      ? { bytes: size, files: 1, sha256: createHash('sha256').update(fs.readFileSync(p)).digest('hex') }
      : { bytes: size, files: 1 };
  }
  let bytes = 0, files = 0;
  const stack = [p];
  while (stack.length) {
    const dir = stack.pop()!;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue; // never follow links while measuring
      if (e.isDirectory()) stack.push(full);
      else { files++; bytes += fs.lstatSync(full).size; }
    }
  }
  return { bytes, files };
}

export class Quarantine {
  readonly base: string;
  readonly tx: string;
  readonly dir: string;
  private readonly manifest: Manifest;

  constructor(base: string, tx: string = randomUUID()) {
    this.base = base;
    this.tx = tx;
    hardenBase(base);
    this.dir = path.join(base, tx);
    fs.mkdirSync(this.dir, { recursive: true });
    this.manifest = { schemaVersion: 1, tx, createdAt: new Date().toISOString(), items: [] };
    this.flush();
  }

  static open(base: string, tx: string): Manifest {
    return JSON.parse(fs.readFileSync(path.join(base, tx, 'manifest.json'), 'utf8')) as Manifest;
  }

  private flush() {
    saveManifest(this.base, this.tx, this.manifest);
  }

  move(target: string, capability: Capability, policy: GuardPolicy): MoveResult {
    const d = decide(target, capability, policy);
    if (!d.allowed) return { ok: false, code: 'GUARD', detail: `${d.code}: ${d.detail}` };
    const source = d.path;

    let st: fs.Stats;
    try { st = fs.lstatSync(source); } catch { return { ok: false, code: 'MISSING', detail: source }; }
    if (parentIsRedirected(source)) return { ok: false, code: 'PARENT_IS_LINK', detail: source };
    if (source[0]!.toUpperCase() !== this.dir[0]!.toUpperCase()) return { ok: false, code: 'CROSS_VOLUME', detail: source };

    const kind: QuarantinedItem['kind'] = st.isSymbolicLink() ? 'link' : st.isDirectory() ? 'dir' : 'file';
    const m = measure(source, kind);
    const id = String(this.manifest.items.length + 1).padStart(4, '0');
    const stored = path.join(this.dir, id);

    const item: QuarantinedItem = { id, source, stored, kind, ...m, pending: true };
    this.manifest.items.push(item);
    this.flush();
    killPoint('quarantine-after-intent');
    try {
      fs.renameSync(source, stored); // same volume: atomic metadata move, links are moved as links
    } catch (e) {
      this.manifest.items.pop();
      this.flush();
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'EXDEV') return { ok: false, code: 'CROSS_VOLUME', detail: source };
      if (code === 'EBUSY' || code === 'EPERM') return { ok: false, code: 'LOCKED', detail: `${source}: ${code}` };
      return { ok: false, code: 'IO', detail: `${source}: ${code}` };
    }
    killPoint('quarantine-after-rename');
    delete item.pending;
    this.flush();
    return { ok: true, item };
  }
}

/** Atomic manifest write (tmp + rename). */
export function saveManifest(base: string, tx: string, manifest: Manifest) {
  const file = path.join(base, tx, 'manifest.json');
  fs.writeFileSync(file + '.tmp', JSON.stringify(manifest, null, 2));
  fs.renameSync(file + '.tmp', file);
}

/** Undo a transaction, newest item first. Never overwrites: an occupied source gets a `.restored` name. */
export function restore(base: string, tx: string, policy?: GuardPolicy): RestoreOutcome[] {
  const manifest = Quarantine.open(base, tx);
  const out: RestoreOutcome[] = [];
  for (const item of [...manifest.items].reverse()) {
    if (item.restoredTo) { out.push({ id: item.id, ok: true, restoredTo: item.restoredTo }); continue; }
    if (item.pending && !exists(item.stored)) continue; // interrupted before the move: nothing was taken
    if (!exists(item.stored)) {
      out.push({ id: item.id, ok: false, code: 'STORED_MISSING', detail: `${item.stored} (removed outside Hydra-bane, possibly by antivirus)` });
      continue;
    }
    if (item.sha256 && createHash('sha256').update(fs.readFileSync(item.stored)).digest('hex') !== item.sha256) {
      out.push({ id: item.id, ok: false, code: 'HASH_MISMATCH', detail: item.stored });
      continue;
    }
    const n = normalizeWinPath(item.source);
    if (!n.ok || parentIsRedirected(item.source) || (policy && policy.protectedPaths.some((p) => isSameOrDescendant(p, item.source)))) {
      out.push({ id: item.id, ok: false, code: 'PARENT_UNSAFE', detail: `${item.source} (parent missing, redirected by a link, or protected)` });
      continue;
    }
    const dest = fs.existsSync(item.source) || isLink(item.source) ? `${item.source}.restored` : item.source;
    try {
      fs.renameSync(item.stored, dest);
      item.restoredTo = dest;
      saveManifest(base, tx, manifest);
      out.push({ id: item.id, ok: true, restoredTo: dest });
      killPoint('undo-after-restore-item');
    } catch (e) {
      out.push({ id: item.id, ok: false, code: 'IO', detail: `${item.source}: ${(e as NodeJS.ErrnoException).code}` });
    }
  }
  return out;
}

export const exists = (p: string) => fs.existsSync(p) || isLink(p);

function isLink(p: string): boolean {
  try { return fs.lstatSync(p).isSymbolicLink(); } catch { return false; }
}
