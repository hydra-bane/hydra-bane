import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// Registry leftovers (PLAN.md §6.9 `reg_value_export+delete`): a key is exported to quarantine before it is
// deleted, and undo imports that export back. reg.exe runs by absolute path with an argument array, never a shell.
// Only HKCU\Software\<Name> or HKCU\Software\<Publisher>\<Name> may be deleted.

export const REG_EXE = path.win32.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'reg.exe');

export type RegRun = (args: string[]) => { status: number | null; stderr: string };

/** The one place reg.exe is spawned. Tests replace `run` so they never touch the real registry. */
export const regHost: { run: RegRun } = {
  run: (args) => {
    const r = spawnSync(REG_EXE, args, { encoding: 'utf8', windowsHide: true, timeout: 60_000 });
    return { status: r.status, stderr: r.stderr ?? '' };
  },
};

/** First segments under Software that belong to Windows or to many programs at once. */
export const RESERVED_KEY_SEGMENTS = new Set(['microsoft', 'windows', 'classes', 'policies', 'wow6432node', 'appdatalow', 'registeredapplications', 'clients', 'wow64', 'odbc']);

/** Why this key may not be deleted, or undefined when it may. */
export function hkcuKeyProblem(key: string): string | undefined {
  if (typeof key !== 'string' || !key.startsWith('HKCU\\Software\\')) return 'only keys under HKCU\\Software\\ may be deleted';
  const segs = key.slice('HKCU\\Software\\'.length).split('\\');
  if (segs.length < 1 || segs.length > 2) return 'only HKCU\\Software\\<Name> or HKCU\\Software\\<Publisher>\\<Name>';
  for (const s of segs) {
    if (!s || s !== s.trim() || /[\0-\x1f"*?]/.test(s)) return `bad key name segment "${s}"`;
    if (RESERVED_KEY_SEGMENTS.has(s.toLowerCase())) return `${s} is shared by Windows or many programs`;
  }
  return undefined;
}

export const keyExists = (key: string) => regHost.run(['query', key, '/ve']).status === 0;

const FULL_ROOT: Record<string, string> = { HKCU: 'HKEY_CURRENT_USER', HKLM: 'HKEY_LOCAL_MACHINE' };
const fullKey = (key: string) => key.replace(/^(HKCU|HKLM)\\/, (_, h: string) => `${FULL_ROOT[h]}\\`).toLowerCase();

export type ExportCheck = { ok: true; sha256: string } | { ok: false; code: 'STORED_MISSING' | 'HASH_MISMATCH' | 'BAD_CONTENT'; detail: string };

/**
 * An export file is only trusted when it exists, is non-empty, matches the SHA-256 recorded at export time, and every
 * section in it is the exported key or below it (no `[-...]` deletions, nothing elsewhere in the registry).
 */
export function checkExport(key: string, file: string, sha256?: string): ExportCheck {
  let buf: Buffer;
  try { buf = fs.readFileSync(file); } catch { return { ok: false, code: 'STORED_MISSING', detail: `${file} (removed outside Hydra-bane, possibly by antivirus)` }; }
  if (!buf.length) return { ok: false, code: 'STORED_MISSING', detail: `${file} is empty` };
  const sha = createHash('sha256').update(buf).digest('hex');
  if (sha256 && sha !== sha256) return { ok: false, code: 'HASH_MISMATCH', detail: `${file} changed after export` };
  const text = buf[0] === 0xff && buf[1] === 0xfe ? buf.subarray(2).toString('utf16le') : buf.toString('utf8');
  const want = fullKey(key);
  const sections = [...text.matchAll(/^\[(.*)\][ \t]*\r?$/gm)].map((m) => m[1]!);
  if (!/^Windows Registry Editor Version 5\.00/.test(text.trimStart()) || !sections.length) return { ok: false, code: 'BAD_CONTENT', detail: `${file} is not a registry export` };
  const stray = sections.find((s) => { const l = s.toLowerCase(); return s.startsWith('-') || (l !== want && !l.startsWith(want + '\\')); });
  if (stray !== undefined) return { ok: false, code: 'BAD_CONTENT', detail: `${file} touches [${stray}], outside ${key}` };
  return { ok: true, sha256: sha };
}

export function exportKey(key: string, file: string): ExportCheck {
  const r = regHost.run(['export', key, file, '/y']);
  if (r.status !== 0) return { ok: false, code: 'STORED_MISSING', detail: `reg export exited ${r.status}: ${r.stderr.trim().slice(0, 200)}` };
  return checkExport(key, file);
}

export const deleteKey = (key: string) => regHost.run(['delete', key, '/f']);
export const importFile = (file: string) => regHost.run(['import', file]);
