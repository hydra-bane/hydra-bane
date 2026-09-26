import path from 'node:path';

export type NormalizeError =
  | 'EMPTY'
  | 'BAD_CHAR'
  | 'POSIX_PATH'
  | 'DEVICE_PATH'
  | 'NETWORK_PATH'
  | 'RELATIVE'
  | 'ALTERNATE_STREAM'
  | 'DOT_SEGMENT'
  | 'TRAILING_DOT_OR_SPACE'
  | 'SHORT_NAME';

export type NormalizeResult =
  | { ok: true; path: string }
  | { ok: false; code: NormalizeError; input: string };

const fail = (code: NormalizeError, input: string): NormalizeResult => ({ ok: false, code, input });

// String-level canonical form used by the guard: `X:\a\b`, no trailing separator except a drive root.
// Anything ambiguous is rejected instead of guessed. Links, 8.3 names and case-sensitive
// directories are resolved later against an open handle (GetFinalPathNameByHandle), not here.
export function normalizeWinPath(input: string): NormalizeResult {
  if (typeof input !== 'string' || input.trim() === '') return fail('EMPTY', String(input));

  let p = input.replace(/\//g, '\\');
  if (input.startsWith('/') && !input.startsWith('//')) return fail('POSIX_PATH', input); // /c/, /mnt/c, /cygdrive/c
  if (input.startsWith('~')) return fail('POSIX_PATH', input);

  if (/^\\\\\?\\UNC\\/i.test(p)) return fail('NETWORK_PATH', input);
  if (p.startsWith('\\\\?\\')) p = p.slice(4);
  if (p.startsWith('\\\\.\\') || /^\\\\\?\\/.test(p)) return fail('DEVICE_PATH', input);
  if (p.startsWith('\\\\')) return fail('NETWORK_PATH', input);
  if (/[\0*?"<>|]/.test(p)) return fail('BAD_CHAR', input);

  if (!/^[A-Za-z]:\\/.test(p)) return fail('RELATIVE', input); // also rejects drive-relative `C:foo`
  if (p.indexOf(':', 2) !== -1) return fail('ALTERNATE_STREAM', input);

  const segments = p.slice(3).split('\\').filter((s) => s !== '');
  for (const s of segments) {
    if (s === '.' || s === '..') return fail('DOT_SEGMENT', input);
    if (/[. ]$/.test(s)) return fail('TRAILING_DOT_OR_SPACE', input);
    if (/~\d/.test(s)) return fail('SHORT_NAME', input);
  }

  const drive = p[0]!.toUpperCase() + ':\\';
  return { ok: true, path: segments.length ? drive + segments.join('\\') : drive };
}

export const pathKey = (normalized: string): string => normalized.toLowerCase();

export function isSameOrDescendant(child: string, parent: string): boolean {
  const c = pathKey(child);
  const p = pathKey(parent);
  if (c === p) return true;
  return c.startsWith(p.endsWith('\\') ? p : p + '\\');
}

export const isDriveRoot = (normalized: string): boolean => /^[A-Z]:\\$/.test(normalized);

export const win32 = path.win32;
