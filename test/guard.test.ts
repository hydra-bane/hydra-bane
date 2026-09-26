import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { normalizeWinPath, isSameOrDescendant } from '../src/guard/normalize.ts';
import { decide, type GuardPolicy } from '../src/guard/decide.ts';
import { buildProtectedPaths, parseRegQuery } from '../src/guard/protected.ts';

const policy: GuardPolicy = {
  protectedPaths: [
    'C:\\Windows',
    'C:\\Program Files',
    'C:\\ProgramData',
    'C:\\Users',
    'C:\\Users\\alice',
    'C:\\Users\\alice\\Documents',
    'D:\\Docs',
    'C:\\Users\\alice\\OneDrive',
  ],
  allowRoots: {
    disk: ['C:\\Users\\alice\\AppData\\Local\\npm-cache', 'C:\\Users\\alice\\AppData\\Local\\Temp', 'C:\\Users'],
    atlas: ['C:\\Program Files (x86)\\RaonSecure\\TouchEn nxKey'],
    purge: ['C:\\.hydra-bane-quarantine\\S-1-5-21-1\\tx1'],
  },
};

describe('normalizeWinPath', () => {
  it.each([
    ['', 'EMPTY'],
    ['/c/', 'POSIX_PATH'], // anthropics/claude-code#95426: $(cygpath -u 'C:\') resolved to /c/
    ['/mnt/c/Users', 'POSIX_PATH'],
    ['/cygdrive/c', 'POSIX_PATH'],
    ['~/AppData', 'POSIX_PATH'],
    ['C:foo', 'RELATIVE'],
    ['npm-cache', 'RELATIVE'],
    ['C:\\a\\..\\Windows', 'DOT_SEGMENT'],
    ['C:\\a\\.\\b', 'DOT_SEGMENT'],
    ['C:\\temp\\x.txt:stream', 'ALTERNATE_STREAM'],
    ['\\\\server\\share\\x', 'NETWORK_PATH'],
    ['\\\\?\\UNC\\server\\share', 'NETWORK_PATH'],
    ['\\\\.\\PhysicalDrive0', 'DEVICE_PATH'],
    ['C:\\PROGRA~1\\x', 'SHORT_NAME'],
    ['C:\\Windows.\\x', 'TRAILING_DOT_OR_SPACE'],
    ['C:\\Windows \\x', 'TRAILING_DOT_OR_SPACE'],
    ['C:\\a\\*', 'BAD_CHAR'],
  ])('rejects %j as %s', (input, code) => {
    const r = normalizeWinPath(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe(code);
  });

  it('canonicalizes separators, drive case, duplicate and trailing separators', () => {
    expect(normalizeWinPath('c:/Users//alice/AppData/Local/npm-cache/')).toEqual({ ok: true, path: 'C:\\Users\\alice\\AppData\\Local\\npm-cache' });
    expect(normalizeWinPath('\\\\?\\C:\\Temp')).toEqual({ ok: true, path: 'C:\\Temp' });
    expect(normalizeWinPath('d:\\')).toEqual({ ok: true, path: 'D:\\' });
  });

  it('descendant check does not treat sibling prefixes as children', () => {
    expect(isSameOrDescendant('C:\\Users\\alice2', 'C:\\Users\\alice')).toBe(false);
    expect(isSameOrDescendant('C:\\USERS\\Alice\\x', 'C:\\Users\\alice')).toBe(true);
    expect(isSameOrDescendant('C:\\x', 'C:\\')).toBe(true);
  });
});

describe('decide', () => {
  it('denies every drive root, including the #95426 input', () => {
    for (const t of ['C:\\', 'd:/', '\\\\?\\C:\\']) expect(decide(t, 'disk', policy)).toMatchObject({ allowed: false, code: 'DRIVE_ROOT' });
    expect(decide('/c/', 'disk', policy)).toMatchObject({ allowed: false, code: 'POSIX_PATH' });
  });

  it('denies protected paths and their ancestors', () => {
    for (const t of ['C:\\Users', 'C:\\Users\\alice', 'C:\\Users\\alice\\Documents', 'D:\\Docs', 'C:\\Windows'])
      expect(decide(t, 'disk', policy)).toMatchObject({ allowed: false, code: 'PROTECTED_OR_ANCESTOR' });
  });

  it('allows only inside an allow root of the requested capability', () => {
    expect(decide('C:\\Users\\alice\\AppData\\Local\\npm-cache\\_cacache', 'disk', policy)).toMatchObject({ allowed: true });
    expect(decide('C:\\Users\\alice\\AppData\\Local\\npm-cache', 'disk', policy)).toMatchObject({ allowed: true });
    expect(decide('C:\\Users\\alice\\AppData\\Local\\npm-cache\\x', 'atlas', policy)).toMatchObject({ allowed: false, code: 'NOT_ALLOWLISTED' });
    expect(decide('C:\\Users\\alice\\AppData\\Roaming\\x', 'disk', policy)).toMatchObject({ allowed: false, code: 'NOT_ALLOWLISTED' });
    expect(decide('C:\\Program Files (x86)\\RaonSecure\\TouchEn nxKey\\x.dll', 'atlas', policy)).toMatchObject({ allowed: true });
  });

  it('ignores an allow root that contains a protected path (hostile catalog entry)', () => {
    // 'C:\\Users' is listed as a disk allow root above; it must not open up anything under it.
    expect(decide('C:\\Users\\bob\\AppData\\x', 'disk', policy)).toMatchObject({ allowed: false, code: 'NOT_ALLOWLISTED' });
  });

  it('denies sensitive segments even inside an allow root', () => {
    expect(decide('C:\\Users\\alice\\AppData\\Local\\Temp\\repo\\.git\\objects', 'disk', policy)).toMatchObject({ allowed: false, code: 'SENSITIVE_SEGMENT' });
  });

  it('property: any ancestor of a protected path is denied', () => {
    fc.assert(fc.property(fc.constantFrom(...policy.protectedPaths), fc.nat(), (p, n) => {
      const parts = p.split('\\');
      const cut = 1 + (n % parts.length);
      const ancestor = parts.slice(0, cut).join('\\') + (cut === 1 ? '\\' : '');
      return decide(ancestor, 'disk', policy).allowed === false;
    }));
  });

  it('property: allowed results are always inside an allow root and never touch P', () => {
    const seg = fc.stringMatching(/^[A-Za-z0-9_\-. ~$]{1,12}$/);
    const arbPath = fc.tuple(fc.constantFrom('C:', 'c:', 'D:', '/c', '\\\\?\\C:', '\\\\srv'), fc.array(fc.oneof(seg, fc.constantFrom('Users', 'alice', 'AppData', 'Local', 'npm-cache', 'Temp', '..', 'Windows')), { maxLength: 7 }), fc.constantFrom('\\', '/'))
      .map(([d, s, sep]) => d + sep + s.join(sep));
    fc.assert(fc.property(arbPath, fc.constantFrom('disk', 'atlas', 'purge') as fc.Arbitrary<'disk' | 'atlas' | 'purge'>, (t, cap) => {
      const d = decide(t, cap, policy);
      if (!d.allowed) return true;
      return isSameOrDescendant(d.path, d.root) && !policy.protectedPaths.some((p) => isSameOrDescendant(p, d.path));
    }), { numRuns: 10_000 });
  });

  it('property: decisions are case-insensitive', () => {
    fc.assert(fc.property(fc.constantFrom('C:\\Users\\alice\\AppData\\Local\\npm-cache\\a', 'C:\\Users\\alice\\Documents\\a', 'C:\\Windows\\Temp'), (t) =>
      decide(t, 'disk', policy).allowed === decide(t.toUpperCase(), 'disk', policy).allowed));
  });
});

describe('protected set', () => {
  it('parses reg.exe output', () => {
    const out = 'HKEY_LOCAL_MACHINE\\X\\S-1-5-21-1\r\n    ProfileImagePath    REG_EXPAND_SZ    C:\\Users\\alice\r\n\r\n';
    expect(parseRegQuery(out)).toEqual([{ key: 'HKEY_LOCAL_MACHINE\\X\\S-1-5-21-1', name: 'ProfileImagePath', type: 'REG_EXPAND_SZ', data: 'C:\\Users\\alice' }]);
  });

  it.runIf(process.platform === 'win32')('includes system folders and the current profile on this machine', () => {
    const p = buildProtectedPaths().map((x) => x.toLowerCase());
    expect(p).toContain((process.env.SystemRoot ?? 'C:\\Windows').toLowerCase());
    expect(p).toContain(process.env.USERPROFILE!.toLowerCase());
  });
});
