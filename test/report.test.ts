import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { parseRegQuery } from '../src/guard/protected.ts';
import { listPrograms, UNINSTALL_ROOTS } from '../src/atlas/programs.ts';
import { buildReport, issueUrl, mainExecutable, sanitize, submit, type Gh, type Identity } from '../src/atlas/report.ts';
import { describeAction } from '../src/hook/describe.ts';

const HKLM = UNINSTALL_ROOTS[0]!.key;
const HKLM_FULL = HKLM.replace(/^HKLM/, 'HKEY_LOCAL_MACHINE');
const REG = [
  `${HKLM_FULL}\\{11111111-2222-3333-4444-555555555555}`,
  '    DisplayName    REG_SZ    CLIPDOWN',
  '    Publisher    REG_SZ    Example Ads Co.',
  '    DisplayVersion    REG_SZ    1.2.3',
  '    WindowsInstaller    REG_DWORD    0x1',
  '    EstimatedSize    REG_DWORD    0x400',
  '',
  `${HKLM_FULL}\\Hidden`,
  '    DisplayName    REG_SZ    Runtime part',
  '    SystemComponent    REG_DWORD    0x1',
  '',
  `${HKLM_FULL}\\KB500`,
  '    DisplayName    REG_SZ    Security Update',
  '    ParentKeyName    REG_SZ    OperatingSystem',
  '',
  `${HKLM_FULL}\\NoName`,
  '    Publisher    REG_SZ    x',
  '',
  `${HKLM_FULL}\\Toolbar`,
  '    DisplayName    REG_SZ    Search Toolbar',
  '    DisplayIcon    REG_SZ    "C:\\Users\\alice\\AppData\\Local\\Toolbar\\tb.exe",0',
  '    InstallLocation    REG_SZ    C:\\Users\\alice\\AppData\\Local\\Toolbar',
].join('\r\n');

const fakeQuery = (key: string) => (key === HKLM ? parseRegQuery(REG) : []);

const alice: Identity = {
  username: 'alice', hostname: 'DESKTOP-7Q2ZX9',
  env: { USERPROFILE: 'C:\\Users\\alice', LOCALAPPDATA: 'C:\\Users\\alice\\AppData\\Local', APPDATA: 'C:\\Users\\alice\\AppData\\Roaming', ProgramFiles: 'C:\\Program Files' },
};

describe('programs', () => {
  it('lists real programs and skips hidden components, updates and nameless keys', () => {
    const progs = listPrograms(fakeQuery);
    expect(progs.map((p) => p.name)).toEqual(['CLIPDOWN', 'Search Toolbar']);
    const clip = progs[0]!;
    expect(clip.msiProductCode).toBe('{11111111-2222-3333-4444-555555555555}');
    expect(clip.estimatedBytes).toBe(1024 * 1024);
    expect(clip.id).toMatch(/^P-[0-9a-f]{6}$/);
    expect(listPrograms(fakeQuery)[0]!.id).toBe(clip.id); // stable
  });

  it('finds the program executable but never Windows Installer', () => {
    const [clip, tb] = listPrograms(fakeQuery);
    expect(mainExecutable(clip!)).toBeUndefined();
    expect(mainExecutable(tb!)).toBe('C:\\Users\\alice\\AppData\\Local\\Toolbar\\tb.exe');
    expect(mainExecutable({ ...tb!, displayIcon: undefined, uninstallString: 'MsiExec.exe /X{1}' })).toBeUndefined();
  });
});

describe('sanitize', () => {
  it('turns paths into %VAR% form and removes user, PC, SID and email', () => {
    expect(sanitize('C:\\Users\\alice\\AppData\\Local\\Toolbar\\tb.exe', alice)).toBe('%LOCALAPPDATA%\\Toolbar\\tb.exe');
    expect(sanitize('c:\\users\\ALICE\\Desktop', alice)).toBe('%USERPROFILE%\\Desktop');
    expect(sanitize('D:\\Users\\bob\\x', alice)).toBe('%USERPROFILE%\\x');
    expect(sanitize('HKU\\S-1-5-21-111-222-333-1001\\Software', alice)).toBe('HKU\\<sid>\\Software');
    expect(sanitize('made on DESKTOP-7Q2ZX9 by alice@example.com', alice)).toBe('made on <redacted> by <email>');
    expect(sanitize('C:\\Program Files\\Vendor\\app.exe', alice)).toBe('%ProgramFiles%\\Vendor\\app.exe');
    expect(sanitize('PC Manager', { ...alice, username: 'PC' })).toBe('PC Manager'); // too short to scrub as a word
  });

  it('never leaks the user name, host name or SID (property test)', () => {
    const word = fc.stringMatching(/^[A-Za-z][A-Za-z0-9._-]{2,14}$/);
    fc.assert(fc.property(word, word, fc.array(fc.stringMatching(/^[A-Za-z0-9 ._-]{0,10}$/), { maxLength: 4 }), fc.constantFrom('C', 'D'), (user, host, parts, drive) => {
      fc.pre(!user.toLowerCase().includes(host.toLowerCase()) && !host.toLowerCase().includes(user.toLowerCase()));
      const id: Identity = { username: user, hostname: host, env: { USERPROFILE: `C:\\Users\\${user}`, LOCALAPPDATA: `C:\\Users\\${user}\\AppData\\Local` } };
      const inputs = [
        `${drive}:\\Users\\${user}\\${parts.join('\\')}`,
        `"C:\\Users\\${user}\\AppData\\Local\\${parts.join('\\')}\\x.exe",0`,
        `${parts.join(' ')} ${host} ${parts.join('-')}`,
        `S-1-5-21-${parts.length}-42-7-1001 ${user}`,
      ];
      for (const s of inputs) {
        const out = sanitize(s, id).toLowerCase();
        expect(out.includes(`\\${user.toLowerCase()}`)).toBe(false);
        expect(new RegExp(`(^|[^\\w-])${host.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^\\w-])`).test(out)).toBe(false);
        expect(/s-1-5-21-\d/.test(out)).toBe(false);
      }
    }), { numRuns: 500 });
  });
});

describe('report', () => {
  const [, tb] = listPrograms(fakeQuery);

  it('contains detection facts and nothing identifying', () => {
    const r = buildReport(tb!, 'came bundled with alice\'s game installer on DESKTOP-7Q2ZX9', {
      id: alice, version: '0.2.0', country: 'KR',
      signerOf: () => ({ status: 'Valid', subject: 'CN=Example Ads Co., O=Example Ads Co.', thumbprint: 'AB12' }),
    });
    expect(r.detect.signer?.thumbprint).toBe('AB12');
    expect(r.detect.file?.path).toBe('%LOCALAPPDATA%\\Toolbar\\tb.exe');
    expect(r.install_location).toBe('%LOCALAPPDATA%\\Toolbar');
    expect(r.suggested_id).toBe('unknown.search-toolbar');
    expect(r.country).toBe('KR');
    const text = JSON.stringify(r).toLowerCase();
    expect(text).not.toContain('alice');
    expect(text).not.toContain('desktop-7q2zx9');
  });

  it('posts with gh when logged in, otherwise gives a pre-filled link', () => {
    const r = buildReport(tb!, undefined, { id: alice, version: '0.2.0', signerOf: () => undefined });
    const calls: string[][] = [];
    const loggedIn: Gh = (args) => { calls.push(args); return { status: 0, stdout: args[0] === 'issue' ? 'https://github.com/hydra-bane/atlas/issues/7\n' : '' }; };
    expect(submit(r, loggedIn)).toEqual({ via: 'gh', url: 'https://github.com/hydra-bane/atlas/issues/7' });
    expect(calls[1]).toContain('hydra-bane/atlas');
    const loggedOut: Gh = () => ({ status: 1, stdout: '' });
    const link = submit(r, loggedOut);
    expect(link.via).toBe('link');
    expect(link.url).toBe(issueUrl(r));
    expect(link.url).toContain('template=report.yml');
  });

  it('the approval prompt says what will be published', () => {
    const state = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-rep-'));
    fs.mkdirSync(path.join(state, 'reports'));
    const r = buildReport(tb!, undefined, { id: alice, version: '0.2.0', country: 'KR', signerOf: () => ({ status: 'Valid', subject: 'CN=Example Ads Co.' }) });
    fs.writeFileSync(path.join(state, 'reports', `${tb!.id}.json`), JSON.stringify(r));
    const text = describeAction('report', tb!.id, state);
    expect(text).toContain('PUBLIC issue on github.com/hydra-bane/atlas');
    expect(text).toContain('Search Toolbar');
    expect(text).toContain('CN=Example Ads Co.');
    expect(describeAction('report', 'P-000000', state)).toContain('Run "hydra-bane report P-000000" first');
  });
});
