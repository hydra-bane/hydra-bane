import { describe, expect, it } from 'vitest';
import type { AtlasBundle, AtlasEntry } from '../src/atlas/entry.ts';
import { measureFacts, programDirs, type RawFacts } from '../src/atlas/facts.ts';
import { scanAtlas } from '../src/atlas/match.ts';
import type { Program } from '../src/atlas/programs.ts';

import { VERDICT_WORDS } from '../src/atlas/entry.ts';

const ENV = { SystemRoot: 'C:\\Windows', ProgramFiles: 'C:\\Program Files', 'ProgramFiles(x86)': 'C:\\Program Files (x86)' };
const DIR = 'C:\\Program Files\\Wizvera\\Veraport20';

const entry = (over: Partial<AtlasEntry> = {}): AtlasEntry => ({
  schema: 2, id: 'kr.wizvera.veraport', names: ['Veraport'], vendor: { name: 'Wizvera', country: 'KR' },
  context: 'Installs and updates the security modules that Korean banking and government sites ask for.', tags: { countries: ['KR'] },
  detect: { signers: [], uninstall_keys: [{ display_name: '^Veraport', publisher: 'Wizvera' }], root_certs: ['Veraport-CA'] },
  uninstall: { command_source: 'msi-product-code', msi_product_codes: [] },
  residue: 'report-only', reversible: 'reinstall-only', reinstall_note: 'Banking sites offer it again when they need it.',
  sources: [{ url: 'https://example.org/about', kind: 'news', date: '2026-01-01' }],
  advisories: [
    { publisher: 'KISA', url: 'https://example.org/kisa', date: '2023-02-01', title: 'Vulnerable Veraport versions', affected: { up_to: '3.8.6.5', inclusive: true } },
    { publisher: 'NVD', url: 'https://example.org/nvd', date: '2020-05-01', title: 'Old issue', cve: ['CVE-2020-1234'], affected: { up_to: '3.1', inclusive: false } },
    { publisher: 'other', url: 'https://example.org/blog', date: '2024-01-01', title: 'Research note' },
  ],
  source: 'original', vendor_response: [], dispute: { status: 'none' }, verified: false, verified_by: null, added: '2026-09-26', last_reviewed: '2026-09-26',
  ...over,
});
const prog = (over: Partial<Program> = {}): Program => ({
  id: 'P-538cd9', name: 'Veraport G3 - 3,8,0,0 - x64', publisher: 'Wizvera', version: '3,8,0,0', hive: 'HKLM', view: '64', keyName: 'Veraport',
  installLocation: `${DIR}\\`, uninstallString: `"${DIR}\\unins000.exe"`, estimatedBytes: 50 * 2 ** 20, installDate: '20260408', ...over,
});

const raw: RawFacts = {
  certs: [
    { store: 'LocalMachine', subject: 'CN=Veraport-CA, O=WIZVERA, C=KR', thumbprint: 'fbd24e', notBefore: '2026-04-08' },
    { store: 'CurrentUser', subject: 'CN=Veraport-CA, O=WIZVERA, C=KR', thumbprint: 'FBD24E', notBefore: '2026-04-08' },
    { store: 'LocalMachine', subject: 'CN=Some Other CA', thumbprint: 'AAAA', notBefore: '2020-01-01' },
  ],
  listeners: [
    { address: '127.0.0.1', port: 16116, pid: 10, exe: 'C:\\program files\\wizvera\\veraport20\\veraport-x64.exe' },
    { address: '::1', port: 16116, pid: 10, exe: 'C:\\program files\\wizvera\\veraport20\\veraport-x64.exe' },
    { address: '0.0.0.0', port: 16106, pid: 11, exe: null }, // service process: path comes from the service
    { address: '0.0.0.0', port: 445, pid: 4, exe: null },
    { address: '127.0.0.1', port: 9000, pid: 12, exe: 'C:\\Program Files\\Wizvera\\Veraport2000\\x.exe' }, // sibling folder, not ours
  ],
  services: [
    { name: 'VeraportSvc', startMode: 'Auto', state: 'Running', path: `"${DIR}\\svc.exe" -k`, pid: 11 },
    { name: 'VeraportUpd', startMode: 'Manual', state: 'Stopped', path: `${DIR}\\upd.exe /run`, pid: 0 },
    { name: 'Spooler', startMode: 'Auto', state: 'Running', path: 'C:\\Windows\\System32\\spoolsv.exe', pid: 20 },
  ],
};

describe('measureFacts', () => {
  it('attributes certificates, listeners and services to the program', () => {
    const [f] = measureFacts([prog()], [entry()], () => raw, ENV);
    expect(f!.installDate).toBe('2026-04-08');
    expect(f!.rootCerts).toEqual([{ subject: 'CN=Veraport-CA, O=WIZVERA, C=KR', thumbprint: 'FBD24E', notBefore: '2026-04-08', stores: ['LocalMachine', 'CurrentUser'] }]);
    expect(f!.listeners).toEqual([
      { port: 16106, address: '0.0.0.0', network: true, process: `${DIR}\\svc.exe` },
      { port: 16116, address: '127.0.0.1', network: false, process: 'C:\\program files\\wizvera\\veraport20\\veraport-x64.exe' },
    ]);
    expect(f!.services).toEqual([
      { name: 'VeraportSvc', startMode: 'Auto', startsWithWindows: true, state: 'Running', exe: `${DIR}\\svc.exe` },
      { name: 'VeraportUpd', startMode: 'Manual', startsWithWindows: false, state: 'Stopped', exe: `${DIR}\\upd.exe` },
    ]);
  });

  it('cert subject match is case-insensitive substring', () => {
    const [f] = measureFacts([prog()], [entry({ detect: { ...entry().detect, root_certs: ['veraport-ca'] } })], () => raw, ENV);
    expect(f!.rootCerts).toHaveLength(1);
  });

  it('falls back to the uninstaller folder and never to shared roots', () => {
    expect(programDirs(prog({ installLocation: undefined }), ENV)).toEqual([DIR]);
    expect(programDirs(prog({ installLocation: undefined, uninstallString: 'C:\\Windows\\System32\\msiexec.exe /x{1}', displayIcon: 'C:\\Program Files\\app.exe,0' }), ENV)).toEqual([]);
    expect(programDirs(prog({ installLocation: 'C:\\' }), ENV)).toEqual([]);
  });

  it('does not measure when nothing matched', () => {
    let calls = 0;
    const run = () => { calls++; return raw; };
    const bundle: AtlasBundle = { schema: 2, bundle_seq: 1, created: '2026-09-26', entries: [entry()] };
    expect(scanAtlas({ bundle, listPrograms: () => [prog({ name: 'Notepad++', publisher: 'Don Ho' })], factsRunner: run, env: ENV })).toEqual([]);
    expect(measureFacts([], [], run)).toEqual([]);
    expect(calls).toBe(0);
    expect(scanAtlas({ bundle, listPrograms: () => [prog(), prog({ id: 'P-2', keyName: 'Veraport2' })], factsRunner: run, env: ENV })).toHaveLength(2);
    expect(calls).toBe(1);
  });
});

describe('atlas item text', () => {
  const bundle: AtlasBundle = { schema: 2, bundle_seq: 1, created: '2026-09-26', entries: [entry()] };
  const scan = (p: Program) => scanAtlas({ bundle, listPrograms: () => [p], factsRunner: () => raw, env: ENV, exists: () => true })[0]!;

  it('title states measured facts and the advisory that covers this version', () => {
    const i = scan(prog());
    expect(i.title).toBe('Veraport by Wizvera (installed as "Veraport G3 - 3,8,0,0 - x64"): accepts network connections on port 16106; runs a local server on port 16116; installed trusted root certificate "Veraport-CA"; starts with Windows (service VeraportSvc); KISA advisory 2023-02-01 covers your version');
    expect(i.risk).toBe('caution');
    expect(i.atlas!.advisories.map((a) => a.applies)).toEqual(['applies', 'not-applicable', 'unknown']);
    const text = i.instructions!;
    expect(text).toContain('KISA 2023-02-01: "Vulnerable Veraport versions" https://example.org/kisa. Covers your version 3,8,0,0');
    expect(text).toContain('NVD 2020-05-01: "Old issue" (CVE-2020-1234) https://example.org/nvd. Does not cover your version 3,8,0,0 (the advisory covers versions before 3.1).');
    expect(text).toContain('The advisory names no version range.');
    expect(text).toContain('What it is: Installs and updates');
    expect(text).toContain('If you need it again: Banking sites');
    expect(text).toContain('other machines can connect unless a firewall blocks them');
  });

  it('a newer version drops the advisory from the title; unreadable version is unknown', () => {
    expect(scan(prog({ version: '4,0,0,0' })).title).not.toMatch(/advisory/);
    expect(scan(prog({ version: undefined })).atlas!.advisories.map((a) => a.applies)).toEqual(['unknown', 'unknown', 'unknown']);
  });

  it('generated titles carry no verdict words (quoted advisory titles may)', () => {
    for (const v of ['3,8,0,0', '4,0,0,0', undefined]) {
      const i = scan(prog({ version: v }));
      expect(i.title).not.toMatch(VERDICT_WORDS);
      expect(i.instructions!.replace(/"[^"]*"/g, '')).not.toMatch(VERDICT_WORDS);
    }
  });
});

describe('advisory version scopes', () => {
  it('handles lower bounds and version lists as published', async () => {
    const { advisoryApplies, validateEntry } = await import('../src/atlas/entry.ts');
    const base = { publisher: 'KISA' as const, url: 'https://example.org/a', date: '2026-06-01', title: 't' };
    const range = { ...base, affected: { from: '1.1.4.4', up_to: '1.1.4.6', inclusive: true } };
    expect(advisoryApplies(range, '1.1.4.3')).toBe('not-applicable');
    expect(advisoryApplies(range, '1.1.4.5')).toBe('applies');
    expect(advisoryApplies(range, '1.1.4.6')).toBe('applies');
    expect(advisoryApplies(range, '1.1.4.7')).toBe('not-applicable');
    const list = { ...base, affected: { versions: ['1.1.1.0', '1.1.2.6'] } };
    expect(advisoryApplies(list, 'AnySign4PC 1.1.2.6')).toBe('applies');
    expect(advisoryApplies(list, '1.1.2.7')).toBe('not-applicable');
    expect(advisoryApplies(list, undefined)).toBe('unknown');
    const bad = (affected: object) => validateEntry({ advisories: [{ ...base, affected }] }).some((x) => x.startsWith('advisory.affected'));
    expect(bad({ versions: ['1.0'], up_to: '2.0', inclusive: true })).toBe(true);
    expect(bad({ from: '1.0' })).toBe(true);
    expect(bad({ up_to: '2.0' })).toBe(true);
    expect(bad({ versions: [] })).toBe(true);
    expect(bad({ from: '1.0', up_to: '2.0', inclusive: false })).toBe(false);
  });
});
