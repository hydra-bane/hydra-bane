import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type { Program } from '../src/atlas/programs.ts';
import type { Signer } from '../src/atlas/report.ts';
import { appItem, appItemId, buildGeneralUninstall, publisherMatches, runUninstall } from '../src/atlas/uninstall.ts';
import { describeAction } from '../src/hook/describe.ts';

// General uninstall (PLAN.md §7.3, v0.3): any program, but only when msi / signed / admin-folder trust holds.
// No real uninstaller ever runs here: spawn, signatures, ACLs and the program list are all injected.

const GUID = '{11111111-2222-3333-4444-555555555555}';
const cliPrograms: { list: Program[] } = { list: [] };
vi.mock('../src/atlas/programs.ts', async (orig) => ({ ...(await orig<typeof import('../src/atlas/programs.ts')>()), listPrograms: () => cliPrograms.list }));
const TP = 'A'.repeat(40), OTHER_TP = 'B'.repeat(40);
const DIR = 'C:\\Program Files\\Acme Tool';
const UNINST = `${DIR}\\unins000.exe`;
const prog = (over: Partial<Program> = {}): Program => ({
  id: 'P-abc123', name: 'Acme Tool', publisher: 'Acme Software Co., Ltd.', version: '2.1', hive: 'HKLM', view: '64', keyName: 'Acme Tool_is1',
  installLocation: `${DIR}\\`, uninstallString: `"${UNINST}"`, displayIcon: `${DIR}\\acme.exe`, estimatedBytes: 4096, ...over,
});
const signed: Signer = { status: 'Valid', subject: 'CN="Acme Software Co.,Ltd", O="Acme Software Co.,Ltd", L=Seoul, C=KR', thumbprint: TP };
const deps = (o: { signer?: Signer | undefined; main?: Signer | undefined; writable?: string[] | 'UNKNOWN' } = {}) => ({
  exists: () => true, env: { SystemRoot: 'C:\\Windows' },
  signerOf: (f: string) => (f === UNINST ? ('signer' in o ? o.signer : signed) : o.main),
  userWritable: () => o.writable ?? [],
});
const unsigned = { status: 'NotSigned' } as Signer;

describe('general uninstall trust', () => {
  it('msi: command is built from the product code only', () => {
    const p = prog({ keyName: GUID, msiProductCode: GUID, uninstallString: 'cmd.exe /c evil & MsiExec.exe /X{...}', hive: 'HKCU' });
    expect(buildGeneralUninstall(p, deps())).toEqual({ trust: 'msi', kind: 'msi', file: 'C:\\Windows\\System32\\msiexec.exe', args: ['/x', GUID], signers: [] });
  });

  it('signed: accepted when the signer organization is the publisher, refused otherwise', () => {
    expect(buildGeneralUninstall(prog({ hive: 'HKCU' }), deps())).toEqual({ trust: 'signed', kind: 'exe', file: UNINST, args: [], signers: [TP] });
    const other = { ...signed, subject: 'CN=Someone Else Inc., O=Someone Else Inc.' };
    expect(buildGeneralUninstall(prog({ hive: 'HKCU' }), deps({ signer: other }))).toMatchObject({ reason: expect.stringMatching(/not the publisher.*HKCU/) });
    // ...unless the same certificate signs the program's own executable
    expect(buildGeneralUninstall(prog({ hive: 'HKCU' }), deps({ signer: other, main: other }))).toMatchObject({ trust: 'signed', signers: [TP] });
    expect(publisherMatches('CN=Google LLC, O=Google LLC, L=Mountain View', 'Google LLC')).toBe(true);
    expect(publisherMatches('CN=Mozilla Corporation', 'Mozilla')).toBe(true);
    expect(publisherMatches('CN=Microsoft Corporation', 'Inc.')).toBe(false);
    expect(publisherMatches('CN=Microsoft Corporation', undefined)).toBe(false);
  });

  it('admin-folder: unsigned HKLM uninstaller in an admin-only folder; refused when user-writable, unreadable or HKCU', () => {
    expect(buildGeneralUninstall(prog(), deps({ signer: unsigned }))).toEqual({ trust: 'admin-folder', kind: 'exe', file: UNINST, args: [], signers: [] });
    expect(buildGeneralUninstall(prog(), deps({ signer: unsigned, writable: ['BUILTIN\\Users'] }))).toMatchObject({ reason: expect.stringMatching(/BUILTIN\\Users/) });
    expect(buildGeneralUninstall(prog(), deps({ signer: unsigned, writable: 'UNKNOWN' }))).toMatchObject({ reason: expect.stringMatching(/could not be read/) });
    expect(buildGeneralUninstall(prog({ hive: 'HKCU' }), deps({ signer: unsigned }))).toMatchObject({ reason: expect.stringMatching(/HKCU/) });
  });

  it('keeps the shell, LOLBin, metacharacter and path refusals', () => {
    const reason = (uninstallString: string) => (buildGeneralUninstall(prog({ uninstallString }), deps()) as { reason?: string }).reason;
    expect(reason('cmd.exe /c del x')).toMatch(/cmd\.exe/);
    expect(reason('rundll32.exe C:\\x.dll,Uninstall')).toMatch(/rundll32/);
    expect(reason('MsiExec.exe /X{1}')).toMatch(/msiexec/i);
    expect(reason(`"${UNINST}" & calc`)).toMatch(/metacharacters/);
    expect(reason(`"${UNINST}" _?=C:\\Users\\alice`)).toMatch(/_\?=/);
    expect(reason(`"${UNINST}" /log C:\\Users\\alice\\x`)).toMatch(/outside/);
    expect(reason('"\\\\server\\share\\u.exe"')).toMatch(/absolute/);
    expect(reason('"C:\\Windows\\System32\\certutil.exe" -f')).toMatch(/Windows folder/);
  });
});

describe('general uninstall at apply time', () => {
  const run = (item: ReturnType<typeof appItem>, now: Program[], d = deps()) => {
    const spawn = vi.fn(() => ({ status: 0 }));
    return { r: runUninstall(item, { bundle: undefined, listPrograms: () => now, spawn, ...d }), spawn };
  };

  it('runs only a re-verified identical command', () => {
    const item = appItem(prog(), deps());
    expect(item).toMatchObject({ id: appItemId(prog()), category: 'app', op: 'uninstall', risk: 'caution', reversible: 'reinstall-only', bytes: 4096, needsAdmin: true, program: { id: 'P-abc123', hive: 'HKLM' } });
    expect(item.title).toBe(`Uninstall Acme Tool 2.1 (Acme Software Co., Ltd.): runs "${UNINST}" [trust: signed]`);
    const ok = run(item, [prog()]);
    expect(ok.spawn).toHaveBeenCalledWith(UNINST, []);
    expect(ok.r.detail).toMatch(/still listed/);
  });

  it('refuses when the command, signature or folder changed since the plan', () => {
    const item = appItem(prog(), deps());
    const changed = [
      run(item, [prog({ uninstallString: `"${UNINST}" /S` })]),
      run(item, [prog()], deps({ signer: { ...signed, thumbprint: OTHER_TP } })),
      run(item, [prog()], deps({ signer: unsigned })), // now only admin-folder: trust changed
      run(item, []),
    ];
    for (const c of changed) { expect(c.r.ok).toBe(false); expect(c.r.detail).toMatch(/^refused/); expect(c.spawn).not.toHaveBeenCalled(); }
    const folder = appItem(prog(), deps({ signer: unsigned }));
    expect(folder.uninstall?.trust).toBe('admin-folder');
    const w = run(folder, [prog()], deps({ signer: unsigned, writable: ['Everyone'] }));
    expect(w.r.detail).toMatch(/refused.*Everyone/);
    expect(w.spawn).not.toHaveBeenCalled();
    const forged = { ...item, uninstall: { ...item.uninstall!, trust: 'atlas' as const } };
    expect(run(forged, [prog()]).r.detail).toMatch(/refused/);
  });

  it('report-only when no trust holds, with Settings instructions', () => {
    const i = appItem(prog({ hive: 'HKCU' }), deps({ signer: unsigned }));
    expect(i).toMatchObject({ op: 'report_only', category: 'app' });
    expect(i.uninstall).toBeUndefined();
    expect(i.instructions).toMatch(/Settings > Apps/);
  });

  it('the approval prompt shows the exact command line and the trust reason', () => {
    const state = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-ug-'));
    try {
      const item = appItem(prog({ uninstallString: `"${UNINST}" /LOG "${DIR}\\u.log"` }), deps());
      const plan = { schemaVersion: 1, id: 'abc', createdAt: '', expiresAt: '', sid: '', host: '', nonce: '', items: [item] };
      fs.mkdirSync(path.join(state, 'plans'));
      fs.writeFileSync(path.join(state, 'plans', 'abc.json'), JSON.stringify({ ...plan, hash: 'x'.repeat(64) }));
      const text = describeAction('apply', 'abc', state);
      expect(text).toContain(`"C:\\Program Files\\Acme Tool\\unins000.exe" /LOG "${DIR}\\u.log"`);
      expect(text).toMatch(/trust: signed, valid signature of the program's publisher/);
    } finally { fs.rmSync(state, { recursive: true, force: true }); }
  });
});

describe('cli uninstall', () => {
  it('seals a one-item plan and changes nothing', async () => {
    const { main } = await import('../src/cli.ts');
    const local = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-cli-'));
    const saved = process.env.LOCALAPPDATA;
    const out: string[] = [];
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((s) => { out.push(String(s)); return true; });
    try {
      process.env.LOCALAPPDATA = local;
      cliPrograms.list = [prog({ id: 'P-def456', keyName: GUID, msiProductCode: GUID })];
      expect(await main(['uninstall', 'P-def456', '--json'])).toBe(0);
      const env = JSON.parse(out.join('')) as { ok: boolean; data: { plan_id: string; items: string[]; item: { op: string; uninstall: { trust: string; args: string[] } } } };
      expect(env.ok).toBe(true);
      expect(env.data.items).toEqual(['APP-def456']);
      expect(env.data.item).toMatchObject({ op: 'uninstall', uninstall: { trust: 'msi', args: ['/x', GUID] } });
      const plan = JSON.parse(fs.readFileSync(path.join(local, 'hydra-bane', 'plans', `${env.data.plan_id}.json`), 'utf8')) as { items: unknown[] };
      expect(plan.items).toHaveLength(1);
      expect(fs.readdirSync(path.join(local, 'hydra-bane'))).toEqual(['plans']); // no ledger: nothing applied
      out.length = 0;
      expect(await main(['uninstall', 'P-nope', '--json'])).toBe(1);
    } finally {
      write.mockRestore();
      if (saved === undefined) delete process.env.LOCALAPPDATA; else process.env.LOCALAPPDATA = saved;
      fs.rmSync(local, { recursive: true, force: true });
    }
  });
});
