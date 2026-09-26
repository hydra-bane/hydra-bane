import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { executeAdminItem, isElevated, nonAdminWriters, parseComponentStore, scanAdmin, verifyAdminItem, type AdminScanDeps } from '../src/core/admin.ts';
import { ADMIN_TEXT } from '../src/core/admin-text.ts';
import { planHash, type Plan } from '../src/core/plan.ts';
import type { ScanItem } from '../src/core/scan.ts';
import { copyPlanForAdmin, elevatedApplyCommand, helperDir, installHelper, parseAdminApplyArgs, readAdminResult, readTgz, runAdminApply, verifyAgainstRegistry, type FetchLike } from '../src/admin/helper.ts';
import type { RegValue } from '../src/guard/protected.ts';

// Everything runs against a fake Windows tree in a temp folder with fake registry, whoami, icacls, fetch and
// process runners. Nothing here elevates, runs DISM/powercfg, stops services or touches C:\.

let root: string, env: Record<string, string>, win: string;
const OLD = new Date(Date.now() - 3 * 86_400_000);
const put = (p: string, body = 'x'.repeat(100), old = false) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, body); if (old) fs.utimesSync(p, OLD, OLD); };
const CLEAN_ACL = (t: string) => `${t} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n    BUILTIN\\Administrators:(OI)(CI)(F)\n    BUILTIN\\Users:(OI)(CI)(RX)\n    CREATOR OWNER:(OI)(CI)(IO)(F)\n\nSuccessfully processed 1 files`;
const noReg = () => [] as RegValue[];

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-adm-')));
  win = path.join(root, 'Windows');
  env = { SystemRoot: win, SystemDrive: path.join(root, 'drive'), ProgramData: path.join(root, 'ProgramData'), LOCALAPPDATA: path.join(root, 'local'), COMPUTERNAME: 'PC1' };
  fs.mkdirSync(env.SystemDrive!, { recursive: true });
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

const deps = (over: Partial<AdminScanDeps> = {}): AdminScanDeps => ({ env, elevated: true, regQuery: noReg, listedSize: () => undefined, analyzeComponentStore: () => { throw new Error('not expected'); }, ...over });
const byId = (items: ScanItem[]) => Object.fromEntries(items.map((i) => [i.id, i]));

describe('isElevated', () => {
  it('reads the mandatory label from whoami /groups', () => {
    expect(isElevated(() => '"Mandatory Label\\High Mandatory Level","Label","S-1-16-12288",""')).toBe(true);
    expect(isElevated(() => '"Mandatory Label\\Medium Mandatory Level","Label","S-1-16-8192",""')).toBe(false);
    expect(isElevated(() => { throw new Error('no whoami'); })).toBe(false);
  });
});

describe('scanAdmin', () => {
  it('finds nothing when no location exists', () => {
    expect(scanAdmin(deps())).toEqual([]);
  });

  it('builds items from well-known locations only', () => {
    put(path.join(win, 'Temp', 'old.tmp'), 'o'.repeat(50), true);
    put(path.join(win, 'Temp', 'new.tmp'));
    fs.mkdirSync(path.join(win, 'Temp', 'olddir'));
    put(path.join(win, 'SoftwareDistribution', 'Download', 'pkg', 'a.cab'));
    put(path.join(win, 'ServiceProfiles', 'NetworkService', 'AppData', 'Local', 'Microsoft', 'Windows', 'DeliveryOptimization', 'Cache', 'x'));
    put(path.join(win, 'MEMORY.DMP'), 'm'.repeat(10));
    put(path.join(win, 'Minidump', '1.dmp'), 'd'.repeat(5));
    put(path.join(env.ProgramData!, 'Microsoft', 'Windows', 'WER', 'ReportArchive', 'r1', 'Report.wer'));
    put(path.join(env.ProgramData!, 'Microsoft', 'Windows', 'WER', 'ReportQueue', 'r2', 'Report.wer'));
    fs.mkdirSync(path.join(win, 'WinSxS'), { recursive: true });
    put(path.join(env.SystemDrive!, 'hiberfil.sys'), 'h'.repeat(64));
    put(path.join(env.SystemDrive!, 'Windows.old', 'Windows', 'x.dll'));
    put(path.join(env.LOCALAPPDATA!, 'Docker', 'wsl', 'disk', 'docker_data.vhdx'), 'v'.repeat(30));
    const distro = path.join(root, 'wsl', 'Ubuntu');
    put(path.join(distro, 'ext4.vhdx'), 'e'.repeat(20));
    const lxss = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss';
    const reg = (key: string): RegValue[] => key.endsWith('Lxss') ? [
      { key: `${lxss}\\{a}`, name: 'DistributionName', type: 'REG_SZ', data: 'Ubuntu' },
      { key: `${lxss}\\{a}`, name: 'BasePath', type: 'REG_SZ', data: `\\\\?\\${distro}` },
      { key: `${lxss}\\{b}`, name: 'DistributionName', type: 'REG_SZ', data: 'evil & calc' },
      { key: `${lxss}\\{b}`, name: 'BasePath', type: 'REG_SZ', data: distro },
    ] : [];
    const analyze = vi.fn(() => 'Actual Size of Component Store : 9.10 GB\n Shared with Windows : 6.00 GB\n Backups and Disabled Features : 2.50 GB\n Cache and Temporary Data : 512.00 MB\n');
    const items = byId(scanAdmin(deps({ regQuery: reg, analyzeComponentStore: analyze })));

    expect(Object.keys(items).sort()).toEqual(['DO-CACHE', 'DOCKER-DISK', 'HIBERNATE', 'SYS-DUMPS', 'SYS-TEMP', 'WER', 'WINDOWS-OLD', 'WINSXS', 'WSL-Ubuntu', 'WU-DOWNLOAD']);
    expect(items['SYS-TEMP']).toMatchObject({ files: 1, bytes: 50, op: 'delete_cache', needsAdmin: true, targets: [path.join(win, 'Temp')] });
    expect(items['WU-DOWNLOAD']!.command!.file).toBe(path.join(win, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'));
    expect(items['WU-DOWNLOAD']!.command!.args.at(-1)).toContain(`$d='${path.join(win, 'SoftwareDistribution', 'Download')}'`);
    expect(items['WU-DOWNLOAD']!.command!.args.at(-1)).toMatch(/Stop-Service -Name wuauserv,bits.*finally \{ \$s \| Start-Service \}/);
    expect(items['DO-CACHE']!.command!.args.at(-1)).toBe('Delete-DeliveryOptimizationCache -Force');
    expect(items['SYS-DUMPS']).toMatchObject({ files: 2, bytes: 15, targets: [path.join(win, 'MEMORY.DMP'), path.join(win, 'Minidump')] });
    expect(items.WER!.needsAdmin).toBeUndefined();
    expect(items.WER).toMatchObject({ op: 'delete_cache', targets: expect.arrayContaining([expect.stringMatching(/r1$/), expect.stringMatching(/r2$/)]) });
    expect(items.WINSXS).toMatchObject({ bytes: 3 * 2 ** 30, command: { file: path.join(win, 'System32', 'Dism.exe'), args: ['/Online', '/Cleanup-Image', '/StartComponentCleanup'] } });
    expect(items.WINSXS!.command!.args.join(' ')).not.toMatch(/ResetBase/i);
    expect(items.HIBERNATE).toMatchObject({ bytes: 64, risk: 'caution', reversible: 'none', command: { file: path.join(win, 'System32', 'powercfg.exe'), args: ['/hibernate', 'off'] } });
    expect(items['WINDOWS-OLD']).toMatchObject({ op: 'report_only' });
    expect(items['WINDOWS-OLD']!.command).toBeUndefined();
    expect(items['WINDOWS-OLD']!.instructions).toMatch(/Settings > System > Storage > Temporary files/);
    expect(items['DOCKER-DISK']).toMatchObject({ op: 'report_only', bytes: 30 });
    expect(items['DOCKER-DISK']!.instructions).toMatch(/docker system prune/);
    expect(items['WSL-Ubuntu']!.needsAdmin).toBeUndefined();
    expect(items['WSL-Ubuntu']).toMatchObject({ op: 'tool_cmd', targets: [path.join(distro, 'ext4.vhdx')], command: { file: path.join(win, 'System32', 'wsl.exe'), args: ['--manage', 'Ubuntu', '--set-sparse', 'true'] } });
    for (const i of Object.values(items)) expect(ADMIN_TEXT[i.category]).toBeDefined();
  });

  it('without elevation WinSxS is offered unmeasured and DISM analysis is not run', () => {
    fs.mkdirSync(path.join(win, 'WinSxS'), { recursive: true });
    const analyze = vi.fn(() => '');
    const [w] = scanAdmin(deps({ elevated: false, analyzeComponentStore: analyze }), ['winsxs']);
    expect(w).toMatchObject({ id: 'WINSXS', bytes: 0, title: expect.stringMatching(/size known after analysis/) });
    expect(analyze).not.toHaveBeenCalled();
  });

  it('no hibernation item when hibernation is disabled', () => {
    put(path.join(env.SystemDrive!, 'hiberfil.sys'));
    const off = () => [{ key: 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power', name: 'HibernateEnabled', type: 'REG_DWORD', data: '0x0' }];
    expect(scanAdmin(deps({ regQuery: off }), ['hibernation'])).toEqual([]);
    fs.rmSync(path.join(env.SystemDrive!, 'hiberfil.sys'));
    expect(scanAdmin(deps(), ['hibernation'])).toEqual([]);
  });

  it('parses DISM sizes with comma decimals', () => {
    expect(parseComponentStore(': 1,00 GB\n: 1,00 GB\n: 1,50 GB\n: 0 bytes')).toBe(1.5 * 2 ** 30);
  });
});

describe('DACL parsing (PLAN §6.7)', () => {
  const t = 'C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive';
  it('flags non-admin write, ignores admins, CREATOR OWNER, labels, read-only and deny ACEs', () => {
    const out = `${t} BUILTIN\\Administrators:(OI)(CI)(F)\n    NT AUTHORITY\\Authenticated Users:(OI)(CI)(R,W,D)\n    BUILTIN\\Users:(RX)\n    Everyone:(DENY)(W)\n    CREATOR OWNER:(OI)(CI)(IO)(F)\n    Mandatory Label\\High Mandatory Level:(OI)(NP)(IO)(NW)\n    S-1-15-3-1:(S,RD,X,RA)\n`;
    expect(nonAdminWriters(out, t)).toEqual(['NT AUTHORITY\\Authenticated Users']);
    expect(nonAdminWriters(CLEAN_ACL(t), t)).toEqual([]);
  });
});

describe('elevated execution', () => {
  const tempItem = (): ScanItem => ({ id: 'SYS-TEMP', category: 'system-temp', title: '', op: 'delete_cache', targets: [path.join(win, 'Temp')], allowRoot: path.join(win, 'Temp'), bytes: 0, files: 0, risk: 'safe', reversible: 'none', needsAdmin: true });
  const run = vi.fn(() => ({ status: 0, stderr: '' }));
  const ad = (over = {}) => ({ env, protectedPaths: [win, env.ProgramData!], icacls: CLEAN_ACL, run, ...over });

  it('system-temp unlinks only old top-level files, never folders', () => {
    put(path.join(win, 'Temp', 'old.tmp'), 'o'.repeat(50), true);
    put(path.join(win, 'Temp', 'new.tmp'));
    put(path.join(win, 'Temp', 'olddir', 'inner.tmp'), 'i', true);
    fs.utimesSync(path.join(win, 'Temp', 'olddir'), OLD, OLD);
    const [o] = executeAdminItem(tempItem(), ad());
    expect(o).toMatchObject({ ok: true, bytes: 50 });
    expect(fs.readdirSync(path.join(win, 'Temp')).sort()).toEqual(['new.tmp', 'olddir']);
    expect(fs.existsSync(path.join(win, 'Temp', 'olddir', 'inner.tmp'))).toBe(true);
  });

  it('refuses when the checked folder is writable by non-admins', () => {
    const icacls = (d: string) => `${d} BUILTIN\\Users:(OI)(CI)(M)`;
    expect(verifyAdminItem(tempItem(), ad({ icacls }))).toMatchObject({ code: 'USER_WRITABLE_PARENT' });
  });

  it('refuses a plan whose command or target was altered, and never runs it', () => {
    fs.mkdirSync(path.join(win, 'WinSxS'), { recursive: true });
    const [w] = scanAdmin(deps({ elevated: false }), ['winsxs']);
    run.mockClear();
    expect(executeAdminItem({ ...w!, command: { file: 'C:\\evil.exe', args: [] } }, ad())[0]).toMatchObject({ ok: false, code: 'COMMAND_MISMATCH' });
    expect(executeAdminItem({ ...w!, targets: [path.join(root, 'Users', 'me')] }, ad())[0]).toMatchObject({ ok: false, code: 'GUARD_NOT_ALLOWLISTED' });
    expect(executeAdminItem({ ...w!, needsAdmin: false }, ad())[0]).toMatchObject({ ok: false, code: 'NOT_ADMIN_ITEM' });
    expect(run).not.toHaveBeenCalled();
    expect(executeAdminItem(w!, ad())[0]).toMatchObject({ ok: true });
    expect(run).toHaveBeenCalledWith(path.join(win, 'System32', 'Dism.exe'), ['/Online', '/Cleanup-Image', '/StartComponentCleanup']);
  });

  it('report-only items are never executed', () => {
    put(path.join(env.SystemDrive!, 'Windows.old', 'x'));
    const [o] = scanAdmin(deps(), ['windows-old']);
    expect(executeAdminItem(o!, ad())[0]).toMatchObject({ ok: false, code: 'REPORT_ONLY' });
  });
});

// --- helper ---

function tarEntry(name: string, body: Buffer, type = '0'): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(body.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write(type, 156);
  h.write('ustar\0', 257); h.write('00', 263);
  h.fill(32, 148, 156);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([h, body, Buffer.alloc((512 - (body.length % 512)) % 512)]);
}
const tgz = (entries: Array<[string, string, string?]>) => gzipSync(Buffer.concat([...entries.map(([n, b, t]) => tarEntry(n, Buffer.from(b), t)), Buffer.alloc(1024)]));
const GOOD = () => tgz([['package/package.json', '{"version":"0.2.0"}'], ['package/dist/cli.js', 'console.log(1)']]);

function fakeFetch(tarball: Buffer, integrityOf: Buffer = tarball, url = 'https://registry.npmjs.org/hydra-bane/-/hydra-bane-0.2.0.tgz'): FetchLike {
  return async (u) => {
    if (u === 'https://registry.npmjs.org/hydra-bane/0.2.0') return { ok: true, status: 200, json: async () => ({ dist: { tarball: url, integrity: `sha512-${createHash('sha512').update(integrityOf).digest('base64')}` } }), arrayBuffer: async () => new ArrayBuffer(0) };
    if (u === url) return { ok: true, status: 200, json: async () => ({}), arrayBuffer: async () => tarball.buffer.slice(tarball.byteOffset, tarball.byteOffset + tarball.length) as ArrayBuffer };
    return { ok: false, status: 404, json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
  };
}

describe('registry verification and tar reader', () => {
  it('accepts a tarball matching the registry integrity', async () => {
    const r = await verifyAgainstRegistry('0.2.0', fakeFetch(GOOD()));
    expect(r.ok).toBe(true);
  });
  it('rejects an integrity mismatch', async () => {
    const r = await verifyAgainstRegistry('0.2.0', fakeFetch(GOOD(), Buffer.from('other')));
    expect(r).toMatchObject({ ok: false, code: 'INTEGRITY_MISMATCH' });
  });
  it('rejects a tarball hosted anywhere but the registry', async () => {
    const r = await verifyAgainstRegistry('0.2.0', fakeFetch(GOOD(), GOOD(), 'https://evil.example/hydra-bane-0.2.0.tgz'));
    expect(r).toMatchObject({ ok: false, code: 'REGISTRY' });
  });
  it('reads regular files under package/', () => {
    expect([...readTgz(GOOD()).keys()]).toEqual(['package.json', 'dist\\cli.js']);
  });
  it.each([
    ['package/../evil.js', '0'], ['/abs.js', '0'], ['package/C:/x.js', '0'], ['package/a/../../x', '0'], ['package/x.js:ads', '0'], ['package/link', '2'], ['package/hard', '1'],
  ])('rejects %s (type %s)', (name, type) => {
    expect(() => readTgz(tgz([[name, 'x', type]]))).toThrow();
  });
  it('rejects a corrupted header', () => {
    const raw = Buffer.concat([tarEntry('package/a.js', Buffer.from('x')), Buffer.alloc(1024)]);
    raw[0] = 'q'.charCodeAt(0);
    expect(() => readTgz(gzipSync(raw))).toThrow(/checksum/);
  });
});

describe('installHelper', () => {
  const icaclsRun = vi.fn(() => ({ status: 0, stdout: '' }));
  const inst = (over = {}) => ({ env, elevated: true, fetchImpl: fakeFetch(GOOD()), icaclsRun, icacls: CLEAN_ACL, ...over });

  it('refuses without elevation', async () => {
    expect(await installHelper('0.2.0', inst({ elevated: false }))).toMatchObject({ ok: false, code: 'NOT_ELEVATED' });
  });

  it('installs verified files with an admin-only ACL, then reuses a matching install', async () => {
    const r = await installHelper('0.2.0', inst());
    expect(r).toMatchObject({ ok: true, reused: false, files: 2 });
    const dir = helperDir('0.2.0', env);
    expect(fs.readFileSync(path.join(dir, 'dist', 'cli.js'), 'utf8')).toBe('console.log(1)');
    const grant = icaclsRun.mock.calls.map((c) => (c as unknown as [string[]])[0]).find((a) => a.includes('/inheritance:r'))!;
    expect(grant).toEqual([path.join(env.ProgramData!, 'hydra-bane'), '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX']);
    expect(await installHelper('0.2.0', inst())).toMatchObject({ ok: true, reused: true });
    fs.appendFileSync(path.join(dir, 'dist', 'cli.js'), 'evil()');
    expect(await installHelper('0.2.0', inst())).toMatchObject({ ok: false, code: 'HELPER_DIR_UNTRUSTED' });
  });

  it('refuses when the local package differs from the registry', async () => {
    const local = path.join(root, 'npm', 'hydra-bane');
    put(path.join(local, 'package.json'), '{"version":"0.2.0"}');
    put(path.join(local, 'dist', 'cli.js'), 'tampered');
    expect(await installHelper('0.2.0', inst({ localRoot: local }))).toMatchObject({ ok: false, code: 'LOCAL_MISMATCH' });
  });

  it('refuses when the base folder stays user-writable', async () => {
    expect(await installHelper('0.2.0', inst({ icacls: (d: string) => `${d} BUILTIN\\Users:(OI)(CI)(M)` }))).toMatchObject({ ok: false, code: 'BASE_UNSAFE' });
  });
});

describe('elevated apply plumbing', () => {
  const SID = 'S-1-5-21-1-2-3-1001';
  const HASH = 'a'.repeat(64);
  const profile = () => path.join(root, 'Users', 'me');
  const reg = (key: string): RegValue[] => key.endsWith(SID) ? [{ key, name: 'ProfileImagePath', type: 'REG_EXPAND_SZ', data: profile() }] : [];

  function writePlan(items: ScanItem[], mutate?: (p: Plan) => void): Plan {
    const body: Omit<Plan, 'hash'> = { schemaVersion: 1, id: 'abc123', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString(), sid: SID, host: 'PC1', nonce: 'n', items };
    const plan: Plan = { ...body, hash: planHash(body) };
    mutate?.(plan);
    put(path.join(profile(), 'AppData', 'Local', 'hydra-bane', 'plans', 'abc123.json'), JSON.stringify(plan));
    return plan;
  }

  it('elevatedApplyCommand puts the plan hash on the elevated command line', () => {
    const r = elevatedApplyCommand('abc123', HASH, SID, { version: '0.2.0', env, nodeExe: 'C:\\Program Files\\nodejs\\node.exe', icacls: CLEAN_ACL });
    expect(r.ok && r.elevated.args).toEqual([path.join(helperDir('0.2.0', env), 'dist', 'cli.js'), 'admin-apply', 'abc123', '--plan-hash', HASH, '--user-sid', SID]);
    expect(r.ok && r.args.at(-1)).toMatch(/-Verb RunAs -Wait -PassThru/);
    expect(elevatedApplyCommand('abc123', HASH, SID, { version: '0.2.0', env, nodeExe: 'C:\\nvm\\node.exe', icacls: (d) => `${d} BUILTIN\\Users:(F)` })).toMatchObject({ ok: false, code: 'NODE_USER_WRITABLE' });
    expect(elevatedApplyCommand('abc123', HASH, 'S-1-5-18', { version: '0.2.0', env })).toMatchObject({ ok: false, code: 'BAD_ARGS' });
    expect(parseAdminApplyArgs(['abc123', '--plan-hash', HASH, '--user-sid', SID])).toEqual({ planId: 'abc123', hash: HASH, userSid: SID });
    expect(parseAdminApplyArgs(['abc123', '--plan-hash', 'x', '--user-sid', SID])).toBeUndefined();
  });

  it('copyPlanForAdmin rejects a plan edited after the UAC prompt showed its hash', () => {
    const p = writePlan([]);
    expect(copyPlanForAdmin('abc123', p.hash, SID, { env, reg, host: 'PC1' })).toMatchObject({ ok: true });
    expect(copyPlanForAdmin('abc123', HASH, SID, { env, reg, host: 'PC1' })).toMatchObject({ ok: false, code: 'TAMPERED' });
    const t = writePlan([], (x) => { x.items = [{ id: 'X' } as ScanItem]; });
    expect(copyPlanForAdmin('abc123', t.hash, SID, { env, reg, host: 'PC1' })).toMatchObject({ ok: false, code: 'TAMPERED' });
  });

  it('runAdminApply runs only from the helper folder and re-checks every item', () => {
    fs.mkdirSync(path.join(win, 'WinSxS'), { recursive: true });
    const [w] = scanAdmin(deps({ elevated: false }), ['winsxs']);
    const forged: ScanItem = { ...w!, id: 'FORGED', command: { file: 'C:\\evil.exe', args: [] } };
    const p = writePlan([w!, forged]);
    const run = vi.fn(() => ({ status: 0, stderr: '' }));
    const base = { env, reg, host: 'PC1', icacls: CLEAN_ACL, run, version: '0.2.0', elevated: true, protectedPaths: () => [win] };
    const args = { planId: 'abc123', hash: p.hash, userSid: SID };
    expect(runAdminApply(args, { ...base, selfPath: path.join(root, 'npm', 'dist', 'cli.js') })).toMatchObject({ ok: false, code: 'NOT_FROM_HELPER' });
    expect(runAdminApply(args, { ...base, elevated: false, selfPath: 'x' })).toMatchObject({ ok: false, code: 'NOT_ELEVATED' });
    const r = runAdminApply(args, { ...base, selfPath: path.join(helperDir('0.2.0', env), 'dist', 'cli.js') });
    expect(r.ok && r.outcomes.map((o) => [o.id, o.ok, o.code])).toEqual([['WINSXS', true, undefined], ['FORGED', false, 'COMMAND_MISMATCH']]);
    expect(run).toHaveBeenCalledTimes(1);
    expect(readAdminResult('abc123', p.hash, env)?.outcomes).toHaveLength(2);
    expect(readAdminResult('abc123', HASH, env)).toBeUndefined();
  });
});
