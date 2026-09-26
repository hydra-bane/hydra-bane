import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { apply, recover, undo } from '../src/core/apply.ts';
import type { Context } from '../src/core/context.ts';
import { nameVariants, publisherVariants, scanLeftovers, type LeftoverDeps } from '../src/core/leftovers.ts';
import { makePlan } from '../src/core/plan.ts';
import { hkcuKeyProblem, keyExists, regHost, type RegRun } from '../src/core/registry.ts';
import { scan, type ScanItem } from '../src/core/scan.ts';
import type { Program } from '../src/atlas/programs.ts';
import { Ledger } from '../src/ledger/ledger.ts';

// Leftovers of programs Hydra-bane uninstalled, and the reg_delete op. Everything runs in a temp folder with a fake
// program list and a fake reg.exe; only the opt-in integration test touches the real registry (its own test key).

let root: string, ctx: Context, env: Record<string, string>;
const APPDATA = () => env.APPDATA!, LOCAL = () => env.LOCALAPPDATA!;
const mk = (...parts: string[]) => { const p = path.join(...parts); fs.mkdirSync(p, { recursive: true }); return p; };
const put = (p: string, text = 'x') => { mk(path.dirname(p)); fs.writeFileSync(p, text); return p; };

const PROGRAM = { id: 'P-abc123', name: 'Foo Editor 2.1 (x64)', publisher: 'Acme, Inc.', version: '2.1', hive: 'HKCU' as const, view: '64' as const, keyName: 'FooEditor', installLocation: '' };
const program = (over: Partial<Program> = {}): Program => ({ id: 'P-000000', name: 'Other App', hive: 'HKLM', view: '64', keyName: 'OtherApp', ...over });

function recordUninstall(p = PROGRAM) {
  const l = new Ledger(path.join(ctx.stateDir, 'ledger'));
  l.lock();
  try {
    l.append('tx-uninstall', 'planned', { item: 'APP-1', op: 'uninstall', target: p.name });
    l.append('tx-uninstall', 'done', { item: 'APP-1', op: 'uninstall', target: p.name, exitCode: 0, stillInstalled: false, program: p });
  } finally { l.unlock(); }
}

const deps = (over: LeftoverDeps = {}): LeftoverDeps => ({ listPrograms: () => [program()], env, keyExists: () => false, shortcutTargets: () => new Map(), ...over });
const byTarget = (items: ScanItem[]) => new Map(items.map((i) => [i.targets[0]!.toLowerCase(), i]));

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-l-')));
  env = {
    APPDATA: mk(root, 'home', 'AppData', 'Roaming'),
    LOCALAPPDATA: mk(root, 'home', 'AppData', 'Local'),
    ProgramData: mk(root, 'pd'),
    ProgramFiles: mk(root, 'pf'),
  };
  ctx = {
    stateDir: path.join(root, 'home', 'AppData', 'Local', 'hydra-bane'),
    tempDir: mk(root, 'temp'),
    home: path.join(root, 'home'),
    locate: () => undefined,
    roots: [],
    protectedPaths: [path.join(root, 'home', 'Documents'), path.join(root, 'protected')],
    sid: 'S-1-5-21-left',
    now: () => new Date(),
    confirmer: { confirm: async () => true },
    run: () => ({ status: 0, stderr: '' }),
    quarantineBaseFor: () => path.join(root, 'quarantine'),
    isRunning: () => false,
  };
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe('name matching', () => {
  it('trims versions and architectures, never to a generic name', () => {
    expect(nameVariants('7-Zip 23.01 (x64)')).toEqual(['7-Zip 23.01 (x64)', '7-Zip']);
    expect(nameVariants('Foo Editor 2.1 (x64)')).toContain('Foo Editor');
    expect(nameVariants('App 1.0')).toEqual(['App 1.0']);
    expect(nameVariants('Microsoft')).toEqual([]);
    expect(publisherVariants('Acme, Inc.')).toEqual(['Acme']); // a folder name cannot end with a dot
    expect(publisherVariants('Acme Corporation')).toEqual(['Acme Corporation', 'Acme']);
  });
});

describe.runIf(process.platform === 'win32')('leftovers scan', () => {
  it('finds nothing unless Hydra-bane uninstalled the program, and reads no program list then', () => {
    mk(APPDATA(), 'Foo Editor');
    let listed = false;
    expect(scanLeftovers(ctx, deps({ listPrograms: () => { listed = true; return []; } }))).toEqual([]);
    expect(listed).toBe(false);
    expect(scan(ctx, ['leftovers'])).toEqual([]);
  });

  it('offers exact-name folders only, quarantining user ones and reporting machine ones', () => {
    const install = mk(LOCAL(), 'Programs', 'Foo Editor');
    put(path.join(install, 'settings.json'));
    recordUninstall({ ...PROGRAM, installLocation: install });
    const roaming = mk(APPDATA(), 'Foo Editor');
    put(path.join(roaming, 'cfg.ini'));
    mk(APPDATA(), 'Foo Editor Backup');
    mk(APPDATA(), 'Foo');
    mk(APPDATA(), 'Foo Editor 2');
    const machine = mk(env.ProgramData!, 'Foo Editor');

    const items = byTarget(scanLeftovers(ctx, deps()));
    expect([...items.keys()].sort()).toEqual([install, roaming, machine].map((p) => p.toLowerCase()).sort());
    for (const p of [install, roaming]) expect(items.get(p.toLowerCase())).toMatchObject({ category: 'leftovers', op: 'quarantine', risk: 'caution', reversible: 'move-back', program: { name: PROGRAM.name } });
    expect(items.get(roaming.toLowerCase())!.id).toMatch(/^LEFT-[0-9a-f]{6}$/);
    expect(items.get(roaming.toLowerCase())!.title).toContain('Leftover of Foo Editor 2.1 (x64) (removed ');
    expect(items.get(machine.toLowerCase())).toMatchObject({ op: 'report_only', reversible: 'none', instructions: expect.stringContaining('administrator') });
  });

  it('skips programs that are installed again, or have another installed version', () => {
    recordUninstall();
    mk(APPDATA(), 'Foo Editor');
    expect(scanLeftovers(ctx, deps({ listPrograms: () => [program({ hive: 'HKCU', keyName: 'FooEditor', name: 'Foo Editor 2.1 (x64)' })] }))).toEqual([]);
    expect(scanLeftovers(ctx, deps({ listPrograms: () => [program({ keyName: 'FooEditor3', name: 'Foo Editor 3.0' })] }))).toEqual([]);
  });

  it('takes the vendor folder only when it holds nothing but this product and no installed program shares it', () => {
    recordUninstall();
    const alone = mk(APPDATA(), 'Acme', 'Foo Editor');
    const shared = mk(LOCAL(), 'Acme', 'Foo Editor');
    mk(LOCAL(), 'Acme', 'Rocket Skates');
    let items = byTarget(scanLeftovers(ctx, deps()));
    expect(items.has(path.dirname(alone).toLowerCase())).toBe(true);
    expect(items.has(shared.toLowerCase())).toBe(true);
    expect(items.has(path.dirname(shared).toLowerCase())).toBe(false);

    items = byTarget(scanLeftovers(ctx, deps({ listPrograms: () => [program({ publisher: 'Acme Inc' })] })));
    expect(items.has(alone.toLowerCase())).toBe(true);
    expect(items.has(path.dirname(alone).toLowerCase())).toBe(false);
  });

  it('only reports folders with documents, and skips git repositories entirely', () => {
    recordUninstall();
    const docs = mk(APPDATA(), 'Foo Editor');
    for (const f of ['a.docx', 'b.pdf', 'c.hwp']) put(path.join(docs, 'exports', f));
    const repo = mk(LOCAL(), 'Foo Editor');
    mk(repo, 'project', '.git');
    const items = byTarget(scanLeftovers(ctx, deps()));
    expect(items.get(docs.toLowerCase())).toMatchObject({ op: 'report_only', instructions: expect.stringContaining('3 documents') });
    expect(items.has(repo.toLowerCase())).toBe(false);
  });

  it('never offers a protected path, a folder containing one, a root folder, or a still-installed program folder', () => {
    recordUninstall({ ...PROGRAM, installLocation: LOCAL() });
    const holder = mk(APPDATA(), 'Foo Editor');
    ctx.protectedPaths.push(mk(holder, 'Synced'));
    const inUse = mk(LOCAL(), 'Programs', 'Foo Editor');
    const items = scanLeftovers(ctx, deps({ listPrograms: () => [program({ installLocation: path.join(inUse, 'bin') })] }));
    expect(items).toEqual([]);
  });

  it('offers HKCU keys for reg_delete and reports HKLM keys', () => {
    recordUninstall();
    const present = new Set(['HKCU\\Software\\Acme\\Foo Editor', 'HKCU\\Software\\Foo Editor 2.1 (x64)', 'HKLM\\SOFTWARE\\WOW6432Node\\Foo Editor']);
    const items = byTarget(scanLeftovers(ctx, deps({ keyExists: (k) => present.has(k) })));
    expect(items.get('hkcu\\software\\acme\\foo editor')).toMatchObject({ op: 'reg_delete', regKeys: ['HKCU\\Software\\Acme\\Foo Editor'], reversible: 'move-back' });
    expect(items.get('hkcu\\software\\foo editor 2.1 (x64)')).toMatchObject({ op: 'reg_delete' });
    expect(items.get('hklm\\software\\wow6432node\\foo editor')).toMatchObject({ op: 'report_only' });
    expect(items.size).toBe(3);
  });

  it('offers Start Menu shortcuts whose target was inside the removed program and is gone', () => {
    const install = path.join(LOCAL(), 'Programs', 'Foo Editor'); // already removed by the uninstaller
    recordUninstall({ ...PROGRAM, installLocation: install });
    const menu = mk(APPDATA(), 'Microsoft', 'Windows', 'Start Menu', 'Programs');
    const dead = put(path.join(menu, 'Foo Editor.lnk'));
    const other = put(path.join(menu, 'Acme', 'Other.lnk'));
    const alive = put(path.join(menu, 'Notes.lnk'));
    const live = put(path.join(root, 'notes.exe'));
    const targets = new Map([[dead, path.join(install, 'foo.exe')], [other, path.join(root, 'elsewhere', 'x.exe')], [alive, live]]);
    const items = scanLeftovers(ctx, deps({ shortcutTargets: () => targets }));
    expect(items.map((i) => [i.targets[0], i.op, i.allowRoot])).toEqual([[dead, 'quarantine', menu]]);
  });
});

// ---- reg_delete through apply / undo / recover, with a fake reg.exe ----

const KEY = 'HKCU\\Software\\Acme\\Foo Editor';
let reg: Map<string, string>, calls: string[][], realRun: RegRun;
const fullKey = (k: string) => k.replace(/^HKCU\\/, 'HKEY_CURRENT_USER\\');

function fakeReg(over: { exportFails?: boolean; deleteThrows?: 'before' | 'after' } = {}): RegRun {
  return (args) => {
    calls.push(args);
    const [verb, a, b] = args;
    if (verb === 'query') return { status: reg.has(a!) ? 0 : 1, stderr: '' };
    if (verb === 'export') {
      if (over.exportFails || !reg.has(a!)) return { status: 1, stderr: 'ERROR' };
      const text = `Windows Registry Editor Version 5.00\r\n\r\n[${fullKey(a!)}]\r\n"v"="${reg.get(a!)}"\r\n\r\n`;
      fs.writeFileSync(b!, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]));
      return { status: 0, stderr: '' };
    }
    if (verb === 'delete') {
      if (over.deleteThrows === 'before') throw new Error('killed before delete');
      reg.delete(a!);
      if (over.deleteThrows === 'after') throw new Error('killed after delete');
      return { status: 0, stderr: '' };
    }
    if (verb === 'import') {
      const text = fs.readFileSync(a!).subarray(2).toString('utf16le');
      const section = /\[HKEY_CURRENT_USER\\(.*)\]/.exec(text)![1]!;
      reg.set(`HKCU\\${section}`, /"v"="(.*)"/.exec(text)![1]!);
      return { status: 0, stderr: '' };
    }
    return { status: 1, stderr: 'unexpected' };
  };
}

const regItem = (keys = [KEY]): ScanItem => ({ id: 'LEFT-aaaaaa', category: 'leftovers', title: 'Leftover of Foo Editor', op: 'reg_delete', targets: keys, regKeys: keys, allowRoot: 'HKCU\\Software', bytes: 0, files: 0, risk: 'caution', reversible: 'move-back' });
const records = () => new Ledger(path.join(ctx.stateDir, 'ledger')).records();

describe.runIf(process.platform === 'win32')('reg_delete apply / undo / recover', () => {
  beforeEach(() => { reg = new Map([[KEY, 'hello']]); calls = []; realRun = regHost.run; regHost.run = fakeReg(); });
  afterEach(() => { regHost.run = realRun; });

  it('only HKCU\\Software\\<Name> or <Publisher>\\<Name> keys pass validation', () => {
    expect(hkcuKeyProblem(KEY)).toBeUndefined();
    expect(hkcuKeyProblem('HKCU\\Software\\FooEditor')).toBeUndefined();
    for (const bad of ['HKCU\\Software', 'HKCU\\Software\\', 'HKLM\\SOFTWARE\\Foo', 'HKCU\\Software\\Microsoft\\Foo', 'HKCU\\Software\\Classes', 'HKCU\\Software\\Foo\\Windows', 'HKCU\\Software\\A\\B\\C', 'HKCU\\Software\\Fo*', 'hkcu\\software\\Foo', 'HKCU\\Software\\Foo\\', 'HKCU\\Software\\ Foo']) {
      expect(hkcuKeyProblem(bad), bad).toBeDefined();
    }
  });

  it('exports to quarantine, deletes, and undo imports the key back', async () => {
    const plan = makePlan(ctx, [regItem()]);
    const r = await apply(ctx, plan.id);
    expect(r).toMatchObject({ ok: true, outcomes: [{ id: 'LEFT-aaaaaa', target: KEY, ok: true }] });
    expect(reg.has(KEY)).toBe(false);
    const done = records().find((x) => x.type === 'done')!.data as { exportFile: string; sha256: string; quarantineBase: string };
    expect(done.exportFile.startsWith(path.join(root, 'quarantine', plan.id))).toBe(true);
    expect(done.sha256).toMatch(/^[0-9a-f]{64}$/);
    // The export was verified before the delete ran.
    expect(calls.map((c) => c[0])).toEqual(['query', 'export', 'delete']);

    expect(await undo(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ id: 'LEFT-aaaaaa', ok: true, restoredTo: KEY }] });
    expect(reg.get(KEY)).toBe('hello');
    expect(await undo(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [] }); // nothing imported twice
    expect(new Ledger(path.join(ctx.stateDir, 'ledger')).verify().ok).toBe(true);
  });

  it('never deletes when the export fails', async () => {
    regHost.run = fakeReg({ exportFails: true });
    const plan = makePlan(ctx, [regItem()]);
    expect(await apply(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: false, code: 'EXPORT_FAILED' }] });
    expect(reg.get(KEY)).toBe('hello');
    expect(calls.some((c) => c[0] === 'delete')).toBe(false);
  });

  it('refuses keys outside HKCU\\Software without calling reg.exe', async () => {
    const plan = makePlan(ctx, [regItem(['HKLM\\SOFTWARE\\Foo', 'HKCU\\Software\\Microsoft\\Windows'])]);
    expect(await apply(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: false, code: 'BAD_KEY' }, { ok: false, code: 'BAD_KEY' }] });
    expect(calls).toEqual([]);
  });

  it('undo refuses a tampered export, and never overwrites a key that exists again', async () => {
    const plan = makePlan(ctx, [regItem()]);
    await apply(ctx, plan.id);
    const { exportFile } = records().find((x) => x.type === 'done')!.data as { exportFile: string };
    const original = fs.readFileSync(exportFile);
    fs.appendFileSync(exportFile, Buffer.from('[HKEY_CURRENT_USER\\Software\\Evil]\r\n', 'utf16le'));
    expect(await undo(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: false, code: 'HASH_MISMATCH' }] });
    expect(calls.some((c) => c[0] === 'import')).toBe(false);

    fs.writeFileSync(exportFile, original);
    reg.set(KEY, 'reinstalled');
    expect(await undo(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: false, code: 'KEY_EXISTS' }] });
    expect(reg.get(KEY)).toBe('reinstalled');
  });

  it.each(['before', 'after'] as const)('a crash %s the delete (export recorded) is resolved by recover and undo restores', async (when) => {
    regHost.run = fakeReg({ deleteThrows: when });
    const plan = makePlan(ctx, [regItem()]);
    await expect(apply(ctx, plan.id)).rejects.toThrow('killed');
    regHost.run = fakeReg();
    const rec = recover(ctx);
    expect(rec.resolved).toEqual([expect.objectContaining({ item: 'LEFT-aaaaaa', target: KEY, type: when === 'after' ? 'done' : 'failed' })]);
    expect(recover(ctx).resolved).toEqual([]);
    expect(await undo(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: true, restoredTo: KEY }] });
    expect(reg.get(KEY)).toBe('hello');
  });

  it('a crash before the export was recorded leaves the key alone', async () => {
    regHost.run = (args) => { if (args[0] === 'export') throw new Error('killed during export'); return fakeReg()(args); };
    const plan = makePlan(ctx, [regItem()]);
    await expect(apply(ctx, plan.id)).rejects.toThrow('killed');
    regHost.run = fakeReg();
    expect(recover(ctx).resolved).toEqual([expect.objectContaining({ type: 'failed', reason: expect.stringContaining('not deleted') })]);
    expect(reg.get(KEY)).toBe('hello');
  });
});

// Opt-in: HYDRA_BANE_TEST_REGISTRY=1. Reads and writes only HKCU\Software\HydraBaneTest\<random>, removed afterwards.
describe.runIf(process.platform === 'win32' && process.env.HYDRA_BANE_TEST_REGISTRY === '1')('real registry (opt-in)', () => {
  it('create, export, delete, import, verify, clean up', async () => {
    const key = `HKCU\\Software\\HydraBaneTest\\${randomBytes(6).toString('hex')}`;
    try {
      expect(regHost.run(['add', key, '/v', 'probe', '/t', 'REG_SZ', '/d', 'hydra-bane', '/f']).status).toBe(0);
      const plan = makePlan(ctx, [regItem([key])]);
      expect(await apply(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: true }] });
      expect(keyExists(key)).toBe(false);
      expect(await undo(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: true, restoredTo: key }] });
      expect(regHost.run(['query', key, '/v', 'probe']).status).toBe(0);
    } finally {
      regHost.run(['delete', 'HKCU\\Software\\HydraBaneTest', '/f']);
    }
    expect(keyExists('HKCU\\Software\\HydraBaneTest')).toBe(false);
  }, 30_000);
});
