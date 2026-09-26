import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { apply, undo, writePrefs } from '../src/core/apply.ts';
import type { Context } from '../src/core/context.ts';
import { makePlan } from '../src/core/plan.ts';
import { scan, type ScanItem } from '../src/core/scan.ts';
import { Ledger } from '../src/ledger/ledger.ts';

// End-to-end scan -> plan -> apply -> undo, entirely inside a temp folder with a fake confirmer.
let root: string, repo: string, ctx: Context, confirmed: string[];
const OLD = (days: number) => new Date(Date.now() - days * 86_400_000);

const setOld = (p: string, days: number) => fs.utimesSync(p, OLD(days), OLD(days));
const git = (...args: string[]) => execFileSync('git', args, { cwd: repo, stdio: 'ignore' });

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-f-')));
  repo = path.join(root, 'work', 'app');
  fs.mkdirSync(path.join(repo, 'node_modules', 'pkg'), { recursive: true });
  fs.writeFileSync(path.join(repo, 'node_modules', 'pkg', 'index.js'), 'module.exports = 1;'.repeat(50));
  fs.writeFileSync(path.join(repo, 'package.json'), '{}');
  fs.writeFileSync(path.join(repo, 'package-lock.json'), '{}');
  fs.writeFileSync(path.join(repo, '.gitignore'), 'node_modules/\n');
  git('init', '-q');
  git('-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '.');
  for (const p of ['node_modules', 'package.json', 'package-lock.json']) setOld(path.join(repo, p), 40);

  const temp = path.join(root, 'temp');
  fs.mkdirSync(temp);
  fs.writeFileSync(path.join(temp, 'old.tmp'), 'o'.repeat(100));
  fs.writeFileSync(path.join(temp, 'new.tmp'), 'n');
  setOld(path.join(temp, 'old.tmp'), 3);

  confirmed = [];
  ctx = {
    stateDir: path.join(root, 'state'),
    tempDir: temp,
    home: path.join(root, 'home'),
    locate: () => undefined,
    roots: [path.join(root, 'work')],
    protectedPaths: [path.join(root, 'protected')],
    sid: 'S-1-5-21-test',
    now: () => new Date(),
    confirmer: { confirm: async (summary) => { confirmed.push(summary); return true; } },
    run: () => ({ status: 0, stderr: '' }),
    quarantineBaseFor: () => path.join(root, 'quarantine'),
  };
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe.runIf(process.platform === 'win32')('scan -> plan -> apply -> undo', () => {
  it('finds only eligible items', () => {
    const items = scan(ctx, ['temp', 'node_modules']);
    expect(items.map((i) => [i.id, i.category])).toEqual([['T1', 'temp'], ['P1', 'node_modules']]);
    expect(items[0]!.targets).toEqual([path.join(ctx.tempDir, 'old.tmp')]);
  });

  it('skips node_modules that is recent or tracked by git', () => {
    setOld(path.join(repo, 'node_modules'), 1);
    expect(scan(ctx, ['node_modules'])).toEqual([]);
    setOld(path.join(repo, 'node_modules'), 40);
    git('-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-f', 'node_modules/pkg/index.js');
    setOld(path.join(repo, 'node_modules'), 40);
    expect(scan(ctx, ['node_modules'])).toEqual([]);
  });

  it('applies with confirmation, writes a valid ledger, and undo restores', async () => {
    const plan = makePlan(ctx, scan(ctx, ['temp', 'node_modules']));
    const r = await apply(ctx, plan.id);
    expect(r).toMatchObject({ ok: true, firstSuccess: true });
    expect(confirmed[0]).toContain(plan.hash.slice(0, 8));
    expect(fs.existsSync(path.join(repo, 'node_modules'))).toBe(false);
    expect(fs.existsSync(path.join(ctx.tempDir, 'old.tmp'))).toBe(false);
    expect(fs.existsSync(path.join(ctx.tempDir, 'new.tmp'))).toBe(true);

    const ledger = new Ledger(path.join(ctx.stateDir, 'ledger'));
    expect(ledger.verify()).toMatchObject({ ok: true, count: 4 });
    expect(ledger.records().map((x) => x.type)).toEqual(['planned', 'done', 'planned', 'done']);

    expect(await apply(ctx, plan.id)).toMatchObject({ ok: false, code: 'PLAN', detail: 'plan was already applied' });

    const u = await undo(ctx, plan.id);
    expect(u).toMatchObject({ ok: true });
    expect(fs.existsSync(path.join(repo, 'node_modules', 'pkg', 'index.js'))).toBe(true);
    expect(fs.existsSync(path.join(ctx.tempDir, 'old.tmp'))).toBe(true);
    expect(ledger.verify()).toMatchObject({ ok: true, count: 6 });
  });

  it('asks for a star only after the first success', async () => {
    writePrefs(ctx, { star_asked: true });
    const r = await apply(ctx, makePlan(ctx, scan(ctx, ['temp'])).id);
    expect(r).toMatchObject({ ok: true, firstSuccess: false });
  });

  it('refuses tampered, expired, foreign and declined plans without touching anything', async () => {
    const plan = makePlan(ctx, scan(ctx, ['temp', 'node_modules']));
    const file = path.join(ctx.stateDir, 'plans', `${plan.id}.json`);
    const original = fs.readFileSync(file, 'utf8');

    fs.writeFileSync(file, original.replace(path.join(ctx.tempDir, 'old.tmp').replace(/\\/g, '\\\\'), 'C:\\\\Windows'));
    expect(await apply(ctx, plan.id)).toMatchObject({ ok: false, code: 'PLAN', detail: expect.stringContaining('TAMPERED') });
    fs.writeFileSync(file, original);

    expect(await apply({ ...ctx, now: () => new Date(Date.now() + 25 * 3_600_000) }, plan.id)).toMatchObject({ detail: expect.stringContaining('EXPIRED') });
    expect(await apply({ ...ctx, sid: 'S-1-5-21-other' }, plan.id)).toMatchObject({ detail: expect.stringContaining('OTHER_USER') });
    expect(await apply({ ...ctx, confirmer: { confirm: async () => false } }, plan.id)).toMatchObject({ ok: false, code: 'DECLINED' });

    expect(fs.existsSync(path.join(repo, 'node_modules'))).toBe(true);
    expect(fs.existsSync(path.join(ctx.tempDir, 'old.tmp'))).toBe(true);
    expect(await apply(ctx, '..\\..\\evil')).toMatchObject({ ok: false, detail: expect.stringContaining('NOT_FOUND') });
  });

  it('runs tool commands through the injected runner and counts freed bytes', async () => {
    const cache = path.join(root, 'cache');
    fs.mkdirSync(cache);
    fs.writeFileSync(path.join(cache, 'blob'), 'c'.repeat(4096));
    const item: ScanItem = { id: 'N1', category: 'npm-cache', title: 'npm cache', op: 'tool_cmd', targets: [cache], allowRoot: cache, command: { file: 'npm', args: ['cache', 'clean', '--force'] }, bytes: 4096, files: 1, risk: 'safe', reversible: 'redownload' };
    const ran: string[] = [];
    const r = await apply({ ...ctx, run: (f, args) => { ran.push([f, ...args].join(' ')); fs.rmSync(path.join(cache, 'blob')); return { status: 0, stderr: '' }; } }, makePlan(ctx, [item]).id);
    expect(ran).toEqual(['npm cache clean --force']);
    expect(r).toMatchObject({ ok: true, freedNowBytes: 4096 });
  });
  it('locates tool caches through the tool and cleans them with the official command', () => {
    const pip = path.join(root, 'pipcache');
    fs.mkdirSync(pip);
    fs.writeFileSync(path.join(pip, 'wheel'), 'w'.repeat(100));
    const items = scan({ ...ctx, locate: (cmd) => (cmd === 'pip cache dir' ? pip : undefined) }, ['pip-cache', 'npm-cache']);
    expect(items).toEqual([expect.objectContaining({ id: 'C1', category: 'pip-cache', op: 'tool_cmd', targets: [pip], allowRoot: pip, command: { file: 'pip', args: ['cache', 'purge'] } })]);
  });

  it('deletes cargo registry folders directly, never ~/.cargo/bin, and never follows a junction inside', async () => {
    const cargo = path.join(ctx.home, '.cargo');
    const cache = path.join(cargo, 'registry', 'cache');
    fs.mkdirSync(path.join(cache, 'index.crates.io'), { recursive: true });
    fs.writeFileSync(path.join(cache, 'index.crates.io', 'serde.crate'), 's'.repeat(500));
    fs.mkdirSync(path.join(cargo, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(cargo, 'bin', 'cargo.exe'), 'bin');
    const outside = path.join(root, 'outside');
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'precious.txt'), 'keep');
    fs.symlinkSync(outside, path.join(cache, 'sneaky'), 'junction');

    const items = scan(ctx, ['cargo-registry']);
    expect(items.map((i) => i.targets[0])).toEqual([cache]);
    const r = await apply(ctx, makePlan(ctx, items).id);
    expect(r).toMatchObject({ ok: true, freedNowBytes: 500 });
    expect(fs.existsSync(cache)).toBe(false);
    expect(fs.readFileSync(path.join(outside, 'precious.txt'), 'utf8')).toBe('keep');
    expect(fs.existsSync(path.join(cargo, 'bin', 'cargo.exe'))).toBe(true);
  });
});
