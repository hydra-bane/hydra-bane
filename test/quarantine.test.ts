import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { GuardPolicy } from '../src/guard/decide.ts';
import { Quarantine, restore } from '../src/quarantine/quarantine.ts';
import { testRoot } from './helpers/crash-ctx.ts';

// All tests run inside a fresh temp folder; nothing outside it is touched.
let root: string, work: string, base: string, policy: GuardPolicy;

beforeEach(() => {
  root = testRoot('hb-q-'); // CI: on the VHDX volume (HYDRA_BANE_TEST_VOLUME)
  work = path.join(root, 'work');
  base = path.join(root, 'qbase');
  fs.mkdirSync(work);
  policy = { protectedPaths: [path.join(root, 'protected')], allowRoots: { disk: [work], atlas: [], purge: [] } };
});
afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
});

const write = (rel: string, data = 'x') => {
  const p = path.join(work, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, data);
  return p;
};

describe.runIf(process.platform === 'win32')('quarantine', () => {
  it('moves a file and a directory, records them, and undo restores both', () => {
    const f = write('cache/a.bin', 'hello');
    write('proj/node_modules/pkg/index.js', 'module.exports=1');
    write('proj/node_modules/pkg/big.js', 'y'.repeat(1000));
    const q = new Quarantine(base, 'tx1');

    const r1 = q.move(f, 'disk', policy);
    const r2 = q.move(path.join(work, 'proj', 'node_modules'), 'disk', policy);
    expect(r1).toMatchObject({ ok: true, item: { kind: 'file', bytes: 5, files: 1 } });
    expect(r2).toMatchObject({ ok: true, item: { kind: 'dir', files: 2, bytes: 1016 } });
    expect(fs.existsSync(f)).toBe(false);
    expect(Quarantine.open(base, 'tx1').items).toHaveLength(2);

    const out = restore(base, 'tx1', policy);
    expect(out.every((o) => o.ok)).toBe(true);
    expect(fs.readFileSync(f, 'utf8')).toBe('hello');
    expect(fs.existsSync(path.join(work, 'proj', 'node_modules', 'pkg', 'big.js'))).toBe(true);
  });

  it('refuses paths the guard denies and never touches them', () => {
    fs.mkdirSync(path.join(root, 'protected'));
    const q = new Quarantine(base, 'tx2');
    expect(q.move(path.join(root, 'protected'), 'disk', policy)).toMatchObject({ ok: false, code: 'GUARD' });
    expect(q.move(root, 'disk', policy)).toMatchObject({ ok: false, code: 'GUARD' });
    expect(q.move('/c/', 'disk', policy)).toMatchObject({ ok: false, code: 'GUARD' });
    expect(fs.existsSync(path.join(root, 'protected'))).toBe(true);
  });

  it('refuses when a parent folder is a junction pointing elsewhere', () => {
    const outside = path.join(root, 'outside');
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'precious.txt'), 'keep');
    fs.symlinkSync(outside, path.join(work, 'jn'), 'junction');
    const q = new Quarantine(base, 'tx3');
    expect(q.move(path.join(work, 'jn', 'precious.txt'), 'disk', policy)).toMatchObject({ ok: false, code: 'PARENT_IS_LINK' });
    expect(fs.existsSync(path.join(outside, 'precious.txt'))).toBe(true);
  });

  it('moves a junction as a link without touching its target', () => {
    const outside = path.join(root, 'outside');
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'precious.txt'), 'keep');
    const link = path.join(work, 'linked');
    fs.symlinkSync(outside, link, 'junction');
    const q = new Quarantine(base, 'tx4');
    expect(q.move(link, 'disk', policy)).toMatchObject({ ok: true, item: { kind: 'link', bytes: 0 } });
    expect(fs.readFileSync(path.join(outside, 'precious.txt'), 'utf8')).toBe('keep');
  });

  it('never overwrites on undo and reports items removed outside Hydra-bane', () => {
    const f = write('a.txt', 'old');
    const g = write('b.txt', 'gone');
    const q = new Quarantine(base, 'tx5');
    q.move(f, 'disk', policy);
    const moved = q.move(g, 'disk', policy);
    fs.writeFileSync(f, 'new'); // user recreated the file
    if (moved.ok) fs.rmSync(moved.item.stored); // e.g. antivirus removed it from quarantine
    const out = restore(base, 'tx5', policy);
    expect(out).toContainEqual(expect.objectContaining({ ok: true, restoredTo: `${f}.restored` }));
    expect(out).toContainEqual(expect.objectContaining({ ok: false, code: 'STORED_MISSING' }));
    expect(fs.readFileSync(f, 'utf8')).toBe('new');
  });

  it('detects a tampered quarantined file', () => {
    const f = write('c.txt', 'orig');
    const q = new Quarantine(base, 'tx6');
    const r = q.move(f, 'disk', policy);
    if (r.ok) fs.writeFileSync(r.item.stored, 'evil');
    expect(restore(base, 'tx6', policy)).toEqual([expect.objectContaining({ ok: false, code: 'HASH_MISMATCH' })]);
  });

  it('hardens the quarantine base: no inherited ACEs, execute denied on files', () => {
    const q = new Quarantine(base, 'tx7');
    const acl = execFileSync('icacls.exe', [base], { encoding: 'utf8' });
    expect(acl).not.toMatch(/\(I\)/); // nothing inherited from the parent
    expect(acl).toMatch(/\(DENY\)/);
    // Deny-execute stops native executables (.exe/.dll). Scripts run by an interpreter (.cmd, .ps1, .js) are
    // only read, so this ACE does not stop them; that limit is documented in PLAN.md §6.6.
    const exe = path.join(q.dir, 'probe.exe');
    fs.copyFileSync(path.join(process.env.SystemRoot ?? 'C:\Windows', 'System32', 'whoami.exe'), exe);
    expect(() => execFileSync(exe, [], { stdio: 'pipe' })).toThrow();
  });
});
