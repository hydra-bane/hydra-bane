import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { apply, recover, undo } from '../src/core/apply.ts';
import type { Context } from '../src/core/context.ts';
import { makePlan } from '../src/core/plan.ts';
import type { ScanItem } from '../src/core/scan.ts';
import { Ledger } from '../src/ledger/ledger.ts';
import { Quarantine, type Manifest } from '../src/quarantine/quarantine.ts';
import { crashCtx, testRoot } from './helpers/crash-ctx.ts';

// PLAN.md §6.6/§6.8/§6.11: kill a real child process at each named point, then recover in-process and check that
// nothing was lost or moved twice, undo brings everything back, and the ledger chain still verifies.
// Runs on HYDRA_BANE_TEST_VOLUME (CI VHDX) when set, else in the temp folder.

const CHILD = fileURLToPath(new URL('./helpers/crash-child.ts', import.meta.url));
const APPLY_POINTS = ['after-planned', 'quarantine-after-intent', 'quarantine-after-rename', 'after-move-before-done', 'after-delete-before-done', 'mid-ledger-append'];

let root: string, ctx: Context;
beforeEach(() => { root = testRoot('hb-c-'); ctx = crashCtx(root); });
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

interface Original { path: string; sig: string }
const exists = (p: string) => { try { fs.lstatSync(p); return true; } catch { return false; } };
const sig = (p: string) => (fs.statSync(p).isDirectory() ? `dir:${fs.readFileSync(path.join(p, 'a.txt'), 'utf8')}` : fs.readFileSync(p, 'utf8'));

/** n quarantine items (alternating file/folder) plus one re-downloadable cache folder deleted directly. */
function fixture(n: number): { items: ScanItem[]; originals: Original[] } {
  const work = path.join(root, 'work');
  const items: ScanItem[] = [];
  const originals: Original[] = [];
  for (let i = 0; i < n; i++) {
    const p = path.join(work, `item${i}${i % 2 ? '' : '.txt'}`);
    fs.mkdirSync(i % 2 ? p : work, { recursive: true });
    if (i % 2) fs.writeFileSync(path.join(p, 'a.txt'), `folder ${i}`); else fs.writeFileSync(p, `file ${i}`);
    originals.push({ path: p, sig: sig(p) });
    items.push({ id: `I${i}`, category: 'crash-dumps', title: `item ${i}`, op: 'quarantine', targets: [p], allowRoot: work, bytes: 7, files: 1, risk: 'safe', reversible: 'move-back' });
  }
  const cache = path.join(work, 'cache');
  fs.mkdirSync(cache);
  fs.writeFileSync(path.join(cache, 'blob'), 'c'.repeat(100));
  items.push({ id: 'CACHE', category: 'shader-cache', title: 'cache', op: 'delete_cache', targets: [cache], allowRoot: work, bytes: 100, files: 1, risk: 'safe', reversible: 'redownload' });
  return { items, originals };
}

function child(mode: 'apply' | 'undo', id: string, killAt: string) {
  const r = spawnSync(process.execPath, [CHILD, mode, root, id], { env: { ...process.env, HYDRA_BANE_TEST_KILL_AT: killAt }, encoding: 'utf8', timeout: 30_000 });
  if (r.status !== 137 && r.status !== 0) throw new Error(`child exited ${r.status}: ${r.stderr}`);
  return r.status;
}

const manifest = (tx: string): Manifest | undefined => { try { return Quarantine.open(path.join(root, 'quarantine'), tx); } catch { return undefined; } };
const ledger = () => new Ledger(path.join(ctx.stateDir, 'ledger'));

/** Every original is in place or in quarantine exactly once; nothing is half-recorded. */
function assertConsistent(tx: string, originals: Original[]) {
  const m = manifest(tx);
  expect(m?.items.some((i) => i.pending) ?? false).toBe(false);
  for (const o of originals) {
    const inQ = (m?.items ?? []).filter((i) => i.source.toLowerCase() === o.path.toLowerCase() && exists(i.stored)).length;
    expect(Number(exists(o.path)) + inQ, o.path).toBe(1);
  }
  if (m) {
    const stored = fs.readdirSync(path.join(root, 'quarantine', tx)).filter((f) => f !== 'manifest.json');
    expect(stored.length, 'no orphan in quarantine').toBe(m.items.length);
  }
  const l = ledger();
  expect(l.verify().ok).toBe(true);
  const recs = l.records();
  for (const p of recs.filter((r) => r.type === 'planned')) {
    const d = p.data as { item: string; target: string };
    expect(recs.some((r) => r.seq > p.seq && r.type !== 'planned' && (r.data as { item?: string }).item === d.item && (r.data as { target?: string }).target === d.target), `planned ${d.item} resolved`).toBe(true);
  }
}

async function assertUndoRestoresAll(tx: string, originals: Original[]) {
  await undo(ctx, tx);
  for (const o of originals) {
    expect(exists(o.path), o.path).toBe(true);
    expect(sig(o.path)).toBe(o.sig);
    expect(exists(`${o.path}.restored`)).toBe(false);
  }
  expect(ledger().verify().ok).toBe(true);
}

async function crashApplyRecoverUndo(n: number, killAt: string) {
  const { items, originals } = fixture(n);
  const plan = makePlan(ctx, items);
  const status = child('apply', plan.id, killAt);
  const rec = recover(ctx);
  expect(rec.ok, rec.detail).toBe(true);
  expect(recover(ctx).resolved).toEqual([]); // idempotent
  assertConsistent(plan.id, originals);
  // A plan with committed records is never re-run; one whose only record was torn never started, so it may run.
  const started = ledger().records().some((r) => r.tx === plan.id);
  expect(await apply(ctx, plan.id)).toMatchObject(started ? { ok: false, detail: 'plan was already applied' } : { ok: true });
  await assertUndoRestoresAll(plan.id, originals);
  return { status, rec };
}

describe.runIf(process.platform === 'win32')('crash injection and recovery', () => {
  it.each(APPLY_POINTS)('apply killed at %s: recover, nothing lost, undo restores all', async (point) => {
    const { status, rec } = await crashApplyRecoverUndo(3, point);
    expect(status).toBe(137);
    expect(rec.resolved.length).toBeLessThanOrEqual(1); // one item can be in flight at a time
    if (point === 'mid-ledger-append') {
      expect(rec.torn).toBeTruthy();
      expect(fs.existsSync(path.join(ctx.stateDir, 'ledger', 'ledger.jsonl.torn'))).toBe(true);
    }
    if (point === 'quarantine-after-rename' || point === 'after-move-before-done') {
      expect(rec.resolved).toEqual([expect.objectContaining({ type: 'done' })]);
    }
    if (point === 'quarantine-after-intent') {
      expect(rec.resolved).toEqual([expect.objectContaining({ type: 'failed' })]);
    }
  }, 30_000);

  it('undo killed midway can simply be run again: everything restored once, nothing overwritten', async () => {
    const { items, originals } = fixture(4);
    const plan = makePlan(ctx, items);
    expect(await apply(ctx, plan.id)).toMatchObject({ ok: true });
    expect(child('undo', plan.id, 'undo-after-restore-item:2')).toBe(137);
    await assertUndoRestoresAll(plan.id, originals);
  }, 30_000);

  it('undo killed in the middle of writing its ledger record recovers the torn line', async () => {
    const { items, originals } = fixture(2);
    const plan = makePlan(ctx, items);
    await apply(ctx, plan.id);
    const before = ledger().verify();
    expect(child('undo', plan.id, 'mid-ledger-append')).toBe(137);
    expect(ledger().verify()).toEqual(before); // readers ignore the torn tail
    await assertUndoRestoresAll(plan.id, originals);
  }, 30_000);

  it('a complete but forged last line is a broken chain, not a torn tail', () => {
    const l = ledger();
    l.lock(); l.append('t', 'planned', {}); l.unlock();
    fs.appendFileSync(l.file, '{"seq":2,"forged":true}\n');
    expect(recover(ctx)).toMatchObject({ ok: false, detail: expect.stringContaining('chain broken') });
  });

  it('property: any kill point, any hit, any item count keeps every file exactly once and undo complete', async () => {
    await fc.assert(fc.asyncProperty(fc.integer({ min: 1, max: 4 }), fc.constantFrom(...APPLY_POINTS), fc.integer({ min: 1, max: 5 }), async (n, point, nth) => {
      fs.rmSync(root, { recursive: true, force: true });
      root = testRoot('hb-c-');
      ctx = crashCtx(root);
      await crashApplyRecoverUndo(n, `${point}:${nth}`);
    }), { numRuns: 25 });
  }, 60_000);
});
