import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { apply } from '../src/core/apply.ts';
import type { Context } from '../src/core/context.ts';
import { makePlan } from '../src/core/plan.ts';
import type { ScanItem } from '../src/core/scan.ts';

// v0.2 ops in apply(): report-only items change nothing, admin items never run in the user process,
// and a vendor uninstaller runs only when the signed Atlas bundle still vouches for it.
let root: string, ctx: Context, spawned: string[];

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-v2-')));
  spawned = [];
  ctx = {
    stateDir: path.join(root, 'state'), tempDir: path.join(root, 'temp'), home: path.join(root, 'home'),
    locate: () => undefined, roots: [], protectedPaths: [path.join(root, 'protected')], sid: 'S-1-5-21-test',
    now: () => new Date(), confirmer: { confirm: async () => true }, run: () => ({ status: 0, stderr: '' }),
    quarantineBaseFor: () => path.join(root, 'quarantine'),
    uninstallDeps: { spawn: (f) => { spawned.push(f); return { status: 0 }; }, listPrograms: () => [] },
  };
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

const item = (x: Partial<ScanItem>): ScanItem => ({ id: 'X', category: 'temp', title: 't', op: 'delete_cache', targets: [], allowRoot: root, bytes: 1, files: 1, risk: 'caution', reversible: 'none', ...x });

describe('apply v0.2 ops', () => {
  it('never runs admin items in-process and never touches report-only items', async () => {
    const sysTemp = path.join(root, 'systemp');
    fs.mkdirSync(sysTemp);
    fs.writeFileSync(path.join(sysTemp, 'keep.tmp'), 'x');
    const plan = makePlan(ctx, [
      item({ id: 'SYS-TEMP', category: 'system-temp', targets: [sysTemp], allowRoot: sysTemp, needsAdmin: true }),
      item({ id: 'WINDOWS-OLD', category: 'windows-old', op: 'report_only', targets: [path.join(root, 'Windows.old')], instructions: 'Use Settings' }),
    ]);
    const r = await apply(ctx, plan.id);
    if (!r.ok) throw new Error(r.detail);
    expect(r.outcomes.map((o) => o.code)).toEqual(['NEEDS_ADMIN', 'REPORT_ONLY']);
    expect(r.outcomes[0]!.detail).toBe(`run: hydra-bane apply-admin ${plan.id}`);
    expect(fs.existsSync(path.join(sysTemp, 'keep.tmp'))).toBe(true);
  });

  it('refuses a vendor uninstaller when no signed Atlas bundle is installed', async () => {
    const plan = makePlan(ctx, [item({
      id: 'ATLAS-abc123', category: 'atlas', op: 'uninstall', reversible: 'reinstall-only', targets: ['HKLM\\x'], allowRoot: 'HKLM\\x', needsAdmin: true,
      uninstall: { entryId: 'kr.vendor.product', trust: 'atlas', kind: 'exe', file: 'C:\\Program Files\\V\\uninst.exe', args: [], signers: ['AB'.repeat(20)] },
    })]);
    const r = await apply(ctx, plan.id);
    if (!r.ok) throw new Error(r.detail);
    expect(r.outcomes[0]).toMatchObject({ ok: false, code: 'UNINSTALL_FAILED' });
    expect(r.outcomes[0]!.detail).toMatch(/not in the installed bundle/);
    expect(spawned).toEqual([]);
  });
});
