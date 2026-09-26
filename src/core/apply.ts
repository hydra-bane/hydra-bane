import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { Ledger } from '../ledger/ledger.ts';
import { decide } from '../guard/decide.ts';
import { defaultQuarantineBase, parentIsRedirected, Quarantine, restore, type RestoreOutcome } from '../quarantine/quarantine.ts';
import { policyFor, type Context } from './context.ts';
import { loadPlan, summarize, type LoadResult } from './plan.ts';
import { measureTree } from './scan.ts';

// PLAN.md §5.2 apply/undo: confirm inside this process (no stored approvals), write-ahead ledger,
// re-measure before acting, never abort the whole plan because one item failed.

const DRIFT = 0.1;

function processRunning(exe: string): boolean {
  const r = spawnSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tasklist.exe'), ['/fi', `imagename eq ${exe}`, '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true, timeout: 15_000 });
  return (r.stdout ?? '').toLowerCase().includes(`"${exe.toLowerCase()}"`);
}

export interface ItemOutcome { id: string; target: string; ok: boolean; code?: string; detail?: string; bytes?: number }
export type ApplyResult =
  | { ok: true; tx: string; outcomes: ItemOutcome[]; freedNowBytes: number; quarantinedBytes: number; firstSuccess: boolean }
  | { ok: false; code: 'PLAN' | 'DECLINED' | 'LEDGER'; detail: string };

const ledgerFor = (ctx: Context) => new Ledger(path.join(ctx.stateDir, 'ledger'));
const prefsFile = (ctx: Context) => path.join(ctx.stateDir, 'prefs.json');

export function readPrefs(ctx: Context): Record<string, unknown> {
  try { return JSON.parse(fs.readFileSync(prefsFile(ctx), 'utf8')) as Record<string, unknown>; } catch { return {}; }
}
export function writePrefs(ctx: Context, patch: Record<string, unknown>) {
  fs.mkdirSync(ctx.stateDir, { recursive: true });
  fs.writeFileSync(prefsFile(ctx), JSON.stringify({ ...readPrefs(ctx), ...patch }, null, 2));
}
export const starAsked = (ctx: Context) => readPrefs(ctx).star_asked === true;

export async function apply(ctx: Context, planId: string): Promise<ApplyResult> {
  const loaded: LoadResult = loadPlan(ctx, planId);
  if (!loaded.ok) return { ok: false, code: 'PLAN', detail: `${loaded.code}: ${loaded.detail}` };
  const plan = loaded.plan;

  const ledger = ledgerFor(ctx);
  const chain = ledger.verify();
  if (!chain.ok) return { ok: false, code: 'LEDGER', detail: `ledger chain broken at ${chain.brokenAt}: ${chain.reason}` };
  if (ledger.records().some((r) => r.tx === plan.id)) return { ok: false, code: 'PLAN', detail: 'plan was already applied' };

  if (!(await ctx.confirmer.confirm(summarize(plan), plan.hash))) return { ok: false, code: 'DECLINED', detail: 'not confirmed' };

  ledger.lock();
  try {
    const outcomes: ItemOutcome[] = [];
    const quarantines = new Map<string, Quarantine>();
    let freedNowBytes = 0, quarantinedBytes = 0;

    for (const item of plan.items) {
      const policy = policyFor(ctx, [item.allowRoot]);
      const running = (item.requiresClosed ?? []).filter((exe) => (ctx.isRunning ?? processRunning)(exe));
      if (running.length) {
        for (const target of item.targets) outcomes.push({ id: item.id, target, ok: false, code: 'APP_RUNNING', detail: `close ${running.join(', ')} and apply again` });
        continue;
      }
      for (const target of item.targets) {
        if (item.targetNames && !item.targetNames.includes(path.basename(target))) {
          outcomes.push({ id: item.id, target, ok: false, code: 'NOT_A_CACHE_FOLDER', detail: `only ${item.targetNames.join(', ')} may be removed` });
          continue;
        }
        const now = measureTree(target);
        const expected = item.targets.length === 1 ? item : undefined;
        if (expected && expected.files > 0 && Math.abs(now.files - expected.files) / expected.files > DRIFT) {
          outcomes.push({ id: item.id, target, ok: false, code: 'DRIFT', detail: `files ${expected.files} -> ${now.files}` });
          continue;
        }
        ledger.append(plan.id, 'planned', { item: item.id, op: item.op, target, bytes: now.bytes });

        if (item.op === 'tool_cmd' && item.command) {
          const r = ctx.run(item.command.file, item.command.args);
          const after = measureTree(target);
          const ok = r.status === 0;
          if (ok) freedNowBytes += Math.max(0, now.bytes - after.bytes);
          ledger.append(plan.id, ok ? 'done' : 'failed', { item: item.id, target, command: item.command, status: r.status, freed: now.bytes - after.bytes });
          outcomes.push({ id: item.id, target, ok, ...(ok ? { bytes: now.bytes - after.bytes } : { code: 'TOOL_FAILED', detail: r.stderr.slice(0, 300) }) });
          continue;
        }

        if (item.op === 'delete_cache' || item.op === 'purge_quarantine') {
          // Permanent deletes: re-downloadable caches with no clean command (cargo), and quarantine past its
          // undo window (purge capability, confined to that quarantine base). fs.rmSync removes links as links
          // and never follows them into their targets.
          const purge = item.op === 'purge_quarantine';
          const d = purge
            ? decide(target, 'purge', { protectedPaths: ctx.protectedPaths, allowRoots: { disk: [], atlas: [], purge: [item.allowRoot] } })
            : decide(target, 'disk', policy);
          const bad = !d.allowed ? `GUARD ${d.code}` : parentIsRedirected(target) ? 'PARENT_IS_LINK' : undefined;
          if (bad) {
            ledger.append(plan.id, 'failed', { item: item.id, target, code: bad });
            outcomes.push({ id: item.id, target, ok: false, code: bad });
            continue;
          }
          try {
            fs.rmSync(target, { recursive: true, force: false, maxRetries: 2 });
            freedNowBytes += now.bytes;
            ledger.append(plan.id, purge ? 'purged' : 'done', { item: item.id, target, op: item.op, freed: now.bytes, ...(purge ? { purgedTx: path.basename(target) } : {}) });
            outcomes.push({ id: item.id, target, ok: true, bytes: now.bytes });
          } catch (e) {
            const code = (e as NodeJS.ErrnoException).code ?? 'IO';
            ledger.append(plan.id, 'failed', { item: item.id, target, code });
            outcomes.push({ id: item.id, target, ok: false, code });
          }
          continue;
        }

        const drive = target.slice(0, 3).toUpperCase();
        let q = quarantines.get(drive);
        if (!q) { q = new Quarantine(ctx.quarantineBaseFor?.(target) ?? defaultQuarantineBase(target, ctx.sid), plan.id); quarantines.set(drive, q); }
        const moved = q.move(target, 'disk', policy);
        if (moved.ok) {
          quarantinedBytes += moved.item.bytes;
          ledger.append(plan.id, 'done', { item: item.id, target, stored: moved.item.stored, quarantineBase: q.base, bytes: moved.item.bytes });
          outcomes.push({ id: item.id, target, ok: true, bytes: moved.item.bytes });
        } else {
          ledger.append(plan.id, 'failed', { item: item.id, target, code: moved.code, detail: moved.detail });
          outcomes.push({ id: item.id, target, ok: false, code: moved.code, detail: moved.detail });
        }
      }
    }
    const firstSuccess = outcomes.some((o) => o.ok) && !starAsked(ctx);
    return { ok: true, tx: plan.id, outcomes, freedNowBytes, quarantinedBytes, firstSuccess };
  } finally {
    ledger.unlock();
  }
}

export type UndoResult = { ok: true; outcomes: RestoreOutcome[] } | { ok: false; code: 'NOT_FOUND' | 'DECLINED' | 'LEDGER'; detail: string };

export async function undo(ctx: Context, tx: string): Promise<UndoResult> {
  const ledger = ledgerFor(ctx);
  const chain = ledger.verify();
  if (!chain.ok) return { ok: false, code: 'LEDGER', detail: `ledger chain broken at ${chain.brokenAt}: ${chain.reason}` };
  const bases = [...new Set(ledger.records().filter((r) => r.tx === tx && r.type === 'done').map((r) => (r.data as { quarantineBase?: string }).quarantineBase).filter((b): b is string => !!b))];
  const purged = ledger.records().find((r) => r.type === 'purged' && (r.data as { purgedTx?: string }).purgedTx === tx);
  if (purged) return { ok: false, code: 'NOT_FOUND', detail: `${tx} was permanently purged on ${purged.ts}; it cannot be undone` };
  if (!bases.length) return { ok: false, code: 'NOT_FOUND', detail: `no quarantined items for ${tx}` };
  if (!(await ctx.confirmer.confirm(`Hydra-bane undo ${tx}: restore quarantined items to their original locations`, tx))) return { ok: false, code: 'DECLINED', detail: 'not confirmed' };

  ledger.lock();
  try {
    const outcomes = bases.flatMap((b) => restore(b, tx, policyFor(ctx, [])));
    for (const o of outcomes) ledger.append(tx, o.ok ? 'restored' : 'failed', o);
    return { ok: true, outcomes };
  } finally {
    ledger.unlock();
  }
}
