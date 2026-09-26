import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { killPoint, Ledger, type LedgerRecord, type RecordType } from '../ledger/ledger.ts';
import { normalizeWinPath, pathKey } from '../guard/normalize.ts';
import { decide } from '../guard/decide.ts';
import { defaultQuarantineBase, exists, parentIsRedirected, Quarantine, restore, saveManifest, type Manifest, type RestoreOutcome } from '../quarantine/quarantine.ts';
import { policyFor, type Context } from './context.ts';
import { loadPlan, summarize, type LoadResult } from './plan.ts';
import { measureTree } from './scan.ts';
import { runUninstall } from '../atlas/uninstall.ts';
import { loadInstalledBundle } from '../atlas/bundle.ts';

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

  recover(ctx);
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
      if (item.op === 'report_only') {
        outcomes.push({ id: item.id, target: item.targets[0] ?? '', ok: false, code: 'REPORT_ONLY', detail: item.instructions ?? 'Hydra-bane only reports this item' });
        continue;
      }
      // Admin items never run in this process, elevated or not: only the admin-only helper runs them (PLAN.md §6.7).
      // Vendor uninstallers are the exception: Windows itself asks for elevation for their signed executable.
      if (item.needsAdmin && item.op !== 'uninstall') {
        outcomes.push({ id: item.id, target: item.targets[0] ?? '', ok: false, code: 'NEEDS_ADMIN', detail: `run: hydra-bane apply-admin ${plan.id}` });
        continue;
      }
      if (item.op === 'uninstall') {
        const target = item.targets[0] ?? '';
        ledger.append(plan.id, 'planned', { item: item.id, op: item.op, target, bytes: item.bytes });
        const r = runUninstall(item, { bundle: loadInstalledBundle(ctx.stateDir), ...ctx.uninstallDeps });
        ledger.append(plan.id, r.ok ? 'done' : 'failed', { item: item.id, target, op: item.op, exitCode: r.code, detail: r.detail, rebootRequired: r.rebootRequired, stillInstalled: r.stillInstalled });
        const freed = r.ok && !r.stillInstalled ? item.bytes : 0;
        freedNowBytes += freed;
        outcomes.push(r.ok ? { id: item.id, target, ok: true, bytes: freed, detail: r.detail } : { id: item.id, target, ok: false, code: 'UNINSTALL_FAILED', detail: r.detail });
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
        killPoint('after-planned');

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
            killPoint('after-delete-before-done');
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
          killPoint('after-move-before-done');
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
  recover(ctx);
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

// ---- Crash recovery (PLAN.md §6.6 "resume from the ledger", §6.8 write-ahead) ----
// A `planned` record with no later done/failed/purged for the same tx+item+target means the process died mid-item.
// Recovery never moves user data: it looks at reality and appends the record apply would have written, with a
// `recovered` field, so every existing reader (undo, scan, describe) sees it unchanged. Safe to run at any time.

export interface Recovery {
  ok: boolean;
  detail?: string;
  /** Torn last ledger line that was moved to ledger.jsonl.torn, if there was one. */
  torn?: string;
  resolved: { tx: string; item: string; target: string; type: RecordType; reason: string }[];
}

export function recover(ctx: Context): Recovery {
  const ledger = ledgerFor(ctx);
  try { ledger.lock(); } catch (e) { return { ok: false, detail: (e as Error).message, resolved: [] }; }
  try {
    const torn = ledger.repairTornTail();
    const chain = ledger.verify();
    if (!chain.ok) return { ok: false, detail: `ledger chain broken at ${chain.brokenAt}: ${chain.reason}`, resolved: [], ...(torn ? { torn } : {}) };
    const key = (r: LedgerRecord) => { const d = r.data as { item?: string; target?: string }; return `${r.tx}\0${d.item}\0${d.target}`; };
    const open = new Map<string, LedgerRecord>();
    for (const r of ledger.records()) { if (r.type === 'planned') open.set(key(r), r); else open.delete(key(r)); }
    const resolved: Recovery['resolved'] = [];
    for (const p of open.values()) {
      const { item, op, target } = p.data as { item: string; op: string; target: string };
      const r = resolveInterrupted(ctx, p.tx, op, target);
      ledger.append(p.tx, r.type, { item, target, op, ...r.data, recovered: { plannedSeq: p.seq, reason: r.reason } });
      resolved.push({ tx: p.tx, item, target, type: r.type, reason: r.reason });
    }
    return { ok: true, resolved, ...(torn ? { torn } : {}) };
  } finally {
    ledger.unlock();
  }
}

function resolveInterrupted(ctx: Context, tx: string, op: string, target: string): { type: RecordType; data: Record<string, unknown>; reason: string } {
  const present = exists(target);
  if (op === 'quarantine') {
    const base = ctx.quarantineBaseFor?.(target) ?? defaultQuarantineBase(target, ctx.sid);
    let m: Manifest | undefined;
    try { m = Quarantine.open(base, tx); } catch { /* died before the quarantine folder existed */ }
    const n = normalizeWinPath(target);
    const want = pathKey(n.ok ? n.path : target);
    const it = m?.items.find((i) => pathKey(i.source) === want);
    if (m && it) {
      // The manifest intent is written before the rename, so the stored copy tells whether the move happened.
      if (!it.pending || exists(it.stored)) {
        if (it.pending) { delete it.pending; saveManifest(base, tx, m); }
        return { type: 'done', data: { stored: it.stored, quarantineBase: base, bytes: it.bytes }, reason: 'moved to quarantine before the interruption' };
      }
      m.items = m.items.filter((x) => x !== it);
      saveManifest(base, tx, m);
    }
    return { type: 'failed', data: { code: 'INTERRUPTED' }, reason: present ? 'not moved; still in its original place' : 'not moved, and no longer at its original place (changed outside Hydra-bane)' };
  }
  if (op === 'delete_cache') {
    return present
      ? { type: 'failed', data: { code: 'INTERRUPTED' }, reason: 'cache deletion was interrupted; it may be partly deleted (re-downloadable)' }
      : { type: 'done', data: {}, reason: 'cache was deleted before the interruption' };
  }
  if (op === 'purge_quarantine') {
    return present
      ? { type: 'failed', data: { code: 'INTERRUPTED' }, reason: 'purge was interrupted; part of this quarantine may already be gone' }
      : { type: 'purged', data: { purgedTx: path.basename(target) }, reason: 'purged before the interruption' };
  }
  return { type: 'failed', data: { code: 'INTERRUPTED' }, reason: `${op} was interrupted; its outcome is unknown, run scan again` };
}
