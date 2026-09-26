import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonical } from '../ledger/ledger.ts';
import type { Context } from './context.ts';
import type { ScanItem } from './scan.ts';

// PLAN.md §6.9: immutable, hash-sealed, bound to user + machine, expires in 24h.

export interface Plan {
  schemaVersion: 1;
  id: string;
  createdAt: string;
  expiresAt: string;
  sid: string;
  host: string;
  nonce: string;
  items: ScanItem[];
  hash: string;
}

const PLAN_TTL_MS = 24 * 3_600_000;

export const planHash = (p: Omit<Plan, 'hash'>) => createHash('sha256').update(canonical(p)).digest('hex');
const plansDir = (ctx: Context) => path.join(ctx.stateDir, 'plans');

export function makePlan(ctx: Context, items: ScanItem[]): Plan {
  const now = ctx.now();
  const body: Omit<Plan, 'hash'> = {
    schemaVersion: 1,
    id: `${now.getTime().toString(36)}${randomBytes(4).toString('hex')}`,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + PLAN_TTL_MS).toISOString(),
    sid: ctx.sid,
    host: process.env.COMPUTERNAME ?? '',
    nonce: randomBytes(16).toString('hex'),
    items,
  };
  const plan: Plan = { ...body, hash: planHash(body) };
  fs.mkdirSync(plansDir(ctx), { recursive: true });
  fs.writeFileSync(path.join(plansDir(ctx), `${plan.id}.json`), JSON.stringify(plan, null, 2), { flag: 'wx' });
  return plan;
}

export type LoadResult = { ok: true; plan: Plan } | { ok: false; code: 'NOT_FOUND' | 'TAMPERED' | 'EXPIRED' | 'OTHER_USER'; detail: string };

export function loadPlan(ctx: Context, id: string): LoadResult {
  if (!/^[a-z0-9]+$/.test(id)) return { ok: false, code: 'NOT_FOUND', detail: id };
  const file = path.join(plansDir(ctx), `${id}.json`);
  if (!fs.existsSync(file)) return { ok: false, code: 'NOT_FOUND', detail: id };
  const plan = JSON.parse(fs.readFileSync(file, 'utf8')) as Plan;
  const { hash, ...body } = plan;
  if (planHash(body) !== hash) return { ok: false, code: 'TAMPERED', detail: 'plan contents do not match its hash' };
  if (ctx.now() > new Date(plan.expiresAt)) return { ok: false, code: 'EXPIRED', detail: plan.expiresAt };
  if (plan.sid !== ctx.sid || plan.host !== (process.env.COMPUTERNAME ?? '')) return { ok: false, code: 'OTHER_USER', detail: 'plan was made for another user or machine' };
  return { ok: true, plan };
}

const gb = (b: number) => `${(b / 2 ** 30).toFixed(2)} GB`;

export function summarize(plan: Plan): string {
  const uninstalls = plan.items.filter((i) => i.op === 'uninstall');
  const now = plan.items.filter((i) => i.reversible !== 'move-back' && i.op !== 'uninstall').reduce((s, i) => s + i.bytes, 0);
  const later = plan.items.filter((i) => i.reversible === 'move-back').reduce((s, i) => s + i.bytes, 0);
  const lines = [
    `Hydra-bane plan ${plan.hash.slice(0, 8)}`,
    `Reclaim now: ${gb(now)} (caches and expired quarantine) | Moved to quarantine: ${gb(later)} (undoable for 7 days)${uninstalls.length ? ` | Uninstalls: ${uninstalls.length} program(s), cannot be undone` : ''}`,
    ...plan.items.slice(0, 10).map((i) => `${i.risk === 'caution' ? '[caution] ' : ''}${i.reversible === 'none' && i.category !== 'optimize' ? '[PERMANENT] ' : ''}${i.id} ${i.title} - ${gb(i.bytes)}`),
    ...(plan.items.length > 10 ? [`... and ${plan.items.length - 10} more`] : []),
  ];
  return lines.join('\n');
}
