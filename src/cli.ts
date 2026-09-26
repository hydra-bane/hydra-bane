#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { apply, starAsked, undo, writePrefs } from './core/apply.ts';
import { defaultProtected, defaultRoots, type Context } from './core/context.ts';
import { loadPlan, makePlan, summarize } from './core/plan.ts';
import { scan, type Category } from './core/scan.ts';
import { Ledger } from './ledger/ledger.ts';
import { human, interactive as analyzeInteractive, listChildren } from './analyze/analyze.ts';
import { currentUserSid } from './quarantine/quarantine.ts';

// PLAN.md §5.2 command contract (v0). JSON envelope on stdout with --json; progress/errors to stderr.
export const VERSION = '0.0.0';
export const API_LEVEL = 0;
const REPO = 'hydra-bane/hydra-bane';

type Exit = 0 | 1 | 2 | 3 | 4;

interface Args { cmd: string; pos: string[]; json: boolean; only?: Category[]; roots: string[]; select?: string[]; allSafe: boolean; yes: boolean; no: boolean }

function parse(argv: string[]): Args {
  const a: Args = { cmd: argv[0] ?? 'help', pos: [], json: false, roots: [], allSafe: false, yes: false, no: false };
  for (let i = 1; i < argv.length; i++) {
    const v = argv[i]!;
    if (v === '--json') a.json = true;
    else if (v === '--all-safe') a.allSafe = true;
    else if (v === '--yes') a.yes = true;
    else if (v === '--no') a.no = true;
    else if (v === '--root') a.roots.push(argv[++i] ?? '');
    else if (v === '--only') a.only = (argv[++i] ?? '').split(',') as Category[];
    else if (v === '--select') a.select = (argv[++i] ?? '').split(',');
    else a.pos.push(v);
  }
  return a;
}

function context(a: Args): Context {
  const stateDir = path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local'), 'hydra-bane');
  return {
    stateDir,
    tempDir: os.tmpdir(),
    home: os.homedir(),
    locate: (command) => {
      // Constant tool queries only (see CACHES in core/scan.ts); .cmd shims need cmd.exe.
      const r = spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', command], { encoding: 'utf8', windowsHide: true, timeout: 20_000 });
      const out = r.status === 0 ? (r.stdout ?? '').trim().split(/\r?\n/).pop() : undefined;
      return out || undefined;
    },
    roots: a.roots.length ? a.roots.map((r) => path.resolve(r)) : defaultRoots(),
    protectedPaths: defaultProtected(),
    sid: currentUserSid(),
    now: () => new Date(),
    confirmer: cliConfirmer(a),
    run: (file, args) => {
      const r = spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', [file, ...args].join(' ')], { encoding: 'utf8', windowsHide: true, timeout: 600_000 });
      return { status: r.status, stderr: r.stderr ?? '' };
    },
  };
}

function emit(a: Args, command: string, ok: boolean, data: unknown, human: string, extra: Record<string, unknown> = {}) {
  if (a.json) process.stdout.write(JSON.stringify({ schema_version: String(API_LEVEL), command, ok, data, warnings: [], ...extra }) + '\n');
  else process.stdout.write(human + '\n');
}

const gb = (b: number) => `${(b / 2 ** 30).toFixed(2)} GB`;

// PLAN.md §6.4 (2026-09-26 CEO decision): the human confirms through the AI agent (the agent shows the plan
// and asks), or at an interactive terminal. `--yes` records that the human already approved.
const interactive = () => !!process.stdin.isTTY && !!process.stdout.isTTY;

function cliConfirmer(a: Args): Context['confirmer'] {
  return {
    async confirm(summary) {
      if (a.yes) return true;
      if (!interactive()) return false;
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const ans = (await rl.question(`${summary}

Apply this plan? [y/N]: `)).trim().toLowerCase();
      rl.close();
      return ans === 'y' || ans === 'yes';
    },
  };
}

async function askStar(ctx: Context, freed: number) {
  if (!process.stdin.isTTY || !process.stdout.isTTY || process.env.HYDRA_BANE_NO_PROMPTS === '1') return;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ans = (await rl.question(`\nHydra-bane just freed ${gb(freed)}. If it helped, a GitHub star helps others find it. [s]tar / [n]o: `)).trim().toLowerCase();
  rl.close();
  if (ans.startsWith('s')) star(true);
  writePrefs(ctx, { star_asked: true });
}

function star(yes: boolean): string {
  if (!yes) return 'ok';
  const auth = spawnSync('gh', ['auth', 'status'], { stdio: 'ignore' });
  if (auth.status !== 0) return `Star it here: https://github.com/${REPO}`;
  const r = spawnSync('gh', ['api', '-X', 'PUT', `/user/starred/${REPO}`], { stdio: 'ignore' });
  return r.status === 0 ? 'Thanks for the star!' : `Star it here: https://github.com/${REPO}`;
}

export async function main(argv: string[]): Promise<Exit> {
  const a = parse(argv);
  switch (a.cmd) {
    case 'version':
      emit(a, 'version', true, { version: VERSION, api: API_LEVEL }, `hydra-bane ${VERSION}\nhttps://github.com/${REPO}`);
      return 0;

    case 'scan': {
      const ctx = context(a);
      const items = scan(ctx, a.only);
      const total = items.reduce((s, i) => s + i.bytes, 0);
      emit(a, 'scan', true, { items, total_bytes: total },
        [`Found ${gb(total)} reclaimable. Nothing was changed.`, ...items.map((i) => `  ${i.id.padEnd(4)} ${gb(i.bytes).padStart(9)}  ${i.risk === 'caution' ? '[caution] ' : ''}${i.title}`),
          items.length ? '\nNext: hydra-bane plan --select <ids>   (or --all-safe)' : ''].join('\n'));
      return 0;
    }

    case 'plan': {
      const ctx = context(a);
      const items = scan(ctx, a.only).filter((i) => (a.allSafe ? i.risk === 'safe' : a.select?.includes(i.id)));
      if (!items.length) { emit(a, 'plan', false, null, 'Nothing selected. Use --select <ids> or --all-safe.', { error: { code: 'EMPTY', message: 'nothing selected' } }); return 1; }
      const plan = makePlan(ctx, items);
      emit(a, 'plan', true, { plan_id: plan.id, hash: plan.hash, items: plan.items.map((i) => i.id), expires_at: plan.expiresAt },
        `Plan ${plan.id} (${plan.hash.slice(0, 8)}), ${items.length} item(s), expires ${plan.expiresAt}.\nNothing was changed. A human applies it with: hydra-bane apply ${plan.id}`);
      return 0;
    }

    case 'apply': {
      const ctx = context(a);
      if (!a.yes && !interactive()) {
        const l = loadPlan(ctx, a.pos[0] ?? '');
        const summary = l.ok ? summarize(l.plan) : '';
        emit(a, 'apply', false, { summary }, `Confirmation required. Show this plan to the user, and after they approve run: hydra-bane apply ${a.pos[0] ?? '<plan-id>'} --yes

${summary}`,
          { error: { code: 'CONFIRMATION_REQUIRED', message: 'ask the user to approve this plan, then re-run with --yes' } });
        return 3;
      }
      const r = await apply(ctx, a.pos[0] ?? '');
      if (!r.ok) {
        emit(a, 'apply', false, null, `Not applied: ${r.code} ${r.detail}`, { error: { code: r.code, message: r.detail } });
        return r.code === 'DECLINED' ? 3 : 1;
      }
      const failed = r.outcomes.filter((o) => !o.ok);
      emit(a, 'apply', true, r,
        [`Receipt ${r.tx}: freed ${gb(r.freedNowBytes)} now, quarantined ${gb(r.quarantinedBytes)} (undo: hydra-bane undo ${r.tx}).`,
          ...failed.map((f) => `  skipped ${f.id} ${f.target}: ${f.code}`)].join('\n'),
        r.firstSuccess ? { hints: { star_prompt: true, freed_bytes: r.freedNowBytes + r.quarantinedBytes } } : {});
      if (r.firstSuccess && !a.json) await askStar(ctx, r.freedNowBytes + r.quarantinedBytes);
      return failed.length ? 4 : 0;
    }

    case 'undo': {
      const ctx = context(a);
      if (!a.yes && !interactive()) {
        emit(a, 'undo', false, null, `Confirmation required. Ask the user, then run: hydra-bane undo ${a.pos[0] ?? '<tx>'} --yes`, { error: { code: 'CONFIRMATION_REQUIRED', message: 'ask the user, then re-run with --yes' } });
        return 3;
      }
      const r = await undo(ctx, a.pos[0] ?? '');
      if (!r.ok) { emit(a, 'undo', false, null, `Not undone: ${r.code} ${r.detail}`, { error: { code: r.code, message: r.detail } }); return r.code === 'DECLINED' ? 3 : 1; }
      const bad = r.outcomes.filter((o) => !o.ok);
      emit(a, 'undo', true, r, [`Restored ${r.outcomes.length - bad.length} item(s).`, ...bad.map((b) => `  not restored ${b.id}: ${'code' in b ? b.code : ''}`)].join('\n'));
      return bad.length ? 4 : 0;
    }

    case 'analyze': {
      const dir = path.resolve(a.pos[0] ?? os.homedir());
      if (a.json || !interactive()) {
        const rows = listChildren(dir).slice(0, 50);
        emit(a, 'analyze', true, { path: dir, rows }, rows.map((r) => `${human(r.bytes).padStart(9)}  ${r.link ? `${r.name} (link, not followed)` : r.name}`).join('\n'));
        return 0;
      }
      await analyzeInteractive(dir);
      return 0;
    }

    case 'ledger': {
      const ctx = context(a);
      const l = new Ledger(path.join(ctx.stateDir, 'ledger'));
      const v = l.verify();
      emit(a, 'ledger', v.ok, { verify: v, records: l.records().slice(-50) }, v.ok ? `Ledger OK: ${v.count} record(s), head ${v.head.slice(0, 12)}` : `LEDGER BROKEN at ${v.brokenAt}: ${v.reason}`);
      return v.ok ? 0 : 1;
    }

    case 'star': {
      const ctx = context(a);
      const msg = star(a.yes);
      writePrefs(ctx, { star_asked: true });
      emit(a, 'star', true, { star_asked: true, already_asked: starAsked(ctx) }, msg);
      return 0;
    }

    default:
      process.stdout.write(['hydra-bane — safe Windows cleanup for humans and AI agents', '',
        '  scan   [--only temp,npm-cache,pnpm-store,pip-cache,uv-cache,cargo-registry,node_modules,target] [--root <dir>]...',
        '                          find reclaimable space (read-only)',
        '  plan   --select <ids> | --all-safe                                      seal a plan (read-only)',
        '  apply  <plan-id> [--yes]   ask the human (via your agent or this terminal), quarantine, write receipts',
        '  undo   <tx> [--yes]        restore a transaction',
        '  analyze [dir]              explore what uses space (read-only, arrow keys)',
        '  ledger                  verify and show receipts',
        '  version', '', 'Add --json for machine-readable output.'].join('\n') + '\n');
      return a.cmd === 'help' ? 0 : 1;
  }
}

if (import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('cli.ts')) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e: Error) => { process.stderr.write(`hydra-bane: ${e.message}\n`); process.exitCode = 1; });
}
