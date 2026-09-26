#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { apply, readPrefs, recover, starAsked, undo, writePrefs } from './core/apply.ts';
import { atlasStatus, updateBundle } from './atlas/bundle.ts';
import { isElevated } from './core/admin.ts';
import { elevatedApplyCommand, installHelper, launchElevated, parseAdminApplyArgs, readAdminResult, runAdminApply } from './admin/helper.ts';
import { buildProtectedPaths } from './guard/protected.ts';
import { listPrograms } from './atlas/programs.ts';
import { buildReport, countryCode, submit } from './atlas/report.ts';
import { defaultProtected, defaultRoots, type Context } from './core/context.ts';
import { loadPlan, makePlan, summarize } from './core/plan.ts';
import { scan, type Category } from './core/scan.ts';
import { explain } from './core/explain.ts';
import { Ledger } from './ledger/ledger.ts';
import { human, interactive as analyzeInteractive, listChildren } from './analyze/analyze.ts';
import { currentUserSid } from './quarantine/quarantine.ts';

// PLAN.md §5.2 command contract (v0). JSON envelope on stdout with --json; progress/errors to stderr.
// package.json sits one level above both src/cli.ts and dist/cli.js.
export const VERSION: string = (JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;
export const API_LEVEL = 0;
const REPO = 'hydra-bane/hydra-bane';

type Exit = 0 | 1 | 2 | 3 | 4;

interface Args { cmd: string; pos: string[]; json: boolean; only?: Category[]; roots: string[]; select?: string[]; allSafe: boolean; yes: boolean; no: boolean; submit: boolean; note?: string }

function parse(argv: string[]): Args {
  const a: Args = { cmd: argv[0] ?? 'help', pos: [], json: false, roots: [], allSafe: false, yes: false, no: false, submit: false };
  for (let i = 1; i < argv.length; i++) {
    const v = argv[i]!;
    if (v === '--json') a.json = true;
    else if (v === '--all-safe') a.allSafe = true;
    else if (v === '--yes') a.yes = true;
    else if (v === '--no') a.no = true;
    else if (v === '--submit') a.submit = true;
    else if (v === '--note') a.note = argv[++i] ?? '';
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
      const adminBytes = items.filter((i) => i.needsAdmin && i.op !== 'uninstall' && i.op !== 'report_only').reduce((s, i) => s + i.bytes, 0);
      emit(a, 'scan', true, { items, total_bytes: total },
        [`Found ${gb(total)} reclaimable${adminBytes ? ` (${gb(adminBytes)} of it needs apply-admin)` : ''}. Nothing was changed.`, ...items.map((i) => `  ${i.id.padEnd(Math.max(18, ...items.map((x) => x.id.length)))} ${gb(i.bytes).padStart(9)}  ${i.risk !== 'safe' ? `[${i.risk}] ` : ''}${i.op === 'uninstall' ? '[vendor uninstaller] ' : i.needsAdmin ? '[admin] ' : ''}${i.op === 'report_only' ? '[report only] ' : ''}${i.title}`),
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

    case 'explain': {
      const ctx = context(a);
      const item = scan(ctx, a.only).find((i) => i.id === a.pos[0]);
      if (!item) { emit(a, 'explain', false, null, `No item ${a.pos[0] ?? ''} in the current scan.`, { error: { code: 'NOT_FOUND', message: 'run scan to see current ids' } }); return 1; }
      const e = explain(item);
      emit(a, 'explain', true, e, [`${e.id}: ${e.title}`, `What: ${e.what}`, `Why it is safe: ${e.why_safe}`, `What happens: ${e.what_happens}`, `How: ${e.how}`, `Size: ${(e.bytes / 2 ** 30).toFixed(2)} GB`, ...e.targets.map((t) => `  ${t}`)].join('\n'));
      return 0;
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

    case 'programs': {
      const progs = listPrograms();
      emit(a, 'programs', true, { programs: progs },
        [`${progs.length} installed program(s). Nothing was changed.`, ...progs.map((p) => `  ${p.id}  ${p.name}${p.version ? ` ${p.version}` : ''}${p.publisher ? `  [${p.publisher}]` : ''}`)].join('\n'));
      return 0;
    }

    case 'report': {
      // PLAN.md §7.7: preview by default; sending needs --submit plus the user's approval.
      const ctx = context(a);
      const id = a.pos[0] ?? '';
      const prog = listPrograms().find((p) => p.id === id);
      if (!prog) { emit(a, 'report', false, null, `No installed program ${id}. Run: hydra-bane programs`, { error: { code: 'NOT_FOUND', message: 'run programs to see current ids' } }); return 1; }
      const reported = (readPrefs(ctx).reported ?? {}) as Record<string, { status: string; url?: string }>;
      const remember = (status: string, url?: string) => writePrefs(ctx, { reported: { ...reported, [id]: { status, ...(url ? { url } : {}) } } });
      if (a.no) { remember('declined'); emit(a, 'report', true, { id, status: 'declined' }, 'OK, this program will not be suggested for a report again.'); return 0; }

      const report = buildReport(prog, a.note, { version: VERSION, country: countryCode() });
      fs.mkdirSync(path.join(ctx.stateDir, 'reports'), { recursive: true });
      fs.writeFileSync(path.join(ctx.stateDir, 'reports', `${id}.json`), JSON.stringify(report, null, 2));
      const shown = JSON.stringify(report, null, 2);
      if (!a.submit) {
        emit(a, 'report', true, { id, report, previous: reported[id] ?? null },
          `This is everything that would be sent to github.com/hydra-bane/atlas (public). Nothing was sent.\n\n${shown}\n\nSend it with: hydra-bane report ${id} --submit`);
        return 0;
      }
      if (!a.yes) {
        let ok = false;
        if (interactive()) {
          const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
          ok = /^y(es)?$/i.test((await rl.question(`${shown}\n\nPost this as a public issue on github.com/hydra-bane/atlas? [y/N]: `)).trim());
          rl.close();
        }
        if (!ok) {
          emit(a, 'report', false, { id, report }, `Confirmation required. Show this report to the user, and after they approve run: hydra-bane report ${id} --submit --yes\n\n${shown}`,
            { error: { code: 'CONFIRMATION_REQUIRED', message: 'show the report to the user, then re-run with --submit --yes' } });
          return 3;
        }
      }
      const sent = submit(report);
      remember(sent.via === 'gh' ? 'submitted' : 'link', sent.url);
      emit(a, 'report', true, { id, via: sent.via, url: sent.url },
        sent.via === 'gh' ? `Reported: ${sent.url}\nThanks! Maintainers review it before it reaches anyone's PC.` : `Open this link to post the report (a GitHub account is needed):\n${sent.url}`);
      return 0;
    }

    case 'mcp': {
      const { serve } = await import('./mcp/server.ts');
      await serve(process.stdin, process.stdout);
      return 0;
    }

    case 'recover': {
      const r = recover(context(a));
      emit(a, 'recover', true, r, JSON.stringify(r, null, 2));
      return 0;
    }

    case 'atlas': {
      const ctx = context(a);
      if (a.pos[0] === 'update') {
        const r = await updateBundle(ctx.stateDir);
        if (!r.ok) { emit(a, 'atlas', false, null, `Atlas not updated: ${r.error}`, { error: { code: 'ATLAS_UPDATE', message: r.error } }); return 1; }
        emit(a, 'atlas', true, { bundle_seq: r.bundle.bundle_seq, entries: r.bundle.entries.length, dropped: r.dropped },
          `Atlas bundle ${r.bundle.bundle_seq} installed: ${r.bundle.entries.length} entries (signature verified).${r.dropped.length ? ` Skipped invalid: ${r.dropped.join(', ')}` : ''}\nNext: hydra-bane scan --only atlas`);
        return 0;
      }
      const s = atlasStatus(ctx.stateDir);
      emit(a, 'atlas', true, s, s.installed ? `Atlas bundle ${s.bundle_seq} (${s.created}), ${s.entries} entries.` : 'atlas: not installed. Run: hydra-bane atlas update');
      return 0;
    }

    case 'apply-admin': {
      // PLAN.md §6.7: the admin items of a plan run only in the admin-only helper, after UAC. The plan hash is on
      // the elevated command line so the UAC details show it; the helper re-checks everything itself.
      const ctx = context(a);
      const l = loadPlan(ctx, a.pos[0] ?? '');
      if (!l.ok) { emit(a, 'apply-admin', false, null, `Not applied: ${l.code} ${l.detail}`, { error: { code: 'PLAN', message: `${l.code}: ${l.detail}` } }); return 1; }
      const adminItems = l.plan.items.filter((i) => i.needsAdmin && i.op !== 'report_only' && i.op !== 'uninstall');
      if (!adminItems.length) { emit(a, 'apply-admin', false, null, 'This plan has no administrator items. Use: hydra-bane apply ' + l.plan.id, { error: { code: 'EMPTY', message: 'no admin items' } }); return 1; }
      if (!(await ctx.confirmer.confirm(`${summarize({ ...l.plan, items: adminItems })}\n\nWindows will ask for administrator approval.`, l.plan.hash))) {
        emit(a, 'apply-admin', false, { summary: summarize({ ...l.plan, items: adminItems }) }, `Confirmation required. Ask the user, then run: hydra-bane apply-admin ${l.plan.id} --yes`,
          { error: { code: 'CONFIRMATION_REQUIRED', message: 'ask the user, then re-run with --yes' } });
        return 3;
      }
      const cmd = elevatedApplyCommand(l.plan.id, l.plan.hash, ctx.sid, { version: VERSION });
      if (!cmd.ok) { emit(a, 'apply-admin', false, null, `Cannot elevate: ${cmd.code} ${cmd.detail}`, { error: { code: cmd.code, message: cmd.detail } }); return 1; }
      if (!fs.existsSync(cmd.elevated.args[0]!)) { emit(a, 'apply-admin', false, null, 'The admin-only helper is not installed. Run: hydra-bane admin-install', { error: { code: 'NO_HELPER', message: 'run hydra-bane admin-install first' } }); return 1; }
      launchElevated(cmd);
      const res = readAdminResult(l.plan.id, l.plan.hash);
      if (!res) { emit(a, 'apply-admin', false, null, 'The elevated helper did not report a result (UAC declined, or it failed).', { error: { code: 'NO_RESULT', message: 'no result from the elevated helper' } }); return 1; }
      const ledger = new Ledger(path.join(ctx.stateDir, 'ledger'));
      ledger.lock();
      try { for (const o of res.outcomes) ledger.append(l.plan.id, o.ok ? 'done' : 'failed', { item: o.id, target: o.target, op: 'admin', ...(o.code ? { code: o.code } : {}), ...(o.bytes ? { freed: o.bytes } : {}), elevated: true }); } finally { ledger.unlock(); }
      const bad = res.outcomes.filter((o) => !o.ok);
      emit(a, 'apply-admin', true, res, [`Administrator items done: ${res.outcomes.length - bad.length}/${res.outcomes.length}. Nothing here can be undone.`, ...bad.map((b) => `  skipped ${b.id}: ${b.code ?? ''} ${b.detail ?? ''}`)].join('\n'));
      return bad.length ? 4 : 0;
    }

    case 'admin-install': {
      if (isElevated()) {
        const pkgRoot = fileURLToPath(new URL('..', import.meta.url));
        const r = await installHelper(VERSION, fs.existsSync(path.join(pkgRoot, 'dist', 'cli.js')) && import.meta.url.includes('/dist/') ? { localRoot: pkgRoot } : {});
        emit(a, 'admin-install', r.ok, r, r.ok ? `Admin-only helper ${r.reused ? 'already installed' : 'installed'} at ${r.dir} (${r.files} files, verified against the npm registry).` : `Not installed: ${r.code} ${r.detail}`);
        return r.ok ? 0 : 1;
      }
      if (!a.yes && !interactive()) {
        emit(a, 'admin-install', false, null, 'Confirmation required. Ask the user, then run: hydra-bane admin-install --yes', { error: { code: 'CONFIRMATION_REQUIRED', message: 'installs into C:\\ProgramData with administrator approval' } });
        return 3;
      }
      const self = fileURLToPath(import.meta.url);
      const ps = `$p = Start-Process -FilePath $env:HB_NODE -ArgumentList @($env:HB_SELF,'admin-install') -Verb RunAs -Wait -PassThru; exit $p.ExitCode`;
      const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { stdio: 'inherit', env: { ...process.env, HB_NODE: process.execPath, HB_SELF: self.includes(' ') ? `"${self}"` : self } });
      emit(a, 'admin-install', r.status === 0, { status: r.status }, r.status === 0 ? 'Admin-only helper installed.' : `Admin helper install did not finish (exit ${r.status}).`);
      return r.status === 0 ? 0 : 1;
    }

    case 'admin-apply': {
      // Runs only inside the elevated helper (see apply-admin). Refuses anywhere else.
      const args = parseAdminApplyArgs(argv.slice(1));
      if (!args) { process.stderr.write('admin-apply: bad arguments\n'); return 1; }
      const r = runAdminApply(args, { selfPath: fileURLToPath(import.meta.url), version: VERSION, protectedPaths: buildProtectedPaths });
      if (!r.ok) process.stderr.write(`admin-apply: ${r.code} ${r.detail}\n`);
      return r.ok ? 0 : 1;
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
        '  scan   [--only temp,npm-cache,pnpm-store,pip-cache,uv-cache,cargo-registry,browser-cache,shader-cache,crash-dumps,node_modules,target,quarantine] [--root <dir>]...',
        '                          find reclaimable space (read-only)',
        '  plan   --select <ids> | --all-safe                                      seal a plan (read-only)',
        '  apply  <plan-id> [--yes]   ask the human (via your agent or this terminal), quarantine, write receipts',
        '  undo   <tx> [--yes]        restore a transaction',
        '  explain <id>               why an item is safe to clean and what happens after',
        '  analyze [dir]              explore what uses space (read-only, arrow keys)',
        '  (quarantine older than 7 days shows up in scan as Q-xxxxxxxx; purging it is permanent)',
        '  ledger                  verify and show receipts',
        '  programs                   list installed programs (read-only)',
        '  report <program-id> [--note <text>] [--submit [--yes]] | --no',
        '                          preview an Atlas report of an unwanted program; --submit posts it after approval',
        '  atlas update | status      download and verify the signed Atlas bundle, or show what is installed',
        '  apply-admin <plan-id> [--yes]  run the plan\'s administrator items through the admin-only helper (UAC)',
        '  admin-install [--yes]      install the admin-only helper into C:\\ProgramData (UAC, verified against npm)',
        '  recover                    finish the ledger of an interrupted apply or undo',
        '  mcp                        run the read-only MCP server on stdio',
        '  version', '', 'Add --json for machine-readable output.'].join('\n') + '\n');
      return a.cmd === 'help' ? 0 : 1;
  }
}

if (import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('cli.ts')) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e: Error) => { process.stderr.write(`hydra-bane: ${e.message}\n`); process.exitCode = 1; });
}
