// Records a real scan -> plan -> apply -> undo session against a throwaway sandbox profile.
// Nothing outside the sandbox is read for cleanup or changed: home, %TEMP%, state dir, project roots
// and the quarantine all live in a fresh temp folder, and cache tools report "not installed".
// Output lines are formatted exactly like src/cli.ts (keep them in sync when the CLI text changes).
// Usage: node scripts/demo/record.ts [out.json]
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { apply, undo } from '../../src/core/apply.ts';
import { defaultProtected, type Context } from '../../src/core/context.ts';
import { makePlan } from '../../src/core/plan.ts';
import { scan } from '../../src/core/scan.ts';
import { currentUserSid } from '../../src/quarantine/quarantine.ts';

for (const k of ['CARGO_HOME', 'GRADLE_USER_HOME', 'HF_HUB_CACHE', 'HF_HOME', 'XDG_CACHE_HOME', 'OLLAMA_MODELS']) delete process.env[k];

const out = path.resolve(process.argv[2] ?? 'scripts/demo/session.json');
const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-demo-')));
const home = path.join(root, 'home'), work = path.join(root, 'work'), temp = path.join(home, 'AppData', 'Local', 'Temp');
const MB = 2 ** 20;
const ago = (days: number) => new Date(Date.now() - days * 86_400_000);
const age = (p: string, days: number) => fs.utimesSync(p, ago(days), ago(days));

// Large files are NTFS sparse so the demo does not need gigabytes of free space; sizes are what scan measures.
function file(p: string, bytes: number, days: number) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, '');
  if (bytes > 4 * MB) spawnSync('fsutil', ['sparse', 'setflag', p], { stdio: 'ignore' });
  fs.truncateSync(p, bytes);
  age(p, days);
}
function project(name: string, markers: string[], artifact: string, files: Array<[string, number]>) {
  const dir = path.join(work, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const m of markers) fs.writeFileSync(path.join(dir, m), '{}');
  fs.writeFileSync(path.join(dir, '.gitignore'), `${artifact}/\n`);
  const git = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  git('init', '-q');
  git('-c', 'user.email=demo@example.com', '-c', 'user.name=demo', 'add', '.');
  for (const [rel, bytes] of files) file(path.join(dir, artifact, rel), bytes, 45);
  for (const p of [artifact, ...markers]) age(path.join(dir, p), 45);
}

for (let i = 0; i < 38; i++) file(path.join(temp, `tmp${(0x4a1 + i * 37).toString(16).toUpperCase()}.tmp`), 3 * MB + i * 97_000, 3 + (i % 9));
file(path.join(temp, 'setup-cache', 'installer-payload.msi'), 212 * MB, 12);
file(path.join(temp, 'new-download.part'), 5 * MB, 0);
file(path.join(home, '.cargo', 'registry', 'cache', 'index.crates.io-6f17d22bba15001f', 'bundle.crate'), 391 * MB, 20);
project('web-dashboard', ['package.json', 'package-lock.json'], 'node_modules',
  Array.from({ length: 60 }, (_, i): [string, number] => [`pkg${i}/dist/index.js`, 19 * MB + i * 211_000]));
project('ray-tracer', ['Cargo.toml', 'Cargo.lock'], 'target',
  [['debug/deps/libray.rlib', 1310 * MB], ['release/ray-tracer.exe', 38 * MB], ['debug/incremental/state.bin', 702 * MB]]);

const events: Array<{ t: number; kind: 'cmd' | 'out' | 'input'; text: string }> = [];
const t0 = performance.now();
const log = (kind: 'cmd' | 'out' | 'input', text: string) => events.push({ t: Math.round(performance.now() - t0), kind, text });
const gb = (b: number) => `${(b / 2 ** 30).toFixed(2)} GB`;

// Stands in for the terminal y/N prompt in cli.ts (cliConfirmer): prints the same text, the recorded answer is "y".
const ctx: Context = {
  stateDir: path.join(home, 'AppData', 'Local', 'hydra-bane'),
  tempDir: temp,
  home,
  locate: () => undefined,
  roots: [work],
  protectedPaths: defaultProtected(),
  sid: currentUserSid(),
  now: () => new Date(),
  confirmer: { async confirm(summary) { log('out', `${summary}\n\nApply this plan? [y/N]: `); log('input', 'y'); return true; } },
  run: () => { throw new Error('demo sandbox: no external tool may run'); },
  quarantineBaseFor: () => path.join(root, 'quarantine'),
};
const guard = (p: string) => { if (!p.startsWith(root)) throw new Error(`outside sandbox: ${p}`); };

try {
  log('cmd', 'hydra-bane scan --root .\\work');
  const items = scan(ctx);
  for (const i of items) i.targets.forEach(guard);
  const total = items.reduce((s, i) => s + i.bytes, 0);
  log('out', [`Found ${gb(total)} reclaimable. Nothing was changed.`, ...items.map((i) => `  ${i.id.padEnd(18)} ${gb(i.bytes).padStart(9)}  ${i.risk === 'caution' ? '[caution] ' : ''}${i.title}`),
    '\nNext: hydra-bane plan --select <ids>   (or --all-safe)'].join('\n'));

  const pick = items.filter((i) => i.category !== 'crash-dumps');
  log('cmd', `hydra-bane plan --select ${pick.map((i) => i.id).join(',')}`);
  const plan = makePlan(ctx, pick);
  log('out', `Plan ${plan.id} (${plan.hash.slice(0, 8)}), ${pick.length} item(s), expires ${plan.expiresAt}.\nNothing was changed. A human applies it with: hydra-bane apply ${plan.id}`);

  log('cmd', `hydra-bane apply ${plan.id}`);
  const r = await apply(ctx, plan.id);
  if (!r.ok) throw new Error(`apply failed: ${r.code} ${r.detail}`);
  const failed = r.outcomes.filter((o) => !o.ok);
  log('out', [`Receipt ${r.tx}: freed ${gb(r.freedNowBytes)} now, quarantined ${gb(r.quarantinedBytes)} (undo: hydra-bane undo ${r.tx}).`,
    ...failed.map((f) => `  skipped ${f.id} ${f.target}: ${f.code}`)].join('\n'));

  log('cmd', `hydra-bane undo ${r.tx}`);
  const u = await undo(ctx, r.tx);
  if (!u.ok) throw new Error(`undo failed: ${u.code} ${u.detail}`);
  const bad = u.outcomes.filter((o) => !o.ok);
  log('out', [`Restored ${u.outcomes.length - bad.length} item(s).`, ...bad.map((b) => `  not restored ${b.id}: ${'code' in b ? b.code : ''}`)].join('\n'));

  const back = fs.existsSync(path.join(work, 'web-dashboard', 'node_modules', 'pkg0', 'dist', 'index.js'));
  fs.writeFileSync(out, JSON.stringify({ recorded_at: new Date().toISOString(), restored_check: back, events }, null, 2));
  process.stdout.write(`${events.map((e) => (e.kind === 'cmd' ? `> ${e.text}` : e.text)).join('\n')}\n\nrestored_check=${back}\nwrote ${out}\n`);
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
