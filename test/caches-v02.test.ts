import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { apply } from '../src/core/apply.ts';
import { compareGradle } from '../src/core/caches-v02.ts';
import type { Context } from '../src/core/context.ts';
import { explain } from '../src/core/explain.ts';
import { makePlan } from '../src/core/plan.ts';
import { measureTree, scan, type Category } from '../src/core/scan.ts';

// v0.2 user-level caches, all inside a temp folder: tool answers come from a fake locate, commands from a fake runner.
let root: string, home: string, ctx: Context;
const ENV = ['HF_HUB_CACHE', 'HF_HOME', 'XDG_CACHE_HOME', 'OLLAMA_MODELS', 'GRADLE_USER_HOME'] as const;
let savedEnv: Record<string, string | undefined>;
const DAYS = (n: number) => new Date(Date.now() - n * 86_400_000);

const put = (p: string, n = 100) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, 'x'.repeat(n)); return p; };
const withTools = (answers: Record<string, string>): Context => ({ ...ctx, locate: (cmd) => answers[cmd] });

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-c2-')));
  home = path.join(root, 'home');
  fs.mkdirSync(home);
  savedEnv = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  for (const k of ENV) delete process.env[k];
  ctx = {
    stateDir: path.join(root, 'state'), tempDir: path.join(root, 'temp'), home, locate: () => undefined, roots: [],
    protectedPaths: [path.join(root, 'protected')], sid: 'S-1-5-21-test', now: () => new Date(),
    confirmer: { confirm: async () => true }, run: () => ({ status: 0, stderr: '' }),
    quarantineBaseFor: () => path.join(root, 'quarantine'), isRunning: () => false,
  };
});
afterEach(() => {
  for (const k of ENV) { if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k]; }
  fs.rmSync(root, { recursive: true, force: true });
});

describe('measureTree hardlink dedupe', () => {
  it('counts a file linked twice inside the tree once and reports linked bytes', () => {
    const dir = path.join(root, 't');
    const a = put(path.join(dir, 'a.bin'), 1000);
    fs.mkdirSync(path.join(dir, 'sub'));
    fs.linkSync(a, path.join(dir, 'sub', 'b.bin'));
    put(path.join(dir, 'c.bin'), 10);
    expect(measureTree(dir)).toEqual({ bytes: 1010, files: 2, linkedBytes: 1000 });
  });

  it('reports linked bytes when the other link is outside the tree, and omits the field without links', () => {
    const dir = path.join(root, 't');
    const a = put(path.join(dir, 'a.bin'), 500);
    fs.linkSync(a, path.join(root, 'outside.bin'));
    expect(measureTree(dir)).toEqual({ bytes: 500, files: 1, linkedBytes: 500 });
    expect(measureTree(path.join(root, 'outside.bin'))).toEqual({ bytes: 500, files: 1, linkedBytes: 500 });
    fs.rmSync(path.join(root, 'outside.bin'));
    expect(measureTree(dir)).toEqual({ bytes: 500, files: 1 });
  });
});

describe('tool-located caches', () => {
  const cases: Array<{ cat: Category; id: string; query: string; answer: (d: string) => string; dir: (d: string) => string; cmd: string }> = [
    { cat: 'yarn-cache', id: 'YARN', query: 'yarn cache dir', answer: (d) => d, dir: (d) => d, cmd: 'yarn cache clean' },
    { cat: 'bun-cache', id: 'BUN', query: 'bun pm cache', answer: (d) => d, dir: (d) => d, cmd: 'bun pm cache rm' },
    { cat: 'conda-pkgs', id: 'CONDA', query: 'conda info --base', answer: (d) => d, dir: (d) => path.join(d, 'pkgs'), cmd: 'conda clean --all -y' },
    { cat: 'poetry-cache', id: 'POETRY', query: 'poetry config cache-dir', answer: (d) => d, dir: (d) => path.join(d, 'cache', 'repositories', 'pypi'), cmd: 'poetry cache clear --all pypi -n' },
    { cat: 'go-cache', id: 'GO-BUILD', query: 'go env GOCACHE', answer: (d) => d, dir: (d) => d, cmd: 'go clean -cache' },
    { cat: 'go-cache', id: 'GO-MOD', query: 'go env GOMODCACHE', answer: (d) => d, dir: (d) => d, cmd: 'go clean -modcache' },
    { cat: 'nuget-cache', id: 'NUGET', query: 'dotnet nuget locals global-packages --list', answer: (d) => `global-packages: ${d}\\`, dir: (d) => d, cmd: 'dotnet nuget locals global-packages --clear' },
    { cat: 'nuget-cache', id: 'NUGET-HTTP', query: 'dotnet nuget locals http-cache --list', answer: (d) => `info : http-cache: ${d}`, dir: (d) => d, cmd: 'dotnet nuget locals http-cache --clear' },
  ];
  for (const c of cases) {
    it(`${c.id}: found from the tool answer, cleaned by "${c.cmd}"`, async () => {
      const base = path.join(root, 'tool', c.id);
      const dir = c.dir(base);
      put(path.join(dir, 'blob'), 300);
      const items = scan(withTools({ [c.query]: c.answer(base) }), [c.cat]);
      expect(items).toEqual([expect.objectContaining({ id: c.id, category: c.cat, op: 'tool_cmd', targets: [dir], allowRoot: dir, bytes: 300, risk: 'safe', reversible: 'redownload' })]);
      expect([items[0]!.command!.file, ...items[0]!.command!.args].join(' ')).toBe(c.cmd);
      expect(explain(items[0]!)).toMatchObject({ how: `runs "${c.cmd}"`, what: expect.not.stringMatching(new RegExp(`^${items[0]!.title}$`)) });

      const ran: string[] = [];
      const r = await apply({ ...ctx, run: (f, a) => { ran.push([f, ...a].join(' ')); fs.rmSync(path.join(dir, 'blob')); return { status: 0, stderr: '' }; } }, makePlan(ctx, items).id);
      expect(ran).toEqual([c.cmd]);
      expect(r).toMatchObject({ ok: true, freedNowBytes: 300 });
    });
  }

  it('emits nothing when the tool is missing, the folder is empty, or the answer is not a plausible cache folder', () => {
    const all: Category[] = ['yarn-cache', 'bun-cache', 'conda-pkgs', 'poetry-cache', 'go-cache', 'nuget-cache'];
    expect(scan(ctx, all)).toEqual([]);
    fs.mkdirSync(path.join(root, 'empty'));
    expect(scan(withTools({ 'yarn cache dir': path.join(root, 'empty') }), all)).toEqual([]);
    put(path.join(home, 'Documents', 'thesis.docx'));
    expect(scan(withTools({ 'yarn cache dir': home, 'bun pm cache': root, 'go env GOCACHE': path.parse(root).root, 'go env GOMODCACHE': 'relative\\dir' }), all)).toEqual([]);
  });

  it('poetry never measures its virtualenvs', () => {
    const d = path.join(root, 'poetry');
    put(path.join(d, 'virtualenvs', 'proj-py3.12', 'lib.py'), 9999);
    expect(scan(withTools({ 'poetry config cache-dir': d }), ['poetry-cache'])).toEqual([]);
  });
});

describe('Gradle', () => {
  it('orders versions', () => {
    expect(['8.5', '8.10', '7.6.1', '8.10-rc-1'].sort(compareGradle)).toEqual(['7.6.1', '8.5', '8.10-rc-1', '8.10']);
  });

  it('offers only version folders older than the newest, never shared caches, with a name allowlist', async () => {
    const g = path.join(home, '.gradle');
    for (const v of ['7.6.1', '8.5', '8.10']) put(path.join(g, 'caches', v, 'file-changes', 'x.bin'), 200);
    put(path.join(g, 'caches', 'modules-2', 'files-2.1', 'dep.jar'), 5000);
    put(path.join(g, 'caches', 'jars-9', 'a.jar'), 50);
    for (const d of ['gradle-8.5-bin', 'gradle-8.10-bin', 'gradle-8.10-all']) put(path.join(g, 'wrapper', 'dists', d, 'h', 'gradle.zip'), 400);

    const items = scan(ctx, ['gradle-cache']);
    const names = items.map((i) => path.basename(i.targets[0]!)).sort();
    expect(names).toEqual(['7.6.1', '8.5', 'gradle-8.5-bin']);
    for (const i of items) {
      expect(i).toMatchObject({ op: 'delete_cache', risk: 'caution', reversible: 'redownload', targetNames: [path.basename(i.targets[0]!)] });
      expect(i.id).toMatch(/^GRADLE-[0-9a-f]{6}$/);
    }
    expect(scan(ctx, ['gradle-cache']).map((i) => i.id)).toEqual(items.map((i) => i.id));

    const r = await apply(ctx, makePlan(ctx, items).id);
    expect(r).toMatchObject({ ok: true, freedNowBytes: 800 });
    expect(fs.existsSync(path.join(g, 'caches', '8.10'))).toBe(true);
    expect(fs.existsSync(path.join(g, 'caches', 'modules-2', 'files-2.1', 'dep.jar'))).toBe(true);
    expect(fs.existsSync(path.join(g, 'wrapper', 'dists', 'gradle-8.10-all'))).toBe(true);
  });

  it('offers nothing when only one version exists', () => {
    put(path.join(home, '.gradle', 'caches', '8.5', 'x'), 10);
    expect(scan(ctx, ['gradle-cache'])).toEqual([]);
  });
});

describe('Maven', () => {
  const repo = () => path.join(home, '.m2', 'repository');
  const artifact = (v: string, days: number, remote = 'central') => {
    const dir = path.join(repo(), 'org', 'example', 'lib', v);
    for (const f of [`lib-${v}.pom`, `lib-${v}.jar`]) put(path.join(dir, f), 300);
    fs.writeFileSync(path.join(dir, '_remote.repositories'), `#NOTE\nlib-${v}.jar>${remote}=\nlib-${v}.pom>${remote}=\n`);
    for (const f of fs.readdirSync(dir)) fs.utimesSync(path.join(dir, f), DAYS(days), DAYS(days));
    return dir;
  };

  it('offers only downloaded versions untouched for 90+ days, grouped per artifact', async () => {
    const old = artifact('1.0', 120);
    artifact('2.0', 10);
    const mine = artifact('3.0-SNAPSHOT', 200, ''); // mvn install: empty repo id, not re-downloadable
    const items = scan(ctx, ['maven-repo']);
    expect(items).toEqual([expect.objectContaining({ category: 'maven-repo', op: 'delete_cache', risk: 'caution', targets: [old], targetNames: ['1.0'], allowRoot: path.dirname(old), bytes: 600 + fs.statSync(path.join(old, '_remote.repositories')).size })]);
    expect(items[0]!.id).toMatch(/^MAVEN-[0-9a-f]{6}$/);
    expect(items[0]!.title).toContain('org.example:lib');
    expect(items[0]!.title).toMatch(/offline/);

    await apply(ctx, makePlan(ctx, items).id);
    expect(fs.existsSync(old)).toBe(false);
    expect(fs.existsSync(mine)).toBe(true);
  });

  it('ignores folders without the <artifactId>-<version>.pom signature or the remote marker', () => {
    put(path.join(repo(), 'org', 'x', 'notes', 'readme.txt'));
    const dir = artifact('1.0', 300);
    fs.rmSync(path.join(dir, '_remote.repositories'));
    fs.utimesSync(path.join(dir, 'lib-1.0.pom'), DAYS(300), DAYS(300));
    expect(scan(ctx, ['maven-repo'])).toEqual([]);
  });
});

describe('HuggingFace', () => {
  it('makes one item per model folder under the default hub, with a name allowlist', async () => {
    const hub = path.join(home, '.cache', 'huggingface', 'hub');
    put(path.join(hub, 'models--meta-llama--Llama-3-8B', 'blobs', 'aaa'), 2000);
    put(path.join(hub, 'models--gpt2', 'blobs', 'bbb'), 700);
    put(path.join(hub, 'datasets--squad', 'blobs', 'ccc'), 900);
    put(path.join(hub, 'version.txt'), 1);
    const items = scan(ctx, ['hf-models']);
    expect(items.map((i) => i.title).sort()).toEqual([expect.stringContaining('HuggingFace model gpt2'), expect.stringContaining('HuggingFace model meta-llama/Llama-3-8B')]);
    for (const i of items) {
      expect(i).toMatchObject({ op: 'delete_cache', risk: 'caution', reversible: 'redownload', allowRoot: hub, targetNames: [path.basename(i.targets[0]!)] });
      expect(i.id).toMatch(/^HF-[0-9a-f]{6}$/);
      expect(i.title).toMatch(/GB/);
    }
    const llama = items.find((i) => i.title.includes('Llama'))!;
    await apply(ctx, makePlan(ctx, [llama]).id);
    expect(fs.existsSync(llama.targets[0]!)).toBe(false);
    expect(fs.existsSync(path.join(hub, 'models--gpt2'))).toBe(true);
    expect(fs.existsSync(path.join(hub, 'datasets--squad'))).toBe(true);

    const evil = await apply(ctx, makePlan(ctx, [{ ...items.find((i) => i.title.includes('gpt2'))!, targets: [path.join(hub, 'datasets--squad')] }]).id);
    expect(evil).toMatchObject({ outcomes: [expect.objectContaining({ ok: false, code: 'NOT_A_CACHE_FOLDER' })] });
  });

  it('honours HF_HUB_CACHE and HF_HOME', () => {
    const custom = path.join(root, 'hfhub');
    put(path.join(custom, 'models--a--b', 'x'), 10);
    process.env.HF_HUB_CACHE = custom;
    expect(scan(ctx, ['hf-models'])).toEqual([expect.objectContaining({ allowRoot: custom })]);
    delete process.env.HF_HUB_CACHE;
    process.env.HF_HOME = path.join(root, 'hfhome');
    put(path.join(root, 'hfhome', 'hub', 'models--c', 'x'), 10);
    expect(scan(ctx, ['hf-models'])).toEqual([expect.objectContaining({ allowRoot: path.join(root, 'hfhome', 'hub') })]);
  });
});

describe('Ollama', () => {
  const digest = (c: string) => `sha256:${c.repeat(64)}`;
  const setup = () => {
    const models = path.join(home, '.ollama', 'models');
    const manifest = (rel: string[], layers: string[]) => {
      const file = put(path.join(models, 'manifests', ...rel), 0);
      fs.writeFileSync(file, JSON.stringify({ config: { digest: layers[0] }, layers: layers.slice(1).map((digest) => ({ digest })) }));
    };
    for (const [c, n] of [['a', 1000], ['b', 3000], ['c', 500], ['d', 7000]] as const) put(path.join(models, 'blobs', `sha256-${c.repeat(64)}`), n);
    manifest(['registry.ollama.ai', 'library', 'llama3', '8b'], [digest('a'), digest('b')]);
    manifest(['registry.ollama.ai', 'library', 'llama3', 'instruct'], [digest('a'), digest('d')]);
    manifest(['registry.ollama.ai', 'someone', 'tiny', 'latest'], [digest('c')]);
    manifest(['registry.ollama.ai', 'library', 'evil', 'x&del C'], [digest('c')]);
    return models;
  };

  it('offers each model through `ollama rm`, sized by the blobs only it uses', () => {
    setup();
    const items = scan(withTools({ 'ollama --version': 'ollama version is 0.12.0' }), ['ollama-models']);
    const byName = Object.fromEntries(items.map((i) => [i.command!.args[1], i]));
    expect(Object.keys(byName).sort()).toEqual(['llama3:8b', 'llama3:instruct', 'someone/tiny:latest']);
    expect(byName['llama3:8b']).toMatchObject({ op: 'tool_cmd', risk: 'caution', reversible: 'redownload', bytes: 3000, command: { file: 'ollama', args: ['rm', 'llama3:8b'] } });
    expect(byName['llama3:8b']!.title).toMatch(/shared with other models stays/);
    expect(byName['llama3:instruct']!.bytes).toBe(7000);
    expect(byName['someone/tiny:latest']!.bytes).toBe(500); // the unsafe-named manifest is skipped, not counted as a sharer
    for (const i of items) expect(i.id).toMatch(/^OLLAMA-[0-9a-f]{6}$/);
  });

  it('emits nothing when ollama is not installed', () => {
    setup();
    expect(scan(ctx, ['ollama-models'])).toEqual([]);
  });
});

describe('explain covers every v0.2 cache category', () => {
  it('has plain text for each', () => {
    const cats: Category[] = ['yarn-cache', 'bun-cache', 'conda-pkgs', 'poetry-cache', 'go-cache', 'nuget-cache', 'gradle-cache', 'maven-repo', 'hf-models', 'ollama-models'];
    for (const category of cats) {
      const e = explain({ id: 'X', category, title: 'title', op: 'delete_cache', targets: [], allowRoot: '', bytes: 0, files: 0, risk: 'safe', reversible: 'redownload' });
      expect(e.what).not.toBe('title');
      expect(e.why_safe.length).toBeGreaterThan(20);
      expect(e.what_happens.length).toBeGreaterThan(20);
    }
  });
});
