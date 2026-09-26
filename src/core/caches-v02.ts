import fs from 'node:fs';
import path from 'node:path';
import type { Context } from './context.ts';
import { measureTree, pathId, type Category, type ScanItem } from './scan.ts';

// PLAN.md §3.1 v0.2 user-level caches. Paths come only from the tool's own answer to a constant query or
// from a fixed well-known location; nothing here ever searches for folders by name across the disk.

const DAY = 86_400_000;
export const MAVEN_STALE_DAYS = 90;
const gb = (b: number) => `${(b / 2 ** 30).toFixed(2)} GB`;

const dirs = (p: string) => { try { return fs.readdirSync(p, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.isSymbolicLink()).map((e) => e.name); } catch { return []; } };

/** A tool answer we are willing to measure: absolute, existing, not a drive root, not the profile or above it. */
function plausible(ctx: Context, dir: string | undefined): string | undefined {
  if (!dir || !path.isAbsolute(dir)) return undefined;
  const d = path.resolve(dir);
  if (path.parse(d).root === d) return undefined;
  const rel = path.relative(d, ctx.home);
  if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) return undefined;
  return fs.existsSync(d) ? d : undefined;
}

// --- Tool-cleaned caches: measured at the tool's answer, cleaned by the tool's official command. ---

interface ToolCache { id: string; category: Category; title: string; locate: (ctx: Context) => string | undefined; clean: { file: string; args: string[] } }

const nugetLocal = (kind: string) => (ctx: Context) => ctx.locate(`dotnet nuget locals ${kind} --list`)?.match(new RegExp(`${kind}:\\s*(.+)$`))?.[1]?.trim();

const TOOL_CACHES: ToolCache[] = [
  { id: 'YARN', category: 'yarn-cache', title: 'yarn cache', locate: (ctx) => ctx.locate('yarn cache dir'), clean: { file: 'yarn', args: ['cache', 'clean'] } },
  { id: 'BUN', category: 'bun-cache', title: 'bun package cache', locate: (ctx) => ctx.locate('bun pm cache'), clean: { file: 'bun', args: ['pm', 'cache', 'rm'] } },
  {
    // The locate hook returns one line, so conda's multi-line pkgs_dirs list is out; <base>\pkgs is conda's default.
    id: 'CONDA', category: 'conda-pkgs', title: 'conda package cache (clean keeps packages environments still use: up to this size)',
    locate: (ctx) => { const base = ctx.locate('conda info --base'); return base ? path.join(base, 'pkgs') : undefined; },
    clean: { file: 'conda', args: ['clean', '--all', '-y'] },
  },
  {
    // Only the pypi repository cache: poetry's cache-dir also holds virtualenvs, which are not a cache.
    id: 'POETRY', category: 'poetry-cache', title: 'poetry PyPI metadata cache',
    locate: (ctx) => { const d = ctx.locate('poetry config cache-dir'); return d ? path.join(d, 'cache', 'repositories', 'pypi') : undefined; },
    clean: { file: 'poetry', args: ['cache', 'clear', '--all', 'pypi', '-n'] },
  },
  { id: 'GO-BUILD', category: 'go-cache', title: 'Go build cache', locate: (ctx) => ctx.locate('go env GOCACHE'), clean: { file: 'go', args: ['clean', '-cache'] } },
  { id: 'GO-MOD', category: 'go-cache', title: 'Go module download cache', locate: (ctx) => ctx.locate('go env GOMODCACHE'), clean: { file: 'go', args: ['clean', '-modcache'] } },
  // One item per NuGet location so each measured folder matches exactly what its command clears.
  // NuGet's "temp" location lives under %TEMP% and is left to the TEMP item.
  { id: 'NUGET', category: 'nuget-cache', title: 'NuGet global packages folder', locate: nugetLocal('global-packages'), clean: { file: 'dotnet', args: ['nuget', 'locals', 'global-packages', '--clear'] } },
  { id: 'NUGET-HTTP', category: 'nuget-cache', title: 'NuGet HTTP cache', locate: nugetLocal('http-cache'), clean: { file: 'dotnet', args: ['nuget', 'locals', 'http-cache', '--clear'] } },
  { id: 'NUGET-PLUGINS', category: 'nuget-cache', title: 'NuGet plugins cache', locate: nugetLocal('plugins-cache'), clean: { file: 'dotnet', args: ['nuget', 'locals', 'plugins-cache', '--clear'] } },
];

function scanToolCaches(ctx: Context, want: (c: Category) => boolean): ScanItem[] {
  return TOOL_CACHES.filter((c) => want(c.category)).flatMap((c) => {
    const dir = plausible(ctx, c.locate(ctx));
    if (!dir) return [];
    const m = measureTree(dir);
    if (!m.bytes) return [];
    return [{ id: c.id, category: c.category, title: c.title, op: 'tool_cmd', targets: [dir], allowRoot: dir, command: c.clean, ...m, risk: 'safe', reversible: 'redownload' } satisfies ScanItem];
  });
}

// --- Gradle: version-named folders older than the newest one. Shared caches (modules-2, jars-*, ...) are never touched. ---

const VERSION = /^(\d+(?:\.\d+)*)(.*)$/;
/** Compares Gradle versions like 8.10, 8.5, 8.10-rc-1 (a suffix sorts before the release). */
export function compareGradle(a: string, b: string): number {
  const [, an = '', as = ''] = VERSION.exec(a) ?? [];
  const [, bn = '', bs = ''] = VERSION.exec(b) ?? [];
  const ap = an.split('.').map(Number), bp = bn.split('.').map(Number);
  for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
    const d = (ap[i] ?? 0) - (bp[i] ?? 0);
    if (d) return d;
  }
  if (as === bs) return 0;
  return !as ? 1 : !bs ? -1 : as < bs ? -1 : 1;
}

function scanGradle(ctx: Context): ScanItem[] {
  const home = process.env.GRADLE_USER_HOME ?? path.join(ctx.home, '.gradle');
  const groups: Array<{ root: string; label: string; version: (name: string) => string | undefined }> = [
    { root: path.join(home, 'caches'), label: 'cache', version: (n) => (/^\d+(\.\d+)+(-[\w.-]+)?$/.test(n) ? n : undefined) },
    { root: path.join(home, 'wrapper', 'dists'), label: 'wrapper distribution', version: (n) => /^gradle-(\d+(?:\.\d+)+(?:-[\w.-]+?)?)-(bin|all)$/.exec(n)?.[1] },
  ];
  const items: ScanItem[] = [];
  for (const g of groups) {
    const found = dirs(g.root).flatMap((name) => { const v = g.version(name); return v ? [{ name, v }] : []; });
    if (found.length < 2) continue;
    const newest = found.map((f) => f.v).reduce((a, b) => (compareGradle(a, b) >= 0 ? a : b));
    for (const f of found) {
      if (compareGradle(f.v, newest) >= 0) continue;
      const dir = path.join(g.root, f.name);
      const m = measureTree(dir);
      if (!m.bytes) continue;
      items.push({
        id: pathId('GRADLE', dir), category: 'gradle-cache', title: `Gradle ${f.v} ${g.label} (older than ${newest}; a project pinned to ${f.v} re-downloads it)`,
        op: 'delete_cache', targets: [dir], allowRoot: g.root, targetNames: [f.name], ...m, risk: 'caution', reversible: 'redownload',
      });
    }
  }
  return items;
}

// --- Maven: version folders untouched for 90+ days that came from a remote repository. ---

/** Marker Maven writes next to downloaded files. Locally `mvn install`ed artifacts have an empty repo id (`file>=`) and are kept. */
function downloadedFromRemote(versionDir: string): boolean {
  let text: string;
  try { text = fs.readFileSync(path.join(versionDir, '_remote.repositories'), 'utf8'); } catch { return false; }
  const entries = text.split(/\r?\n/).filter((l) => l && !l.startsWith('#'));
  return entries.length > 0 && entries.every((l) => /^[^>]+>[^=\s]+=/.test(l));
}

function scanMaven(ctx: Context): ScanItem[] {
  const repo = path.join(ctx.home, '.m2', 'repository');
  const cutoff = ctx.now().getTime() - MAVEN_STALE_DAYS * DAY;
  const byArtifact = new Map<string, string[]>();
  const stack: Array<[string, number]> = [[repo, 0]];
  while (stack.length) {
    const [dir, depth] = stack.pop()!;
    for (const name of dirs(dir)) {
      const full = path.join(dir, name);
      // A version folder holds <artifactId>-<version>.pom, where artifactId is its parent folder.
      if (fs.existsSync(path.join(full, `${path.basename(dir)}-${name}.pom`))) {
        if (lastTouched(full) < cutoff && downloadedFromRemote(full)) byArtifact.set(dir, [...(byArtifact.get(dir) ?? []), name]);
        continue;
      }
      if (depth < 12) stack.push([full, depth + 1]);
    }
  }
  const items: ScanItem[] = [];
  for (const [artifactDir, versions] of byArtifact) {
    const targets = versions.map((v) => path.join(artifactDir, v));
    const m = targets.map(measureTree).reduce((a, b) => ({ bytes: a.bytes + b.bytes, files: a.files + b.files }), { bytes: 0, files: 0 });
    if (!m.bytes) continue;
    const coord = `${path.relative(repo, path.dirname(artifactDir)).split(path.sep).join('.')}:${path.basename(artifactDir)}`;
    items.push({
      id: pathId('MAVEN', artifactDir), category: 'maven-repo',
      title: `Maven ${coord} ${versions.sort().join(', ')} (unused ${MAVEN_STALE_DAYS}+ days; offline builds that need them fail until re-downloaded)`,
      op: 'delete_cache', targets, allowRoot: artifactDir, targetNames: versions, ...m, risk: 'caution', reversible: 'redownload',
    });
  }
  return items;
}

/** Latest modification or access time of the artifact files in the folder (version folders are flat).
 *  The marker file is skipped because our own read of it may refresh its access time. */
function lastTouched(dir: string): number {
  let t = 0, names: string[] = [];
  try { names = fs.readdirSync(dir); } catch { return Infinity; }
  for (const f of names) {
    if (f === '_remote.repositories') continue;
    try { const st = fs.lstatSync(path.join(dir, f)); t = Math.max(t, st.mtimeMs, st.atimeMs); } catch { /* vanished */ }
  }
  return t;
}

// --- HuggingFace hub: one item per models--<org>--<name> folder. ---

function hfHub(ctx: Context): string {
  if (process.env.HF_HUB_CACHE) return process.env.HF_HUB_CACHE;
  if (process.env.HF_HOME) return path.join(process.env.HF_HOME, 'hub');
  return path.join(process.env.XDG_CACHE_HOME ?? path.join(ctx.home, '.cache'), 'huggingface', 'hub');
}

function scanHf(ctx: Context): ScanItem[] {
  const hub = hfHub(ctx);
  if (!path.isAbsolute(hub)) return [];
  return dirs(hub).filter((n) => /^models--.+/.test(n)).flatMap((name) => {
    const dir = path.join(hub, name);
    const m = measureTree(dir);
    if (!m.bytes) return [];
    const model = name.slice('models--'.length).split('--').join('/');
    return [{
      id: pathId('HF', dir), category: 'hf-models', title: `HuggingFace model ${model} (${gb(m.bytes)}; downloaded again on next use)`,
      op: 'delete_cache', targets: [dir], allowRoot: hub, targetNames: [name], ...m, risk: 'caution', reversible: 'redownload',
    } satisfies ScanItem];
  });
}

// --- Ollama: one item per model, removed with `ollama rm` (the server drops blobs no other model uses). ---

// The command is run through cmd.exe, so a model name read from disk must be plain before it reaches argv.
const SAFE_MODEL = /^[A-Za-z0-9][A-Za-z0-9._\-/:]*$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

function scanOllama(ctx: Context): ScanItem[] {
  if (!ctx.locate('ollama --version')) return [];
  const models = process.env.OLLAMA_MODELS ?? path.join(ctx.home, '.ollama', 'models');
  const manifests = path.join(models, 'manifests');
  const found: Array<{ name: string; file: string; blobs: string[] }> = [];
  for (const host of dirs(manifests)) for (const ns of dirs(path.join(manifests, host))) for (const model of dirs(path.join(manifests, host, ns))) {
    const mdir = path.join(manifests, host, ns, model);
    let tags: string[] = [];
    try { tags = fs.readdirSync(mdir, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name); } catch { continue; }
    for (const tag of tags) {
      const file = path.join(mdir, tag);
      let m: { config?: { digest?: string }; layers?: Array<{ digest?: string }> };
      try { m = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { continue; }
      const blobs = [m.config?.digest, ...(m.layers ?? []).map((l) => l.digest)].filter((d): d is string => !!d && DIGEST.test(d));
      const name = host === 'registry.ollama.ai' ? `${ns === 'library' ? '' : `${ns}/`}${model}:${tag}` : `${host}/${ns}/${model}:${tag}`;
      if (SAFE_MODEL.test(name)) found.push({ name, file, blobs });
    }
  }
  const users = new Map<string, number>();
  for (const f of found) for (const b of new Set(f.blobs)) users.set(b, (users.get(b) ?? 0) + 1);
  const size = (d: string) => { try { return fs.lstatSync(path.join(models, 'blobs', d.replace(':', '-'))).size; } catch { return 0; } };
  return found.flatMap((f) => {
    const unique = [...new Set(f.blobs)];
    const own = unique.filter((b) => users.get(b) === 1).reduce((s, b) => s + size(b), 0);
    const shared = unique.filter((b) => users.get(b)! > 1).reduce((s, b) => s + size(b), 0);
    if (!own) return [];
    return [{
      id: pathId('OLLAMA', f.file), category: 'ollama-models',
      title: `Ollama model ${f.name} (${gb(own)} used only by it${shared ? `; ${gb(shared)} shared with other models stays` : ''}; \`ollama pull\` gets it back)`,
      // Target is the manifest: its existence is what `ollama rm` removes, so drift and freed checks track this model only.
      op: 'tool_cmd', targets: [f.file], allowRoot: models, command: { file: 'ollama', args: ['rm', f.name] },
      bytes: own, files: 1, risk: 'caution', reversible: 'redownload',
    } satisfies ScanItem];
  });
}

export function scanCachesV02(ctx: Context, want: (c: Category) => boolean): ScanItem[] {
  return [
    ...scanToolCaches(ctx, want),
    ...(want('gradle-cache') ? scanGradle(ctx) : []),
    ...(want('maven-repo') ? scanMaven(ctx) : []),
    ...(want('hf-models') ? scanHf(ctx) : []),
    ...(want('ollama-models') ? scanOllama(ctx) : []),
  ];
}
