import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { apply, undo } from '../src/core/apply.ts';
import type { Context } from '../src/core/context.ts';
import { policyFor } from '../src/core/context.ts';
import { isInstallerName, scanInstallers, zipLooksLikeInstaller, type InstallerDeps } from '../src/core/downloads.ts';
import { scanOrphans, type OrphanDeps } from '../src/core/orphans.ts';
import { makePlan } from '../src/core/plan.ts';
import type { ScanItem } from '../src/core/scan.ts';
import { decide } from '../src/guard/decide.ts';
import { isSameOrDescendant } from '../src/guard/normalize.ts';
import type { Program } from '../src/atlas/programs.ts';

// Old installers in Downloads and remnants of programs removed outside Hydra-bane. Temp-folder fixtures, a fake
// program list, fake shortcut reader and fake Run keys: nothing reads this PC.

let root: string, ctx: Context, env: Record<string, string>, downloads: string, programs: string, startMenu: string;
const mk = (...parts: string[]) => { const p = path.join(...parts); fs.mkdirSync(p, { recursive: true }); return p; };
const put = (p: string, text = 'x') => { mk(path.dirname(p)); fs.writeFileSync(p, text); return p; };
const OLD = new Date(Date.now() - 60 * 86_400_000);
/** Sets every entry of a tree (children first) to OLD, so the folder itself ends up old too. */
function age(p: string) {
  if (fs.lstatSync(p).isDirectory()) for (const e of fs.readdirSync(p)) age(path.join(p, e));
  fs.utimesSync(p, OLD, OLD);
}
const program = (over: Partial<Program> = {}): Program => ({ id: 'P-000000', name: 'Other App', hive: 'HKCU', view: '64', keyName: 'OtherApp', ...over });
const inst = (over: InstallerDeps = {}): InstallerDeps => ({ downloadsDir: downloads, isLocked: () => false, ...over });
const orph = (over: OrphanDeps = {}): OrphanDeps => ({ env, listPrograms: () => [program()], shortcutTargets: () => new Map(), otherRefs: () => [], ...over });
const targetsOf = (items: ScanItem[]) => items.flatMap((i) => i.targets.map((t) => t.toLowerCase())).sort();

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-io-')));
  const home = mk(root, 'home');
  env = { APPDATA: mk(home, 'AppData', 'Roaming'), LOCALAPPDATA: mk(home, 'AppData', 'Local'), ProgramData: mk(root, 'pd') };
  downloads = mk(home, 'Downloads');
  programs = mk(env.LOCALAPPDATA!, 'Programs');
  startMenu = mk(env.APPDATA!, 'Microsoft', 'Windows', 'Start Menu', 'Programs');
  ctx = {
    stateDir: path.join(env.LOCALAPPDATA!, 'hydra-bane'),
    tempDir: mk(root, 'temp'),
    home,
    locate: () => undefined,
    roots: [],
    // Like the real set P: the profile and the Downloads known folder.
    protectedPaths: [home, downloads, path.join(home, 'Documents')],
    sid: 'S-1-5-21-io',
    now: () => new Date(),
    confirmer: { confirm: async () => true },
    run: () => ({ status: 0, stderr: '' }),
    quarantineBaseFor: () => path.join(root, 'quarantine'),
    isRunning: () => false,
  };
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe('installer names', () => {
  it('takes installer extensions, and zips only when the name says installer', () => {
    for (const n of ['Foo.exe', 'foo.MSI', 'app.msixbundle', 'x.appx', 'ubuntu.iso', 'pi.img', 'a.dmg', 'b.pkg']) expect(isInstallerName(n)).toBe(true);
    for (const n of ['FooSetup.zip', 'foo-installer.zip', 'tool_portable.zip', 'app-1.2.3-win64.zip', 'node-v22.1.0-x64.zip', 'Install Me.zip']) expect(zipLooksLikeInstaller(n)).toBe(true);
    for (const n of ['photos 2024.05.zip', 'report-v1.2.zip', 'win64.zip', 'reinstallation notes.zip', 'thesis.zip']) expect(zipLooksLikeInstaller(n)).toBe(false);
    for (const n of ['notes.txt', 'photo.jpg', 'foo.exe.crdownload', 'thesis.zip']) expect(isInstallerName(n)).toBe(false);
  });
});

describe.runIf(process.platform === 'win32')('Downloads and the guard', () => {
  it('denies Downloads itself, and ignores Downloads as an allow root because it is in P', () => {
    const f = put(path.join(downloads, 'setup.exe'));
    expect(decide(downloads, 'disk', policyFor(ctx, [downloads]))).toMatchObject({ allowed: false, code: 'PROTECTED_OR_ANCESTOR' });
    // An allow root in P is ignored, so a grouped item with allowRoot = Downloads could never be applied.
    expect(decide(f, 'disk', policyFor(ctx, [downloads]))).toMatchObject({ allowed: false, code: 'NOT_ALLOWLISTED' });
    // Hence one item per file, allowed exactly at that file.
    expect(decide(f, 'disk', policyFor(ctx, [f]))).toMatchObject({ allowed: true });
    expect(decide(path.join(downloads, 'other.exe'), 'disk', policyFor(ctx, [f]))).toMatchObject({ allowed: false, code: 'NOT_ALLOWLISTED' });
  });
});

describe.runIf(process.platform === 'win32')('installers scan', () => {
  it('offers old installer files at the top level of Downloads, one item per file', () => {
    const offered = ['Foo Setup 1.2.exe', 'bar.msi', 'ubuntu-24.04.iso', 'tool-portable.zip'].map((n) => put(path.join(downloads, n)));
    const img = put(path.join(downloads, 'card-backup.img'));
    const refused = [
      put(path.join(downloads, 'new.exe')), // recent
      put(path.join(downloads, 'photos 2024.05.zip')), // not an installer zip
      put(path.join(downloads, 'notes.txt')),
      put(path.join(downloads, 'sub', 'deep.exe')), // not top level
      put(path.join(downloads, 'locked.msi')),
    ];
    mk(downloads, 'folder.exe'); // a folder, not a file
    for (const p of [...offered, img, ...refused]) if (!p.endsWith('new.exe')) age(p);
    const items = scanInstallers(ctx, inst({ isLocked: (f) => f.endsWith('locked.msi') }));
    expect(targetsOf(items)).toEqual([...offered, img].map((p) => p.toLowerCase()).sort());
    for (const i of items) {
      expect(i).toMatchObject({ category: 'installers', risk: 'caution', allowRoot: i.targets[0], targetNames: [path.basename(i.targets[0]!)] });
      expect(i.id).toMatch(/^INST-[0-9a-f]{6}$/);
    }
    const byName = new Map(items.map((i) => [path.basename(i.targets[0]!), i]));
    expect(byName.get('Foo Setup 1.2.exe')).toMatchObject({ op: 'quarantine', reversible: 'move-back', requiresClosed: ['Foo Setup 1.2.exe'] });
    expect(byName.get('card-backup.img')).toMatchObject({ op: 'report_only', reversible: 'none', instructions: expect.stringContaining('backup') });
  });

  it('finds nothing when Downloads is missing, a drive root or not a path', () => {
    expect(scanInstallers(ctx, inst({ downloadsDir: path.join(root, 'nope') }))).toEqual([]);
    expect(scanInstallers(ctx, inst({ downloadsDir: path.parse(root).root }))).toEqual([]);
    expect(scanInstallers(ctx, inst({ downloadsDir: 'relative\\Downloads' }))).toEqual([]);
  });

  it('applies by moving exactly that file to quarantine, and undo puts it back', async () => {
    const f = put(path.join(downloads, 'setup.exe'), 'installer');
    const keep = put(path.join(downloads, 'keep.txt'));
    age(f);
    const items = scanInstallers(ctx, inst());
    const plan = makePlan(ctx, items);
    const r = await apply(ctx, plan.id);
    expect(r).toMatchObject({ ok: true, outcomes: [{ ok: true, target: f }] });
    expect(fs.existsSync(f)).toBe(false);
    expect(fs.existsSync(keep)).toBe(true);
    expect(fs.existsSync(downloads)).toBe(true);
    expect(await undo(ctx, plan.id)).toMatchObject({ ok: true });
    expect(fs.readFileSync(f, 'utf8')).toBe('installer');
  });

  it('refuses at apply time while the installer is running', async () => {
    const f = put(path.join(downloads, 'setup.exe'));
    age(f);
    const plan = makePlan(ctx, scanInstallers(ctx, inst()));
    expect(await apply({ ...ctx, isRunning: (exe) => exe === 'setup.exe' }, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: false, code: 'APP_RUNNING' }] });
    expect(fs.existsSync(f)).toBe(true);
  });
});

describe.runIf(process.platform === 'win32')('orphans scan', () => {
  const app = (name: string, files: string[] = ['app.exe']) => {
    const d = mk(programs, name);
    for (const f of files) put(path.join(d, f));
    age(d);
    return d;
  };

  it('offers an old per-user program folder that nothing references', () => {
    const d = app('Gone App', ['Gone.exe', 'resources/app.asar']);
    const items = scanOrphans(ctx, orph());
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ category: 'orphans', op: 'quarantine', risk: 'caution', reversible: 'move-back', targets: [d], allowRoot: programs, targetNames: ['Gone App'], requiresClosed: ['Gone.exe'] });
    expect(items[0]!.id).toMatch(/^ORPHAN-[0-9a-f]{6}$/);
  });

  it('refuses folders an installed program, a shortcut, a Run entry or PATH points into', () => {
    const a = app('ByLocation'), b = app('ByIcon'), c = app('ByUninstall'), d = app('ByShortcut'), e = app('ByRun'), f = app('ByEnvVar'), g = app('Acme'), h = app('OnPath');
    const lnk = put(path.join(env.ProgramData!, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'd.lnk'));
    const deps = orph({
      listPrograms: () => [
        program({ installLocation: a.toUpperCase() + '\\' }),
        program({ displayIcon: `"${path.join(b, 'bin', 'x.exe')}",0` }),
        program({ uninstallString: `"${path.join(c, 'Uninstall.exe')}" /currentuser` }),
        program({ uninstallString: '%LOCALAPPDATA%/Programs/ByEnvVar/unins000.exe' }),
        program({ name: 'Rocket', publisher: 'Acme, Inc.', installLocation: path.join(root, 'pf', 'Rocket') }),
      ],
      shortcutTargets: (files) => new Map(files.map((x) => [x, x === lnk ? path.join(d, 'app.exe') : 'C:\\Windows\\notepad.exe'])),
      otherRefs: () => [`"${path.join(e, 'app.exe')}" --autostart`, `C:\\Windows;${path.join(h, 'bin-v2')}`],
    });
    const items = scanOrphans(ctx, deps);
    expect(targetsOf(items)).toEqual([]);
    for (const x of [a, b, c, d, e, f, g, h]) expect(fs.existsSync(x)).toBe(true);
  });

  it('a reference to a longer sibling name does not protect a different folder, but a prefix match errs on refusing', () => {
    const foo = app('Foo');
    app('Foo2');
    const items = scanOrphans(ctx, orph({ listPrograms: () => [program({ installLocation: path.join(programs, 'Foo2') })] }));
    expect(targetsOf(items)).toEqual([foo.toLowerCase()]);
    // "Foo Bar" contains "Foo" followed by a space: treated as a reference to Foo (conservative).
    expect(scanOrphans(ctx, orph({ listPrograms: () => [program({ installLocation: path.join(programs, 'Foo Bar') })] })).map((i) => i.targets[0])).not.toContain(foo);
  });

  it('refuses recent, exe-less, git, Common and linked folders, and reports document-heavy ones', () => {
    const recent = mk(programs, 'Recent');
    put(path.join(recent, 'app.exe'));
    age(recent);
    put(path.join(recent, 'new.log')); // one recent file is enough
    app('NoExe', ['readme.txt', 'lib/x.dll']);
    app('Repo', ['app.exe', '.git/HEAD']);
    app('Common', ['shared.exe']);
    const target = app('LinkTarget');
    fs.symlinkSync(target, path.join(programs, 'Junction'), 'junction');
    const docs = app('Docs', ['app.exe', 'a.docx', 'b.pdf', 'c.jpg']);
    const items = scanOrphans(ctx, orph({ listPrograms: () => [program({ installLocation: target })] }));
    expect(targetsOf(items)).toEqual([docs.toLowerCase()]);
    expect(items[0]).toMatchObject({ op: 'report_only', reversible: 'none', instructions: expect.stringContaining('3 documents') });
  });

  it('offers nothing in Programs once a protected path lies inside it (the guard drops the whole root)', () => {
    app('Gone App');
    const prot = app('Guarded', ['app.exe', 'Synced/a.txt']);
    ctx.protectedPaths.push(path.join(prot, 'Synced'));
    expect(scanOrphans(ctx, orph())).toEqual([]);
  });

  it('never offers the Hydra-bane state folder', () => {
    const programsState = mk(programs, 'hydra-bane');
    put(path.join(programsState, 'x.exe'));
    age(programsState);
    expect(scanOrphans({ ...ctx, stateDir: programsState }, orph())).toEqual([]);
  });

  it('refuses a folder whose name is an installed program or publisher', () => {
    app('Foo Editor');
    app('Acme');
    const items = scanOrphans(ctx, orph({ listPrograms: () => [program({ name: 'Foo Editor 2.1 (x64)', publisher: 'Acme Corporation', installLocation: path.join(root, 'pf', 'x') })] }));
    expect(items).toEqual([]);
  });

  it('reads no program list and no Run keys when there is no candidate folder', () => {
    let read = false;
    expect(scanOrphans(ctx, orph({ listPrograms: () => { read = true; return []; }, otherRefs: () => { read = true; return []; } }))).toEqual([]);
    expect(read).toBe(false);
  });

  it('groups user Start Menu shortcuts whose target is gone, and only those', async () => {
    const dead1 = put(path.join(startMenu, 'Gone.lnk'));
    const dead2 = put(path.join(startMenu, 'Vendor', 'Gone Too.lnk'));
    const alive = put(path.join(startMenu, 'Alive.lnk'));
    const unc = put(path.join(startMenu, 'Share.lnk'));
    const noDrive = put(path.join(startMenu, 'Usb.lnk'));
    const empty = put(path.join(startMenu, 'Advertised.lnk'));
    const tgt = new Map([
      [dead1, path.join(root, 'missing', 'gone.exe')], [dead2, path.join(root, 'gone2.exe')], [alive, alive],
      [unc, '\\\\server\\share\\app.exe'], [noDrive, 'Q:\\nowhere\\app.exe'], [empty, ''],
    ]);
    const items = scanOrphans(ctx, orph({ shortcutTargets: () => tgt }));
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ id: 'DEAD-SHORTCUTS', category: 'orphans', op: 'quarantine', allowRoot: startMenu, title: expect.stringContaining('(2)') });
    expect(targetsOf(items)).toEqual([dead1, dead2].map((p) => p.toLowerCase()).sort());

    const plan = makePlan(ctx, items);
    expect(await apply(ctx, plan.id)).toMatchObject({ ok: true, outcomes: [{ ok: true }, { ok: true }] });
    expect([dead1, dead2].map((p) => fs.existsSync(p))).toEqual([false, false]);
    expect(fs.existsSync(alive)).toBe(true);
  });
});

describe.runIf(process.platform === 'win32')('property: targets stay inside the scan roots', () => {
  it('random trees never yield a target outside Downloads (top level), Programs (top level) or the Start Menu', () => {
    const seg = fc.constantFrom('a', 'b', 'App', 'Common', '.git', 'x.exe', 'setup.exe', 'y.msi', 'z.iso', 'p.zip', 'q-setup.zip', 'doc.pdf', 'l.lnk', 'k');
    const tree = fc.array(fc.tuple(fc.constantFrom('dl', 'pr', 'sm', 'home'), fc.array(seg, { minLength: 1, maxLength: 4 }), fc.boolean(), fc.boolean()), { maxLength: 25 });
    fc.assert(fc.property(tree, (entries) => {
      for (const r of [downloads, programs, startMenu]) { fs.rmSync(r, { recursive: true, force: true }); mk(r); }
      const bases = { dl: downloads, pr: programs, sm: startMenu, home: ctx.home };
      for (const [base, segs, asDir, old] of entries) {
        const p = path.join(bases[base], ...segs);
        try {
          if (asDir) mk(p); else put(p);
          if (old) age(p);
        } catch { /* a file where a folder is wanted, or the reverse: skip */ }
      }
      for (const r of [downloads, programs]) age(r);
      const items = [
        ...scanInstallers(ctx, inst()),
        ...scanOrphans(ctx, orph({ shortcutTargets: (files) => new Map(files.map((f) => [f, path.join(root, 'gone', path.basename(f))])) })),
      ];
      for (const i of items) {
        for (const t of i.targets) {
          const ok = i.category === 'installers' ? path.dirname(t).toLowerCase() === downloads.toLowerCase()
            : i.id === 'DEAD-SHORTCUTS' ? isSameOrDescendant(t, startMenu) && t.toLowerCase() !== startMenu.toLowerCase()
            : path.dirname(t).toLowerCase() === programs.toLowerCase();
          expect(ok, `${i.id} ${t}`).toBe(true);
          expect(decide(t, 'disk', policyFor(ctx, [i.allowRoot])).allowed || i.op === 'report_only').toBe(true);
          for (const p of ctx.protectedPaths) expect(isSameOrDescendant(p, t)).toBe(false);
        }
      }
    }), { numRuns: 40 });
  });
});
