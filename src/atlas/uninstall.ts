import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { ScanItem, UninstallSpec } from '../core/scan.ts';
import { atlasItemId, entryThumbprints, GUID, keyMatches, signerMatches, type AtlasBundle, type AtlasEntry } from './entry.ts';
import { listPrograms as defaultListPrograms, UNINSTALL_ROOTS, type Program } from './programs.ts';
import { authenticode, mainExecutable, type Signer, type SignerOf } from './report.ts';
import { userWritable as defaultUserWritable } from '../core/admin.ts';

// Vendor uninstaller rules (PLAN.md §7.3). The registry's UninstallString is data, never a command line:
// MSI commands are built from the product code alone, EXE uninstallers are parsed and must earn trust:
// Atlas items by a pinned Authenticode signature; any other program (category 'app') by a valid signature from
// its own publisher, or (HKLM only) by living in a folder only administrators can write.
// QuietUninstallString is never used (interactive vendor UI only).
// HKCU keys are writable by the user and by anything running as the user, so their content proves nothing:
// the trust must come from the file (its signature), never from the key or its folder.

export interface UninstallDeps {
  signerOf?: SignerOf;
  exists?: (file: string) => boolean;
  env?: Record<string, string | undefined>;
  /** Non-admin trustees that can write a folder or file ('UNKNOWN' = unreadable ACL). */
  userWritable?: (target: string) => string[] | 'UNKNOWN';
}

const BLOCKED = /^(cmd|powershell|pwsh|rundll32|mshta|wscript|cscript|msiexec|conhost|explorer|regsvr32)\.exe$/i;
const DRIVE_PATH = /[a-z]:\\[^;,"]*/gi; // args are already split, so a path may contain spaces
const isFile = (f: string) => { try { return fs.statSync(f).isFile(); } catch { return false; } };
const under = (p: string, dir: string | undefined) => {
  if (!dir) return false;
  const a = path.win32.normalize(p).toLowerCase(), d = path.win32.normalize(dir).replace(/\\+$/, '').toLowerCase();
  return a === d || a.startsWith(d + '\\');
};

/** Split an UninstallString into an executable and its arguments. No shell ever sees the result. */
export function parseUninstallString(raw: string, env: Record<string, string | undefined> = process.env): { file: string; args: string[] } | { reason: string } {
  if (/[&|<>^\r\n\0`]/.test(raw)) return { reason: 'uninstall string contains shell metacharacters' };
  let bad = false;
  const s = raw.trim().replace(/%([^%\s]+)%/g, (all, n: string) => { const v = env[n]; if (v === undefined) bad = true; return v ?? all; });
  if (bad || s.includes('%')) return { reason: 'uninstall string has an unknown or malformed %VARIABLE%' };
  const m = /^"([^"]+)"(.*)$/.exec(s) ?? /^([^"]+?\.exe)(?=\s|$)(.*)$/i.exec(s);
  if (!m) return { reason: 'uninstall string does not start with an .exe path' };
  const rest = m[2]!;
  if ((rest.match(/"/g) ?? []).length % 2) return { reason: 'unbalanced quotes in uninstall arguments' };
  const args = [...rest.matchAll(/"([^"]*)"|([^\s"]+)/g)].map((t) => t[1] ?? t[2]!);
  return { file: m[1]!.trim(), args };
}

const msiexec = (env: Record<string, string | undefined>) => {
  const file = path.win32.join(env.SystemRoot ?? 'C:\\Windows', 'System32', 'msiexec.exe');
  return path.win32.isAbsolute(file) ? file : undefined;
};

/** Checks shared by every EXE uninstaller: parsed, no shell or LOLBin, plain local path, no arguments outside the program. */
function checkExe(p: Program, deps: UninstallDeps, nameCheck?: (name: string) => string | undefined): { file: string; args: string[] } | { reason: string } {
  if (!p.uninstallString) return { reason: 'the program has no UninstallString' };
  const parsed = parseUninstallString(p.uninstallString, deps.env ?? process.env);
  if ('reason' in parsed) return parsed;
  const { file, args } = parsed;
  const name = path.win32.basename(file);
  if (BLOCKED.test(name)) return { reason: `uninstall string runs ${name}, which is never allowed` };
  const bad = nameCheck?.(name);
  if (bad) return { reason: bad };
  if (!/^[a-z]:\\/i.test(file) || path.win32.normalize(file) !== file) return { reason: 'uninstaller path is not a plain absolute local path' };
  if (!(deps.exists ?? isFile)(file)) return { reason: `uninstaller not found: ${file}` };
  // NSIS `_?=<dir>` makes the uninstaller treat <dir> as its install folder and delete it.
  if (args.some((a) => /_\?=/.test(a))) return { reason: 'uninstall arguments redirect the install folder (_?=)' };
  const dirs = [path.win32.dirname(file), p.installLocation];
  for (const a of args) for (const pth of a.match(DRIVE_PATH) ?? []) if (!dirs.some((d) => under(pth, d))) return { reason: `uninstall argument points outside the program folder: ${pth}` };
  return { file, args };
}

export function buildUninstall(p: Program, e: AtlasEntry, deps: UninstallDeps = {}): UninstallSpec | { reason: string } {
  if (e.uninstall.command_source === 'msi-product-code') {
    const code = p.msiProductCode?.toUpperCase();
    if (!code || !GUID.test(code)) return { reason: 'not installed with Windows Installer (no product code)' };
    const listed = e.uninstall.msi_product_codes.map((g) => g.toUpperCase());
    if (listed.length ? !listed.includes(code) : !keyMatches(e, p)) return { reason: `product code ${code} is not one the Atlas entry lists` };
    const file = msiexec(deps.env ?? process.env);
    if (!file) return { reason: 'SystemRoot is not an absolute path' };
    return { entryId: e.id, trust: 'atlas', kind: 'msi', file, args: ['/x', code], signers: [] };
  }

  const exe = checkExe(p, deps, (name) => (!e.uninstall.exe_name || name.toLowerCase() !== e.uninstall.exe_name.toLowerCase() ? `uninstaller ${name} is not the one the Atlas entry names (${e.uninstall.exe_name ?? 'none'})` : undefined));
  if ('reason' in exe) return exe;
  const { file, args } = exe;
  const allowed = entryThumbprints(e);
  if (!allowed.length) return { reason: 'the Atlas entry pins no signer thumbprint' };
  const sig = (deps.signerOf ?? authenticode)(file);
  if (sig?.status !== 'Valid') return { reason: `uninstaller signature is ${sig?.status ?? 'unreadable'}` };
  if (!sig.thumbprint || !allowed.includes(sig.thumbprint.toUpperCase())) return { reason: `uninstaller is signed by ${sig.subject ?? 'an unknown signer'}, not a certificate the Atlas entry pins` };
  return { entryId: e.id, trust: 'atlas', kind: 'exe', file, args, signers: allowed };
}

// Legal-form words that differ between a registry Publisher and a certificate subject ("Co., Ltd." vs "Co.,Ltd").
const LEGAL = new Set(['inc', 'incorporated', 'llc', 'ltd', 'limited', 'co', 'corp', 'corporation', 'company', 'gmbh', 'ag', 'sa', 'sas', 'bv', 'nv', 'plc', 'kk', 'pty', 'pte', 'oy', 'ab', 'as', 'srl', 'spa', 'the', '주식회사', '주']);
export const normalizeOrg = (s: string | undefined) =>
  (s ?? '').normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim().split(' ').filter((w) => w && !LEGAL.has(w)).join(' ');

/** O= and CN= values of a certificate subject (quoted values may contain commas). */
export const subjectOrgs = (subject: string | undefined) =>
  [...(subject ?? '').matchAll(/(?:^|,)\s*(?:O|CN)=("(?:[^"]|"")*"|[^,]*)/g)].map((m) => m[1]!.replace(/^"|"$/g, '').replace(/""/g, '"').trim());

export const publisherMatches = (subject: string | undefined, publisher: string | undefined) => {
  const want = normalizeOrg(publisher);
  return !!want && subjectOrgs(subject).some((o) => normalizeOrg(o) === want);
};

/** Scan-item id of a general uninstall: stable, derived from the program id (P-xxxxxx). */
export const appItemId = (p: Program) => `APP-${p.id.replace(/^P-/, '')}`;

/**
 * A program not vouched for by the Atlas (PLAN.md §7.3, v0.3). One of these must hold, checked in this order:
 * 'msi' (Windows Installer product: we build msiexec /x {GUID}), 'signed' (valid Authenticode signature whose O= or
 * CN= is the program's Publisher, or whose certificate also signs the program's main executable), 'admin-folder'
 * (HKLM key and an uninstaller that only administrators can write). Otherwise a reason is returned (report only).
 */
export function buildGeneralUninstall(p: Program, deps: UninstallDeps = {}): UninstallSpec | { reason: string } {
  const env = deps.env ?? process.env;
  const code = p.msiProductCode?.toUpperCase();
  if (code && GUID.test(code) && code === p.keyName.toUpperCase()) {
    const file = msiexec(env);
    if (!file) return { reason: 'SystemRoot is not an absolute path' };
    return { trust: 'msi', kind: 'msi', file, args: ['/x', code], signers: [] };
  }
  const exe = checkExe(p, deps);
  if ('reason' in exe) return exe;
  const { file, args } = exe;
  // Windows' own signed binaries are not uninstallers; with a forged Publisher they would pass the signature rule.
  if (env.SystemRoot && under(file, env.SystemRoot)) return { reason: `uninstaller is inside the Windows folder (${file}), which a program's own uninstaller never is` };

  const signerOf = deps.signerOf ?? authenticode;
  const sig = signerOf(file);
  if (sig?.status === 'Valid' && sig.thumbprint) {
    const tp = sig.thumbprint.toUpperCase();
    const main = mainExecutable(p, env);
    const sameAsMain = (): boolean => { if (!main || main.toLowerCase() === file.toLowerCase()) return false; const m: Signer | undefined = signerOf(main); return m?.status === 'Valid' && m.thumbprint?.toUpperCase() === tp; };
    if (publisherMatches(sig.subject, p.publisher) || sameAsMain()) return { trust: 'signed', kind: 'exe', file, args, signers: [tp] };
  }
  const sigText = sig?.status === 'Valid' ? `signed by ${sig.subject ?? 'an unknown signer'}, which is not the publisher "${p.publisher ?? 'unknown'}"` : `signature is ${sig?.status ?? 'unreadable'}`;
  if (p.hive !== 'HKLM') return { reason: `the uninstaller's ${sigText}, and the program is registered per user (HKCU), where any program running as you could have written it` };
  const writable = deps.userWritable ?? ((t: string) => defaultUserWritable(t));
  for (const t of [path.win32.dirname(file), file]) {
    const w = writable(t);
    if (w === 'UNKNOWN') return { reason: `the uninstaller's ${sigText}, and the permissions of ${t} could not be read` };
    if (w.length) return { reason: `the uninstaller's ${sigText}, and ${t} can be changed by ${w.join(', ')}` };
  }
  return { trust: 'admin-folder', kind: 'exe', file, args, signers: [] };
}

export interface RunDeps extends UninstallDeps {
  bundle: AtlasBundle | undefined;
  listPrograms?: () => Program[];
  spawn?: (file: string, args: string[]) => { status: number | null; error?: Error | undefined };
}

export interface UninstallResult { ok: boolean; code: number | null; detail: string; rebootRequired: boolean; stillInstalled: boolean }

const refuse = (detail: string): UninstallResult => ({ ok: false, code: null, detail: `refused: ${detail}`, rebootRequired: false, stillInstalled: true });

/**
 * Runs the vendor uninstaller without a shell. Uninstallers whose manifest requires administrator rights cannot be
 * started by CreateProcess (ERROR_ELEVATION_REQUIRED); those are started through ShellExecute "runas", so Windows
 * shows its own UAC prompt naming the vendor's signed executable. Path and arguments travel in env vars.
 */
export function spawnVendor(file: string, args: string[]): { status: number | null; error?: Error | undefined } {
  const r = spawnSync(file, args, { windowsHide: false, stdio: 'ignore' });
  const code = String((r.error as NodeJS.ErrnoException | undefined)?.code ?? '');
  if (r.status !== null || !/EACCES|740/.test(code + (r.error?.message ?? ''))) return { status: r.status, error: r.error };
  const quoted = args.map((a) => (/\s/.test(a) ? `"${a}"` : a));
  const ps = '$ErrorActionPreference="Stop"; try { $a = @(ConvertFrom-Json $env:HB_ARGS); $p = if ($a.Count) { Start-Process -FilePath $env:HB_FILE -ArgumentList $a -Verb RunAs -Wait -PassThru } else { Start-Process -FilePath $env:HB_FILE -Verb RunAs -Wait -PassThru }; exit $p.ExitCode } catch { exit 1223 }';
  const e = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { windowsHide: true, stdio: 'ignore', env: { ...process.env, HB_FILE: file, HB_ARGS: JSON.stringify(quoted) } });
  return { status: e.status, error: e.error };
}

/** Apply time: everything checked at scan time is checked again before the uninstaller runs. */
export function runUninstall(item: ScanItem, deps: RunDeps): UninstallResult {
  const spec = item.uninstall;
  if (item.op !== 'uninstall' || !spec) return refuse('item is not an uninstall');
  const list = deps.listPrograms ?? (() => defaultListPrograms());
  const signerOf = deps.signerOf ?? authenticode;
  let program: Program | undefined, now: UninstallSpec | { reason: string };
  if (spec.entryId === undefined) {
    if (spec.trust === 'atlas') return refuse('an Atlas uninstall without its Atlas entry');
    program = list().find((p) => appItemId(p) === item.id);
    if (!program) return refuse('the program is no longer listed in the Uninstall keys');
    now = buildGeneralUninstall(program, { ...deps, signerOf });
  } else {
    const entry = deps.bundle?.entries.find((x) => x.id === spec.entryId);
    if (!entry) return refuse(`Atlas entry ${spec.entryId} is not in the installed bundle`);
    program = list().find((p) => atlasItemId(entry.id, p.id) === item.id);
    if (!program) return refuse('the program is no longer listed in the Uninstall keys');
    const exe = mainExecutable(program, deps.env ?? process.env);
    if (!keyMatches(entry, program) && !signerMatches(entry, exe ? signerOf(exe) : undefined)) return refuse('the uninstall key no longer matches the Atlas entry');
    now = buildUninstall(program, entry, { ...deps, signerOf });
  }
  if ('reason' in now) return refuse(now.reason);
  if (now.trust !== spec.trust) return refuse(`the uninstaller is now trusted as ${now.trust}, not ${spec.trust} as when the plan was made`);
  if (now.kind !== spec.kind || now.file !== spec.file || JSON.stringify(now.args) !== JSON.stringify(spec.args)) return refuse('the uninstall command changed since the scan');
  if (now.kind === 'exe' && now.trust !== 'admin-folder' && !now.signers.some((t) => spec.signers.includes(t))) return refuse('signer pins changed since the scan');
  if (now.kind === 'msi' && !(deps.exists ?? isFile)(now.file)) return refuse(`${now.file} not found`);

  const spawn = deps.spawn ?? spawnVendor;
  const r = spawn(now.file, now.args);
  const stillInstalled = list().some((p) => p.hive === program.hive && p.view === program.view && p.keyName.toLowerCase() === program.keyName.toLowerCase());
  const base = { code: r.status, stillInstalled };
  if (r.status === null) {
    const elev = /EACCES|740/.test(String((r.error as NodeJS.ErrnoException | undefined)?.code ?? r.error?.message));
    return { ...base, ok: false, rebootRequired: false, detail: elev ? 'the uninstaller needs administrator rights: run hydra-bane from an elevated terminal' : `could not start the uninstaller: ${r.error?.message ?? 'unknown error'}` };
  }
  const reboot = r.status === 3010 || r.status === 1641;
  const ok = r.status === 0 || reboot;
  const detail = ok
    ? (stillInstalled ? 'uninstaller finished, but the program is still listed (it may still be running, or was cancelled): scan again later' : 'removed') + (reboot ? '; restart Windows to finish' : '')
    : r.status === 1602 ? 'cancelled in the uninstaller window'
    : r.status === 1223 ? 'the administrator prompt was declined'
    : r.status === 1603 ? 'the uninstaller reported a fatal error (1603)'
    : `the uninstaller exited with code ${r.status}`;
  return { ...base, ok, rebootRequired: reboot, detail };
}

/** Plain-language reason a vendor uninstaller may run, for titles and the approval prompt. */
export function trustText(spec: UninstallSpec): string {
  switch (spec.trust) {
    case 'atlas': return `signed with a certificate the Atlas entry ${spec.entryId ?? ''} pins`;
    case 'msi': return 'Windows Installer, command built by Hydra-bane from the product code';
    case 'signed': return `valid signature of the program's publisher (certificate ${spec.signers[0] ?? '?'})`;
    case 'admin-folder': return 'machine-wide install; only administrators can change the uninstaller';
  }
}

export const commandLine = (spec: UninstallSpec) => [spec.file, ...spec.args].map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(' ');

const regKey = (p: Program) => `${UNINSTALL_ROOTS.find((r) => r.hive === p.hive && r.view === p.view)?.key ?? p.hive}\\${p.keyName}`;

/** One general uninstall item (category 'app') for a program the user named. Builds nothing it would run blindly. */
export function appItem(p: Program, deps: UninstallDeps = {}): ScanItem {
  const spec = buildGeneralUninstall(p, deps);
  const label = `${p.name}${p.version && !p.name.includes(p.version) ? ` ${p.version}` : ''}${p.publisher ? ` (${p.publisher})` : ''}`;
  const target = p.installLocation && /^[a-z]:\\/i.test(p.installLocation) ? p.installLocation : regKey(p);
  const base = {
    id: appItemId(p), category: 'app' as const, targets: [target], allowRoot: target, bytes: p.estimatedBytes ?? 0, files: 0,
    risk: 'caution' as const, reversible: 'reinstall-only' as const,
    program: { id: p.id, name: p.name, publisher: p.publisher, version: p.version, hive: p.hive, view: p.view, keyName: p.keyName, installLocation: p.installLocation },
  };
  if ('reason' in spec) {
    return { ...base, op: 'report_only', title: `${label}: remove it in Settings > Apps (Hydra-bane will not run its uninstaller)`,
      instructions: `Open Settings > Apps > Installed apps, find "${p.name}" and choose Uninstall. Hydra-bane will not run its uninstaller: ${spec.reason}.` };
  }
  // ponytail: per-machine EXE uninstallers usually demand elevation, and CreateProcess cannot raise UAC; MSI elevates itself.
  return { ...base, op: 'uninstall', uninstall: spec, ...(p.hive === 'HKLM' && spec.kind === 'exe' ? { needsAdmin: true } : {}),
    title: `Uninstall ${label}: runs ${commandLine(spec)} [trust: ${spec.trust}]`,
    instructions: `Runs the program's own uninstaller (${trustText(spec)}); its window opens and you finish there. Leftover files and settings are not removed by the uninstaller: scan them afterwards with: hydra-bane scan --only leftovers` };
}
