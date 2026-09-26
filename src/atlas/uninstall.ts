import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { ScanItem, UninstallSpec } from '../core/scan.ts';
import { atlasItemId, entryThumbprints, GUID, keyMatches, signerMatches, type AtlasBundle, type AtlasEntry } from './entry.ts';
import { listPrograms as defaultListPrograms, type Program } from './programs.ts';
import { authenticode, mainExecutable, type SignerOf } from './report.ts';

// Vendor uninstaller rules (PLAN.md §7.3). The registry's UninstallString is data, never a command line:
// MSI commands are built from the product code alone, EXE uninstallers are parsed and must carry a pinned
// Authenticode signature. QuietUninstallString is never used in v0.2 (interactive vendor UI only).
// HKCU keys are writable by the user and by anything running as the user, so their content proves nothing.
// They are still accepted because the trust does not come from the key: the file it points to must be
// signed with a certificate the Atlas entry pins, and arguments may not point outside the program's folders.

export interface UninstallDeps {
  signerOf?: SignerOf;
  exists?: (file: string) => boolean;
  env?: Record<string, string | undefined>;
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

export function buildUninstall(p: Program, e: AtlasEntry, deps: UninstallDeps = {}): UninstallSpec | { reason: string } {
  const env = deps.env ?? process.env;
  if (e.uninstall.command_source === 'msi-product-code') {
    const code = p.msiProductCode?.toUpperCase();
    if (!code || !GUID.test(code)) return { reason: 'not installed with Windows Installer (no product code)' };
    const listed = e.uninstall.msi_product_codes.map((g) => g.toUpperCase());
    if (listed.length ? !listed.includes(code) : !keyMatches(e, p)) return { reason: `product code ${code} is not one the Atlas entry lists` };
    const file = path.win32.join(env.SystemRoot ?? 'C:\\Windows', 'System32', 'msiexec.exe');
    if (!path.win32.isAbsolute(file)) return { reason: 'SystemRoot is not an absolute path' };
    return { entryId: e.id, kind: 'msi', file, args: ['/x', code], signers: [] };
  }

  if (!p.uninstallString) return { reason: 'the program has no UninstallString' };
  const parsed = parseUninstallString(p.uninstallString, env);
  if ('reason' in parsed) return parsed;
  const { file, args } = parsed;
  const name = path.win32.basename(file);
  if (BLOCKED.test(name)) return { reason: `uninstall string runs ${name}, which is never allowed` };
  if (!e.uninstall.exe_name || name.toLowerCase() !== e.uninstall.exe_name.toLowerCase()) return { reason: `uninstaller ${name} is not the one the Atlas entry names (${e.uninstall.exe_name ?? 'none'})` };
  if (!/^[a-z]:\\/i.test(file) || path.win32.normalize(file) !== file) return { reason: 'uninstaller path is not a plain absolute local path' };
  if (!(deps.exists ?? isFile)(file)) return { reason: `uninstaller not found: ${file}` };
  // NSIS `_?=<dir>` makes the uninstaller treat <dir> as its install folder and delete it.
  if (args.some((a) => /_\?=/.test(a))) return { reason: 'uninstall arguments redirect the install folder (_?=)' };
  const dirs = [path.win32.dirname(file), p.installLocation];
  for (const a of args) for (const pth of a.match(DRIVE_PATH) ?? []) if (!dirs.some((d) => under(pth, d))) return { reason: `uninstall argument points outside the program folder: ${pth}` };
  const allowed = entryThumbprints(e);
  if (!allowed.length) return { reason: 'the Atlas entry pins no signer thumbprint' };
  const sig = (deps.signerOf ?? authenticode)(file);
  if (sig?.status !== 'Valid') return { reason: `uninstaller signature is ${sig?.status ?? 'unreadable'}` };
  if (!sig.thumbprint || !allowed.includes(sig.thumbprint.toUpperCase())) return { reason: `uninstaller is signed by ${sig.subject ?? 'an unknown signer'}, not a certificate the Atlas entry pins` };
  return { entryId: e.id, kind: 'exe', file, args, signers: allowed };
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
  const entry = deps.bundle?.entries.find((x) => x.id === spec.entryId);
  if (!entry) return refuse(`Atlas entry ${spec.entryId} is not in the installed bundle`);
  const list = deps.listPrograms ?? (() => defaultListPrograms());
  const program = list().find((p) => atlasItemId(entry.id, p.id) === item.id);
  if (!program) return refuse('the program is no longer listed in the Uninstall keys');
  const signerOf = deps.signerOf ?? authenticode;
  const exe = mainExecutable(program, deps.env ?? process.env);
  if (!keyMatches(entry, program) && !signerMatches(entry, exe ? signerOf(exe) : undefined)) return refuse('the uninstall key no longer matches the Atlas entry');
  const now = buildUninstall(program, entry, { ...deps, signerOf });
  if ('reason' in now) return refuse(now.reason);
  if (now.kind !== spec.kind || now.file !== spec.file || JSON.stringify(now.args) !== JSON.stringify(spec.args)) return refuse('the uninstall command changed since the scan');
  if (now.kind === 'exe' && !now.signers.some((t) => spec.signers.includes(t))) return refuse('signer pins changed since the scan');
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
