import { spawnSync } from 'node:child_process';
import path from 'node:path';
import type { AtlasEntry } from './entry.ts';
import type { Program } from './programs.ts';

// What a matched program does on this PC, measured read-only (PLAN.md §7, schema 2): root certificates it
// installed, TCP ports its processes listen on, and services that run its executables. Facts, never verdicts.

export interface RawFacts {
  certs: { store: string; subject: string; thumbprint: string; notBefore: string }[];
  listeners: { address: string; port: number; pid: number; name?: string | null; exe?: string | null }[];
  services: { name: string; startMode: string; state: string; path?: string | null; pid?: number }[];
}
export type FactsRunner = () => RawFacts | undefined;

export interface ProgramFacts {
  version?: string | undefined;
  installDate?: string | undefined;
  bytes?: number | undefined;
  dirs: string[];
  rootCerts: { subject: string; thumbprint: string; notBefore: string; stores: string[] }[];
  /** network: bound to 0.0.0.0, :: or a LAN address, so other machines can connect unless a firewall blocks them. */
  listeners: { port: number; address: string; network: boolean; process: string }[];
  services: { name: string; startMode: string; startsWithWindows: boolean; state: string; exe: string }[];
}

// One read-only PowerShell call (~2.5 s). Nothing it runs changes state.
const PS = [
  "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'SilentlyContinue'",
  "$certs = @('LocalMachine','CurrentUser') | ForEach-Object { $s = $_; Get-ChildItem -LiteralPath \"Cert:\\$s\\Root\" | ForEach-Object { @{store=$s; subject=$_.Subject; thumbprint=$_.Thumbprint; notBefore=$_.NotBefore.ToString('yyyy-MM-dd')} } }",
  '$procs = @{}; Get-CimInstance Win32_Process -Property ProcessId,Name,ExecutablePath | ForEach-Object { $procs[[int]$_.ProcessId] = @($_.Name, $_.ExecutablePath) }',
  '$listen = Get-NetTCPConnection -State Listen | ForEach-Object { $p = $procs[[int]$_.OwningProcess]; @{address=$_.LocalAddress; port=[int]$_.LocalPort; pid=[int]$_.OwningProcess; name=$p[0]; exe=$p[1]} }',
  '$svc = Get-CimInstance Win32_Service -Property Name,StartMode,State,PathName,ProcessId | ForEach-Object { @{name=$_.Name; startMode=$_.StartMode; state=$_.State; path=$_.PathName; pid=[int]$_.ProcessId} }',
  'ConvertTo-Json -Compress -Depth 3 -InputObject @{certs=@($certs); listeners=@($listen); services=@($svc)}',
].join('; ');

export const powershellFacts: FactsRunner = () => {
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS], { encoding: 'utf8', windowsHide: true, timeout: 20_000, maxBuffer: 16 * 2 ** 20 });
  try { return JSON.parse(r.stdout.replace(/^\uFEFF/, '')) as RawFacts; } catch { return undefined; }
};

const norm = (p: string) => path.win32.normalize(p).replace(/\\+$/, '').toLowerCase();
const under = (file: string, dir: string) => { const f = norm(file), d = norm(dir); return f === d || f.startsWith(d + '\\'); };
const exeOf = (cmd: string | null | undefined) => {
  const m = cmd && (/^\s*"([^"]+)"/.exec(cmd) ?? /^\s*(.+?\.exe)(?=\s|$)/i.exec(cmd));
  return m ? m[1]!.trim() : undefined;
};

/** Folders whose contents belong to the program. Shared roots (drive, Windows, Program Files…) never count. */
export function programDirs(p: Program, env: Record<string, string | undefined> = process.env): string[] {
  const cands = p.installLocation && /^[a-z]:\\/i.test(p.installLocation) ? [p.installLocation]
    : [p.displayIcon, p.uninstallString].map((c) => exeOf(c?.replace(/,\s*-?\d+$/, ''))).filter((f): f is string => !!f && /^[a-z]:\\/i.test(f)).map((f) => path.win32.dirname(f));
  const shared = ['ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'ProgramData', 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'PUBLIC', 'TEMP'].map((n) => env[n]).filter((d): d is string => !!d).map(norm);
  const sys = env.SystemRoot ?? 'C:\\Windows';
  const byKey = new Map(cands.map((d) => [norm(d), path.win32.normalize(d).replace(/\\+$/, '')]));
  return [...byKey].filter(([d]) => !/^[a-z]:$/.test(d) && !shared.includes(d) && !under(d, sys) && !/^[a-z]:\\(program files( \(x86\))?|programdata|users)$/.test(d)).map(([, d]) => d);
}

const LOOPBACK = /^(127\.|::1$|0:0:0:0:0:0:0:1$)/;

/** Facts per matched program (programs[i] matched entries[i]). Runs the measurement only when something matched. */
export function measureFacts(programs: Program[], entries: AtlasEntry[], run: FactsRunner = powershellFacts, env: Record<string, string | undefined> = process.env): ProgramFacts[] {
  if (!programs.length) return [];
  const raw = run() ?? { certs: [], listeners: [], services: [] };
  const svcPid = new Map(raw.services.filter((s) => s.pid).map((s) => [s.pid!, exeOf(s.path)]));
  return programs.map((p, i) => {
    const dirs = programDirs(p, env);
    const mine = (f: string | undefined) => !!f && dirs.some((d) => under(f, d));
    const subs = entries[i]!.detect.root_certs.map((s) => s.toLowerCase());
    const certs = new Map<string, ProgramFacts['rootCerts'][number]>();
    for (const c of raw.certs) {
      if (!subs.some((s) => (c.subject ?? '').toLowerCase().includes(s))) continue;
      const k = c.thumbprint.toUpperCase();
      const have = certs.get(k);
      if (have) { if (!have.stores.includes(c.store)) have.stores.push(c.store); } else certs.set(k, { subject: c.subject, thumbprint: k, notBefore: c.notBefore, stores: [c.store] });
    }
    const listeners = new Map<string, ProgramFacts['listeners'][number]>();
    for (const l of raw.listeners) {
      // Processes of other users (services) have no readable path when not elevated; their service's path stands in.
      const exe = l.exe || svcPid.get(l.pid);
      if (!mine(exe)) continue;
      const network = !LOOPBACK.test(l.address);
      const key = `${l.port}|${network}`;
      if (!listeners.has(key)) listeners.set(key, { port: l.port, address: l.address, network, process: exe! });
    }
    const services = raw.services.flatMap((s) => { const exe = exeOf(s.path); return mine(exe) ? [{ name: s.name, startMode: s.startMode, startsWithWindows: /^auto/i.test(s.startMode), state: s.state, exe: exe! }] : []; });
    const d = /^(\d{4})(\d{2})(\d{2})$/.exec(p.installDate ?? '');
    return {
      version: p.version, installDate: d ? `${d[1]}-${d[2]}-${d[3]}` : undefined, bytes: p.estimatedBytes, dirs,
      rootCerts: [...certs.values()], listeners: [...listeners.values()].sort((a, b) => a.port - b.port), services,
    };
  });
}
