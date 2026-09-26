import { execFile } from 'node:child_process';

// Read-only system snapshot (like Mole's `mo status`). One PowerShell call takes two samples ~1 s apart; every
// rate (CPU, disk I/O, network, GPU, per-process CPU) is a delta between them. Nothing in the script writes anything.
// CIM perf classes are used instead of Get-Counter because counter paths are localized (e.g. Korean Windows).

export type StatusRunner = (script: string) => Promise<string>;
export interface StatusDeps { run?: StatusRunner; now?: () => Date }

export interface Drive { drive: string; totalBytes: number; freeBytes: number; freePct: number; low: boolean }
export interface Adapter { name: string; description: string; linkBitsPerSec: number; rxBytesPerSec: number | null; txBytesPerSec: number | null }
export interface Proc { pid: number; name: string; workingSetBytes: number; cpuPct: number | null }
export interface HealthReason { points: number; reason: string }
export interface StatusSnapshot {
  takenAt: string;
  sampleMs: number;
  cpu: { model: string; cores: number; threads: number; loadPct: number | null };
  memory: { totalBytes: number; usedBytes: number; usedPct: number };
  drives: Drive[];
  diskIo: { readBytesPerSec: number; writeBytesPerSec: number } | null;
  network: Adapter[];
  gpu: { names: string[]; utilizationPct: number | null };
  battery: { percent: number; onAc: boolean; charging: boolean } | null;
  uptimeSec: number;
  pendingReboot: string[];
  topByMemory: Proc[];
  topByCpu: Proc[];
  health: { score: number; reasons: HealthReason[] };
}

// Raw shape printed by SCRIPT (exported so tests can build fakes).
export interface RawNet { n: string; d: string; sp: number; r: number; s: number }
export interface RawProc { i: number; n: string; c: number | null; w: number }
export interface RawSample { idle: number | null; ts: number | null; disk: [number, number] | null; net: RawNet[]; procs: RawProc[] }
export interface RawStatus {
  cpu: { n: string; c: number; t: number }[];
  mem: { total: number; free: number };
  uptime: number;
  drives: { d: string; size: number; free: number }[];
  battery: { pct: number; status: number }[];
  gpus: string[];
  gpu: Record<string, number> | null; // 100ns busy time per engine type between samples
  reboot: string[];
  elapsed: number; // 100ns ticks between samples
  a: RawSample;
  b: RawSample;
}

const SAMPLE = [
  "$p = Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Filter \"Name='_Total'\"",
  "$d = Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter \"Name='_Total'\"",
  '@{ idle = $p.PercentProcessorTime; ts = $p.Timestamp_Sys100NS; disk = $(if ($d) { @([double]$d.DiskReadBytesPersec, [double]$d.DiskWriteBytesPersec) } else { $null });',
  "   net = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |",
  '     ForEach-Object { $s = $_.GetIPStatistics(); @{ n = $_.Name; d = $_.Description; sp = [double]$_.Speed; r = [double]$s.BytesReceived; s = [double]$s.BytesSent } });',
  '   procs = @(Get-Process | ForEach-Object { @{ i = $_.Id; n = $_.ProcessName; c = $_.CPU; w = [double]$_.WorkingSet64 } }) }',
].join('\n');

export const SCRIPT = [
  "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'SilentlyContinue'",
  `function Sample {\n${SAMPLE}\n}`,
  'function Gpu { $h = @{}; Get-CimInstance Win32_PerfRawData_GPUPerformanceCounters_GPUEngine | ForEach-Object { $h[$_.Name] = [double]$_.UtilizationPercentage }; $h }',
  '$g1 = Gpu; $t1 = [DateTime]::UtcNow.Ticks; $a = Sample',
  'Start-Sleep -Milliseconds 1000',
  '$g2 = Gpu; $t2 = [DateTime]::UtcNow.Ticks; $b = Sample',
  '$gpu = $null; if ($g1.Count -and $g2.Count) { $gpu = @{}; foreach ($k in $g2.Keys) { if ($g1.ContainsKey($k)) { $t = ($k -split "engtype_")[1]; $gpu[$t] = [double]$gpu[$t] + $g2[$k] - $g1[$k] } } }',
  '$os = Get-CimInstance Win32_OperatingSystem',
  '$reboot = @()',
  "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $reboot += 'Component Based Servicing' }",
  "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $reboot += 'Windows Update' }",
  "if ((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations).PendingFileRenameOperations) { $reboot += 'Pending file renames' }",
  'ConvertTo-Json -Compress -Depth 4 -InputObject @{',
  '  cpu = @(Get-CimInstance Win32_Processor -Property Name,NumberOfCores,NumberOfLogicalProcessors | ForEach-Object { @{ n = $_.Name.Trim(); c = [int]$_.NumberOfCores; t = [int]$_.NumberOfLogicalProcessors } });',
  '  mem = @{ total = [double]$os.TotalVisibleMemorySize * 1024; free = [double]$os.FreePhysicalMemory * 1024 };',
  '  uptime = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds;',
  "  drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { @{ d = $_.DeviceID; size = [double]$_.Size; free = [double]$_.FreeSpace } });",
  '  battery = @(Get-CimInstance Win32_Battery | ForEach-Object { @{ pct = [int]$_.EstimatedChargeRemaining; status = [int]$_.BatteryStatus } });',
  '  gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name });',
  '  gpu = $gpu; reboot = $reboot; elapsed = $t2 - $t1; a = $a; b = $b',
  '}',
].join('\n');

export const powershellRunner: StatusRunner = (script) => new Promise((resolve, reject) => {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
    { encoding: 'utf8', windowsHide: true, timeout: 20_000, maxBuffer: 16 * 2 ** 20 },
    (err, stdout) => (stdout.trim() ? resolve(stdout) : reject(err ?? new Error('status: no output from PowerShell'))));
});

const LOW_FREE_PCT = 10;
const round1 = (n: number) => Math.round(n * 10) / 10;
const clampPct = (n: number) => round1(Math.min(100, Math.max(0, n)));

/**
 * Health score: start at 100 and subtract, each deduction listed as a reason. Integer points on purpose; this is a
 * coarse triage signal, not a measurement.
 *  - each fixed drive under 10% free: -15 (under 5%: -25); disk deductions capped at 40
 *  - memory in use >= 90%: -20, >= 80%: -10
 *  - a reboot is pending: -10
 *  - uptime over 14 days: -10
 */
export function healthScore(s: Pick<StatusSnapshot, 'drives' | 'memory' | 'pendingReboot' | 'uptimeSec'>): StatusSnapshot['health'] {
  const reasons: HealthReason[] = [];
  let disk = 0;
  for (const d of s.drives) {
    if (!d.low) continue;
    const pts = d.freePct < 5 ? 25 : 15;
    const take = Math.min(pts, 40 - disk);
    disk += take;
    if (take) reasons.push({ points: -take, reason: `${d.drive} has only ${d.freePct}% free` });
  }
  if (s.memory.usedPct >= 90) reasons.push({ points: -20, reason: `memory ${s.memory.usedPct}% in use` });
  else if (s.memory.usedPct >= 80) reasons.push({ points: -10, reason: `memory ${s.memory.usedPct}% in use` });
  if (s.pendingReboot.length) reasons.push({ points: -10, reason: `reboot pending (${s.pendingReboot.join(', ')})` });
  const days = Math.floor(s.uptimeSec / 86400);
  if (days > 14) reasons.push({ points: -10, reason: `up ${days} days without a restart` });
  return { score: Math.max(0, 100 + reasons.reduce((t, r) => t + r.points, 0)), reasons };
}

export function parseStatus(raw: RawStatus, takenAt: Date): StatusSnapshot {
  const secs = raw.elapsed > 0 ? raw.elapsed / 1e7 : 1;
  const rate = (x: number, y: number) => Math.max(0, Math.round((y - x) / secs));
  const { a, b } = raw;

  const cpu0 = raw.cpu[0];
  const threads = raw.cpu.reduce((t, c) => t + c.t, 0) || 1;
  // PercentProcessorTime raw is idle time (PERF_100NSEC_TIMER_INV) against Timestamp_Sys100NS.
  const loadPct = a.idle != null && b.idle != null && a.ts != null && b.ts != null && b.ts > a.ts
    ? clampPct(100 * (1 - (b.idle - a.idle) / (b.ts - a.ts))) : null;

  const usedBytes = Math.max(0, raw.mem.total - raw.mem.free);
  const memory = { totalBytes: raw.mem.total, usedBytes, usedPct: raw.mem.total ? round1((100 * usedBytes) / raw.mem.total) : 0 };

  const drives = raw.drives.filter((d) => d.size > 0).map((d) => {
    const freePct = round1((100 * d.free) / d.size);
    return { drive: d.d, totalBytes: d.size, freeBytes: d.free, freePct, low: freePct < LOW_FREE_PCT };
  });

  const netA = new Map(a.net.map((n) => [n.n, n]));
  const network = b.net.map((y) => {
    const x = netA.get(y.n);
    return { name: y.n, description: y.d, linkBitsPerSec: y.sp,
      rxBytesPerSec: x ? rate(x.r, y.r) : null, txBytesPerSec: x ? rate(x.s, y.s) : null };
  });

  // Task Manager style: the busiest engine type (3D, Copy, VideoDecode...), each type summed over its engines.
  const gpuVals = raw.gpu ? Object.values(raw.gpu) : [];
  const utilizationPct = gpuVals.length && raw.elapsed > 0 ? clampPct((100 * Math.max(...gpuVals)) / raw.elapsed) : null;

  const cpuBefore = new Map(a.procs.map((p) => [p.i, p.c]));
  const procs: Proc[] = b.procs.map((p) => {
    const before = cpuBefore.get(p.i);
    return { pid: p.i, name: p.n, workingSetBytes: p.w,
      cpuPct: p.c != null && before != null ? clampPct((100 * (p.c - before)) / secs / threads) : null };
  });

  const bat = raw.battery[0];
  const snap = {
    takenAt: takenAt.toISOString(),
    sampleMs: Math.round(secs * 1000),
    cpu: { model: cpu0?.n ?? 'unknown', cores: raw.cpu.reduce((t, c) => t + c.c, 0), threads, loadPct },
    memory,
    drives,
    diskIo: a.disk && b.disk ? { readBytesPerSec: rate(a.disk[0], b.disk[0]), writeBytesPerSec: rate(a.disk[1], b.disk[1]) } : null,
    network,
    gpu: { names: raw.gpus, utilizationPct },
    // BatteryStatus: 1 = discharging, 2 = on AC, 6-9 = charging (Win32_Battery docs).
    battery: bat ? { percent: bat.pct, onAc: bat.status !== 1, charging: bat.status >= 6 && bat.status <= 9 } : null,
    uptimeSec: raw.uptime,
    pendingReboot: raw.reboot,
    topByMemory: [...procs].sort((x, y) => y.workingSetBytes - x.workingSetBytes).slice(0, 5),
    topByCpu: procs.filter((p) => p.cpuPct != null && p.name !== 'Idle').sort((x, y) => y.cpuPct! - x.cpuPct!).slice(0, 5),
  };
  return { ...snap, health: healthScore(snap) };
}

// ConvertTo-Json turns a one-element array into a bare value in some spots and empty collections into null/{}.
const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? v : v == null || (typeof v === 'object' && !Object.keys(v).length) ? [] : [v]) as T[];
function normalize(r: Record<string, any>): RawStatus {
  const sample = (s: any): RawSample => ({ idle: s?.idle ?? null, ts: s?.ts ?? null, disk: Array.isArray(s?.disk) ? s.disk : null, net: arr(s?.net), procs: arr(s?.procs) });
  return { cpu: arr(r.cpu), mem: r.mem ?? { total: 0, free: 0 }, uptime: r.uptime ?? 0, drives: arr(r.drives), battery: arr(r.battery),
    gpus: arr<string>(r.gpus).filter(Boolean), gpu: r.gpu && typeof r.gpu === 'object' && Object.keys(r.gpu).length ? r.gpu : null,
    reboot: arr(r.reboot), elapsed: r.elapsed ?? 0, a: sample(r.a), b: sample(r.b) };
}

export async function collectStatus(deps: StatusDeps = {}): Promise<StatusSnapshot> {
  const out = await (deps.run ?? powershellRunner)(SCRIPT);
  return parseStatus(normalize(JSON.parse(out.replace(/^﻿/, '').trim()) as Record<string, any>), (deps.now ?? (() => new Date()))());
}

const GB = 2 ** 30;
const size = (n: number) => (n >= GB ? `${(n / GB).toFixed(1)} GB` : `${(n / 2 ** 20).toFixed(0)} MB`);
const speed = (n: number | null) => (n == null ? '?' : n >= 2 ** 20 ? `${(n / 2 ** 20).toFixed(1)} MB/s` : `${(n / 1024).toFixed(0)} KB/s`);
const bar = (pct: number, w = 20) => { const f = Math.round((Math.min(100, Math.max(0, pct)) / 100) * w); return `[${'#'.repeat(f)}${'-'.repeat(w - f)}]`; };
const link = (bps: number) => (bps >= 1e9 ? `${+(bps / 1e9).toFixed(1)} Gbps` : `${+(bps / 1e6).toFixed(0)} Mbps`);
const pct = (n: number | null) => (n == null ? 'n/a' : `${n.toFixed(0)}%`);

export function formatStatus(s: StatusSnapshot): string[] {
  const d = Math.floor(s.uptimeSec / 86400), h = Math.floor((s.uptimeSec % 86400) / 3600);
  return [
    `Health  ${s.health.score}/100${s.health.reasons.length ? '' : '  (no deductions)'}`,
    ...s.health.reasons.map((r) => `        ${r.points} ${r.reason}`),
    `CPU     ${bar(s.cpu.loadPct ?? 0)} ${pct(s.cpu.loadPct).padStart(4)}  ${s.cpu.model} (${s.cpu.cores}C/${s.cpu.threads}T)`,
    `Memory  ${bar(s.memory.usedPct)} ${pct(s.memory.usedPct).padStart(4)}  ${size(s.memory.usedBytes)} / ${size(s.memory.totalBytes)}`,
    ...s.drives.map((v) => `Disk ${v.drive.padEnd(3)}${bar(100 - v.freePct)} ${pct(100 - v.freePct).padStart(4)}  ${size(v.freeBytes)} free of ${size(v.totalBytes)}${v.low ? '  LOW' : ''}`),
    `Disk IO read ${speed(s.diskIo?.readBytesPerSec ?? null)}  write ${speed(s.diskIo?.writeBytesPerSec ?? null)}`,
    ...s.gpu.names.map((n, i) => `GPU     ${n}${i === 0 ? `  ${s.gpu.utilizationPct == null ? 'utilization n/a' : `${bar(s.gpu.utilizationPct)} ${pct(s.gpu.utilizationPct)}`}` : ''}`),
    ...s.network.map((n) => `Net     ${n.name} (${link(n.linkBitsPerSec)})  down ${speed(n.rxBytesPerSec)}  up ${speed(n.txBytesPerSec)}`),
    s.battery ? `Battery ${bar(s.battery.percent)} ${s.battery.percent}%  ${s.battery.charging ? 'charging' : s.battery.onAc ? 'on AC' : 'on battery'}` : 'Battery none (desktop)',
    `Uptime  ${d}d ${h}h${s.pendingReboot.length ? `  reboot pending: ${s.pendingReboot.join(', ')}` : ''}`,
    'Top memory: ' + s.topByMemory.map((p) => `${p.name} ${size(p.workingSetBytes)}`).join(', '),
    'Top CPU:    ' + (s.topByCpu.map((p) => `${p.name} ${p.cpuPct!.toFixed(1)}%`).join(', ') || 'n/a'),
  ];
}

/** Collect, hand over, wait, repeat until the signal aborts. Errors per snapshot go to onError (or stop the loop). */
export async function watchStatus(intervalMs: number, onSnapshot: (s: StatusSnapshot) => void, signal: AbortSignal, deps: StatusDeps = {}, onError?: (e: Error) => void): Promise<void> {
  while (!signal.aborted) {
    try { onSnapshot(await collectStatus(deps)); } catch (e) { if (!onError) throw e; onError(e as Error); }
    if (signal.aborted) break;
    await new Promise<void>((resolve) => {
      const t = setTimeout(done, Math.max(0, intervalMs));
      function done() { clearTimeout(t); signal.removeEventListener('abort', done); resolve(); }
      signal.addEventListener('abort', done, { once: true });
    });
  }
}
