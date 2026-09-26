import { describe, expect, it } from 'vitest';
import { collectStatus, formatStatus, healthScore, SCRIPT, watchStatus, type RawStatus } from '../src/core/status.ts';

// Fake PowerShell output: two samples exactly 1 s apart (1e7 ticks of 100 ns).
const GB = 2 ** 30;
function raw(over: Partial<RawStatus> = {}): RawStatus {
  return {
    cpu: [{ n: 'Test CPU', c: 4, t: 8 }],
    mem: { total: 16 * GB, free: 4 * GB },
    uptime: 3 * 86400 + 7200,
    drives: [{ d: 'C:', size: 100 * GB, free: 40 * GB }, { d: 'D:', size: 0, free: 0 }],
    battery: [{ pct: 76, status: 6 }],
    gpus: ['Test GPU'],
    gpu: { '3D': 2.5e6, Copy: 1e5 },
    reboot: [],
    elapsed: 1e7,
    a: { idle: 0, ts: 0, disk: [1000, 5000], net: [{ n: 'Wi-Fi', d: 'Wireless', sp: 866.7e6, r: 1000, s: 2000 }],
      procs: [{ i: 1, n: 'busy', c: 10, w: 100 }, { i: 2, n: 'fat', c: 1, w: 5 * GB }, { i: 3, n: 'locked', c: null, w: 50 }] },
    b: { idle: 6e6, ts: 1e7, disk: [3_000_000, 5000], net: [{ n: 'Wi-Fi', d: 'Wireless', sp: 866.7e6, r: 1_049_576, s: 2000 }],
      procs: [{ i: 1, n: 'busy', c: 14, w: 100 }, { i: 2, n: 'fat', c: 1, w: 5 * GB }, { i: 3, n: 'locked', c: null, w: 50 }, { i: 4, n: 'new', c: 0.1, w: 10 }] },
    ...over,
  };
}
const fake = (r: unknown) => ({ run: async (script: string) => { expect(script).toBe(SCRIPT); return '﻿' + JSON.stringify(r); }, now: () => new Date('2026-09-26T00:00:00Z') });

describe('status', () => {
  it('parses a snapshot and computes rates from the two samples', async () => {
    const s = await collectStatus(fake(raw()));
    expect(s.cpu).toEqual({ model: 'Test CPU', cores: 4, threads: 8, loadPct: 40 });
    expect(s.memory).toEqual({ totalBytes: 16 * GB, usedBytes: 12 * GB, usedPct: 75 });
    expect(s.drives).toEqual([{ drive: 'C:', totalBytes: 100 * GB, freeBytes: 40 * GB, freePct: 40, low: false }]);
    expect(s.diskIo).toEqual({ readBytesPerSec: 2_999_000, writeBytesPerSec: 0 });
    expect(s.network[0]).toMatchObject({ name: 'Wi-Fi', rxBytesPerSec: 1_048_576, txBytesPerSec: 0 });
    expect(s.gpu).toEqual({ names: ['Test GPU'], utilizationPct: 25 });
    expect(s.battery).toEqual({ percent: 76, onAc: true, charging: true });
    expect(s.topByMemory[0]!.name).toBe('fat');
    expect(s.topByCpu[0]).toMatchObject({ name: 'busy', cpuPct: 50 }); // 4 s CPU / 1 s / 8 threads
    expect(s.topByCpu.map((p) => p.name)).not.toContain('locked'); // CPU not readable, not "0%"
    expect(s.topByCpu.map((p) => p.name)).not.toContain('new'); // no first sample
    expect(s.health).toEqual({ score: 100, reasons: [] });
    expect(s.takenAt).toBe('2026-09-26T00:00:00.000Z');
    const text = formatStatus(s).join('\n');
    expect(text).toContain('CPU     [########------------]  40%');
    expect(text).toContain('charging');
    expect(text).toContain('Net     Wi-Fi (867 Mbps)  down 1.0 MB/s');
  });

  it('desktop without battery, GPU counters or disk counters', async () => {
    const r = raw({ battery: [], gpu: null });
    r.a.disk = null;
    // PowerShell 5.1 ConvertTo-Json quirks: empty arrays may come back as null/{} and single items unwrapped.
    const s = await collectStatus(fake({ ...r, battery: null, gpu: {}, reboot: null, gpus: 'Basic Display', cpu: r.cpu[0] }));
    expect(s.battery).toBeNull();
    expect(s.gpu).toEqual({ names: ['Basic Display'], utilizationPct: null });
    expect(s.diskIo).toBeNull();
    expect(s.pendingReboot).toEqual([]);
    const text = formatStatus(s).join('\n');
    expect(text).toContain('Battery none (desktop)');
    expect(text).toContain('utilization n/a');
    expect(text).toContain('Disk IO read ?');
  });

  it('health score lists every deduction', () => {
    const drive = (d: string, freePct: number) => ({ drive: d, totalBytes: 100, freeBytes: freePct, freePct, low: freePct < 10 });
    const h = healthScore({ drives: [drive('C:', 4), drive('D:', 8), drive('E:', 9), drive('F:', 50)], memory: { totalBytes: 1, usedBytes: 1, usedPct: 93 },
      pendingReboot: ['Windows Update'], uptimeSec: 20 * 86400 });
    expect(h.reasons).toEqual([
      { points: -25, reason: 'C: has only 4% free' },
      { points: -15, reason: 'D: has only 8% free' }, // disk total capped at 40, so E: adds nothing
      { points: -20, reason: 'memory 93% in use' },
      { points: -10, reason: 'reboot pending (Windows Update)' },
      { points: -10, reason: 'up 20 days without a restart' },
    ]);
    expect(h.score).toBe(20);
    expect(healthScore({ drives: [], memory: { totalBytes: 1, usedBytes: 1, usedPct: 85 }, pendingReboot: [], uptimeSec: 14 * 86400 + 5 }))
      .toEqual({ score: 90, reasons: [{ points: -10, reason: 'memory 85% in use' }] });
  });

  it('watch emits snapshots until aborted', async () => {
    const ac = new AbortController();
    const got: number[] = [];
    await watchStatus(1, (s) => { got.push(s.health.score); if (got.length === 3) ac.abort(); }, ac.signal, fake(raw()));
    expect(got).toEqual([100, 100, 100]);
  });

  it('never runs anything that writes', () => {
    expect(SCRIPT).not.toMatch(/\b(Set|Remove|New|Stop|Start-Process|Invoke|Clear|Restart)-/);
  });
});
