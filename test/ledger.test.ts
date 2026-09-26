import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { canonical, Ledger } from '../src/ledger/ledger.ts';

let dir: string;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-l-')); });
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const filled = (n: number) => {
  const l = new Ledger(dir);
  l.lock();
  for (let i = 0; i < n; i++) l.append('tx1', i % 2 ? 'done' : 'planned', { item: i, path: `C:\\x\\${i}` });
  l.unlock();
  return l;
};

describe('ledger', () => {
  it('chains records and verifies', () => {
    const l = filled(5);
    expect(l.verify()).toMatchObject({ ok: true, count: 5 });
    const r = l.records();
    expect(r[0]!.prev).toBe('0'.repeat(64));
    expect(r[3]!.prev).toBe(r[2]!.hash);
  });

  it('detects an edited record', () => {
    const l = filled(4);
    const lines = fs.readFileSync(l.file, 'utf8').split('\n');
    lines[1] = lines[1]!.replace('C:\\\\x\\\\1', 'C:\\\\Windows');
    fs.writeFileSync(l.file, lines.join('\n'));
    expect(l.verify()).toMatchObject({ ok: false, brokenAt: 2 });
  });

  it('detects a deleted or reordered record', () => {
    const l = filled(4);
    const lines = fs.readFileSync(l.file, 'utf8').split('\n').filter(Boolean);
    fs.writeFileSync(l.file, [lines[0], lines[2], lines[3]].join('\n') + '\n');
    expect(l.verify().ok).toBe(false);
    fs.writeFileSync(l.file, [lines[1], lines[0], lines[2], lines[3]].join('\n') + '\n');
    expect(l.verify().ok).toBe(false);
  });

  it('refuses to append to a broken chain', () => {
    const l = filled(2);
    fs.appendFileSync(l.file, '{"seq":3,"forged":true}\n');
    l.lock();
    expect(() => l.append('tx2', 'planned', {})).toThrow(/chain broken/);
    l.unlock();
  });

  it('allows one writer at a time and reclaims stale locks', () => {
    const a = new Ledger(dir);
    const b = new Ledger(dir);
    a.lock();
    expect(() => b.lock()).toThrow(/locked by running process/);
    expect(() => b.append('t', 'planned', {})).toThrow(/requires lock/);
    a.unlock();
    fs.writeFileSync(path.join(dir, 'ledger.lock'), '999999'); // dead pid
    expect(() => b.lock()).not.toThrow();
    b.unlock();
  });

  it('property: canonical JSON ignores key order', () => {
    fc.assert(fc.property(fc.dictionary(fc.string(), fc.jsonValue()), (o) => {
      const reversed = Object.fromEntries(Object.entries(o).reverse());
      return canonical(o) === canonical(reversed);
    }));
  });
});
