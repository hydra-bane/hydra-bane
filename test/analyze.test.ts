import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { human, listChildren, renderRows } from '../src/analyze/analyze.ts';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-a-'));
  fs.mkdirSync(path.join(dir, 'big'));
  fs.writeFileSync(path.join(dir, 'big', 'a.bin'), Buffer.alloc(5000));
  fs.writeFileSync(path.join(dir, 'small.txt'), 'x');
  fs.mkdirSync(path.join(dir, 'elsewhere'));
  fs.writeFileSync(path.join(dir, 'elsewhere', 'huge.bin'), Buffer.alloc(9000));
  fs.symlinkSync(path.join(dir, 'elsewhere'), path.join(dir, 'link'), 'junction');
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('analyze', () => {
  it('lists children by size and does not follow links', () => {
    const rows = listChildren(dir);
    expect(rows.map((r) => [r.name, r.bytes])).toEqual([['elsewhere', 9000], ['big', 5000], ['small.txt', 1], ['link', 0]]);
    expect(rows.find((r) => r.name === 'link')?.link).toBe(true);
  });

  it('renders bars with the selected row highlighted and no line wider than the terminal', () => {
    const lines = renderRows(listChildren(dir), 1, 80, 10);
    expect(lines).toHaveLength(4);
    expect(lines[1]).toContain('\x1b[7m');
    expect(lines[3]).toContain('link, not followed');
    for (const l of lines) expect(l.replace(/\x1b\[\d+m/g, '').length).toBeLessThanOrEqual(80);
  });

  it('formats sizes', () => {
    expect(human(0)).toBe('0 B');
    expect(human(1536)).toBe('1.5 KB');
    expect(human(9.00 * 2 ** 30)).toBe('9.0 GB');
  });
});
