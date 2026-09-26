import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { measureTree } from '../core/scan.ts';

// PLAN.md §3.5: read-only disk explorer (Mole `analyze` counterpart). Never deletes anything;
// the user takes what they find to `hydra-bane plan`.

export interface Row { name: string; path: string; bytes: number; files: number; dir: boolean; link: boolean }

export function listChildren(dir: string, onProgress?: (done: number, total: number) => void): Row[] {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  const rows = entries.map((e, i) => {
    onProgress?.(i, entries.length);
    const p = path.join(dir, e.name);
    const link = e.isSymbolicLink();
    const m = link ? { bytes: 0, files: 0 } : measureTree(p);
    return { name: e.name, path: p, ...m, dir: e.isDirectory(), link };
  });
  return rows.sort((a, b) => b.bytes - a.bytes);
}

export const human = (b: number) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
};

export function renderRows(rows: Row[], selected: number, width: number, height: number): string[] {
  const total = rows.reduce((s, r) => s + r.bytes, 0) || 1;
  const barW = Math.max(10, Math.min(30, width - 50));
  const start = Math.max(0, Math.min(selected - Math.floor(height / 2), rows.length - height));
  return rows.slice(start, start + height).map((r, i) => {
    const idx = start + i;
    const frac = r.bytes / total;
    const bar = '█'.repeat(Math.round(frac * barW)).padEnd(barW, '░');
    const name = (r.link ? `${r.name} (link, not followed)` : r.dir ? `${r.name}\\` : r.name).slice(0, Math.max(10, width - barW - 21));
    const line = `${idx === selected ? '›' : ' '} ${human(r.bytes).padStart(9)} ${bar} ${(frac * 100).toFixed(1).padStart(5)}%  ${name}`;
    return idx === selected ? `\x1b[7m${line}\x1b[0m` : line;
  });
}

export async function interactive(startDir: string): Promise<void> {
  const out = process.stdout;
  const stack: Array<{ dir: string; rows: Row[]; selected: number }> = [];
  const load = (dir: string) => {
    out.write(`\x1b[2J\x1b[H Scanning ${dir} ...`);
    return { dir, rows: listChildren(dir, (d, t) => out.write(`\r Scanning ${dir} ... ${d}/${t}`)), selected: 0 };
  };
  let cur = load(startDir);
  const draw = () => {
    const h = Math.max(5, (out.rows ?? 24) - 5);
    const total = cur.rows.reduce((s, r) => s + r.bytes, 0);
    out.write(`\x1b[2J\x1b[H hydra-bane analyze  ${cur.dir}  (${human(total)}, read-only)\n\n`);
    out.write(renderRows(cur.rows, cur.selected, out.columns ?? 100, h).join('\n'));
    out.write(`\n\n ↑↓ move  Enter open  ← back  q quit   Found something? Ask your agent: "hydra-bane scan"\n`);
  };
  draw();
  readline.emitKeypressEvents(process.stdin);
  process.stdin.setRawMode?.(true);
  await new Promise<void>((resolve) => {
    process.stdin.on('keypress', (_s, key: { name?: string; ctrl?: boolean }) => {
      if (key.name === 'q' || (key.ctrl && key.name === 'c')) { process.stdin.setRawMode?.(false); process.stdin.pause(); out.write('\n'); resolve(); return; }
      if (key.name === 'down') cur.selected = Math.min(cur.rows.length - 1, cur.selected + 1);
      if (key.name === 'up') cur.selected = Math.max(0, cur.selected - 1);
      const sel = cur.rows[cur.selected];
      if ((key.name === 'return' || key.name === 'right') && sel?.dir && !sel.link) { stack.push(cur); cur = load(sel.path); }
      if ((key.name === 'left' || key.name === 'backspace') && stack.length) cur = stack.pop()!;
      draw();
    });
  });
}
