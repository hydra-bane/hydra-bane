import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Context } from '../src/core/context.ts';
import { lnkTarget, OPTIMIZE_TEXT, RUN_KEYS, scanOptimize, type OptimizeDeps } from '../src/core/optimize.ts';
import type { RegValue } from '../src/guard/protected.ts';

// Everything is faked: no command runs, no real registry or Startup folder is read.
const ctx = { home: 'C:\\Users\\me' } as Context;
const env = { SystemRoot: 'C:\\Windows', SystemDrive: 'C:', APPDATA: 'C:\\Users\\me\\AppData\\Roaming', ProgramData: 'C:\\ProgramData', LOCALAPPDATA: 'C:\\Users\\me\\AppData\\Local' };
const userStartup = 'C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup';

/** Minimal .lnk: header + LinkInfo with a Unicode local base path (MS-SHLLINK). */
function fakeLnk(target: string): Buffer {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  header.writeUInt32LE(2, 0x14); // HasLinkInfo
  const wide = Buffer.from(`${target}\0`, 'utf16le');
  const info = Buffer.alloc(0x24);
  info.writeUInt32LE(0x24 + wide.length, 0);
  info.writeUInt32LE(0x24, 4);
  info.writeUInt32LE(1, 8);
  info.writeUInt32LE(0x24, 0x1c);
  return Buffer.concat([header, info, wide]);
}

const deps = (over: Partial<OptimizeDeps> = {}): Partial<OptimizeDeps> => ({
  env, exists: () => true, regQuery: () => [], readdir: () => [], readFile: () => Buffer.alloc(0), ...over,
});

describe('scanOptimize', () => {
  it('builds tool_cmd items with absolute System32 paths and constant args', () => {
    const items = scanOptimize(ctx, deps());
    const tools = items.filter((i) => i.op === 'tool_cmd');
    expect(tools.map((i) => i.id)).toEqual(['OPT-DNS', 'OPT-ICON-CACHE']);
    expect(tools.map((i) => i.command)).toEqual([
      { file: 'C:\\Windows\\System32\\ipconfig.exe', args: ['/flushdns'] },
      { file: 'C:\\Windows\\System32\\ie4uinit.exe', args: ['-show'] },
    ]);
    for (const i of tools) {
      expect(path.win32.isAbsolute(i.command!.file)).toBe(true);
      expect(i.targets).toEqual([i.command!.file]);
      expect(i).toMatchObject({ category: 'optimize', bytes: 0, files: 0, risk: 'safe', reversible: 'none' });
      expect(i.instructions).toMatch(/Harmless/);
      expect(i.needsAdmin).toBeUndefined();
    }
  });

  it('never puts PC data into command args, even with hostile Run entries and env', () => {
    const hostile = 'x & del /s /q C:\\*';
    const items = scanOptimize(ctx, deps({
      env: { ...env, APPDATA: `C:\\${hostile}` },
      regQuery: () => [{ key: 'HKEY_CURRENT_USER\\x', name: hostile, type: 'REG_SZ', data: hostile }],
      readdir: () => [`${hostile}.lnk`],
    }));
    const argv = items.flatMap((i) => (i.command ? [i.command.file, ...i.command.args] : []));
    expect(argv.join(' ')).not.toContain(hostile);
  });

  it('keeps IDs stable and every report_only item without a command but with instructions', () => {
    const items = scanOptimize(ctx, deps({ regQuery: (k) => (k === RUN_KEYS[0] ? [{ key: k, name: 'App', type: 'REG_SZ', data: 'C:\\a.exe' }] : []) }));
    expect(items.map((i) => i.id)).toEqual(['OPT-DNS', 'OPT-ICON-CACHE', 'OPT-STORE-CACHE', 'OPT-THUMB-CACHE', 'OPT-SEARCH-INDEX', 'OPT-RECYCLE-BIN', 'OPT-STARTUP']);
    for (const i of items.filter((x) => x.op === 'report_only')) {
      expect(i.command).toBeUndefined();
      expect(i.instructions).toBeTruthy();
      expect(i.bytes).toBe(0);
    }
    expect(items.find((i) => i.id === 'OPT-RECYCLE-BIN')!.risk).toBe('danger');
  });

  it('skips a tool whose executable is missing', () => {
    const items = scanOptimize(ctx, deps({ exists: (p) => !p.endsWith('ie4uinit.exe') }));
    expect(items.some((i) => i.id === 'OPT-ICON-CACHE')).toBe(false);
    expect(items.some((i) => i.id === 'OPT-DNS')).toBe(true);
  });

  it('lists Run-key values and Startup-folder shortcuts with their targets', () => {
    const reg: Record<string, RegValue[]> = {
      [RUN_KEYS[0]]: [{ key: 'HKEY_CURRENT_USER\\...\\Run', name: 'Discord', type: 'REG_SZ', data: '"C:\\Users\\me\\Discord.exe" --start-minimized' }],
      [RUN_KEYS[1]]: [{ key: 'HKEY_LOCAL_MACHINE\\...\\Run', name: 'SecurityHealth', type: 'REG_EXPAND_SZ', data: '%windir%\\system32\\SecurityHealthSystray.exe' }],
    };
    const files: Record<string, Buffer> = { [path.win32.join(userStartup, 'Notes.lnk')]: fakeLnk('C:\\Tools\\notes.exe') };
    const items = scanOptimize(ctx, deps({
      regQuery: (k) => reg[k] ?? [],
      readdir: (d) => (d === userStartup ? ['desktop.ini', 'Notes.lnk', 'script.bat'] : []),
      readFile: (p) => { const b = files[p]; if (!b) throw new Error('nope'); return b; },
    }));
    const s = items.find((i) => i.id === 'OPT-STARTUP')!;
    expect(s.title).toContain('(4,');
    expect(s.instructions).toContain('Discord = "C:\\Users\\me\\Discord.exe" --start-minimized (HKCU Run)');
    expect(s.instructions).toContain('SecurityHealth = %windir%\\system32\\SecurityHealthSystray.exe (HKLM Run)');
    expect(s.instructions).toContain('Notes.lnk = C:\\Tools\\notes.exe (Startup folder)');
    expect(s.instructions).toContain(`script.bat = ${path.win32.join(userStartup, 'script.bat')}`);
    expect(s.instructions).not.toContain('desktop.ini');
  });

  it('omits the startup item when nothing starts with Windows', () => {
    expect(scanOptimize(ctx, deps()).some((i) => i.id === 'OPT-STARTUP')).toBe(false);
  });
});

describe('lnkTarget', () => {
  it('reads the Unicode local path and rejects garbage', () => {
    expect(lnkTarget(fakeLnk('D:\\한글\\app.exe'))).toBe('D:\\한글\\app.exe');
    expect(lnkTarget(Buffer.from('not a shortcut'))).toBeUndefined();
    expect(lnkTarget(Buffer.alloc(0x4c))).toBeUndefined();
  });
});

it('explains the optimize category', () => {
  expect(OPTIMIZE_TEXT.optimize?.after).toMatch(/no disk space/i);
});
