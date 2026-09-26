import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

// Drives the real MCP server over stdio. State and TEMP are redirected into a throwaway folder,
// so the scan finds only our planted file and nothing on the PC is touched.
let root: string, temp: string, child: ChildProcessWithoutNullStreams;
const pending = new Map<unknown, (m: any) => void>();
const unmatched: any[] = [];
let nextId = 1;

const write = (line: string) => child.stdin.write(line + '\n');
function request(method: string, params: object = {}): Promise<any> {
  const id = nextId++;
  return new Promise((resolve) => { pending.set(id, resolve); write(JSON.stringify({ jsonrpc: '2.0', id, method, params })); });
}
const call = (name: string, args: object = {}) => request('tools/call', { name, arguments: args });
const waitUnmatched = async () => { for (let i = 0; i < 100 && !unmatched.length; i++) await new Promise((r) => setTimeout(r, 20)); return unmatched.shift(); };

beforeAll(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'hb-mcp-')));
  temp = path.join(root, 'temp');
  fs.mkdirSync(temp);
  const old = path.join(temp, 'old.tmp');
  fs.writeFileSync(old, 'x'.repeat(4096));
  const t = new Date(Date.now() - 3 * 86_400_000);
  fs.utimesSync(old, t, t);
  child = spawn(process.execPath, [path.join(import.meta.dirname, '..', 'src', 'mcp', 'run.ts')], {
    env: { ...process.env, LOCALAPPDATA: path.join(root, 'state'), TEMP: temp, TMP: temp }, stdio: 'pipe',
  });
  readline.createInterface({ input: child.stdout }).on('line', (l) => {
    const m = JSON.parse(l);
    const r = pending.get(m.id);
    if (r) { pending.delete(m.id); r(m); } else unmatched.push(m);
  });
});
afterAll(() => { child.kill(); fs.rmSync(root, { recursive: true, force: true }); });

describe.runIf(process.platform === 'win32')('mcp server over stdio', () => {
  it('legacy initialize handshake negotiates the version', async () => {
    const r = await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    expect(r.result.protocolVersion).toBe('2025-06-18');
    expect(r.result.capabilities.tools).toEqual({});
    write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
    const u = await request('initialize', { protocolVersion: '1999-01-01' });
    expect(u.result.protocolVersion).toBe('2025-11-25');
    expect((await request('ping')).result).toBeDefined();
  });

  it('modern discover and version rejection', async () => {
    const meta = (v: string) => ({ _meta: { 'io.modelcontextprotocol/protocolVersion': v, 'io.modelcontextprotocol/clientInfo': { name: 't', version: '1' }, 'io.modelcontextprotocol/clientCapabilities': {} } });
    const d = await request('server/discover', meta('2026-07-28'));
    expect(d.result.supportedVersions).toContain('2026-07-28');
    const bad = await request('tools/list', meta('1900-01-01'));
    expect(bad.error.code).toBe(-32022);
    expect(bad.error.data.supported).toContain('2026-07-28');
  });

  it('lists exactly the allowed tools, none destructive', async () => {
    const r = await request('tools/list');
    const names = r.result.tools.map((t: any) => t.name);
    expect(names.sort()).toEqual(['analyze', 'explain', 'ledger_verify', 'plan', 'plan_summary', 'programs', 'report_preview', 'scan']);
    for (const n of names) expect(n).not.toMatch(/apply|undo|purge|submit|star/);
    for (const t of r.result.tools) expect(t.description).toContain('hydra-bane apply <plan-id>');
  });

  it('scan -> plan -> plan_summary changes nothing', async () => {
    const s = await call('scan', { only: ['temp'] });
    expect(s.result.isError).toBe(false);
    const items = s.result.structuredContent.data.items;
    expect(items.map((i: any) => i.id)).toEqual(['TEMP']);
    expect(s.result.structuredContent.next).toContain('hydra-bane apply');

    const p = await call('plan', { select: ['TEMP'], only: ['temp'] });
    const planId = p.result.structuredContent.data.plan_id;
    expect(planId).toMatch(/^[a-z0-9]+$/);

    const sum = await call('plan_summary', { plan_id: planId });
    expect(sum.result.isError).toBe(false);
    expect(sum.result.structuredContent.data.summary).toContain('Hydra-bane plan');
    expect(sum.result.content[0].text).toContain(`hydra-bane apply`);
    expect(fs.existsSync(path.join(temp, 'old.tmp'))).toBe(true);
    expect(fs.existsSync(path.join(root, 'state', 'hydra-bane', 'ledger'))).toBe(false);
  });

  it('rejects unknown tools and flag smuggling', async () => {
    for (const name of ['apply', 'undo', 'purge', 'nope']) {
      const r = await call(name, { plan_id: 'x' });
      expect(r.error.code).toBe(-32602);
    }
    const r = await call('explain', { id: '--yes' });
    expect(r.result.isError).toBe(true);
    const bad = await call('plan_summary', { plan_id: 'doesnotexist' });
    expect(bad.result.structuredContent.error.code).toBe('NOT_FOUND');
  });

  it('survives malformed input', async () => {
    write('{not json');
    expect((await waitUnmatched()).error.code).toBe(-32700);
    write('[1,2]');
    expect((await waitUnmatched()).error.code).toBe(-32600);
    expect((await request('no/such')).error.code).toBe(-32601);
    expect((await request('ping')).result).toBeDefined();
  });
});
