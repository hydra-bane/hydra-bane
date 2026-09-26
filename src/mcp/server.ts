import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import type { Readable, Writable } from 'node:stream';
import type { Context } from '../core/context.ts';
import { loadPlan, summarize } from '../core/plan.ts';
import { currentUserSid } from '../quarantine/quarantine.ts';

// MCP over stdio (newline-delimited JSON-RPC 2.0), hand-written: no runtime dependencies (PLAN.md §5).
// Dual-era per the MCP spec 2026-07-28 versioning page: modern clients send per-request `_meta` and may call
// `server/discover`; legacy clients open with `initialize` (2025-11-25 and earlier).
// SAFETY: only read-only / non-destructive tools. Nothing here can apply, undo, purge, submit or star.

export const MODERN_VERSIONS = ['2026-07-28'];
export const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const SUPPORTED = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
const VERSION_KEY = 'io.modelcontextprotocol/protocolVersion';
const SERVER_INFO = { name: 'hydra-bane', version: (JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string }).version };

const CLI = fileURLToPath(new URL(import.meta.url.endsWith('.ts') ? '../cli.ts' : '../cli.js', import.meta.url));

export const APPROVAL =
  'Hydra-bane MCP is read-only: it cannot apply, undo or purge anything. To change the PC, show the plan summary to the human. ' +
  'Only after they explicitly approve, run `hydra-bane apply <plan-id>` (it prompts at a terminal; an agent adds `--yes` only after that explicit approval).';

const INSTRUCTIONS = `Safe Windows cleanup. Loop: scan -> explain -> plan (sealed, 24h) -> plan_summary -> the human approves -> the human-approved CLI command \`hydra-bane apply <plan-id>\`. ${APPROVAL}`;

type Json = Record<string, unknown>;
const str = { type: 'string' } as const;
const strs = { type: 'array', items: str } as const;
const ro = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

export const TOOLS = [
  { name: 'scan', title: 'Scan reclaimable space', annotations: ro,
    description: `Find reclaimable disk space (read-only, changes nothing). Returns items with id, title, bytes, risk, reversible. ${APPROVAL}`,
    inputSchema: { type: 'object', properties: { only: { ...strs, description: 'Categories, e.g. ["temp","npm-cache","node_modules"]' }, roots: { ...strs, description: 'Project folders to search for stale node_modules / target' } }, additionalProperties: false } },
  { name: 'explain', title: 'Explain an item', annotations: ro,
    description: `Plain-language what / why it is safe / what happens for one scan item id (read-only). ${APPROVAL}`,
    inputSchema: { type: 'object', properties: { id: str, only: strs, roots: strs }, required: ['id'], additionalProperties: false } },
  { name: 'analyze', title: 'Analyze folder sizes', annotations: ro,
    description: `List the largest children of a folder (read-only). To free space, go back to scan/plan; never delete directly. ${APPROVAL}`,
    inputSchema: { type: 'object', properties: { path: str }, additionalProperties: false } },
  { name: 'programs', title: 'List installed programs', annotations: ro,
    description: `List installed programs (read-only). Removal is not automated. ${APPROVAL}`,
    inputSchema: { type: 'object', additionalProperties: false } },
  { name: 'report_preview', title: 'Preview an Atlas report', annotations: { ...ro, readOnlyHint: false },
    description: `Show exactly what an Atlas report for an installed program would contain. It NEVER sends anything (it only saves the preview locally). Sending needs the human's approval and the CLI. ${APPROVAL}`,
    inputSchema: { type: 'object', properties: { id: str, note: str }, required: ['id'], additionalProperties: false } },
  { name: 'plan', title: 'Seal a cleanup plan', annotations: { ...ro, readOnlyHint: false, idempotentHint: false },
    description: `Seal a plan file for the selected scan ids (or all safe items). Only writes the sealed plan; changes nothing else. Plans expire in 24h. ${APPROVAL}`,
    inputSchema: { type: 'object', properties: { select: strs, all_safe: { type: 'boolean' }, only: strs, roots: strs }, additionalProperties: false } },
  { name: 'plan_summary', title: 'Summarize a sealed plan', annotations: ro,
    description: `Show what applying a sealed plan would do (read-only), to show the human before asking for approval. ${APPROVAL}`,
    inputSchema: { type: 'object', properties: { plan_id: str }, required: ['plan_id'], additionalProperties: false } },
  { name: 'ledger_verify', title: 'Verify receipts ledger', annotations: ro,
    description: `Verify the receipts ledger hash chain and show recent receipts (read-only). ${APPROVAL}`,
    inputSchema: { type: 'object', additionalProperties: false } },
];

class BadArgs extends Error {}

// Values become argv of the CLI (no shell); refusing a leading '-' stops smuggling flags such as --yes/--submit.
function val(v: unknown, name: string, re = /^[^-\0][^\0]{0,4095}$/): string {
  if (typeof v !== 'string' || !re.test(v)) throw new BadArgs(`invalid ${name}`);
  return v;
}
function list(v: unknown, name: string, re?: RegExp): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new BadArgs(`${name} must be an array of strings`);
  return v.map((x) => val(x, name, re));
}
const ID = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const CAT = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const scope = (a: Json) => {
  const only = list(a.only, 'only', CAT);
  return [...(only.length ? ['--only', only.join(',')] : []), ...list(a.roots, 'roots').flatMap((r) => ['--root', r])];
};

function cli(args: string[]): Promise<Json> {
  return new Promise((resolve, reject) => {
    // stdin is not a TTY and HYDRA_BANE_NO_PROMPTS is set, so the CLI can never prompt or self-confirm.
    const child = execFile(process.execPath, [CLI, ...args, '--json'], { encoding: 'utf8', windowsHide: true, timeout: 600_000, maxBuffer: 64 * 2 ** 20, env: { ...process.env, HYDRA_BANE_NO_PROMPTS: '1' } },
      (err, stdout, stderr) => {
        const line = stdout.trim().split(/\r?\n/).pop() ?? '';
        try { resolve(JSON.parse(line) as Json); } catch { reject(new Error(`hydra-bane ${args[0]} failed: ${(stderr || err?.message || 'no output').trim()}`)); }
      });
    child.stdin?.end();
  });
}

function planSummary(id: string): Json {
  const stateDir = path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local'), 'hydra-bane');
  const l = loadPlan({ stateDir, sid: currentUserSid(), now: () => new Date() } as Context, id);
  if (!l.ok) return { command: 'plan_summary', ok: false, data: null, error: { code: l.code, message: l.detail } };
  const p = l.plan;
  return { command: 'plan_summary', ok: true, data: { plan_id: p.id, hash: p.hash, expires_at: p.expiresAt, summary: summarize(p),
    items: p.items.map((i) => ({ id: i.id, title: i.title, bytes: i.bytes, risk: i.risk, reversible: i.reversible, targets: i.targets.slice(0, 20) })) } };
}

async function runTool(name: string, a: Json): Promise<Json> {
  switch (name) {
    case 'scan': return cli(['scan', ...scope(a)]);
    case 'explain': return cli(['explain', val(a.id, 'id', ID), ...scope(a)]);
    case 'analyze': return cli(['analyze', ...(a.path === undefined ? [] : [val(a.path, 'path')])]);
    case 'programs': return cli(['programs']);
    case 'report_preview': return cli(['report', val(a.id, 'id', ID), ...(a.note === undefined ? [] : ['--note', val(a.note, 'note', /^[^\0]{0,500}$/)])]);
    case 'plan': {
      const select = list(a.select, 'select', ID);
      if (a.all_safe !== undefined && typeof a.all_safe !== 'boolean') throw new BadArgs('all_safe must be a boolean');
      if (!select.length && a.all_safe !== true) throw new BadArgs('pass select (scan ids) or all_safe: true');
      return cli(['plan', ...(a.all_safe === true ? ['--all-safe'] : ['--select', select.join(',')]), ...scope(a)]);
    }
    case 'plan_summary': return planSummary(val(a.plan_id, 'plan_id', /^[a-z0-9]{1,64}$/));
    case 'ledger_verify': return cli(['ledger']);
  }
  throw new Error('unreachable');
}

const TOOL_NAMES = new Set(TOOLS.map((t) => t.name));
type Reply = { result: Json } | { error: { code: number; message: string; data?: unknown } };
const complete = (r: Json): Reply => ({ result: { resultType: 'complete', ...r } });

async function callTool(p: Json): Promise<Reply> {
  const name = p.name;
  if (typeof name !== 'string' || !TOOL_NAMES.has(name)) return { error: { code: -32602, message: `Unknown tool: ${String(name)}` } };
  const args = (p.arguments ?? {}) as Json;
  if (typeof args !== 'object' || Array.isArray(args)) return { error: { code: -32602, message: 'arguments must be an object' } };
  try {
    const out = await runTool(name, args);
    const next = name === 'plan' && out.ok ? `Next: call plan_summary with this plan_id and show it to the human. ${APPROVAL}` : APPROVAL;
    const body = { ...out, next };
    return complete({ content: [{ type: 'text', text: JSON.stringify(body) }], structuredContent: body, isError: out.ok === false });
  } catch (e) {
    return complete({ content: [{ type: 'text', text: `${(e as Error).message}\n${APPROVAL}` }], isError: true });
  }
}

export async function handle(method: string, params: Json): Promise<Reply> {
  const meta = (params._meta ?? {}) as Json;
  const requested = meta[VERSION_KEY];
  if (requested !== undefined && !MODERN_VERSIONS.includes(requested as string))
    return { error: { code: -32022, message: 'Unsupported protocol version', data: { supported: SUPPORTED, requested } } };
  switch (method) {
    case 'initialize': {
      const want = params.protocolVersion;
      const protocolVersion = typeof want === 'string' && LEGACY_VERSIONS.includes(want) ? want : LEGACY_VERSIONS[0]!;
      return { result: { protocolVersion, capabilities: { tools: {} }, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS } };
    }
    case 'server/discover':
      return complete({ supportedVersions: SUPPORTED, capabilities: { tools: {} }, _meta: { 'io.modelcontextprotocol/serverInfo': SERVER_INFO }, instructions: INSTRUCTIONS });
    case 'ping': return complete({});
    case 'tools/list': return complete({ tools: TOOLS });
    case 'tools/call': return callTool(params);
    default: return { error: { code: -32601, message: `Method not found: ${method}` } };
  }
}

export function serve(input: Readable, output: Writable): Promise<void> {
  const send = (m: Json) => output.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n');
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg: Json;
    try { msg = JSON.parse(line) as Json; } catch { send({ id: null, error: { code: -32700, message: 'Parse error' } }); return; }
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) { send({ id: null, error: { code: -32600, message: 'Invalid Request' } }); return; }
    const id = msg.id;
    const isRequest = typeof id === 'string' || typeof id === 'number';
    if (typeof msg.method !== 'string') { if (isRequest) send({ id, error: { code: -32600, message: 'Invalid Request' } }); return; }
    if (!isRequest) return; // notifications (notifications/initialized, cancelled, ...) need no reply
    const params = (msg.params && typeof msg.params === 'object' ? msg.params : {}) as Json;
    handle(msg.method, params).then((r) => send({ id, ...r }), (e: Error) => send({ id, error: { code: -32603, message: e.message } }));
  });
  return new Promise((resolve) => rl.on('close', resolve));
}
